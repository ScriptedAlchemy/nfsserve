use crate::context::RPCContext;
use crate::rpcwire::handle_rpc;
use crate::transaction_tracker::TransactionTracker;
use crate::vfs::NFSFileSystem;
use anyhow;
use async_trait::async_trait;
use futures::stream::{self, FuturesUnordered};
use futures::StreamExt;
use std::future::Future;
use std::io::Cursor;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::{io, net::IpAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

// Bound both sides of an RPC for its full wire lifetime. These are wire-byte
// credits, not an RSS limit: XDR and VFS decoding can create additional owned
// copies. The credits make that amplification finite. A READ reply remains
// charged until the client consumes it, so neither a count-only nor a
// request-only limit is sufficient.
const MAX_INFLIGHT_REQUESTS: usize = 32;
pub(crate) const MAX_RPC_RECORD_BYTES: usize = 2 * 1024 * 1024;
const CONNECTION_INFLIGHT_BYTES: usize = 64 * 1024 * 1024;
const GLOBAL_INFLIGHT_BYTES: usize = 256 * 1024 * 1024;
// A partial first record can charge one full record per connection. Preserve
// half the global budget for clients that are still making progress.
const MAX_ACTIVE_CONNECTIONS: usize = GLOBAL_INFLIGHT_BYTES / MAX_RPC_RECORD_BYTES / 2;
const HEADER_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const FRAGMENT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const RECORD_ASSEMBLY_TIMEOUT: Duration = Duration::from_secs(120);
const REPLY_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const REPLY_TOTAL_TIMEOUT: Duration = Duration::from_secs(120);

static NEXT_CONNECTION_INCARNATION: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy)]
struct TransportLimits {
    max_inflight_requests: usize,
    max_record_bytes: usize,
    connection_inflight_bytes: usize,
    max_connections: usize,
    header_idle_timeout: Duration,
    fragment_idle_timeout: Duration,
    record_assembly_timeout: Duration,
    reply_idle_timeout: Duration,
    reply_total_timeout: Duration,
}

impl Default for TransportLimits {
    fn default() -> Self {
        Self {
            max_inflight_requests: MAX_INFLIGHT_REQUESTS,
            max_record_bytes: MAX_RPC_RECORD_BYTES,
            connection_inflight_bytes: CONNECTION_INFLIGHT_BYTES,
            max_connections: MAX_ACTIVE_CONNECTIONS,
            header_idle_timeout: HEADER_IDLE_TIMEOUT,
            fragment_idle_timeout: FRAGMENT_IDLE_TIMEOUT,
            record_assembly_timeout: RECORD_ASSEMBLY_TIMEOUT,
            reply_idle_timeout: REPLY_IDLE_TIMEOUT,
            reply_total_timeout: REPLY_TOTAL_TIMEOUT,
        }
    }
}

struct AdmissionCredit {
    _connection: OwnedSemaphorePermit,
    _global: OwnedSemaphorePermit,
}

struct AdmittedRecord {
    bytes: Vec<u8>,
    credit: AdmissionCredit,
}

type RpcFuture =
    Pin<Box<dyn Future<Output = (anyhow::Result<Option<Vec<u8>>>, AdmissionCredit)> + Send>>;
type Reply = (Vec<u8>, AdmissionCredit);

/// A NFS Tcp Connection Handler
pub struct NFSTcpListener<T: NFSFileSystem + Send + Sync + 'static> {
    listener: TcpListener,
    port: u16,
    arcfs: Arc<T>,
    mount_signal: Option<mpsc::Sender<bool>>,
    export_name: Arc<String>,
    transaction_tracker: Arc<TransactionTracker>,
    transport_budget: Arc<Semaphore>,
    connection_slots: Arc<Semaphore>,
    transport_limits: TransportLimits,
}

pub fn generate_host_ip(hostnum: u16) -> String {
    format!(
        "127.88.{}.{}",
        ((hostnum >> 8) & 0xFF) as u8,
        (hostnum & 0xFF) as u8
    )
}

/// processes an established socket
async fn process_socket(
    socket: tokio::net::TcpStream,
    context: RPCContext,
    shutdown: CancellationToken,
    limits: TransportLimits,
    global_budget: Arc<Semaphore>,
    _connection_slot: OwnedSemaphorePermit,
) -> Result<(), anyhow::Error> {
    let _ = socket.set_nodelay(true);
    let (reader, writer) = socket.into_split();
    process_stream(reader, writer, context, shutdown, limits, global_budget).await
}

async fn read_with_idle_timeout<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut [u8],
    idle_timeout: Duration,
    phase: &'static str,
) -> io::Result<usize> {
    tokio::time::timeout(idle_timeout, reader.read(buf))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, format!("{phase} idle timeout")))?
}

async fn read_exact_with_idle_timeout<R: AsyncRead + Unpin>(
    reader: &mut R,
    mut buf: &mut [u8],
    idle_timeout: Duration,
    phase: &'static str,
) -> io::Result<()> {
    while !buf.is_empty() {
        let read = read_with_idle_timeout(reader, buf, idle_timeout, phase).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("connection closed during {phase}"),
            ));
        }
        buf = &mut buf[read..];
    }
    Ok(())
}

async fn write_all_with_idle_timeout<W: AsyncWrite + Unpin>(
    writer: &mut W,
    mut buf: &[u8],
    idle_timeout: Duration,
) -> io::Result<()> {
    while !buf.is_empty() {
        let written = tokio::time::timeout(idle_timeout, writer.write(buf))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "RPC reply idle timeout"))??;
        if written == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "connection stopped accepting an RPC reply",
            ));
        }
        buf = &buf[written..];
    }
    Ok(())
}

async fn write_record_with_idle_timeout<W: AsyncWrite + Unpin>(
    writer: &mut W,
    reply: &[u8],
    idle_timeout: Duration,
) -> anyhow::Result<()> {
    let length = u32::try_from(reply.len())
        .map_err(|_| anyhow::anyhow!("RPC reply length exceeds record marker capacity"))?;
    if length >= 1 << 31 {
        return Err(anyhow::anyhow!(
            "RPC reply length exceeds record marker capacity"
        ));
    }
    let marker = (length | (1 << 31)).to_be_bytes();
    write_all_with_idle_timeout(writer, &marker, idle_timeout).await?;
    write_all_with_idle_timeout(writer, reply, idle_timeout).await?;
    Ok(())
}

async fn write_record_with_deadlines<W: AsyncWrite + Unpin>(
    writer: &mut W,
    reply: &[u8],
    idle_timeout: Duration,
    total_timeout: Duration,
) -> anyhow::Result<()> {
    tokio::time::timeout(
        total_timeout,
        write_record_with_idle_timeout(writer, reply, idle_timeout),
    )
    .await
    .map_err(|_| anyhow::anyhow!("RPC reply total timeout"))?
}

async fn read_first_marker<R: AsyncRead + Unpin>(
    reader: &mut R,
    idle_timeout: Duration,
) -> io::Result<Option<u32>> {
    let mut marker = [0_u8; 4];
    let mut filled = 0;
    while filled < marker.len() {
        let read = read_with_idle_timeout(
            reader,
            &mut marker[filled..],
            idle_timeout,
            "RPC record header",
        )
        .await?;
        if read == 0 {
            if filled == 0 {
                return Ok(None);
            }
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed during RPC record header",
            ));
        }
        filled += read;
    }
    Ok(Some(u32::from_be_bytes(marker)))
}

async fn read_admitted_record<R: AsyncRead + Unpin>(
    reader: &mut R,
    limits: TransportLimits,
    connection_budget: Arc<Semaphore>,
    global_budget: Arc<Semaphore>,
) -> anyhow::Result<Option<AdmittedRecord>> {
    tokio::time::timeout(
        limits.record_assembly_timeout,
        read_admitted_record_inner(reader, limits, connection_budget, global_budget),
    )
    .await
    .map_err(|_| anyhow::anyhow!("RPC record assembly timeout"))?
}

async fn read_admitted_record_inner<R: AsyncRead + Unpin>(
    reader: &mut R,
    limits: TransportLimits,
    connection_budget: Arc<Semaphore>,
    global_budget: Arc<Semaphore>,
) -> anyhow::Result<Option<AdmittedRecord>> {
    let Some(mut marker) = read_first_marker(reader, limits.header_idle_timeout).await? else {
        return Ok(None);
    };
    let first_length = (marker & 0x7fff_ffff) as usize;
    if first_length > limits.max_record_bytes {
        return Err(anyhow::anyhow!(
            "RPC record fragment length {first_length} exceeds limit {}",
            limits.max_record_bytes
        ));
    }

    // Reserve before growing the record Vec. Charging the maximum record size
    // also covers a small READ request whose reply can be much larger.
    let cost = u32::try_from(limits.max_record_bytes)
        .map_err(|_| anyhow::anyhow!("RPC record limit exceeds semaphore capacity"))?;
    let global = global_budget.acquire_many_owned(cost).await?;
    let connection = connection_budget.acquire_many_owned(cost).await?;
    let credit = AdmissionCredit {
        _connection: connection,
        _global: global,
    };
    let mut record = Vec::new();

    loop {
        let is_last = marker & (1 << 31) != 0;
        let length = (marker & 0x7fff_ffff) as usize;
        let new_length = record
            .len()
            .checked_add(length)
            .ok_or_else(|| anyhow::anyhow!("RPC record length overflow"))?;
        if new_length > limits.max_record_bytes {
            return Err(anyhow::anyhow!(
                "RPC record length {new_length} exceeds limit {}",
                limits.max_record_bytes
            ));
        }
        record
            .try_reserve_exact(length)
            .map_err(|error| anyhow::anyhow!("unable to reserve RPC record: {error}"))?;
        record.resize(new_length, 0);
        read_exact_with_idle_timeout(
            reader,
            &mut record[new_length - length..],
            limits.fragment_idle_timeout,
            "RPC record fragment",
        )
        .await?;
        if is_last {
            return Ok(Some(AdmittedRecord {
                bytes: record,
                credit,
            }));
        }
        let mut next_marker = [0_u8; 4];
        read_exact_with_idle_timeout(
            reader,
            &mut next_marker,
            limits.header_idle_timeout,
            "RPC record header",
        )
        .await?;
        marker = u32::from_be_bytes(next_marker);
    }
}

async fn process_record(
    bytes: Vec<u8>,
    context: RPCContext,
    connection_incarnation: u64,
) -> anyhow::Result<Option<Vec<u8>>> {
    let mut output = Vec::new();
    let should_reply = handle_rpc(
        &mut Cursor::new(bytes),
        &mut Cursor::new(&mut output),
        context,
        connection_incarnation,
    )
    .await?;
    Ok(should_reply.then_some(output))
}

async fn process_stream<R, W>(
    reader: R,
    writer: W,
    context: RPCContext,
    shutdown: CancellationToken,
    limits: TransportLimits,
    global_budget: Arc<Semaphore>,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    assert!(limits.max_inflight_requests > 0);
    assert!(limits.max_record_bytes > 0);
    assert!(limits.connection_inflight_bytes >= limits.max_record_bytes);
    let connection_budget = Arc::new(Semaphore::new(limits.connection_inflight_bytes));
    let connection_incarnation = NEXT_CONNECTION_INCARNATION.fetch_add(1, Ordering::Relaxed);
    let command_connection_budget = Arc::clone(&connection_budget);
    let command_global_budget = Arc::clone(&global_budget);
    // Keep read and write progress independently pollable. With one coupled
    // socket loop, waiting for input-buffer space can prevent replies from
    // draining and deadlock a bounded reply channel.
    let mut commands = Box::pin(stream::unfold(
        (reader, false),
        move |(mut reader, stopped)| {
            let connection_budget = Arc::clone(&command_connection_budget);
            let global_budget = Arc::clone(&command_global_budget);
            async move {
                if stopped {
                    return None;
                }
                match read_admitted_record(&mut reader, limits, connection_budget, global_budget)
                    .await
                {
                    Ok(None) => None,
                    Ok(Some(record)) => Some((Ok(record), (reader, false))),
                    Err(error) => Some((Err(error), (reader, true))),
                }
            }
        },
    ));
    let (reply_tx, reply_rx) = mpsc::channel::<Reply>(limits.max_inflight_requests);
    let reply_limit = limits.max_record_bytes;
    let reply_idle_timeout = limits.reply_idle_timeout;
    let reply_total_timeout = limits.reply_total_timeout;
    let mut replies = Box::pin(stream::unfold(
        (writer, reply_rx, false),
        move |(mut writer, mut receiver, writer_failed)| async move {
            let (reply, credit) = receiver.recv().await?;
            let result = if writer_failed {
                Ok(())
            } else if reply.len() > reply_limit {
                Err(anyhow::anyhow!(
                    "RPC reply length {} exceeds limit {reply_limit}",
                    reply.len()
                ))
            } else {
                write_record_with_deadlines(
                    &mut writer,
                    &reply,
                    reply_idle_timeout,
                    reply_total_timeout,
                )
                .await
            };
            drop(credit);
            let writer_failed = writer_failed || result.is_err();
            Some((result, (writer, receiver, writer_failed)))
        },
    ));
    let mut inflight = FuturesUnordered::<RpcFuture>::new();
    let mut accepting = true;
    let mut unwritten = 0usize;
    let mut terminal_error = None;

    loop {
        if accepting && shutdown.is_cancelled() {
            accepting = false;
        }
        // A request owns its count slot and byte credits until its reply has
        // reached the socket, or has been deliberately discarded after a
        // terminal writer failure.
        let reading = accepting && inflight.len() + unwritten < limits.max_inflight_requests;
        if !reading && inflight.is_empty() && unwritten == 0 {
            return match terminal_error {
                Some(error) => Err(error),
                None => Ok(()),
            };
        }

        tokio::select! {
            biased;
            Some(result) = replies.next(), if unwritten > 0 => {
                unwritten -= 1;
                if let Err(error) = result {
                    accepting = false;
                    terminal_error.get_or_insert(error);
                }
            }
            Some((result, credit)) = inflight.next(), if !inflight.is_empty() => {
                match result {
                    Ok(Some(reply)) => {
                        unwritten += 1;
                        assert!(
                            reply_tx.try_send((reply, credit)).is_ok(),
                            "reply channel is sized for the in-flight cap"
                        );
                    }
                    Ok(None) => drop(credit),
                    Err(error) => {
                        drop(credit);
                        accepting = false;
                        terminal_error.get_or_insert(error);
                    }
                }
            }
            _ = shutdown.cancelled(), if accepting => accepting = false,
            next = commands.next(), if reading => {
                match next {
                    None => accepting = false,
                    Some(Err(error)) => {
                        accepting = false;
                        terminal_error.get_or_insert(error);
                    }
                    Some(Ok(record)) => {
                        let record_context = context.clone();
                        inflight.push(Box::pin(async move {
                            let result = process_record(
                                record.bytes,
                                record_context,
                                connection_incarnation,
                            )
                            .await;
                            (result, record.credit)
                        }));
                    }
                }
            }
        }
    }
}

#[async_trait]
pub trait NFSTcp: Send + Sync {
    /// Gets the true listening port. Useful if the bound port number is 0
    fn get_listen_port(&self) -> u16;

    /// Gets the true listening IP. Useful on windows when the IP may be random
    fn get_listen_ip(&self) -> IpAddr;

    /// Sets a mount listener. A "true" signal will be sent on a mount
    /// and a "false" will be sent on an unmount
    fn set_mount_listener(&mut self, signal: mpsc::Sender<bool>);

    /// Handles incoming connections until shutdown is signaled.
    async fn handle_with_shutdown(&self, shutdown: CancellationToken) -> io::Result<()>;
}

impl<T: NFSFileSystem + Send + Sync + 'static> NFSTcpListener<T> {
    /// Binds to a ipstr of the form [ip address]:port. For instance
    /// "127.0.0.1:12000". fs is an instance of an implementation
    /// of NFSFileSystem.
    pub async fn bind(socket: SocketAddr, fs: T) -> io::Result<NFSTcpListener<T>> {
        let arcfs: Arc<T> = Arc::new(fs);

        NFSTcpListener::bind_internal(socket, arcfs).await
    }

    async fn bind_internal(socket: SocketAddr, arcfs: Arc<T>) -> io::Result<NFSTcpListener<T>> {
        let listener = TcpListener::bind(&socket).await?;
        info!("Listening on {:?}", &socket);

        let port = match listener.local_addr().unwrap() {
            SocketAddr::V4(s) => s.port(),
            SocketAddr::V6(s) => s.port(),
        };
        let transport_limits = TransportLimits::default();
        Ok(NFSTcpListener {
            listener,
            port,
            arcfs,
            mount_signal: None,
            export_name: Arc::from("/".to_string()),
            transaction_tracker: Arc::new(TransactionTracker::new(Duration::from_secs(60))),
            transport_budget: Arc::new(Semaphore::new(GLOBAL_INFLIGHT_BYTES)),
            connection_slots: Arc::new(Semaphore::new(transport_limits.max_connections)),
            transport_limits,
        })
    }

    /// Sets an optional NFS export name.
    ///
    /// - `export_name`: The desired export name without slashes.
    ///
    /// Example: Name `foo` results in the export path `/foo`.
    /// Default path is `/` if not set.
    pub fn with_export_name<S: AsRef<str>>(&mut self, export_name: S) {
        self.export_name = Arc::new(format!(
            "/{}",
            export_name
                .as_ref()
                .trim_end_matches('/')
                .trim_start_matches('/')
        ))
    }
}

#[async_trait]
impl<T: NFSFileSystem + Send + Sync + 'static> NFSTcp for NFSTcpListener<T> {
    /// Gets the true listening port. Useful if the bound port number is 0
    fn get_listen_port(&self) -> u16 {
        let addr = self.listener.local_addr().unwrap();
        addr.port()
    }

    fn get_listen_ip(&self) -> IpAddr {
        let addr = self.listener.local_addr().unwrap();
        addr.ip()
    }

    /// Sets a mount listener. A "true" signal will be sent on a mount
    /// and a "false" will be sent on an unmount
    fn set_mount_listener(&mut self, signal: mpsc::Sender<bool>) {
        self.mount_signal = Some(signal);
    }

    /// Handles incoming connections until shutdown is signaled.
    async fn handle_with_shutdown(&self, shutdown: CancellationToken) -> io::Result<()> {
        let mut clients = JoinSet::new();
        let mut accept_error = None;
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    info!("NFS TCP server shutting down on {}", self.listener.local_addr().unwrap());
                    break;
                }
                Some(result) = clients.join_next(), if !clients.is_empty() => {
                    match result {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => debug!("NFS client handler stopped: {error:#}"),
                        Err(error) => debug!("NFS client handler task failed: {error}"),
                    }
                }
                result = self.listener.accept(), if self.connection_slots.available_permits() > 0 => {
                    let (socket, _) = match result {
                        Ok(connection) => connection,
                        Err(error) => {
                            accept_error = Some(error);
                            break;
                        }
                    };
                    let connection_slot = Arc::clone(&self.connection_slots)
                        .try_acquire_owned()
                        .map_err(|_| io::Error::other("NFS connection admission race"))?;
                    let context = RPCContext {
                        local_port: self.port,
                        client_addr: socket.peer_addr().unwrap().to_string(),
                        auth: crate::rpc::auth_unix::default(),
                        vfs: self.arcfs.clone(),
                        mount_signal: self.mount_signal.clone(),
                        export_name: self.export_name.clone(),
                        transaction_tracker: self.transaction_tracker.clone(),
                    };
                    info!("Accepting connection from {}", context.client_addr);
                    debug!("Accepting socket {:?} {:?}", socket, context);
                    let client_shutdown = shutdown.child_token();
                    let global_budget = Arc::clone(&self.transport_budget);
                    clients.spawn(process_socket(
                        socket,
                        context,
                        client_shutdown,
                        self.transport_limits,
                        global_budget,
                        connection_slot,
                    ));
                }
            }
        }

        while let Some(result) = clients.join_next().await {
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => debug!("NFS client handler stopped during shutdown: {error:#}"),
                Err(error) => debug!("NFS client handler task failed during shutdown: {error}"),
            }
        }

        match accept_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nfs::{
        fattr3, fileid3, filename3, ftype3, nfspath3, nfsstat3, sattr3, specdata3, stable_how,
    };
    use crate::vfs::test_support::ContextRecordingFs;
    use crate::vfs::{AuthContext, DirEntry, ReadDirResult, VFSCapabilities};
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::sync::{Notify, Semaphore};

    struct PendingWriter;

    impl AsyncWrite for PendingWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            _: &[u8],
        ) -> std::task::Poll<io::Result<usize>> {
            std::task::Poll::Pending
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    struct DripWriter {
        delay: Duration,
        sleep: Pin<Box<tokio::time::Sleep>>,
    }

    impl DripWriter {
        fn new(delay: Duration) -> Self {
            Self {
                delay,
                sleep: Box::pin(tokio::time::sleep(Duration::ZERO)),
            }
        }
    }

    impl AsyncWrite for DripWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<io::Result<usize>> {
            if self.sleep.as_mut().poll(cx).is_pending() {
                return std::task::Poll::Pending;
            }
            let delay = self.delay;
            self.sleep
                .as_mut()
                .reset(tokio::time::Instant::now() + delay);
            std::task::Poll::Ready(Ok(buf.len().min(1)))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    struct BlockingWriteFs {
        started: AtomicUsize,
        reads: AtomicUsize,
        readdir_calls: AtomicUsize,
        readdir_max_entries: AtomicUsize,
        started_notify: Notify,
        release: Semaphore,
    }

    impl BlockingWriteFs {
        fn new() -> Self {
            Self {
                started: AtomicUsize::new(0),
                reads: AtomicUsize::new(0),
                readdir_calls: AtomicUsize::new(0),
                readdir_max_entries: AtomicUsize::new(0),
                started_notify: Notify::new(),
                release: Semaphore::new(0),
            }
        }

        async fn wait_for_started(&self, target: usize) {
            while self.started.load(Ordering::SeqCst) < target {
                self.started_notify.notified().await;
            }
        }
    }

    #[async_trait]
    impl NFSFileSystem for BlockingWriteFs {
        fn capabilities(&self) -> VFSCapabilities {
            VFSCapabilities::ReadWrite
        }

        fn root_dir(&self) -> fileid3 {
            1
        }

        async fn lookup(
            &self,
            _: &AuthContext,
            _: fileid3,
            _: &filename3,
        ) -> Result<fileid3, nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }

        async fn getattr(&self, _: &AuthContext, _: fileid3) -> Result<fattr3, nfsstat3> {
            Ok(fattr3::default())
        }

        async fn setattr(
            &self,
            _: &AuthContext,
            _: fileid3,
            _: sattr3,
        ) -> Result<fattr3, nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }

        async fn read(
            &self,
            _: &AuthContext,
            _: fileid3,
            _: u64,
            _: u32,
        ) -> Result<(Vec<u8>, bool), nfsstat3> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }

        async fn write(
            &self,
            _: &AuthContext,
            _: fileid3,
            _: u64,
            _: &[u8],
        ) -> Result<fattr3, nfsstat3> {
            self.started.fetch_add(1, Ordering::SeqCst);
            self.started_notify.notify_waiters();
            self.release.acquire().await.unwrap().forget();
            Ok(fattr3::default())
        }

        async fn create(
            &self,
            _: &AuthContext,
            _: fileid3,
            _: &filename3,
            _: sattr3,
        ) -> Result<(fileid3, fattr3), nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }

        async fn create_exclusive(
            &self,
            _: &AuthContext,
            _: fileid3,
            _: &filename3,
        ) -> Result<fileid3, nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }

        async fn mkdir(
            &self,
            _: &AuthContext,
            _: fileid3,
            _: &filename3,
            _: &sattr3,
        ) -> Result<(fileid3, fattr3), nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }

        async fn remove(&self, _: &AuthContext, _: fileid3, _: &filename3) -> Result<(), nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }

        async fn rename(
            &self,
            _: &AuthContext,
            _: fileid3,
            _: &filename3,
            _: fileid3,
            _: &filename3,
        ) -> Result<(), nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }

        async fn readdir(
            &self,
            _: &AuthContext,
            _: fileid3,
            _: fileid3,
            max_entries: usize,
        ) -> Result<ReadDirResult, nfsstat3> {
            self.readdir_calls.fetch_add(1, Ordering::SeqCst);
            self.readdir_max_entries
                .store(max_entries, Ordering::SeqCst);
            let entries = [
                DirEntry {
                    fileid: 1,
                    name: crate::nfs::nfsstring(b".".to_vec()),
                    attr: fattr3 {
                        fileid: 1,
                        ..fattr3::default()
                    },
                    cookie: 1,
                },
                DirEntry {
                    fileid: 1,
                    name: crate::nfs::nfsstring(b"..".to_vec()),
                    attr: fattr3 {
                        fileid: 1,
                        ..fattr3::default()
                    },
                    cookie: 2,
                },
            ];
            let end = max_entries >= entries.len();
            Ok(ReadDirResult {
                entries: entries.into_iter().take(max_entries).collect(),
                end,
            })
        }

        async fn symlink(
            &self,
            _: &AuthContext,
            _: fileid3,
            _: &filename3,
            _: &nfspath3,
            _: &sattr3,
        ) -> Result<(fileid3, fattr3), nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }

        async fn readlink(&self, _: &AuthContext, _: fileid3) -> Result<nfspath3, nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }

        async fn mknod(
            &self,
            _: &AuthContext,
            _: fileid3,
            _: &filename3,
            _: ftype3,
            _: &sattr3,
            _: Option<&specdata3>,
        ) -> Result<(fileid3, fattr3), nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }

        async fn link(
            &self,
            _: &AuthContext,
            _: fileid3,
            _: fileid3,
            _: &filename3,
        ) -> Result<(), nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
    }

    fn write_call(xid: u32, bytes: usize) -> Vec<u8> {
        let mut call = Vec::with_capacity(bytes + 96);
        {
            let mut push_u32 = |value: u32| call.extend_from_slice(&value.to_be_bytes());
            push_u32(xid);
            push_u32(0); // CALL
            push_u32(2); // RPC version
            push_u32(100003); // NFS
            push_u32(3); // NFSv3
            push_u32(7); // WRITE
            for _ in 0..4 {
                push_u32(0); // AUTH_NULL cred + verifier
            }
            push_u32(16);
        }
        call.extend_from_slice(&0u64.to_le_bytes());
        call.extend_from_slice(&1u64.to_le_bytes());
        call.extend_from_slice(&0u64.to_be_bytes());
        call.extend_from_slice(&(bytes as u32).to_be_bytes());
        call.extend_from_slice(&2u32.to_be_bytes()); // FILE_SYNC
        call.extend_from_slice(&(bytes as u32).to_be_bytes());
        call.resize(call.len() + bytes, 0xA5);
        call
    }

    fn null_call(xid: u32) -> Vec<u8> {
        let mut call = Vec::with_capacity(40);
        for value in [xid, 0, 2, 100003, 3, 0, 0, 0, 0, 0] {
            call.extend_from_slice(&value.to_be_bytes());
        }
        call
    }

    fn read_call(xid: u32, count: u32) -> Vec<u8> {
        let mut call = Vec::with_capacity(80);
        for value in [xid, 0, 2, 100003, 3, 6, 0, 0, 0, 0, 16] {
            call.extend_from_slice(&value.to_be_bytes());
        }
        call.extend_from_slice(&0u64.to_le_bytes());
        call.extend_from_slice(&1u64.to_le_bytes());
        call.extend_from_slice(&0u64.to_be_bytes());
        call.extend_from_slice(&count.to_be_bytes());
        call
    }

    fn readdir_call(xid: u32, plus: bool, dircount: u32, maxcount: u32) -> Vec<u8> {
        let mut call = Vec::with_capacity(96);
        for value in [
            xid,
            0,
            2,
            100003,
            3,
            if plus { 17 } else { 16 },
            0,
            0,
            0,
            0,
            16,
        ] {
            call.extend_from_slice(&value.to_be_bytes());
        }
        call.extend_from_slice(&0u64.to_le_bytes());
        call.extend_from_slice(&1u64.to_le_bytes());
        call.extend_from_slice(&0u64.to_be_bytes()); // cookie
        call.extend_from_slice(&[0; 8]); // cookie verifier
        call.extend_from_slice(&dircount.to_be_bytes());
        if plus {
            call.extend_from_slice(&maxcount.to_be_bytes());
        }
        call
    }

    fn test_context(fs: Arc<BlockingWriteFs>) -> RPCContext {
        RPCContext {
            local_port: 2049,
            client_addr: "127.0.0.1:12345".to_string(),
            auth: crate::rpc::auth_unix::default(),
            vfs: fs,
            mount_signal: None,
            export_name: Arc::new("/".to_string()),
            transaction_tracker: Arc::new(TransactionTracker::new(Duration::from_secs(60))),
        }
    }

    async fn send_record<W: AsyncWrite + Unpin>(socket: &mut W, record: &[u8]) {
        let marker = (record.len() as u32) | (1 << 31);
        socket.write_all(&marker.to_be_bytes()).await.unwrap();
        socket.write_all(record).await.unwrap();
    }

    async fn read_record<R: tokio::io::AsyncRead + Unpin>(socket: &mut R) -> io::Result<Vec<u8>> {
        let mut marker = [0_u8; 4];
        socket.read_exact(&mut marker).await?;
        let length = (u32::from_be_bytes(marker) & 0x7fff_ffff) as usize;
        let mut record = vec![0; length];
        socket.read_exact(&mut record).await?;
        Ok(record)
    }

    async fn execute_one_call(fs: Arc<BlockingWriteFs>, call: Vec<u8>) -> Vec<u8> {
        let context = test_context(fs);
        let limits = TransportLimits::default();
        let global_budget = Arc::new(Semaphore::new(GLOBAL_INFLIGHT_BYTES));
        let (server_socket, client_socket) = tokio::io::duplex(4 * 1024 * 1024);
        let (server_reader, server_writer) = tokio::io::split(server_socket);
        let (mut client_reader, mut client_writer) = tokio::io::split(client_socket);
        let server = tokio::spawn(process_stream(
            server_reader,
            server_writer,
            context,
            CancellationToken::new(),
            limits,
            global_budget,
        ));
        send_record(&mut client_writer, &call).await;
        client_writer.shutdown().await.unwrap();
        let reply = read_record(&mut client_reader).await.unwrap();
        server.await.unwrap().unwrap();
        reply
    }

    async fn wait_for_permits(semaphore: &Semaphore, expected: usize) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while semaphore.available_permits() != expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "semaphore has {} permits, expected {expected}",
                semaphore.available_permits()
            )
        });
    }

    fn nfs_status(reply: &[u8]) -> u32 {
        u32::from_be_bytes(reply[24..28].try_into().unwrap())
    }

    #[derive(Debug, PartialEq)]
    struct ParsedDirectoryReply {
        names: Vec<Vec<u8>>,
        eof: bool,
    }

    fn take_u32(reply: &[u8], offset: &mut usize) -> u32 {
        let value = u32::from_be_bytes(reply[*offset..*offset + 4].try_into().unwrap());
        *offset += 4;
        value
    }

    fn skip_bytes(reply: &[u8], offset: &mut usize, bytes: usize) {
        assert!(*offset + bytes <= reply.len());
        *offset += bytes;
    }

    fn parse_directory_reply(reply: &[u8], plus: bool) -> ParsedDirectoryReply {
        assert_eq!(nfs_status(reply), nfsstat3::NFS3_OK as u32);
        let mut offset = 28;
        let attributes_follow = take_u32(reply, &mut offset) != 0;
        if attributes_follow {
            skip_bytes(reply, &mut offset, 84);
        }
        skip_bytes(reply, &mut offset, 8); // cookie verifier

        let mut names = Vec::new();
        while take_u32(reply, &mut offset) != 0 {
            skip_bytes(reply, &mut offset, 8); // fileid
            let name_len = take_u32(reply, &mut offset) as usize;
            let name = reply[offset..offset + name_len].to_vec();
            skip_bytes(reply, &mut offset, name_len.div_ceil(4) * 4);
            skip_bytes(reply, &mut offset, 8); // cookie
            if plus {
                let entry_attributes_follow = take_u32(reply, &mut offset) != 0;
                if entry_attributes_follow {
                    skip_bytes(reply, &mut offset, 84);
                }
                let handle_follows = take_u32(reply, &mut offset) != 0;
                if handle_follows {
                    let handle_len = take_u32(reply, &mut offset) as usize;
                    skip_bytes(reply, &mut offset, handle_len.div_ceil(4) * 4);
                }
            }
            names.push(name);
        }
        let eof = take_u32(reply, &mut offset) != 0;
        assert_eq!(offset, reply.len(), "unparsed directory reply bytes");
        ParsedDirectoryReply { names, eof }
    }

    #[tokio::test]
    async fn partial_header_times_out_without_consuming_wire_credit() {
        const RECORD_LIMIT: usize = 1024;
        let limits = TransportLimits {
            max_record_bytes: RECORD_LIMIT,
            connection_inflight_bytes: RECORD_LIMIT,
            header_idle_timeout: Duration::from_millis(40),
            fragment_idle_timeout: Duration::from_millis(40),
            ..TransportLimits::default()
        };
        let global_budget = Arc::new(Semaphore::new(RECORD_LIMIT));
        let (server_socket, mut client) = tokio::io::duplex(64);
        let (server_reader, server_writer) = tokio::io::split(server_socket);
        let server = tokio::spawn(process_stream(
            server_reader,
            server_writer,
            test_context(Arc::new(BlockingWriteFs::new())),
            CancellationToken::new(),
            limits,
            Arc::clone(&global_budget),
        ));

        client.write_all(&[0x80]).await.unwrap();
        let error = tokio::time::timeout(Duration::from_millis(250), server)
            .await
            .expect("partial header did not hit its idle deadline")
            .unwrap()
            .expect_err("partial header unexpectedly succeeded");

        assert!(error.to_string().contains("header idle timeout"));
        assert_eq!(global_budget.available_permits(), RECORD_LIMIT);
    }

    #[tokio::test]
    async fn partial_fragment_times_out_and_releases_wire_credit() {
        const RECORD_LIMIT: usize = 1024;
        let limits = TransportLimits {
            max_record_bytes: RECORD_LIMIT,
            connection_inflight_bytes: RECORD_LIMIT,
            header_idle_timeout: Duration::from_millis(40),
            fragment_idle_timeout: Duration::from_millis(40),
            ..TransportLimits::default()
        };
        let global_budget = Arc::new(Semaphore::new(RECORD_LIMIT));
        let (server_socket, mut client) = tokio::io::duplex(64);
        let (server_reader, server_writer) = tokio::io::split(server_socket);
        let server = tokio::spawn(process_stream(
            server_reader,
            server_writer,
            test_context(Arc::new(BlockingWriteFs::new())),
            CancellationToken::new(),
            limits,
            Arc::clone(&global_budget),
        ));

        client
            .write_all(&((64_u32) | (1 << 31)).to_be_bytes())
            .await
            .unwrap();
        client.write_all(&[0]).await.unwrap();
        wait_for_permits(&global_budget, 0).await;
        let error = tokio::time::timeout(Duration::from_millis(250), server)
            .await
            .expect("partial fragment did not hit its idle deadline")
            .unwrap()
            .expect_err("partial fragment unexpectedly succeeded");

        assert!(error.to_string().contains("fragment idle timeout"));
        assert_eq!(global_budget.available_permits(), RECORD_LIMIT);
    }

    #[tokio::test]
    async fn partial_continuation_header_times_out_and_releases_wire_credit() {
        const RECORD_LIMIT: usize = 1024;
        let limits = TransportLimits {
            max_record_bytes: RECORD_LIMIT,
            connection_inflight_bytes: RECORD_LIMIT,
            header_idle_timeout: Duration::from_millis(40),
            fragment_idle_timeout: Duration::from_millis(40),
            ..TransportLimits::default()
        };
        let global_budget = Arc::new(Semaphore::new(RECORD_LIMIT));
        let (server_socket, mut client) = tokio::io::duplex(64);
        let (server_reader, server_writer) = tokio::io::split(server_socket);
        let server = tokio::spawn(process_stream(
            server_reader,
            server_writer,
            test_context(Arc::new(BlockingWriteFs::new())),
            CancellationToken::new(),
            limits,
            Arc::clone(&global_budget),
        ));

        client.write_all(&0_u32.to_be_bytes()).await.unwrap();
        client.write_all(&[0x80]).await.unwrap();
        wait_for_permits(&global_budget, 0).await;
        let error = tokio::time::timeout(Duration::from_millis(250), server)
            .await
            .expect("partial continuation header did not hit its idle deadline")
            .unwrap()
            .expect_err("partial continuation header unexpectedly succeeded");

        assert!(error.to_string().contains("header idle timeout"));
        assert_eq!(global_budget.available_permits(), RECORD_LIMIT);
    }

    #[tokio::test]
    async fn drip_fed_record_hits_its_total_assembly_deadline() {
        const RECORD_LIMIT: usize = 1024;
        let limits = TransportLimits {
            max_record_bytes: RECORD_LIMIT,
            connection_inflight_bytes: RECORD_LIMIT,
            header_idle_timeout: Duration::from_millis(40),
            fragment_idle_timeout: Duration::from_millis(40),
            record_assembly_timeout: Duration::from_millis(90),
            ..TransportLimits::default()
        };
        let global_budget = Arc::new(Semaphore::new(RECORD_LIMIT));
        let (server_socket, mut client) = tokio::io::duplex(64);
        let (server_reader, server_writer) = tokio::io::split(server_socket);
        let server = tokio::spawn(process_stream(
            server_reader,
            server_writer,
            test_context(Arc::new(BlockingWriteFs::new())),
            CancellationToken::new(),
            limits,
            Arc::clone(&global_budget),
        ));

        let drip = tokio::spawn(async move {
            for byte in [0x80, 0, 0, 64, 0, 0] {
                if client.write_all(&[byte]).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        });
        let error = tokio::time::timeout(Duration::from_millis(250), server)
            .await
            .expect("drip-fed record exceeded its total assembly deadline")
            .unwrap()
            .expect_err("drip-fed record unexpectedly succeeded");
        drip.abort();
        let _ = drip.await;

        assert!(error.to_string().contains("record assembly timeout"));
        assert_eq!(global_budget.available_permits(), RECORD_LIMIT);
    }

    #[tokio::test]
    async fn stalled_reply_times_out_and_releases_wire_credit_during_shutdown() {
        const RECORD_LIMIT: usize = 1024;
        let limits = TransportLimits {
            max_record_bytes: RECORD_LIMIT,
            connection_inflight_bytes: RECORD_LIMIT,
            reply_idle_timeout: Duration::from_millis(40),
            ..TransportLimits::default()
        };
        let global_budget = Arc::new(Semaphore::new(RECORD_LIMIT));
        let (server_reader, mut client) = tokio::io::duplex(256);
        let shutdown = CancellationToken::new();
        let server_shutdown = shutdown.clone();
        let server = tokio::spawn(process_stream(
            server_reader,
            PendingWriter,
            test_context(Arc::new(BlockingWriteFs::new())),
            server_shutdown,
            limits,
            Arc::clone(&global_budget),
        ));

        send_record(&mut client, &null_call(1)).await;
        wait_for_permits(&global_budget, 0).await;
        shutdown.cancel();
        let error = tokio::time::timeout(Duration::from_millis(250), server)
            .await
            .expect("stalled reply prevented shutdown from settling")
            .unwrap()
            .expect_err("stalled reply unexpectedly succeeded");

        assert!(error.to_string().contains("reply idle timeout"));
        assert_eq!(global_budget.available_permits(), RECORD_LIMIT);
    }

    #[tokio::test]
    async fn drip_drained_reply_hits_its_total_deadline_during_shutdown() {
        const RECORD_LIMIT: usize = 1024;
        let limits = TransportLimits {
            max_record_bytes: RECORD_LIMIT,
            connection_inflight_bytes: RECORD_LIMIT,
            reply_idle_timeout: Duration::from_millis(40),
            reply_total_timeout: Duration::from_millis(90),
            ..TransportLimits::default()
        };
        let global_budget = Arc::new(Semaphore::new(RECORD_LIMIT));
        let (server_reader, mut client) = tokio::io::duplex(256);
        let shutdown = CancellationToken::new();
        let server_shutdown = shutdown.clone();
        let server = tokio::spawn(process_stream(
            server_reader,
            DripWriter::new(Duration::from_millis(25)),
            test_context(Arc::new(BlockingWriteFs::new())),
            server_shutdown,
            limits,
            Arc::clone(&global_budget),
        ));

        send_record(&mut client, &null_call(1)).await;
        wait_for_permits(&global_budget, 0).await;
        shutdown.cancel();
        let error = tokio::time::timeout(Duration::from_millis(250), server)
            .await
            .expect("drip-drained reply prevented shutdown from settling")
            .unwrap()
            .expect_err("drip-drained reply unexpectedly succeeded");

        assert!(error.to_string().contains("reply total timeout"));
        assert_eq!(global_budget.available_permits(), RECORD_LIMIT);
    }

    #[tokio::test]
    async fn valid_client_progresses_after_stalled_peers_release_credit() {
        const RECORD_LIMIT: usize = 1024;
        let limits = TransportLimits {
            max_record_bytes: RECORD_LIMIT,
            connection_inflight_bytes: RECORD_LIMIT,
            header_idle_timeout: Duration::from_millis(50),
            fragment_idle_timeout: Duration::from_millis(50),
            ..TransportLimits::default()
        };
        let global_budget = Arc::new(Semaphore::new(2 * RECORD_LIMIT));
        let mut stalled_servers = Vec::new();
        let mut stalled_clients = Vec::new();
        for _ in 0..2 {
            let (server_socket, mut client) = tokio::io::duplex(64);
            let (server_reader, server_writer) = tokio::io::split(server_socket);
            stalled_servers.push(tokio::spawn(process_stream(
                server_reader,
                server_writer,
                test_context(Arc::new(BlockingWriteFs::new())),
                CancellationToken::new(),
                limits,
                Arc::clone(&global_budget),
            )));
            client
                .write_all(&((64_u32) | (1 << 31)).to_be_bytes())
                .await
                .unwrap();
            client.write_all(&[0]).await.unwrap();
            stalled_clients.push(client);
        }
        wait_for_permits(&global_budget, 0).await;

        let (server_socket, client_socket) = tokio::io::duplex(4096);
        let (server_reader, server_writer) = tokio::io::split(server_socket);
        let (mut client_reader, mut client_writer) = tokio::io::split(client_socket);
        let valid_server = tokio::spawn(process_stream(
            server_reader,
            server_writer,
            test_context(Arc::new(BlockingWriteFs::new())),
            CancellationToken::new(),
            limits,
            Arc::clone(&global_budget),
        ));
        send_record(&mut client_writer, &null_call(99)).await;
        let reply =
            tokio::time::timeout(Duration::from_millis(500), read_record(&mut client_reader))
                .await
                .expect("valid client starved behind stalled peers")
                .unwrap();
        assert_eq!(u32::from_be_bytes(reply[..4].try_into().unwrap()), 99);
        client_writer.shutdown().await.unwrap();
        valid_server.await.unwrap().unwrap();

        for server in stalled_servers {
            assert!(server.await.unwrap().is_err());
        }
        drop(stalled_clients);
        assert_eq!(global_budget.available_permits(), 2 * RECORD_LIMIT);
    }

    #[tokio::test]
    async fn listener_admission_bounds_partial_record_connections() {
        let fs = BlockingWriteFs::new();
        let mut listener = NFSTcpListener::bind("127.0.0.1:0".parse().unwrap(), fs)
            .await
            .unwrap();
        listener.transport_limits.max_connections = 1;
        listener.connection_slots = Arc::new(Semaphore::new(1));
        let connection_slots = Arc::clone(&listener.connection_slots);
        let global_budget = Arc::clone(&listener.transport_budget);
        let initial_budget = global_budget.available_permits();
        let port = listener.get_listen_port();
        let shutdown = CancellationToken::new();
        let server_shutdown = shutdown.clone();
        let server =
            tokio::spawn(async move { listener.handle_with_shutdown(server_shutdown).await });

        let mut first = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        first
            .write_all(&((64_u32) | (1 << 31)).to_be_bytes())
            .await
            .unwrap();
        first.write_all(&[0]).await.unwrap();
        wait_for_permits(&global_budget, initial_budget - MAX_RPC_RECORD_BYTES).await;

        let mut second = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        second
            .write_all(&((64_u32) | (1 << 31)).to_be_bytes())
            .await
            .unwrap();
        second.write_all(&[0]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            global_budget.available_permits(),
            initial_budget - MAX_RPC_RECORD_BYTES,
            "listener accepted more partial-record peers than its connection bound"
        );

        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(1), server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(connection_slots.available_permits(), 1);
    }

    #[tokio::test]
    async fn listener_admits_a_valid_client_after_a_stalled_slot_expires() {
        let fs = BlockingWriteFs::new();
        let mut listener = NFSTcpListener::bind("127.0.0.1:0".parse().unwrap(), fs)
            .await
            .unwrap();
        listener.transport_limits.max_connections = 1;
        listener.transport_limits.header_idle_timeout = Duration::from_millis(100);
        listener.transport_limits.fragment_idle_timeout = Duration::from_millis(100);
        listener.connection_slots = Arc::new(Semaphore::new(1));
        let connection_slots = Arc::clone(&listener.connection_slots);
        let port = listener.get_listen_port();
        let shutdown = CancellationToken::new();
        let server_shutdown = shutdown.clone();
        let server =
            tokio::spawn(async move { listener.handle_with_shutdown(server_shutdown).await });

        let mut stalled = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        stalled.write_all(&[0x80]).await.unwrap();
        wait_for_permits(&connection_slots, 0).await;
        let mut valid = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        send_record(&mut valid, &null_call(77)).await;
        let reply = tokio::time::timeout(Duration::from_millis(500), read_record(&mut valid))
            .await
            .expect("valid client remained blocked behind an expired connection slot")
            .unwrap();
        assert_eq!(u32::from_be_bytes(reply[..4].try_into().unwrap()), 77);

        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(1), server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn write_ingress_stops_at_the_connection_limit() {
        let fs = BlockingWriteFs::new();
        let listener = NFSTcpListener::bind("127.0.0.1:0".parse().unwrap(), fs)
            .await
            .unwrap();
        let port = listener.get_listen_port();
        let fs = Arc::clone(&listener.arcfs);
        let shutdown = CancellationToken::new();
        let server_shutdown = shutdown.clone();
        let server = tokio::spawn(async move {
            listener
                .handle_with_shutdown(server_shutdown)
                .await
                .unwrap();
        });
        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();

        for xid in 1..=40 {
            send_record(&mut client, &write_call(xid, 64 * 1024)).await;
        }

        let thirty_third_started =
            tokio::time::timeout(Duration::from_millis(500), fs.wait_for_started(33)).await;
        fs.release.add_permits(40);
        shutdown.cancel();
        let _ = server.await;

        assert!(
            thirty_third_started.is_err(),
            "more than 32 blocked NFS RPCs entered the filesystem"
        );
    }

    #[tokio::test]
    async fn listener_shutdown_waits_for_an_accepted_write() {
        let fs = BlockingWriteFs::new();
        let listener = NFSTcpListener::bind("127.0.0.1:0".parse().unwrap(), fs)
            .await
            .unwrap();
        let port = listener.get_listen_port();
        let fs = Arc::clone(&listener.arcfs);
        let shutdown = CancellationToken::new();
        let server_shutdown = shutdown.clone();
        let mut server = tokio::spawn(async move {
            listener
                .handle_with_shutdown(server_shutdown)
                .await
                .unwrap();
        });
        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        send_record(&mut client, &write_call(1, 64 * 1024)).await;
        tokio::time::timeout(Duration::from_secs(1), fs.wait_for_started(1))
            .await
            .unwrap();

        shutdown.cancel();
        assert!(
            tokio::time::timeout(Duration::from_millis(200), &mut server)
                .await
                .is_err(),
            "listener returned before its accepted write settled"
        );

        fs.release.add_permits(1);
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("listener did not join the drained connection")
            .unwrap();
    }

    #[tokio::test]
    async fn fresh_tcp_connections_receive_distinct_request_incarnations() {
        let fs = ContextRecordingFs::new(stable_how::UNSTABLE, [3; 8]);
        let writes = Arc::clone(&fs.writes);
        let listener = NFSTcpListener::bind("127.0.0.1:0".parse().unwrap(), fs)
            .await
            .unwrap();
        let port = listener.get_listen_port();
        let shutdown = CancellationToken::new();
        let server_shutdown = shutdown.clone();
        let server =
            tokio::spawn(async move { listener.handle_with_shutdown(server_shutdown).await });

        for xid in [11, 12] {
            let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            send_record(&mut client, &write_call(xid, 16)).await;
            read_record(&mut client).await.unwrap();
        }

        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(1), server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let writes = writes.lock().unwrap();
        assert_eq!(writes.len(), 2);
        assert_eq!(writes[0].xid, 11);
        assert_eq!(writes[1].xid, 12);
        assert_ne!(
            writes[0].connection_incarnation,
            writes[1].connection_incarnation
        );
    }

    #[tokio::test]
    async fn write_ingress_stops_at_the_byte_limit() {
        const RECORD_LIMIT: usize = 128 * 1024;
        let fs = Arc::new(BlockingWriteFs::new());
        let context = test_context(Arc::clone(&fs));
        let limits = TransportLimits {
            max_inflight_requests: 8,
            max_record_bytes: RECORD_LIMIT,
            connection_inflight_bytes: 2 * RECORD_LIMIT,
            ..TransportLimits::default()
        };
        let global_budget = Arc::new(Semaphore::new(8 * RECORD_LIMIT));
        let (server_socket, mut client) = tokio::io::duplex(1024 * 1024);
        let (server_reader, server_writer) = tokio::io::split(server_socket);
        let shutdown = CancellationToken::new();
        let server = tokio::spawn(process_stream(
            server_reader,
            server_writer,
            context,
            shutdown,
            limits,
            global_budget,
        ));

        for xid in 1..=3 {
            send_record(&mut client, &write_call(xid, 64 * 1024)).await;
        }

        let third_started =
            tokio::time::timeout(Duration::from_millis(250), fs.wait_for_started(3)).await;
        fs.release.add_permits(3);
        drop(client);
        let _ = tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap();

        assert!(
            third_started.is_err(),
            "the byte budget admitted a third RPC"
        );
    }

    #[tokio::test]
    async fn oversized_record_is_rejected_before_its_body_is_read() {
        let limits = TransportLimits {
            max_inflight_requests: 1,
            max_record_bytes: 1024,
            connection_inflight_bytes: 1024,
            ..TransportLimits::default()
        };
        let connection_budget = Arc::new(Semaphore::new(1024));
        let global_budget = Arc::new(Semaphore::new(1024));
        let (mut writer, mut reader) = tokio::io::duplex(16);
        writer
            .write_all(&((1025_u32) | (1 << 31)).to_be_bytes())
            .await
            .unwrap();

        let result = read_admitted_record(
            &mut reader,
            limits,
            Arc::clone(&connection_budget),
            Arc::clone(&global_budget),
        )
        .await;
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("oversized record was admitted"),
        };

        assert!(error.to_string().contains("exceeds limit 1024"));
        assert_eq!(connection_budget.available_permits(), 1024);
        assert_eq!(global_budget.available_permits(), 1024);
    }

    #[tokio::test]
    async fn bounded_reply_queue_drains_while_input_is_backpressured() {
        const RECORD_LIMIT: usize = 128 * 1024;
        let fs = Arc::new(BlockingWriteFs::new());
        fs.release.add_permits(8);
        let context = test_context(fs);
        let limits = TransportLimits {
            max_inflight_requests: 2,
            max_record_bytes: RECORD_LIMIT,
            connection_inflight_bytes: 2 * RECORD_LIMIT,
            ..TransportLimits::default()
        };
        let global_budget = Arc::new(Semaphore::new(2 * RECORD_LIMIT));
        let (server_socket, client_socket) = tokio::io::duplex(256);
        let (server_reader, server_writer) = tokio::io::split(server_socket);
        let (mut client_reader, mut client_writer) = tokio::io::split(client_socket);
        let server = tokio::spawn(process_stream(
            server_reader,
            server_writer,
            context,
            CancellationToken::new(),
            limits,
            global_budget,
        ));
        let producer = tokio::spawn(async move {
            for xid in 1..=8 {
                send_record(&mut client_writer, &write_call(xid, 64 * 1024)).await;
            }
            client_writer.shutdown().await.unwrap();
        });
        let consumer = tokio::spawn(async move {
            let mut replies = 0;
            while read_record(&mut client_reader).await.is_ok() {
                replies += 1;
            }
            replies
        });

        tokio::time::timeout(Duration::from_secs(3), producer)
            .await
            .expect("input remained deadlocked")
            .unwrap();
        tokio::time::timeout(Duration::from_secs(3), server)
            .await
            .expect("server remained deadlocked")
            .unwrap()
            .unwrap();
        assert_eq!(consumer.await.unwrap(), 8);
    }

    #[tokio::test]
    async fn disconnect_drains_accepted_writes_and_returns_global_credit() {
        const RECORD_LIMIT: usize = 128 * 1024;
        let fs = Arc::new(BlockingWriteFs::new());
        let context = test_context(Arc::clone(&fs));
        let limits = TransportLimits {
            max_inflight_requests: 2,
            max_record_bytes: RECORD_LIMIT,
            connection_inflight_bytes: 2 * RECORD_LIMIT,
            ..TransportLimits::default()
        };
        let global_budget = Arc::new(Semaphore::new(2 * RECORD_LIMIT));
        let (server_socket, mut client) = tokio::io::duplex(512 * 1024);
        let (server_reader, server_writer) = tokio::io::split(server_socket);
        let server = tokio::spawn(process_stream(
            server_reader,
            server_writer,
            context,
            CancellationToken::new(),
            limits,
            Arc::clone(&global_budget),
        ));
        for xid in 1..=2 {
            send_record(&mut client, &write_call(xid, 64 * 1024)).await;
        }
        tokio::time::timeout(Duration::from_secs(1), fs.wait_for_started(2))
            .await
            .unwrap();
        drop(client);

        assert_eq!(global_budget.available_permits(), 0);
        fs.release.add_permits(2);
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("accepted writes did not settle after disconnect")
            .unwrap()
            .expect_err("the disconnected reply writer unexpectedly succeeded");
        assert_eq!(global_budget.available_permits(), 2 * RECORD_LIMIT);
        assert_eq!(fs.started.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn cancellation_interrupts_an_idle_reader_without_leaking_credit() {
        const RECORD_LIMIT: usize = 1024;
        let fs = Arc::new(BlockingWriteFs::new());
        let context = test_context(fs);
        let limits = TransportLimits {
            max_inflight_requests: 1,
            max_record_bytes: RECORD_LIMIT,
            connection_inflight_bytes: RECORD_LIMIT,
            ..TransportLimits::default()
        };
        let global_budget = Arc::new(Semaphore::new(RECORD_LIMIT));
        let (server_socket, _client) = tokio::io::duplex(64);
        let (server_reader, server_writer) = tokio::io::split(server_socket);
        let shutdown = CancellationToken::new();
        let server = tokio::spawn(process_stream(
            server_reader,
            server_writer,
            context,
            shutdown.clone(),
            limits,
            Arc::clone(&global_budget),
        ));

        tokio::time::sleep(Duration::from_millis(50)).await;
        shutdown.cancel();
        tokio::time::timeout(Duration::from_millis(250), server)
            .await
            .expect("idle reader ignored cancellation")
            .unwrap()
            .unwrap();
        assert_eq!(global_budget.available_permits(), RECORD_LIMIT);
    }

    #[tokio::test]
    async fn cancellation_drains_already_accepted_writes() {
        const RECORD_LIMIT: usize = 128 * 1024;
        let fs = Arc::new(BlockingWriteFs::new());
        let context = test_context(Arc::clone(&fs));
        let limits = TransportLimits {
            max_inflight_requests: 2,
            max_record_bytes: RECORD_LIMIT,
            connection_inflight_bytes: 2 * RECORD_LIMIT,
            ..TransportLimits::default()
        };
        let global_budget = Arc::new(Semaphore::new(2 * RECORD_LIMIT));
        let (server_socket, mut client) = tokio::io::duplex(512 * 1024);
        let (server_reader, server_writer) = tokio::io::split(server_socket);
        let shutdown = CancellationToken::new();
        let server = tokio::spawn(process_stream(
            server_reader,
            server_writer,
            context,
            shutdown.clone(),
            limits,
            Arc::clone(&global_budget),
        ));
        for xid in 1..=2 {
            send_record(&mut client, &write_call(xid, 64 * 1024)).await;
        }
        tokio::time::timeout(Duration::from_secs(1), fs.wait_for_started(2))
            .await
            .unwrap();

        shutdown.cancel();
        fs.release.add_permits(2);
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("accepted writes did not settle after cancellation")
            .unwrap()
            .unwrap();
        assert_eq!(global_budget.available_permits(), 2 * RECORD_LIMIT);
        assert_eq!(fs.started.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn retransmissions_share_one_bounded_transaction() {
        const RECORD_LIMIT: usize = 1024;
        let fs = Arc::new(BlockingWriteFs::new());
        let context = test_context(fs);
        let limits = TransportLimits {
            max_inflight_requests: 4,
            max_record_bytes: RECORD_LIMIT,
            connection_inflight_bytes: 4 * RECORD_LIMIT,
            ..TransportLimits::default()
        };
        let global_budget = Arc::new(Semaphore::new(4 * RECORD_LIMIT));
        let (server_socket, client_socket) = tokio::io::duplex(64 * 1024);
        let (server_reader, server_writer) = tokio::io::split(server_socket);
        let (mut client_reader, mut client_writer) = tokio::io::split(client_socket);
        let server = tokio::spawn(process_stream(
            server_reader,
            server_writer,
            context,
            CancellationToken::new(),
            limits,
            Arc::clone(&global_budget),
        ));
        for _ in 0..100 {
            send_record(&mut client_writer, &null_call(7)).await;
        }
        client_writer.shutdown().await.unwrap();

        let mut replies = 0;
        while read_record(&mut client_reader).await.is_ok() {
            replies += 1;
        }
        server.await.unwrap().unwrap();

        assert_eq!(replies, 1);
        assert_eq!(global_budget.available_permits(), 4 * RECORD_LIMIT);
    }

    #[tokio::test]
    async fn oversized_read_is_rejected_before_entering_the_filesystem() {
        const RECORD_LIMIT: usize = 2 * 1024 * 1024;
        let fs = Arc::new(BlockingWriteFs::new());
        let context = test_context(Arc::clone(&fs));
        let limits = TransportLimits {
            max_inflight_requests: 1,
            max_record_bytes: RECORD_LIMIT,
            connection_inflight_bytes: RECORD_LIMIT,
            ..TransportLimits::default()
        };
        let global_budget = Arc::new(Semaphore::new(RECORD_LIMIT));
        let (server_socket, client_socket) = tokio::io::duplex(4096);
        let (server_reader, server_writer) = tokio::io::split(server_socket);
        let (mut client_reader, mut client_writer) = tokio::io::split(client_socket);
        let server = tokio::spawn(process_stream(
            server_reader,
            server_writer,
            context,
            CancellationToken::new(),
            limits,
            global_budget,
        ));
        send_record(&mut client_writer, &read_call(1, 1024 * 1024 + 1)).await;
        client_writer.shutdown().await.unwrap();

        read_record(&mut client_reader).await.unwrap();
        server.await.unwrap().unwrap();

        assert_eq!(fs.reads.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn readdir_caps_client_count_before_calling_the_filesystem() {
        let fs = Arc::new(BlockingWriteFs::new());
        execute_one_call(Arc::clone(&fs), readdir_call(1, false, u32::MAX, 0)).await;

        assert_eq!(fs.readdir_calls.load(Ordering::SeqCst), 1);
        assert!(fs.readdir_max_entries.load(Ordering::SeqCst) <= MAX_RPC_RECORD_BYTES / 24);
    }

    #[tokio::test]
    async fn readdirplus_caps_both_client_counts_before_calling_the_filesystem() {
        let fs = Arc::new(BlockingWriteFs::new());
        execute_one_call(Arc::clone(&fs), readdir_call(1, true, u32::MAX, u32::MAX)).await;

        assert_eq!(fs.readdir_calls.load(Ordering::SeqCst), 1);
        assert!(fs.readdir_max_entries.load(Ordering::SeqCst) <= MAX_RPC_RECORD_BYTES / 120);
    }

    #[tokio::test]
    async fn readdir_uses_exact_wire_budget_and_makes_progress() {
        for count in [127, 128, 129, 131] {
            let fs = Arc::new(BlockingWriteFs::new());
            let reply = execute_one_call(Arc::clone(&fs), readdir_call(1, false, count, 0)).await;
            assert_eq!(
                nfs_status(&reply),
                nfsstat3::NFS3ERR_TOOSMALL as u32,
                "count {count}"
            );
        }

        for count in [132, 143, 144, 159] {
            let fs = Arc::new(BlockingWriteFs::new());
            let one = execute_one_call(fs, readdir_call(1, false, count, 0)).await;
            assert_eq!(one.len(), 160, "count {count}");
            assert_eq!(
                parse_directory_reply(&one, false),
                ParsedDirectoryReply {
                    names: vec![b".".to_vec()],
                    eof: false,
                },
                "count {count}"
            );
        }

        let fs = Arc::new(BlockingWriteFs::new());
        let two = execute_one_call(fs, readdir_call(2, false, 160, 0)).await;
        assert_eq!(two.len(), 188);
        assert_eq!(
            parse_directory_reply(&two, false),
            ParsedDirectoryReply {
                names: vec![b".".to_vec(), b"..".to_vec()],
                eof: true,
            }
        );
    }

    #[tokio::test]
    async fn readdirplus_uses_exact_dir_and_total_wire_budgets() {
        for count in [127, 128, 129, 143, 144, 159, 160] {
            let fs = Arc::new(BlockingWriteFs::new());
            let reply =
                execute_one_call(Arc::clone(&fs), readdir_call(1, true, count, count)).await;
            assert_eq!(
                nfs_status(&reply),
                nfsstat3::NFS3ERR_TOOSMALL as u32,
                "count {count}"
            );
        }
        for (dircount, maxcount) in [(35, 244), (36, 243)] {
            let fs = Arc::new(BlockingWriteFs::new());
            let reply =
                execute_one_call(Arc::clone(&fs), readdir_call(1, true, dircount, maxcount)).await;
            assert_eq!(
                nfs_status(&reply),
                nfsstat3::NFS3ERR_TOOSMALL as u32,
                "dircount {dircount}, maxcount {maxcount}"
            );
        }

        let fs = Arc::new(BlockingWriteFs::new());
        let one = execute_one_call(Arc::clone(&fs), readdir_call(1, true, 36, 244)).await;
        assert_eq!(one.len(), 272);
        assert_eq!(
            parse_directory_reply(&one, true),
            ParsedDirectoryReply {
                names: vec![b".".to_vec()],
                eof: false,
            }
        );

        let two = execute_one_call(fs, readdir_call(2, true, 64, 384)).await;
        assert_eq!(two.len(), 412);
        assert_eq!(
            parse_directory_reply(&two, true),
            ParsedDirectoryReply {
                names: vec![b".".to_vec(), b"..".to_vec()],
                eof: true,
            }
        );
    }
}
