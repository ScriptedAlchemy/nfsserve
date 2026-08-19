use crate::context::RPCContext;
use crate::rpcwire::{handle_rpc, write_fragment};
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
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use std::{io, net::IpAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
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

static NEXT_CONNECTION_INCARNATION: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy)]
struct TransportLimits {
    max_inflight_requests: usize,
    max_record_bytes: usize,
    connection_inflight_bytes: usize,
}

impl Default for TransportLimits {
    fn default() -> Self {
        Self {
            max_inflight_requests: MAX_INFLIGHT_REQUESTS,
            max_record_bytes: MAX_RPC_RECORD_BYTES,
            connection_inflight_bytes: CONNECTION_INFLIGHT_BYTES,
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
    global_budget: Arc<Semaphore>,
) -> Result<(), anyhow::Error> {
    let _ = socket.set_nodelay(true);
    let (reader, writer) = socket.into_split();
    process_stream(
        reader,
        writer,
        context,
        shutdown,
        TransportLimits::default(),
        global_budget,
    )
    .await
}

async fn read_first_marker<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Option<u32>> {
    let mut marker = [0_u8; 4];
    if reader.read(&mut marker[..1]).await? == 0 {
        return Ok(None);
    }
    reader.read_exact(&mut marker[1..]).await?;
    Ok(Some(u32::from_be_bytes(marker)))
}

async fn read_admitted_record<R: AsyncRead + Unpin>(
    reader: &mut R,
    limits: TransportLimits,
    connection_budget: Arc<Semaphore>,
    global_budget: Arc<Semaphore>,
) -> anyhow::Result<Option<AdmittedRecord>> {
    let Some(mut marker) = read_first_marker(reader).await? else {
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
        reader
            .read_exact(&mut record[new_length - length..])
            .await?;
        if is_last {
            return Ok(Some(AdmittedRecord {
                bytes: record,
                credit,
            }));
        }
        let mut next_marker = [0_u8; 4];
        reader.read_exact(&mut next_marker).await?;
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
    let connection_incarnation =
        NEXT_CONNECTION_INCARNATION.fetch_add(1, Ordering::Relaxed);
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
                write_fragment(&mut writer, &reply).await
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
        Ok(NFSTcpListener {
            listener,
            port,
            arcfs,
            mount_signal: None,
            export_name: Arc::from("/".to_string()),
            transaction_tracker: Arc::new(TransactionTracker::new(Duration::from_secs(60))),
            transport_budget: Arc::new(Semaphore::new(GLOBAL_INFLIGHT_BYTES)),
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
                result = self.listener.accept() => {
                    let (socket, _) = result?;
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
                        global_budget,
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

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nfs::{fattr3, fileid3, filename3, ftype3, nfspath3, nfsstat3, sattr3, specdata3};
    use crate::vfs::{AuthContext, ReadDirResult, VFSCapabilities};
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::sync::{Notify, Semaphore};

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
            Ok(ReadDirResult {
                entries: Vec::new(),
                end: true,
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

    fn nfs_status(reply: &[u8]) -> u32 {
        u32::from_be_bytes(reply[24..28].try_into().unwrap())
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
    async fn write_ingress_stops_at_the_byte_limit() {
        const RECORD_LIMIT: usize = 128 * 1024;
        let fs = Arc::new(BlockingWriteFs::new());
        let context = test_context(Arc::clone(&fs));
        let limits = TransportLimits {
            max_inflight_requests: 8,
            max_record_bytes: RECORD_LIMIT,
            connection_inflight_bytes: 2 * RECORD_LIMIT,
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
        assert!(fs.readdir_max_entries.load(Ordering::SeqCst) <= (MAX_RPC_RECORD_BYTES - 128) / 16);
    }

    #[tokio::test]
    async fn readdirplus_caps_both_client_counts_before_calling_the_filesystem() {
        let fs = Arc::new(BlockingWriteFs::new());
        execute_one_call(Arc::clone(&fs), readdir_call(1, true, u32::MAX, u32::MAX)).await;

        assert_eq!(fs.readdir_calls.load(Ordering::SeqCst), 1);
        assert!(fs.readdir_max_entries.load(Ordering::SeqCst) <= (MAX_RPC_RECORD_BYTES - 128) / 16);
    }

    #[tokio::test]
    async fn readdir_rejects_counts_that_cannot_fit_required_entries() {
        for count in [127, 128, 129, 143, 144, 159] {
            let fs = Arc::new(BlockingWriteFs::new());
            let reply = execute_one_call(Arc::clone(&fs), readdir_call(1, false, count, 0)).await;

            assert_eq!(
                nfs_status(&reply),
                nfsstat3::NFS3ERR_TOOSMALL as u32,
                "count {count}"
            );
            assert_eq!(fs.readdir_calls.load(Ordering::SeqCst), 0, "count {count}");
        }
    }

    #[tokio::test]
    async fn readdirplus_rejects_counts_that_cannot_fit_required_entries() {
        for count in [127, 128, 129, 143, 144, 159] {
            let fs = Arc::new(BlockingWriteFs::new());
            let reply =
                execute_one_call(Arc::clone(&fs), readdir_call(1, true, count, count)).await;

            assert_eq!(
                nfs_status(&reply),
                nfsstat3::NFS3ERR_TOOSMALL as u32,
                "count {count}"
            );
            assert_eq!(fs.readdir_calls.load(Ordering::SeqCst), 0, "count {count}");
        }
    }

    #[tokio::test]
    async fn readdir_accepts_the_minimum_progress_budget() {
        for plus in [false, true] {
            let fs = Arc::new(BlockingWriteFs::new());
            let reply = execute_one_call(Arc::clone(&fs), readdir_call(1, plus, 160, 160)).await;

            assert_eq!(nfs_status(&reply), nfsstat3::NFS3_OK as u32);
            assert_eq!(fs.readdir_calls.load(Ordering::SeqCst), 1);
            assert_eq!(fs.readdir_max_entries.load(Ordering::SeqCst), 2);
        }
    }
}
