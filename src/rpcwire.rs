use anyhow::anyhow;
use std::io::Cursor;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{debug, error, trace, warn};

use crate::context::RPCContext;
use crate::rpc::*;
use crate::xdr::*;

use crate::mount;
use crate::mount_handlers;

use crate::nfs;
use crate::nfs_handlers;

use crate::portmap;
use crate::portmap_handlers;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::io::DuplexStream;
use tokio::sync::mpsc;

// Information from RFC 5531
// https://datatracker.ietf.org/doc/html/rfc5531

const NFS_ACL_PROGRAM: u32 = 100227;
const NFS_ID_MAP_PROGRAM: u32 = 100270;
const NFS_METADATA_PROGRAM: u32 = 200024;

/// Mints identifiers that are unique per accepted transport connection,
/// so a client reconnecting from the same address observes a fresh value.
static NEXT_CONNECTION_INCARNATION: AtomicU64 = AtomicU64::new(1);

async fn handle_rpc(
    input: &mut impl Read,
    output: &mut impl Write,
    mut context: RPCContext,
    connection_incarnation: u64,
) -> Result<bool, anyhow::Error> {
    let mut recv = rpc_msg::default();
    recv.deserialize(input)?;
    let xid = recv.xid;
    if let rpc_body::CALL(call) = recv.body {
        if let auth_flavor::AUTH_UNIX = call.cred.flavor {
            let mut auth = auth_unix::default();
            auth.deserialize(&mut Cursor::new(&call.cred.body))?;
            context.auth = auth;
        }
        if call.rpcvers != 2 {
            warn!("Invalid RPC version {} != 2", call.rpcvers);
            rpc_vers_mismatch(xid).serialize(output)?;
            return Ok(true);
        }

        if context
            .transaction_tracker
            .is_retransmission(xid, &context.client_addr)
        {
            // This is a retransmission
            // Drop the message and return
            debug!(
                "Retransmission detected, xid: {}, client_addr: {}, call: {:?}",
                xid, context.client_addr, call
            );
            return Ok(false);
        }

        let res = {
            if call.prog == nfs::PROGRAM {
                nfs_handlers::handle_nfs(xid, call, input, output, &context, connection_incarnation)
                    .await
            } else if call.prog == portmap::PROGRAM {
                portmap_handlers::handle_portmap(xid, call, input, output, &context)
            } else if call.prog == mount::PROGRAM {
                mount_handlers::handle_mount(xid, call, input, output, &context).await
            } else if call.prog == NFS_ACL_PROGRAM
                || call.prog == NFS_ID_MAP_PROGRAM
                || call.prog == NFS_METADATA_PROGRAM
            {
                trace!("ignoring NFS_ACL packet");
                prog_unavail_reply_message(xid).serialize(output)?;
                Ok(())
            } else {
                warn!(
                    "Unknown RPC Program number {} != {}",
                    call.prog,
                    nfs::PROGRAM
                );
                prog_unavail_reply_message(xid).serialize(output)?;
                Ok(())
            }
        }
        .map(|_| true);
        context
            .transaction_tracker
            .mark_processed(xid, &context.client_addr);
        res
    } else {
        error!("Unexpectedly received a Reply instead of a Call");
        Err(anyhow!("Bad RPC Call format"))
    }
}

/// RFC 1057 Section 10
/// When RPC messages are passed on top of a byte stream transport
/// protocol (like TCP), it is necessary to delimit one message from
/// another in order to detect and possibly recover from protocol errors.
/// This is called record marking (RM).  Sun uses this RM/TCP/IP
/// transport for passing RPC messages on TCP streams.  One RPC message
/// fits into one RM record.
///
/// A record is composed of one or more record fragments.  A record
/// fragment is a four-byte header followed by 0 to (2**31) - 1 bytes of
/// fragment data.  The bytes encode an unsigned binary number; as with
/// XDR integers, the byte order is from highest to lowest.  The number
/// encodes two values -- a boolean which indicates whether the fragment
/// is the last fragment of the record (bit value 1 implies the fragment
/// is the last fragment) and a 31-bit unsigned binary value which is the
/// length in bytes of the fragment's data.  The boolean value is the
/// highest-order bit of the header; the length is the 31 low-order bits.
/// (Note that this record specification is NOT in XDR standard form!)
async fn read_fragment(
    socket: &mut DuplexStream,
    append_to: &mut Vec<u8>,
) -> Result<bool, anyhow::Error> {
    let mut header_buf = [0_u8; 4];
    socket.read_exact(&mut header_buf).await?;
    let fragment_header = u32::from_be_bytes(header_buf);
    let is_last = (fragment_header & (1 << 31)) > 0;
    let length = (fragment_header & ((1 << 31) - 1)) as usize;
    trace!("Reading fragment length:{}, last:{}", length, is_last);
    let start_offset = append_to.len();
    append_to.resize(append_to.len() + length, 0);
    socket.read_exact(&mut append_to[start_offset..]).await?;
    trace!(
        "Finishing Reading fragment length:{}, last:{}",
        length,
        is_last
    );
    Ok(is_last)
}

pub async fn write_fragment(
    socket: &mut tokio::net::TcpStream,
    buf: &Vec<u8>,
) -> Result<(), anyhow::Error> {
    // TODO: split into many fragments
    assert!(buf.len() < (1 << 31));
    // set the last flag
    let fragment_header = buf.len() as u32 + (1 << 31);
    let header_buf = u32::to_be_bytes(fragment_header);
    socket.write_all(&header_buf).await?;
    trace!("Writing fragment length:{}", buf.len());
    socket.write_all(buf).await?;
    Ok(())
}

pub type SocketMessageType = Result<Vec<u8>, anyhow::Error>;

/// The Socket Message Handler reads from a TcpStream and spawns off
/// subtasks to handle each message. replies are queued into the
/// reply_send_channel.
#[derive(Debug)]
pub struct SocketMessageHandler {
    cur_fragment: Vec<u8>,
    socket_receive_channel: DuplexStream,
    reply_send_channel: mpsc::UnboundedSender<SocketMessageType>,
    context: RPCContext,
    connection_incarnation: u64,
}

impl SocketMessageHandler {
    /// Creates a new SocketMessageHandler with the receiver for queued message replies.
    /// A handler is created once per accepted transport connection, so each
    /// one is minted a fresh connection incarnation.
    pub fn new(
        context: &RPCContext,
    ) -> (
        Self,
        DuplexStream,
        mpsc::UnboundedReceiver<SocketMessageType>,
    ) {
        let (socksend, sockrecv) = tokio::io::duplex(256000);
        let (msgsend, msgrecv) = mpsc::unbounded_channel();
        (
            Self {
                cur_fragment: Vec::new(),
                socket_receive_channel: sockrecv,
                reply_send_channel: msgsend,
                context: context.clone(),
                connection_incarnation: NEXT_CONNECTION_INCARNATION.fetch_add(1, Ordering::Relaxed),
            },
            socksend,
            msgrecv,
        )
    }

    /// Reads a fragment from the socket. This should be looped.
    pub async fn read(&mut self) -> Result<(), anyhow::Error> {
        let is_last =
            read_fragment(&mut self.socket_receive_channel, &mut self.cur_fragment).await?;
        if is_last {
            let fragment = std::mem::take(&mut self.cur_fragment);
            let context = self.context.clone();
            let send = self.reply_send_channel.clone();
            let connection_incarnation = self.connection_incarnation;
            tokio::spawn(async move {
                let mut write_buf: Vec<u8> = Vec::new();
                let mut write_cursor = Cursor::new(&mut write_buf);
                let maybe_reply = handle_rpc(
                    &mut Cursor::new(fragment),
                    &mut write_cursor,
                    context,
                    connection_incarnation,
                )
                .await;
                match maybe_reply {
                    Err(e) => {
                        error!("RPC Error: {:?}", e);
                        let _ = send.send(Err(e));
                    }
                    Ok(true) => {
                        let _ = std::io::Write::flush(&mut write_cursor);
                        let _ = send.send(Ok(write_buf));
                    }
                    Ok(false) => {
                        // do not reply
                    }
                }
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nfs::stable_how;
    use crate::tcp::{NFSTcp, NFSTcpListener};
    use crate::transaction_tracker::TransactionTracker;
    use crate::vfs::test_support::ContextRecordingFs;
    use crate::vfs::NFSFileSystem;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::net::TcpStream;
    use tokio_util::sync::CancellationToken;

    #[test]
    fn each_accepted_connection_gets_a_fresh_incarnation() {
        let fs = ContextRecordingFs::new(stable_how::FILE_SYNC, [0u8; 8]);
        let context = RPCContext {
            local_port: 2049,
            client_addr: "10.0.0.7:702".to_string(),
            auth: auth_unix::default(),
            vfs: Arc::new(fs),
            mount_signal: None,
            export_name: Arc::new("/".to_string()),
            transaction_tracker: Arc::new(TransactionTracker::new(Duration::from_secs(60))),
        };
        // The same client address reconnecting produces a new handler, and
        // every handler is minted a fresh connection incarnation.
        let (first, _, _) = SocketMessageHandler::new(&context);
        let (second, _, _) = SocketMessageHandler::new(&context);
        assert_ne!(first.connection_incarnation, second.connection_incarnation);
    }

    /// Serializes a framed NFSv3 WRITE call with AUTH_UNIX credentials.
    fn framed_write_call(fh: nfs::nfs_fh3, xid: u32, offset: u64, data: &[u8]) -> Vec<u8> {
        let mut auth_body = Vec::new();
        auth_unix {
            stamp: 0,
            machinename: b"testhost".to_vec(),
            uid: 1000,
            gid: 100,
            gids: vec![100, 20],
        }
        .serialize(&mut auth_body)
        .unwrap();

        let mut msg = Vec::new();
        rpc_msg {
            xid,
            body: rpc_body::CALL(call_body {
                rpcvers: 2,
                prog: nfs::PROGRAM,
                vers: nfs::VERSION,
                proc: 7, // NFSPROC3_WRITE
                cred: opaque_auth {
                    flavor: auth_flavor::AUTH_UNIX,
                    body: auth_body,
                },
                verf: opaque_auth::default(),
            }),
        }
        .serialize(&mut msg)
        .unwrap();
        // WRITE3args: file, offset, count, stable, data
        fh.serialize(&mut msg).unwrap();
        offset.serialize(&mut msg).unwrap();
        (data.len() as u32).serialize(&mut msg).unwrap();
        (stable_how::DATA_SYNC as u32).serialize(&mut msg).unwrap();
        data.to_vec().serialize(&mut msg).unwrap();

        let mut framed = Vec::new();
        framed.extend_from_slice(&((msg.len() as u32 | (1 << 31)).to_be_bytes()));
        framed.extend_from_slice(&msg);
        framed
    }

    /// Opens a fresh connection, sends one framed call, and waits for the
    /// framed reply so the request is fully processed before returning.
    async fn send_on_fresh_connection(port: u16, framed: &[u8]) {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        stream.write_all(framed).await.unwrap();
        let mut header = [0u8; 4];
        stream.read_exact(&mut header).await.unwrap();
        let len = (u32::from_be_bytes(header) & ((1 << 31) - 1)) as usize;
        let mut reply = vec![0u8; len];
        stream.read_exact(&mut reply).await.unwrap();
    }

    #[tokio::test]
    async fn reconnect_from_same_address_mints_fresh_incarnation() {
        let fs = ContextRecordingFs::new(stable_how::UNSTABLE, [3u8; 8]);
        let writes = fs.writes.clone();
        let fh = fs.id_to_fh(42);

        let listener = NFSTcpListener::bind("127.0.0.1:0".parse().unwrap(), fs)
            .await
            .unwrap();
        let port = listener.get_listen_port();
        let shutdown = CancellationToken::new();
        let server_shutdown = shutdown.clone();
        tokio::spawn(async move {
            let _ = listener.handle_with_shutdown(server_shutdown).await;
        });

        send_on_fresh_connection(port, &framed_write_call(fh.clone(), 11, 0, b"first")).await;
        send_on_fresh_connection(port, &framed_write_call(fh, 12, 5, b"second")).await;
        shutdown.cancel();

        let writes = writes.lock().unwrap();
        assert_eq!(writes.len(), 2);
        assert_eq!(writes[0].xid, 11);
        assert_eq!(writes[1].xid, 12);
        assert_eq!(writes[0].requested_stability, stable_how::DATA_SYNC);
        assert_eq!(writes[0].auth.uid, 1000);
        assert_eq!(writes[0].auth.gid, 100);
        assert_eq!(writes[0].auth.gids, vec![100, 20]);
        assert_eq!(writes[0].id, 42);
        assert_eq!(writes[1].offset, 5);
        assert_eq!(writes[1].data, b"second");
        // Both connections come from the same client address, but each
        // accepted transport observes a fresh incarnation.
        assert!(writes[0].client_addr.starts_with("127.0.0.1:"));
        assert!(writes[1].client_addr.starts_with("127.0.0.1:"));
        assert_ne!(
            writes[0].connection_incarnation,
            writes[1].connection_incarnation
        );
    }
}
