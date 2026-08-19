use anyhow::anyhow;
use std::io::Cursor;
use std::io::{Read, Write};
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
use tokio::io::{AsyncWrite, AsyncWriteExt};

// Information from RFC 5531
// https://datatracker.ietf.org/doc/html/rfc5531

const NFS_ACL_PROGRAM: u32 = 100227;
const NFS_ID_MAP_PROGRAM: u32 = 100270;
const NFS_METADATA_PROGRAM: u32 = 200024;

pub(crate) async fn handle_rpc(
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

pub async fn write_fragment<W: AsyncWrite + Unpin>(
    socket: &mut W,
    buf: &[u8],
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
