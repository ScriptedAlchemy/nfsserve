#![allow(clippy::upper_case_acronyms)]
#![allow(dead_code)]
use crate::context::RPCContext;
use crate::nfs;
use crate::nfs::stable_how;
use crate::rpc::*;
use crate::tcp::MAX_RPC_RECORD_BYTES;
use crate::vfs::{
    AuthContext, CommitRequestContext, RpcRequestContext, VFSCapabilities, WriteRequestContext,
};
use crate::xdr::*;
use byteorder::{ReadBytesExt, WriteBytesExt};
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::cast::FromPrimitive;
use std::io::{Read, Write};
use tracing::{debug, error, trace, warn};

const MAX_NFS_IO_BYTES: u32 = 1024 * 1024;
// XDR list tail: a false next-entry discriminator followed by the EOF bool.
const DIRECTORY_LIST_TAIL_BYTES: usize = 8;
// Minimum XDR entry: true discriminator + fileid + empty opaque name + cookie.
const MIN_READDIR_ENTRY_BYTES: usize = 24;
// READDIRPLUS always emits a present fattr3 and file handle. This minimum uses
// an empty name and empty handle body; concrete handles only increase it.
const MIN_READDIRPLUS_ENTRY_BYTES: usize = 120;

fn fits_with_tail(current: usize, added: usize, limit: usize) -> bool {
    current
        .checked_add(added)
        .and_then(|bytes| bytes.checked_add(DIRECTORY_LIST_TAIL_BYTES))
        .is_some_and(|bytes| bytes <= limit)
}

fn entry_capacity(limit: usize, fixed: usize, minimum_entry: usize) -> usize {
    fixed
        .checked_add(DIRECTORY_LIST_TAIL_BYTES)
        .and_then(|used| limit.checked_sub(used))
        .map(|bytes| bytes / minimum_entry)
        .unwrap_or(0)
}

fn write_readdir_error(
    xid: u32,
    status: nfs::nfsstat3,
    dir_attr: nfs::post_op_attr,
    output: &mut impl Write,
) -> Result<(), anyhow::Error> {
    make_success_reply(xid).serialize(output)?;
    status.serialize(output)?;
    dir_attr.serialize(output)?;
    Ok(())
}

/// Helper function to create AuthContext from RPCContext
fn auth_from_context(context: &RPCContext) -> AuthContext {
    AuthContext::from_rpc_auth(&context.auth)
}

/*
program NFS_PROGRAM {
 version NFS_V3 {

    void
     NFSPROC3_NULL(void)                    = 0;

    GETATTR3res
     NFSPROC3_GETATTR(GETATTR3args)         = 1;

    SETATTR3res
     NFSPROC3_SETATTR(SETATTR3args)         = 2;

    LOOKUP3res
     NFSPROC3_LOOKUP(LOOKUP3args)           = 3;

    ACCESS3res
     NFSPROC3_ACCESS(ACCESS3args)           = 4;

    READLINK3res
     NFSPROC3_READLINK(READLINK3args)       = 5;

    READ3res
     NFSPROC3_READ(READ3args)               = 6;

    WRITE3res
     NFSPROC3_WRITE(WRITE3args)             = 7;

    CREATE3res
     NFSPROC3_CREATE(CREATE3args)           = 8;

    MKDIR3res
     NFSPROC3_MKDIR(MKDIR3args)             = 9;

    SYMLINK3res
     NFSPROC3_SYMLINK(SYMLINK3args)         = 10;

    MKNOD3res
     NFSPROC3_MKNOD(MKNOD3args)             = 11;

    REMOVE3res
     NFSPROC3_REMOVE(REMOVE3args)           = 12;

    RMDIR3res
     NFSPROC3_RMDIR(RMDIR3args)             = 13;

    RENAME3res
     NFSPROC3_RENAME(RENAME3args)           = 14;

    LINK3res
     NFSPROC3_LINK(LINK3args)               = 15;

    READDIR3res
     NFSPROC3_READDIR(READDIR3args)         = 16;

    READDIRPLUS3res
     NFSPROC3_READDIRPLUS(READDIRPLUS3args) = 17;

    FSSTAT3res
     NFSPROC3_FSSTAT(FSSTAT3args)           = 18;

    FSINFO3res
     NFSPROC3_FSINFO(FSINFO3args)           = 19;

    PATHCONF3res
     NFSPROC3_PATHCONF(PATHCONF3args)       = 20;

    COMMIT3res
     NFSPROC3_COMMIT(COMMIT3args)           = 21;

 } = 3;
} = 100003;
*/

#[allow(non_camel_case_types)]
#[allow(clippy::upper_case_acronyms)]
#[derive(Copy, Clone, Debug, FromPrimitive, ToPrimitive)]
enum NFSProgram {
    NFSPROC3_NULL = 0,
    NFSPROC3_GETATTR = 1,
    NFSPROC3_SETATTR = 2,
    NFSPROC3_LOOKUP = 3,
    NFSPROC3_ACCESS = 4,
    NFSPROC3_READLINK = 5,
    NFSPROC3_READ = 6,
    NFSPROC3_WRITE = 7,
    NFSPROC3_CREATE = 8,
    NFSPROC3_MKDIR = 9,
    NFSPROC3_SYMLINK = 10,
    NFSPROC3_MKNOD = 11,
    NFSPROC3_REMOVE = 12,
    NFSPROC3_RMDIR = 13,
    NFSPROC3_RENAME = 14,
    NFSPROC3_LINK = 15,
    NFSPROC3_READDIR = 16,
    NFSPROC3_READDIRPLUS = 17,
    NFSPROC3_FSSTAT = 18,
    NFSPROC3_FSINFO = 19,
    NFSPROC3_PATHCONF = 20,
    NFSPROC3_COMMIT = 21,
    INVALID = 22,
}

pub async fn handle_nfs(
    xid: u32,
    call: call_body,
    input: &mut impl Read,
    output: &mut impl Write,
    context: &RPCContext,
    connection_incarnation: u64,
) -> Result<(), anyhow::Error> {
    if call.vers != nfs::VERSION {
        warn!(
            "Invalid NFS Version number {} != {}",
            call.vers,
            nfs::VERSION
        );
        prog_mismatch_reply_message(xid, nfs::VERSION).serialize(output)?;
        return Ok(());
    }
    let prog = NFSProgram::from_u32(call.proc).unwrap_or(NFSProgram::INVALID);

    match prog {
        NFSProgram::NFSPROC3_NULL => nfsproc3_null(xid, input, output)?,
        NFSProgram::NFSPROC3_GETATTR => nfsproc3_getattr(xid, input, output, context).await?,
        NFSProgram::NFSPROC3_LOOKUP => nfsproc3_lookup(xid, input, output, context).await?,
        NFSProgram::NFSPROC3_READ => nfsproc3_read(xid, input, output, context).await?,
        NFSProgram::NFSPROC3_FSINFO => nfsproc3_fsinfo(xid, input, output, context).await?,
        NFSProgram::NFSPROC3_ACCESS => nfsproc3_access(xid, input, output, context).await?,
        NFSProgram::NFSPROC3_PATHCONF => nfsproc3_pathconf(xid, input, output, context).await?,
        NFSProgram::NFSPROC3_FSSTAT => nfsproc3_fsstat(xid, input, output, context).await?,
        NFSProgram::NFSPROC3_READDIR => nfsproc3_readdir(xid, input, output, context).await?,
        NFSProgram::NFSPROC3_READDIRPLUS => {
            nfsproc3_readdirplus(xid, input, output, context).await?
        }
        NFSProgram::NFSPROC3_WRITE => {
            nfsproc3_write(xid, input, output, context, connection_incarnation).await?
        }
        NFSProgram::NFSPROC3_CREATE => nfsproc3_create(xid, input, output, context).await?,
        NFSProgram::NFSPROC3_SETATTR => nfsproc3_setattr(xid, input, output, context).await?,
        NFSProgram::NFSPROC3_REMOVE => nfsproc3_remove(xid, input, output, context).await?,
        NFSProgram::NFSPROC3_RMDIR => nfsproc3_remove(xid, input, output, context).await?,
        NFSProgram::NFSPROC3_RENAME => nfsproc3_rename(xid, input, output, context).await?,
        NFSProgram::NFSPROC3_MKDIR => nfsproc3_mkdir(xid, input, output, context).await?,
        NFSProgram::NFSPROC3_SYMLINK => nfsproc3_symlink(xid, input, output, context).await?,
        NFSProgram::NFSPROC3_READLINK => nfsproc3_readlink(xid, input, output, context).await?,
        NFSProgram::NFSPROC3_MKNOD => nfsproc3_mknod(xid, input, output, context).await?,
        NFSProgram::NFSPROC3_LINK => nfsproc3_link(xid, input, output, context).await?,
        NFSProgram::NFSPROC3_COMMIT => {
            nfsproc3_commit(xid, input, output, context, connection_incarnation).await?
        }
        _ => {
            warn!("Unimplemented message {:?}", prog);
            proc_unavail_reply_message(xid).serialize(output)?;
        }
    }
    Ok(())
}

pub fn nfsproc3_null(
    xid: u32,
    _: &mut impl Read,
    output: &mut impl Write,
) -> Result<(), anyhow::Error> {
    debug!("nfsproc3_null({:?}) ", xid);
    let msg = make_success_reply(xid);
    debug!("\t{:?} --> {:?}", xid, msg);
    msg.serialize(output)?;
    Ok(())
}
/*
GETATTR3res NFSPROC3_GETATTR(GETATTR3args) = 1;
struct GETATTR3args {
  nfs_fh3  object;
};

struct GETATTR3resok {
  fattr3   obj_attributes;
};

union GETATTR3res switch (nfsstat3 status) {
 case NFS3_OK:
  GETATTR3resok  resok;
 default:
  void;
};
 */
pub async fn nfsproc3_getattr(
    xid: u32,
    input: &mut impl Read,
    output: &mut impl Write,
    context: &RPCContext,
) -> Result<(), anyhow::Error> {
    let mut handle = nfs::nfs_fh3::default();
    handle.deserialize(input)?;
    debug!("nfsproc3_getattr({:?},{:?}) ", xid, handle);

    let id = context.vfs.fh_to_id(&handle);
    // fail if unable to convert file handle
    if let Err(stat) = id {
        make_success_reply(xid).serialize(output)?;
        stat.serialize(output)?;
        return Ok(());
    }
    let id = id.unwrap();
    match context.vfs.getattr(&auth_from_context(context), id).await {
        Ok(fh) => {
            debug!(" {:?} --> {:?}", xid, fh);
            make_success_reply(xid).serialize(output)?;
            nfs::nfsstat3::NFS3_OK.serialize(output)?;
            fh.serialize(output)?;
        }
        Err(stat) => {
            error!("getattr error {:?} --> {:?}", xid, stat);
            make_success_reply(xid).serialize(output)?;
            stat.serialize(output)?;
        }
    }
    Ok(())
}

/*
 LOOKUP3res NFSPROC3_LOOKUP(LOOKUP3args) = 3;

 struct LOOKUP3args {
      diropargs3  what;
 };

 struct LOOKUP3resok {
      nfs_fh3      object;
      post_op_attr obj_attributes;
      post_op_attr dir_attributes;
 };

 struct LOOKUP3resfail {
      post_op_attr dir_attributes;
 };

 union LOOKUP3res switch (nfsstat3 status) {
 case NFS3_OK:
      LOOKUP3resok    resok;
 default:
      LOOKUP3resfail  resfail;
 };
*
*/
pub async fn nfsproc3_lookup(
    xid: u32,
    input: &mut impl Read,
    output: &mut impl Write,
    context: &RPCContext,
) -> Result<(), anyhow::Error> {
    let mut dirops = nfs::diropargs3::default();
    dirops.deserialize(input)?;
    debug!("nfsproc3_lookup({:?},{:?}) ", xid, dirops);

    let dirid = context.vfs.fh_to_id(&dirops.dir);
    // fail if unable to convert file handle
    if let Err(stat) = dirid {
        make_success_reply(xid).serialize(output)?;
        stat.serialize(output)?;
        nfs::post_op_attr::Void.serialize(output)?;
        return Ok(());
    }
    let dirid = dirid.unwrap();

    let dir_attr = match context
        .vfs
        .getattr(&auth_from_context(context), dirid)
        .await
    {
        Ok(v) => nfs::post_op_attr::attributes(v),
        Err(_) => nfs::post_op_attr::Void,
    };
    match context
        .vfs
        .lookup(&auth_from_context(context), dirid, &dirops.name)
        .await
    {
        Ok(fid) => {
            let obj_attr = match context.vfs.getattr(&auth_from_context(context), fid).await {
                Ok(v) => nfs::post_op_attr::attributes(v),
                Err(_) => nfs::post_op_attr::Void,
            };

            debug!("lookup success {:?} --> {:?}", xid, obj_attr);
            make_success_reply(xid).serialize(output)?;
            nfs::nfsstat3::NFS3_OK.serialize(output)?;
            context.vfs.id_to_fh(fid).serialize(output)?;
            obj_attr.serialize(output)?;
            dir_attr.serialize(output)?;
        }
        Err(stat) => {
            debug!("lookup error {:?}({:?}) --> {:?}", xid, dirops.name, stat);
            make_success_reply(xid).serialize(output)?;
            stat.serialize(output)?;
            dir_attr.serialize(output)?;
        }
    }
    Ok(())
}

#[allow(non_camel_case_types)]
#[derive(Debug, Default)]
struct READ3args {
    file: nfs::nfs_fh3,
    offset: nfs::offset3,
    count: nfs::count3,
}
XDRStruct!(READ3args, file, offset, count);

#[allow(non_camel_case_types)]
#[derive(Debug, Default)]
struct READ3resok {
    file_attributes: nfs::post_op_attr,
    count: nfs::count3,
    eof: bool,
    data: Vec<u8>,
}
XDRStruct!(READ3resok, file_attributes, count, eof, data);
/*
READ3res NFSPROC3_READ(READ3args) = 6;

struct READ3args {
   nfs_fh3  file;
   offset3  offset;
   count3   count;
};

struct READ3resok {
   post_op_attr   file_attributes;
   count3         count;
   bool           eof;
   opaque         data<>;
};

struct READ3resfail {
   post_op_attr   file_attributes;
};

union READ3res switch (nfsstat3 status) {
case NFS3_OK:
   READ3resok   resok;
default:
   READ3resfail resfail;
};
 */
pub async fn nfsproc3_read(
    xid: u32,
    input: &mut impl Read,
    output: &mut impl Write,
    context: &RPCContext,
) -> Result<(), anyhow::Error> {
    let mut args = READ3args::default();
    args.deserialize(input)?;
    debug!("nfsproc3_read({:?},{:?}) ", xid, args);
    if args.count > MAX_NFS_IO_BYTES {
        make_success_reply(xid).serialize(output)?;
        nfs::nfsstat3::NFS3ERR_INVAL.serialize(output)?;
        nfs::post_op_attr::Void.serialize(output)?;
        return Ok(());
    }

    let id = context.vfs.fh_to_id(&args.file);
    if let Err(stat) = id {
        make_success_reply(xid).serialize(output)?;
        stat.serialize(output)?;
        nfs::post_op_attr::Void.serialize(output)?;
        return Ok(());
    }
    let id = id.unwrap();

    let obj_attr = match context.vfs.getattr(&auth_from_context(context), id).await {
        Ok(v) => nfs::post_op_attr::attributes(v),
        Err(_) => nfs::post_op_attr::Void,
    };
    match context
        .vfs
        .read(&auth_from_context(context), id, args.offset, args.count)
        .await
    {
        Ok((bytes, eof)) => {
            let res = READ3resok {
                file_attributes: obj_attr,
                count: bytes.len() as u32,
                eof,
                data: bytes,
            };
            make_success_reply(xid).serialize(output)?;
            nfs::nfsstat3::NFS3_OK.serialize(output)?;
            res.serialize(output)?;
        }
        Err(stat) => {
            error!("read error {:?} --> {:?}", xid, stat);
            make_success_reply(xid).serialize(output)?;
            stat.serialize(output)?;
            obj_attr.serialize(output)?;
        }
    }
    Ok(())
}

/*

  FSINFO3res NFSPROC3_FSINFO(FSINFO3args) = 19;

  const FSF3_LINK        = 0x0001;
  const FSF3_SYMLINK     = 0x0002;
  const FSF3_HOMOGENEOUS = 0x0008;
  const FSF3_CANSETTIME  = 0x0010;

  struct FSINFOargs {
       nfs_fh3   fsroot;
  };

  struct FSINFO3resok {
       post_op_attr obj_attributes;
       uint32       rtmax;
       uint32       rtpref;
       uint32       rtmult;
       uint32       wtmax;
       uint32       wtpref;
       uint32       wtmult;
       uint32       dtpref;
       size3        maxfilesize;
       nfstime3     time_delta;
       uint32       properties;
  };

  struct FSINFO3resfail {
       post_op_attr obj_attributes;
  };

  union FSINFO3res switch (nfsstat3 status) {
  case NFS3_OK:
       FSINFO3resok   resok;
  default:
       FSINFO3resfail resfail;
  };
*/

pub async fn nfsproc3_fsinfo(
    xid: u32,
    input: &mut impl Read,
    output: &mut impl Write,
    context: &RPCContext,
) -> Result<(), anyhow::Error> {
    let mut handle = nfs::nfs_fh3::default();
    handle.deserialize(input)?;
    debug!("nfsproc3_fsinfo({:?},{:?}) ", xid, handle);

    let id = context.vfs.fh_to_id(&handle);
    // fail if unable to convert file handle
    if let Err(stat) = id {
        make_success_reply(xid).serialize(output)?;
        stat.serialize(output)?;
        nfs::post_op_attr::Void.serialize(output)?;
        return Ok(());
    }
    let id = id.unwrap();

    match context.vfs.fsinfo(&auth_from_context(context), id).await {
        Ok(fsinfo) => {
            debug!(" {:?} --> {:?}", xid, fsinfo);
            make_success_reply(xid).serialize(output)?;
            nfs::nfsstat3::NFS3_OK.serialize(output)?;
            fsinfo.serialize(output)?;
        }
        Err(stat) => {
            error!("fsinfo error {:?} --> {:?}", xid, stat);
            make_success_reply(xid).serialize(output)?;
            stat.serialize(output)?;
        }
    }
    Ok(())
}

const ACCESS3_READ: u32 = 0x0001;
const ACCESS3_LOOKUP: u32 = 0x0002;
const ACCESS3_MODIFY: u32 = 0x0004;
const ACCESS3_EXTEND: u32 = 0x0008;
const ACCESS3_DELETE: u32 = 0x0010;
const ACCESS3_EXECUTE: u32 = 0x0020;
/*

 ACCESS3res NFSPROC3_ACCESS(ACCESS3args) = 4;


 struct ACCESS3args {
      nfs_fh3  object;
      uint32   access;
 };

 struct ACCESS3resok {
      post_op_attr   obj_attributes;
      uint32         access;
 };

 struct ACCESS3resfail {
      post_op_attr   obj_attributes;
 };

 union ACCESS3res switch (nfsstat3 status) {
 case NFS3_OK:
      ACCESS3resok   resok;
 default:
      ACCESS3resfail resfail;
 };
*/

pub async fn nfsproc3_access(
    xid: u32,
    input: &mut impl Read,
    output: &mut impl Write,
    context: &RPCContext,
) -> Result<(), anyhow::Error> {
    let mut handle = nfs::nfs_fh3::default();
    handle.deserialize(input)?;
    let mut access: u32 = 0;
    access.deserialize(input)?;
    debug!("nfsproc3_access({:?},{:?},{:?})", xid, handle, access);

    let id = context.vfs.fh_to_id(&handle);
    // fail if unable to convert file handle
    if let Err(stat) = id {
        make_success_reply(xid).serialize(output)?;
        stat.serialize(output)?;
        nfs::post_op_attr::Void.serialize(output)?;
        return Ok(());
    }
    let id = id.unwrap();

    let obj_attr = match context.vfs.getattr(&auth_from_context(context), id).await {
        Ok(v) => nfs::post_op_attr::attributes(v),
        Err(_) => nfs::post_op_attr::Void,
    };
    // TODO better checks here
    if !matches!(context.vfs.capabilities(), VFSCapabilities::ReadWrite) {
        access &= ACCESS3_READ | ACCESS3_LOOKUP;
    }
    debug!(" {:?} ---> {:?}", xid, access);
    make_success_reply(xid).serialize(output)?;
    nfs::nfsstat3::NFS3_OK.serialize(output)?;
    obj_attr.serialize(output)?;
    access.serialize(output)?;
    Ok(())
}

#[allow(non_camel_case_types)]
#[derive(Debug, Default)]
struct PATHCONF3resok {
    obj_attributes: nfs::post_op_attr,
    linkmax: u32,
    name_max: u32,
    no_trunc: bool,
    chown_restricted: bool,
    case_insensitive: bool,
    case_preserving: bool,
}
XDRStruct!(
    PATHCONF3resok,
    obj_attributes,
    linkmax,
    name_max,
    no_trunc,
    chown_restricted,
    case_insensitive,
    case_preserving
);
/*

     PATHCONF3res NFSPROC3_PATHCONF(PATHCONF3args) = 20;

     struct PATHCONF3args {
          nfs_fh3   object;
     };

     struct PATHCONF3resok {
          post_op_attr obj_attributes;
          uint32       linkmax;
          uint32       name_max;
          bool         no_trunc;
          bool         chown_restricted;
          bool         case_insensitive;
          bool         case_preserving;
     };

     struct PATHCONF3resfail {
          post_op_attr obj_attributes;
     };

     union PATHCONF3res switch (nfsstat3 status) {
     case NFS3_OK:
          PATHCONF3resok   resok;
     default:
          PATHCONF3resfail resfail;
     };
*/
pub async fn nfsproc3_pathconf(
    xid: u32,
    input: &mut impl Read,
    output: &mut impl Write,
    context: &RPCContext,
) -> Result<(), anyhow::Error> {
    let mut handle = nfs::nfs_fh3::default();
    handle.deserialize(input)?;
    debug!("nfsproc3_pathconf({:?},{:?})", xid, handle);

    let id = context.vfs.fh_to_id(&handle);
    // fail if unable to convert file handle
    if let Err(stat) = id {
        make_success_reply(xid).serialize(output)?;
        stat.serialize(output)?;
        nfs::post_op_attr::Void.serialize(output)?;
        return Ok(());
    }
    let id = id.unwrap();

    let obj_attr = match context.vfs.getattr(&auth_from_context(context), id).await {
        Ok(v) => nfs::post_op_attr::attributes(v),
        Err(_) => nfs::post_op_attr::Void,
    };
    let res = PATHCONF3resok {
        obj_attributes: obj_attr,
        linkmax: 0,
        name_max: 32768,
        no_trunc: true,
        chown_restricted: true,
        case_insensitive: false,
        case_preserving: true,
    };
    debug!(" {:?} ---> {:?}", xid, res);
    make_success_reply(xid).serialize(output)?;
    nfs::nfsstat3::NFS3_OK.serialize(output)?;
    res.serialize(output)?;
    Ok(())
}

// FSSTAT3resok is now defined as nfs::fsstat3 in the nfs module

/*
 FSSTAT3res NFSPROC3_FSSTAT(FSSTAT3args) = 18;

     struct FSSTAT3args {
          nfs_fh3   fsroot;
     };

     struct FSSTAT3resok {
          post_op_attr obj_attributes;
          size3        tbytes;
          size3        fbytes;
          size3        abytes;
          size3        tfiles;
          size3        ffiles;
          size3        afiles;
          uint32       invarsec;
     };

     struct FSSTAT3resfail {
          post_op_attr obj_attributes;
     };

     union FSSTAT3res switch (nfsstat3 status) {
     case NFS3_OK:
          FSSTAT3resok   resok;
     default:
          FSSTAT3resfail resfail;
     };

*/

pub async fn nfsproc3_fsstat(
    xid: u32,
    input: &mut impl Read,
    output: &mut impl Write,
    context: &RPCContext,
) -> Result<(), anyhow::Error> {
    let mut handle = nfs::nfs_fh3::default();
    handle.deserialize(input)?;
    debug!("nfsproc3_fsstat({:?},{:?}) ", xid, handle);
    let id = context.vfs.fh_to_id(&handle);
    // fail if unable to convert file handle
    if let Err(stat) = id {
        make_success_reply(xid).serialize(output)?;
        stat.serialize(output)?;
        nfs::post_op_attr::Void.serialize(output)?;
        return Ok(());
    }
    let id = id.unwrap();

    match context.vfs.fsstat(&auth_from_context(context), id).await {
        Ok(res) => {
            make_success_reply(xid).serialize(output)?;
            nfs::nfsstat3::NFS3_OK.serialize(output)?;
            debug!(" {:?} ---> {:?}", xid, res);
            res.serialize(output)?;
        }
        Err(stat) => {
            make_success_reply(xid).serialize(output)?;
            stat.serialize(output)?;
            // FSSTAT3resfail - just post_op_attr
            let obj_attr = match context.vfs.getattr(&auth_from_context(context), id).await {
                Ok(v) => nfs::post_op_attr::attributes(v),
                Err(_) => nfs::post_op_attr::Void,
            };
            obj_attr.serialize(output)?;
        }
    }
    Ok(())
}

#[allow(non_camel_case_types)]
#[derive(Debug, Default)]
struct READDIRPLUS3args {
    dir: nfs::nfs_fh3,
    cookie: nfs::cookie3,
    cookieverf: nfs::cookieverf3,
    dircount: nfs::count3,
    maxcount: nfs::count3,
}
XDRStruct!(
    READDIRPLUS3args,
    dir,
    cookie,
    cookieverf,
    dircount,
    maxcount
);

#[allow(non_camel_case_types)]
#[derive(Debug, Default)]
struct entry3 {
    fileid: nfs::fileid3,
    name: nfs::filename3,
    cookie: nfs::cookie3,
}
XDRStruct!(entry3, fileid, name, cookie);

#[allow(non_camel_case_types)]
#[derive(Debug, Default)]
struct READDIR3args {
    dir: nfs::nfs_fh3,
    cookie: nfs::cookie3,
    cookieverf: nfs::cookieverf3,
    dircount: nfs::count3,
}
XDRStruct!(READDIR3args, dir, cookie, cookieverf, dircount);

#[allow(non_camel_case_types)]
#[derive(Debug, Default)]
struct entryplus3 {
    fileid: nfs::fileid3,
    name: nfs::filename3,
    cookie: nfs::cookie3,
    name_attributes: nfs::post_op_attr,
    name_handle: nfs::post_op_fh3,
}
XDRStruct!(
    entryplus3,
    fileid,
    name,
    cookie,
    name_attributes,
    name_handle
);
/*

      READDIRPLUS3res NFSPROC3_READDIRPLUS(READDIRPLUS3args) = 17;

      struct READDIRPLUS3args {
           nfs_fh3      dir;
           cookie3      cookie;
           cookieverf3  cookieverf;
           count3       dircount;
           count3       maxcount;
      };


      struct dirlistplus3 {
           entryplus3   *entries;
           bool         eof;
      };

      struct READDIRPLUS3resok {
           post_op_attr dir_attributes;
           cookieverf3  cookieverf;
           dirlistplus3 reply;
      };
   struct READDIRPLUS3resfail {
           post_op_attr dir_attributes;
      };
*/
pub async fn nfsproc3_readdirplus(
    xid: u32,
    input: &mut impl Read,
    output: &mut impl Write,
    context: &RPCContext,
) -> Result<(), anyhow::Error> {
    let mut args = READDIRPLUS3args::default();
    args.deserialize(input)?;
    debug!("nfsproc3_readdirplus({:?},{:?}) ", xid, args);

    let dirid = context.vfs.fh_to_id(&args.dir);
    // fail if unable to convert file handle
    if let Err(stat) = dirid {
        make_success_reply(xid).serialize(output)?;
        stat.serialize(output)?;
        nfs::post_op_attr::Void.serialize(output)?;
        return Ok(());
    }
    let dirid = dirid.unwrap();
    let dir_attr_maybe = context
        .vfs
        .getattr(&auth_from_context(context), dirid)
        .await;

    let dir_attr = match dir_attr_maybe {
        Ok(v) => nfs::post_op_attr::attributes(v),
        Err(_) => nfs::post_op_attr::Void,
    };

    let dirversion = if let Ok(ref dir_attr) = dir_attr_maybe {
        let cvf_version = (dir_attr.mtime.seconds as u64) << 32 | (dir_attr.mtime.nseconds as u64);
        cvf_version.to_be_bytes()
    } else {
        nfs::cookieverf3::default()
    };
    debug!(" -- Dir attr {:?}", dir_attr);
    debug!(" -- Dir version {:?}", dirversion);
    let has_version = args.cookieverf != nfs::cookieverf3::default();
    // initial call should hve empty cookie verf
    // subsequent calls should have cvf_version as defined above
    // which is based off the mtime.
    //
    // TODO: This is *far* too aggressive. and unnecessary.
    // The client should maintain this correctly typically.
    //
    // The way cookieverf is handled is quite interesting...
    //
    // There are 2 notes in the RFC of interest:
    // 1. If the
    // server detects that the cookie is no longer valid, the
    // server will reject the READDIR request with the status,
    // NFS3ERR_BAD_COOKIE. The client should be careful to
    // avoid holding directory entry cookies across operations
    // that modify the directory contents, such as REMOVE and
    // CREATE.
    //
    // 2. One implementation of the cookie-verifier mechanism might
    //  be for the server to use the modification time of the
    //  directory. This might be overly restrictive, however. A
    //  better approach would be to record the time of the last
    //  directory modification that changed the directory
    //  organization in a way that would make it impossible to
    //  reliably interpret a cookie. Servers in which directory
    //  cookies are always valid are free to use zero as the
    //  verifier always.
    //
    //  Basically, as long as the cookie is "kinda" intepretable,
    //  we should keep accepting it.
    //  On testing, the Mac NFS client pretty much expects that
    //  especially on highly concurrent modifications to the directory.
    //
    //  1. If part way through a directory enumeration we fail with BAD_COOKIE
    //  if the directory contents change, the client listing may fail resulting
    //  in a "no such file or directory" error.
    //  2. if we cache readdir results. i.e. we think of a readdir as two parts
    //     a. enumerating everything first
    //     b. the cookie is then used to paginate the enumeration
    //     we can run into file time synchronization issues. i.e. while one
    //     listing occurs and another file is touched, the listing may report
    //     an outdated file status.
    //
    //     This cache also appears to have to be *quite* long lasting
    //     as the client may hold on to a directory enumerator
    //     with unbounded time.
    //
    //  Basically, if we think about how linux directory listing works
    //  is that you just get an enumerator. There is no mechanic available for
    //  "restarting" a pagination and this enumerator is assumed to be valid
    //  even across directory modifications and should reflect changes
    //  immediately.
    //
    //  The best solution is simply to really completely avoid sending
    //  BAD_COOKIE all together and to ignore the cookie mechanism.
    //
    /*if args.cookieverf != nfs::cookieverf3::default() && args.cookieverf != dirversion {
        info!(" -- Dir version mismatch. Received {:?}", args.cookieverf);
        make_success_reply(xid).serialize(output)?;
        nfs::nfsstat3::NFS3ERR_BAD_COOKIE.serialize(output)?;
        dir_attr.serialize(output)?;
        return Ok(());
    }*/
    let result_limit = args.maxcount as usize;
    let dir_limit = args.dircount as usize;
    let mut reply = Vec::new();
    make_success_reply(xid).serialize(&mut reply)?;
    nfs::nfsstat3::NFS3_OK.serialize(&mut reply)?;
    let result_start = reply.len();
    dir_attr.serialize(&mut reply)?;
    dirversion.serialize(&mut reply)?;

    let result_capacity = entry_capacity(
        result_limit,
        reply.len() - result_start,
        MIN_READDIRPLUS_ENTRY_BYTES,
    );
    let wire_capacity = entry_capacity(
        MAX_RPC_RECORD_BYTES,
        reply.len(),
        MIN_READDIRPLUS_ENTRY_BYTES,
    );
    let dir_capacity = entry_capacity(dir_limit, 0, MIN_READDIR_ENTRY_BYTES);
    let max_results = result_capacity.min(wire_capacity).min(dir_capacity);
    if max_results == 0 {
        write_readdir_error(xid, nfs::nfsstat3::NFS3ERR_TOOSMALL, dir_attr, output)?;
        return Ok(());
    }
    let mut ctr = 0;
    match context
        .vfs
        .readdir(&auth_from_context(context), dirid, args.cookie, max_results)
        .await
    {
        Ok(result) => {
            let entry_count = result.entries.len();
            if entry_count == 0 && !result.end {
                write_readdir_error(xid, nfs::nfsstat3::NFS3ERR_SERVERFAULT, dir_attr, output)?;
                return Ok(());
            }
            let mut accumulated_dircount = 0usize;
            for entry in result.entries {
                let obj_attr = entry.attr;
                let display_fileid = obj_attr.fileid;
                let handle = nfs::post_op_fh3::handle(context.vfs.id_to_fh(entry.fileid));
                let dir_entry = entry3 {
                    fileid: display_fileid,
                    name: entry.name.clone(),
                    cookie: entry.cookie,
                };
                let plus_entry = entryplus3 {
                    fileid: display_fileid,
                    name: entry.name,
                    cookie: entry.cookie,
                    name_attributes: nfs::post_op_attr::attributes(obj_attr),
                    name_handle: handle,
                };
                let mut dir_bytes = Vec::new();
                true.serialize(&mut dir_bytes)?;
                dir_entry.serialize(&mut dir_bytes)?;
                let mut plus_bytes = Vec::new();
                true.serialize(&mut plus_bytes)?;
                plus_entry.serialize(&mut plus_bytes)?;

                if fits_with_tail(reply.len() - result_start, plus_bytes.len(), result_limit)
                    && fits_with_tail(reply.len(), plus_bytes.len(), MAX_RPC_RECORD_BYTES)
                    && fits_with_tail(accumulated_dircount, dir_bytes.len(), dir_limit)
                {
                    trace!("  -- dirent {:?}", plus_entry);
                    ctr += 1;
                    reply.extend_from_slice(&plus_bytes);
                    accumulated_dircount += dir_bytes.len();
                    trace!(
                        "  -- lengths: {:?} / {:?} {:?} / {:?}",
                        accumulated_dircount,
                        dir_limit,
                        reply.len(),
                        result_limit
                    );
                } else {
                    trace!(" -- insufficient space. truncating");
                    break;
                }
            }
            if ctr == 0 && entry_count > 0 {
                write_readdir_error(xid, nfs::nfsstat3::NFS3ERR_TOOSMALL, dir_attr, output)?;
                return Ok(());
            }
            let all_entries_written = ctr == entry_count;
            false.serialize(&mut reply)?;
            let eof = all_entries_written && result.end;
            eof.serialize(&mut reply)?;
            debug!("  -- readdir eof {:?}", eof);
            output.write_all(&reply)?;
            debug!(
                "readir {}, has_version {},  start at {}, flushing {} entries, complete {}",
                dirid, has_version, args.cookie, ctr, all_entries_written
            );
        }
        Err(stat) => {
            error!("readdir error {:?} --> {:?} ", xid, stat);
            write_readdir_error(xid, stat, dir_attr, output)?;
        }
    };
    Ok(())
}

pub async fn nfsproc3_readdir(
    xid: u32,
    input: &mut impl Read,
    output: &mut impl Write,
    context: &RPCContext,
) -> Result<(), anyhow::Error> {
    let mut args = READDIR3args::default();
    args.deserialize(input)?;
    debug!("nfsproc3_readdirplus({:?},{:?}) ", xid, args);

    let dirid = context.vfs.fh_to_id(&args.dir);
    // fail if unable to convert file handle
    if let Err(stat) = dirid {
        make_success_reply(xid).serialize(output)?;
        stat.serialize(output)?;
        nfs::post_op_attr::Void.serialize(output)?;
        return Ok(());
    }
    let dirid = dirid.unwrap();
    let dir_attr_maybe = context
        .vfs
        .getattr(&auth_from_context(context), dirid)
        .await;

    let dir_attr = match dir_attr_maybe {
        Ok(v) => nfs::post_op_attr::attributes(v),
        Err(_) => nfs::post_op_attr::Void,
    };

    let dirversion = if let Ok(ref dir_attr) = dir_attr_maybe {
        let cvf_version = (dir_attr.mtime.seconds as u64) << 32 | (dir_attr.mtime.nseconds as u64);
        cvf_version.to_be_bytes()
    } else {
        nfs::cookieverf3::default()
    };
    debug!(" -- Dir attr {:?}", dir_attr);
    debug!(" -- Dir version {:?}", dirversion);
    let has_version = args.cookieverf != nfs::cookieverf3::default();
    let result_limit = args.dircount as usize;
    let mut reply = Vec::new();
    make_success_reply(xid).serialize(&mut reply)?;
    nfs::nfsstat3::NFS3_OK.serialize(&mut reply)?;
    let result_start = reply.len();
    dir_attr.serialize(&mut reply)?;
    dirversion.serialize(&mut reply)?;
    let result_capacity = entry_capacity(
        result_limit,
        reply.len() - result_start,
        MIN_READDIR_ENTRY_BYTES,
    );
    let wire_capacity = entry_capacity(MAX_RPC_RECORD_BYTES, reply.len(), MIN_READDIR_ENTRY_BYTES);
    let max_results = result_capacity.min(wire_capacity);
    if max_results == 0 {
        write_readdir_error(xid, nfs::nfsstat3::NFS3ERR_TOOSMALL, dir_attr, output)?;
        return Ok(());
    }
    let mut ctr = 0;
    match context
        .vfs
        .readdir(&auth_from_context(context), dirid, args.cookie, max_results)
        .await
    {
        Ok(result) => {
            let entry_count = result.entries.len();
            if entry_count == 0 && !result.end {
                write_readdir_error(xid, nfs::nfsstat3::NFS3ERR_SERVERFAULT, dir_attr, output)?;
                return Ok(());
            }
            for entry in result.entries {
                let entry = entry3 {
                    fileid: entry.fileid,
                    name: entry.name,
                    cookie: entry.cookie,
                };
                // write the entry into a buffer first
                let mut entry_bytes = Vec::new();
                true.serialize(&mut entry_bytes)?;
                entry.serialize(&mut entry_bytes)?;
                if fits_with_tail(reply.len() - result_start, entry_bytes.len(), result_limit)
                    && fits_with_tail(reply.len(), entry_bytes.len(), MAX_RPC_RECORD_BYTES)
                {
                    trace!("  -- dirent {:?}", entry);
                    ctr += 1;
                    reply.extend_from_slice(&entry_bytes);
                    trace!("  -- length: {:?} / {:?}", reply.len(), result_limit);
                } else {
                    trace!(" -- insufficient space. truncating");
                    break;
                }
            }
            if ctr == 0 && entry_count > 0 {
                write_readdir_error(xid, nfs::nfsstat3::NFS3ERR_TOOSMALL, dir_attr, output)?;
                return Ok(());
            }
            let all_entries_written = ctr == entry_count;
            false.serialize(&mut reply)?;
            let eof = all_entries_written && result.end;
            eof.serialize(&mut reply)?;
            debug!("  -- readdir eof {:?}", eof);
            output.write_all(&reply)?;
            debug!(
                "readir {}, has_version {},  start at {}, flushing {} entries, complete {}",
                dirid, has_version, args.cookie, ctr, all_entries_written
            );
        }
        Err(stat) => {
            error!("readdir error {:?} --> {:?} ", xid, stat);
            write_readdir_error(xid, stat, dir_attr, output)?;
        }
    };
    Ok(())
}

#[allow(non_camel_case_types)]
#[derive(Debug, Default)]
struct WRITE3args {
    file: nfs::nfs_fh3,
    offset: nfs::offset3,
    count: nfs::count3,
    stable: u32,
    data: Vec<u8>,
}
XDRStruct!(WRITE3args, file, offset, count, stable, data);

#[allow(non_camel_case_types)]
#[derive(Debug, Default)]
struct WRITE3resok {
    file_wcc: nfs::wcc_data,
    count: nfs::count3,
    committed: stable_how,
    verf: nfs::writeverf3,
}
XDRStruct!(WRITE3resok, file_wcc, count, committed, verf);
/*
enum stable_how {
    UNSTABLE = 0,
    DATA_SYNC = 1,
    FILE_SYNC = 2
};


struct WRITE3args {
    nfs_fh3 file;
    offset3 offset;
    count3 count;
    stable_how stable;
    opaque data<>;
};

struct WRITE3resok {
    wcc_data file_wcc;
    count3 count;
    stable_how committed;
    writeverf3 verf;
};


struct WRITE3resfail {
    wcc_data file_wcc;
};


union WRITE3res switch (nfsstat3 status) {
    case NFS3_OK:
        WRITE3resok resok;
    default:
        WRITE3resfail resfail;
};

 */
pub async fn nfsproc3_write(
    xid: u32,
    input: &mut impl Read,
    output: &mut impl Write,
    context: &RPCContext,
    connection_incarnation: u64,
) -> Result<(), anyhow::Error> {
    // if we do not have write capabilities
    if !matches!(context.vfs.capabilities(), VFSCapabilities::ReadWrite) {
        warn!("No write capabilities.");
        make_success_reply(xid).serialize(output)?;
        nfs::nfsstat3::NFS3ERR_ROFS.serialize(output)?;
        nfs::wcc_data::default().serialize(output)?;
        return Ok(());
    }

    let mut args = WRITE3args::default();
    args.deserialize(input)?;
    debug!("nfsproc3_write({:?},...) ", xid);
    // sanity check the length
    if args.count > MAX_NFS_IO_BYTES {
        make_success_reply(xid).serialize(output)?;
        nfs::nfsstat3::NFS3ERR_INVAL.serialize(output)?;
        nfs::wcc_data::default().serialize(output)?;
        return Ok(());
    }
    if args.data.len() != args.count as usize {
        garbage_args_reply_message(xid).serialize(output)?;
        return Ok(());
    }
    // sanity check the requested stability level
    let requested_stability = match stable_how::from_u32(args.stable) {
        Some(stability) => stability,
        None => {
            garbage_args_reply_message(xid).serialize(output)?;
            return Ok(());
        }
    };

    let id = context.vfs.fh_to_id(&args.file);
    if let Err(stat) = id {
        make_success_reply(xid).serialize(output)?;
        stat.serialize(output)?;
        nfs::wcc_data::default().serialize(output)?;
        return Ok(());
    }
    let id = id.unwrap();

    // get the object attributes before the write
    let pre_obj_attr = match context.vfs.getattr(&auth_from_context(context), id).await {
        Ok(v) => {
            let wccattr = nfs::wcc_attr {
                size: v.size,
                mtime: v.mtime,
                ctime: v.ctime,
            };
            nfs::pre_op_attr::attributes(wccattr)
        }
        Err(_) => nfs::pre_op_attr::Void,
    };

    let write_context = WriteRequestContext {
        rpc: RpcRequestContext {
            xid,
            client_addr: context.client_addr.clone(),
            connection_incarnation,
        },
        requested_stability,
    };

    match context
        .vfs
        .write_with_context(
            &write_context,
            &auth_from_context(context),
            id,
            args.offset,
            &args.data,
        )
        .await
    {
        Ok(result) => {
            debug!("write success {:?} --> {:?}", xid, result.attributes);
            let res = WRITE3resok {
                file_wcc: nfs::wcc_data {
                    before: pre_obj_attr,
                    after: nfs::post_op_attr::attributes(result.attributes),
                },
                count: args.count,
                committed: result.committed,
                verf: result.verifier,
            };
            make_success_reply(xid).serialize(output)?;
            nfs::nfsstat3::NFS3_OK.serialize(output)?;
            res.serialize(output)?;
        }
        Err(stat) => {
            error!("write error {:?} --> {:?}", xid, stat);
            make_success_reply(xid).serialize(output)?;
            stat.serialize(output)?;
            nfs::wcc_data::default().serialize(output)?;
        }
    }
    Ok(())
}

#[allow(non_camel_case_types)]
#[derive(Debug, Default)]
struct COMMIT3args {
    file: nfs::nfs_fh3,
    offset: nfs::offset3,
    count: nfs::count3,
}
XDRStruct!(COMMIT3args, file, offset, count);

#[allow(non_camel_case_types)]
#[derive(Debug, Default)]
struct COMMIT3resok {
    file_wcc: nfs::wcc_data,
    verf: nfs::writeverf3,
}
XDRStruct!(COMMIT3resok, file_wcc, verf);

#[allow(non_camel_case_types)]
#[derive(Debug, Default)]
struct COMMIT3resfail {
    file_wcc: nfs::wcc_data,
}
XDRStruct!(COMMIT3resfail, file_wcc);

#[allow(non_camel_case_types)]
#[derive(Debug)]
#[repr(u32)]
enum COMMIT3res {
    NFS3_OK(COMMIT3resok),
    Error(nfs::nfsstat3, COMMIT3resfail),
}

impl XDR for COMMIT3res {
    fn serialize<R: Write>(&self, dest: &mut R) -> std::io::Result<()> {
        match self {
            COMMIT3res::NFS3_OK(resok) => {
                nfs::nfsstat3::NFS3_OK.serialize(dest)?;
                resok.serialize(dest)?;
            }
            COMMIT3res::Error(status, resfail) => {
                status.serialize(dest)?;
                resfail.serialize(dest)?;
            }
        }
        Ok(())
    }

    fn deserialize<R: Read>(&mut self, _src: &mut R) -> std::io::Result<()> {
        unimplemented!("COMMIT3res deserialize not needed for server")
    }
}

pub async fn nfsproc3_commit(
    xid: u32,
    input: &mut impl Read,
    output: &mut impl Write,
    context: &RPCContext,
    connection_incarnation: u64,
) -> Result<(), anyhow::Error> {
    debug!("Handling COMMIT request: xid = {:?}", xid);

    let mut args = COMMIT3args::default();
    args.deserialize(input)?;

    if matches!(context.vfs.capabilities(), VFSCapabilities::ReadOnly) {
        make_success_reply(xid).serialize(output)?;
        nfs::nfsstat3::NFS3ERR_ROFS.serialize(output)?;
        nfs::wcc_data::default().serialize(output)?;
        return Ok(());
    }

    let id = context.vfs.fh_to_id(&args.file);
    if let Err(stat) = id {
        make_success_reply(xid).serialize(output)?;
        stat.serialize(output)?;
        nfs::wcc_data::default().serialize(output)?;
        return Ok(());
    }
    let id = id.unwrap();

    // Get pre-operation attributes
    let pre_obj_attr = match context.vfs.getattr(&auth_from_context(context), id).await {
        Ok(v) => {
            let wccattr = nfs::wcc_attr {
                size: v.size,
                mtime: v.mtime,
                ctime: v.ctime,
            };
            nfs::pre_op_attr::attributes(wccattr)
        }
        Err(_) => nfs::pre_op_attr::Void,
    };

    let commit_context = CommitRequestContext {
        rpc: RpcRequestContext {
            xid,
            client_addr: context.client_addr.clone(),
            connection_incarnation,
        },
    };

    match context
        .vfs
        .commit_with_context(
            &commit_context,
            &auth_from_context(context),
            id,
            args.offset,
            args.count,
        )
        .await
    {
        Ok(result) => {
            debug!("commit success {:?}", xid);

            // Get post-operation attributes
            let post_obj_attr = match context.vfs.getattr(&auth_from_context(context), id).await {
                Ok(v) => nfs::post_op_attr::attributes(v),
                Err(_) => nfs::post_op_attr::Void,
            };

            let file_wcc = nfs::wcc_data {
                before: pre_obj_attr,
                after: post_obj_attr,
            };

            let res = COMMIT3resok {
                file_wcc,
                verf: result.verifier,
            };

            make_success_reply(xid).serialize(output)?;
            nfs::nfsstat3::NFS3_OK.serialize(output)?;
            res.serialize(output)?;
        }
        Err(stat) => {
            error!("commit error {:?} --> {:?}", xid, stat);
            make_success_reply(xid).serialize(output)?;
            stat.serialize(output)?;
            nfs::wcc_data::default().serialize(output)?;
        }
    }
    Ok(())
}

#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug, Default, FromPrimitive, ToPrimitive)]
#[repr(u32)]
pub enum createmode3 {
    #[default]
    UNCHECKED = 0,
    GUARDED = 1,
    EXCLUSIVE = 2,
}
XDREnumSerde!(createmode3);
/*
CREATE3res NFSPROC3_CREATE(CREATE3args) = 8;

      enum createmode3 {
           UNCHECKED = 0,
           GUARDED   = 1,
           EXCLUSIVE = 2
      };

      union createhow3 switch (createmode3 mode) {
      case UNCHECKED:
      case GUARDED:
           sattr3       obj_attributes;
      case EXCLUSIVE:
           createverf3  verf;
      };

      struct CREATE3args {
           diropargs3   where;
           createhow3   how;
      };

      struct CREATE3resok {
           post_op_fh3   obj;
           post_op_attr  obj_attributes;
           wcc_data      dir_wcc;
      };

      struct CREATE3resfail {
           wcc_data      dir_wcc;
      };

      union CREATE3res switch (nfsstat3 status) {
      case NFS3_OK:
           CREATE3resok    resok;
      default:
           CREATE3resfail  resfail;
      };
*/

pub async fn nfsproc3_create(
    xid: u32,
    input: &mut impl Read,
    output: &mut impl Write,
    context: &RPCContext,
) -> Result<(), anyhow::Error> {
    // if we do not have write capabilities
    if !matches!(context.vfs.capabilities(), VFSCapabilities::ReadWrite) {
        warn!("No write capabilities.");
        make_success_reply(xid).serialize(output)?;
        nfs::nfsstat3::NFS3ERR_ROFS.serialize(output)?;
        nfs::wcc_data::default().serialize(output)?;
        return Ok(());
    }

    let mut dirops = nfs::diropargs3::default();
    dirops.deserialize(input)?;
    let mut createhow = createmode3::default();
    createhow.deserialize(input)?;

    debug!("nfsproc3_create({:?}, {:?}, {:?}) ", xid, dirops, createhow);

    // find the directory we are supposed to create the
    // new file in
    let dirid = context.vfs.fh_to_id(&dirops.dir);
    if let Err(stat) = dirid {
        // directory does not exist
        make_success_reply(xid).serialize(output)?;
        stat.serialize(output)?;
        nfs::wcc_data::default().serialize(output)?;
        error!("Directory does not exist");
        return Ok(());
    }
    // found the directory, get the attributes
    let dirid = dirid.unwrap();

    // get the object attributes before the write
    let pre_dir_attr = match context
        .vfs
        .getattr(&auth_from_context(context), dirid)
        .await
    {
        Ok(v) => {
            let wccattr = nfs::wcc_attr {
                size: v.size,
                mtime: v.mtime,
                ctime: v.ctime,
            };
            nfs::pre_op_attr::attributes(wccattr)
        }
        Err(stat) => {
            error!("Cannot stat directory");
            make_success_reply(xid).serialize(output)?;
            stat.serialize(output)?;
            nfs::wcc_data::default().serialize(output)?;
            return Ok(());
        }
    };
    let mut target_attributes = nfs::sattr3::default();

    match createhow {
        createmode3::UNCHECKED => {
            target_attributes.deserialize(input)?;
            debug!("create unchecked {:?}", target_attributes);
        }
        createmode3::GUARDED => {
            target_attributes.deserialize(input)?;
            debug!("create guarded {:?}", target_attributes);
            if context
                .vfs
                .lookup(&auth_from_context(context), dirid, &dirops.name)
                .await
                .is_ok()
            {
                // file exists. Fail with NFS3ERR_EXIST.
                // Re-read dir attributes
                // for post op attr
                let post_dir_attr = match context
                    .vfs
                    .getattr(&auth_from_context(context), dirid)
                    .await
                {
                    Ok(v) => nfs::post_op_attr::attributes(v),
                    Err(_) => nfs::post_op_attr::Void,
                };

                make_success_reply(xid).serialize(output)?;
                nfs::nfsstat3::NFS3ERR_EXIST.serialize(output)?;
                nfs::wcc_data {
                    before: pre_dir_attr,
                    after: post_dir_attr,
                }
                .serialize(output)?;
                return Ok(());
            }
        }
        createmode3::EXCLUSIVE => {
            debug!("create exclusive");
        }
    }

    let fid: Result<nfs::fileid3, nfs::nfsstat3>;
    let postopattr: nfs::post_op_attr;
    // fill in the fid and post op attr here
    if matches!(createhow, createmode3::EXCLUSIVE) {
        // the API for exclusive is very slightly different
        // We are not returning a post op attribute
        fid = context
            .vfs
            .create_exclusive(&auth_from_context(context), dirid, &dirops.name)
            .await;
        postopattr = nfs::post_op_attr::Void;
    } else {
        // create!
        let res = context
            .vfs
            .create(
                &auth_from_context(context),
                dirid,
                &dirops.name,
                target_attributes,
            )
            .await;
        fid = res.map(|x| x.0);
        postopattr = if let Ok((_, fattr)) = res {
            nfs::post_op_attr::attributes(fattr)
        } else {
            nfs::post_op_attr::Void
        };
    }

    // Re-read dir attributes for post op attr
    let post_dir_attr = match context
        .vfs
        .getattr(&auth_from_context(context), dirid)
        .await
    {
        Ok(v) => nfs::post_op_attr::attributes(v),
        Err(_) => nfs::post_op_attr::Void,
    };
    let wcc_res = nfs::wcc_data {
        before: pre_dir_attr,
        after: post_dir_attr,
    };

    match fid {
        Ok(fid) => {
            debug!("create success --> {:?}, {:?}", fid, postopattr);
            make_success_reply(xid).serialize(output)?;
            nfs::nfsstat3::NFS3_OK.serialize(output)?;
            // serialize CREATE3resok
            let fh = context.vfs.id_to_fh(fid);
            nfs::post_op_fh3::handle(fh).serialize(output)?;
            postopattr.serialize(output)?;
            wcc_res.serialize(output)?;
        }
        Err(e) => {
            error!("create error --> {:?}", e);
            // serialize CREATE3resfail
            make_success_reply(xid).serialize(output)?;
            e.serialize(output)?;
            wcc_res.serialize(output)?;
        }
    }

    Ok(())
}

#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug, Default)]
#[repr(u32)]
pub enum sattrguard3 {
    #[default]
    Void,
    obj_ctime(nfs::nfstime3),
}
XDRBoolUnion!(sattrguard3, obj_ctime, nfs::nfstime3);

#[allow(non_camel_case_types)]
#[derive(Clone, Debug, Default)]
struct SETATTR3args {
    object: nfs::nfs_fh3,
    new_attribute: nfs::sattr3,
    guard: sattrguard3,
}
XDRStruct!(SETATTR3args, object, new_attribute, guard);

/*
    SETATTR3res NFSPROC3_SETATTR(SETATTR3args) = 2;

      union sattrguard3 switch (bool check) {
      case TRUE:
         nfstime3  obj_ctime;
      case FALSE:
         void;
      };

      struct SETATTR3args {
         nfs_fh3      object;
         sattr3       new_attributes;
         sattrguard3  guard;
      };

      struct SETATTR3resok {
         wcc_data  obj_wcc;
      };

      struct SETATTR3resfail {
         wcc_data  obj_wcc;
      };
      union SETATTR3res switch (nfsstat3 status) {
      case NFS3_OK:
         SETATTR3resok   resok;
      default:
         SETATTR3resfail resfail;
      };
*/

pub async fn nfsproc3_setattr(
    xid: u32,
    input: &mut impl Read,
    output: &mut impl Write,
    context: &RPCContext,
) -> Result<(), anyhow::Error> {
    if !matches!(context.vfs.capabilities(), VFSCapabilities::ReadWrite) {
        warn!("No write capabilities.");
        make_success_reply(xid).serialize(output)?;
        nfs::nfsstat3::NFS3ERR_ROFS.serialize(output)?;
        nfs::wcc_data::default().serialize(output)?;
        return Ok(());
    }
    let mut args = SETATTR3args::default();
    args.deserialize(input)?;
    debug!("nfsproc3_setattr({:?},{:?}) ", xid, args);

    let id = context.vfs.fh_to_id(&args.object);
    // fail if unable to convert file handle
    if let Err(stat) = id {
        make_success_reply(xid).serialize(output)?;
        stat.serialize(output)?;
        return Ok(());
    }
    let id = id.unwrap();

    let ctime;

    let pre_op_attr = match context.vfs.getattr(&auth_from_context(context), id).await {
        Ok(v) => {
            let wccattr = nfs::wcc_attr {
                size: v.size,
                mtime: v.mtime,
                ctime: v.ctime,
            };
            ctime = v.ctime;
            nfs::pre_op_attr::attributes(wccattr)
        }
        Err(stat) => {
            make_success_reply(xid).serialize(output)?;
            stat.serialize(output)?;
            nfs::wcc_data::default().serialize(output)?;
            return Ok(());
        }
    };
    // handle the guard
    match args.guard {
        sattrguard3::Void => {}
        sattrguard3::obj_ctime(c) => {
            if c.seconds != ctime.seconds || c.nseconds != ctime.nseconds {
                make_success_reply(xid).serialize(output)?;
                nfs::nfsstat3::NFS3ERR_NOT_SYNC.serialize(output)?;
                nfs::wcc_data::default().serialize(output)?;
            }
        }
    }

    match context
        .vfs
        .setattr(&auth_from_context(context), id, args.new_attribute)
        .await
    {
        Ok(post_op_attr) => {
            debug!(" setattr success {:?} --> {:?}", xid, post_op_attr);
            let wcc_res = nfs::wcc_data {
                before: pre_op_attr,
                after: nfs::post_op_attr::attributes(post_op_attr),
            };
            make_success_reply(xid).serialize(output)?;
            nfs::nfsstat3::NFS3_OK.serialize(output)?;
            wcc_res.serialize(output)?;
        }
        Err(stat) => {
            error!("setattr error {:?} --> {:?}", xid, stat);
            make_success_reply(xid).serialize(output)?;
            stat.serialize(output)?;
            nfs::wcc_data::default().serialize(output)?;
        }
    }
    Ok(())
}

/*
      REMOVE3res NFSPROC3_REMOVE(REMOVE3args) = 12;

      struct REMOVE3args {
           diropargs3  object;
      };

      struct REMOVE3resok {
           wcc_data    dir_wcc;
      };

      struct REMOVE3resfail {
           wcc_data    dir_wcc;
      };

      union REMOVE3res switch (nfsstat3 status) {
      case NFS3_OK:
           REMOVE3resok   resok;
      default:
           REMOVE3resfail resfail;
      };

      RMDIR is basically identically structured
*/

pub async fn nfsproc3_remove(
    xid: u32,
    input: &mut impl Read,
    output: &mut impl Write,
    context: &RPCContext,
) -> Result<(), anyhow::Error> {
    // if we do not have write capabilities
    if !matches!(context.vfs.capabilities(), VFSCapabilities::ReadWrite) {
        warn!("No write capabilities.");
        make_success_reply(xid).serialize(output)?;
        nfs::nfsstat3::NFS3ERR_ROFS.serialize(output)?;
        nfs::wcc_data::default().serialize(output)?;
        return Ok(());
    }

    let mut dirops = nfs::diropargs3::default();
    dirops.deserialize(input)?;

    debug!("nfsproc3_remove({:?}, {:?}) ", xid, dirops);

    // find the directory with the file
    let dirid = context.vfs.fh_to_id(&dirops.dir);
    if let Err(stat) = dirid {
        // directory does not exist
        make_success_reply(xid).serialize(output)?;
        stat.serialize(output)?;
        nfs::wcc_data::default().serialize(output)?;
        error!("Directory does not exist");
        return Ok(());
    }
    let dirid = dirid.unwrap();

    // get the object attributes before the write
    let pre_dir_attr = match context
        .vfs
        .getattr(&auth_from_context(context), dirid)
        .await
    {
        Ok(v) => {
            let wccattr = nfs::wcc_attr {
                size: v.size,
                mtime: v.mtime,
                ctime: v.ctime,
            };
            nfs::pre_op_attr::attributes(wccattr)
        }
        Err(stat) => {
            error!("Cannot stat directory");
            make_success_reply(xid).serialize(output)?;
            stat.serialize(output)?;
            nfs::wcc_data::default().serialize(output)?;
            return Ok(());
        }
    };

    // delete!
    let res = context
        .vfs
        .remove(&auth_from_context(context), dirid, &dirops.name)
        .await;

    // Re-read dir attributes for post op attr
    let post_dir_attr = match context
        .vfs
        .getattr(&auth_from_context(context), dirid)
        .await
    {
        Ok(v) => nfs::post_op_attr::attributes(v),
        Err(_) => nfs::post_op_attr::Void,
    };
    let wcc_res = nfs::wcc_data {
        before: pre_dir_attr,
        after: post_dir_attr,
    };

    match res {
        Ok(()) => {
            debug!("remove success");
            make_success_reply(xid).serialize(output)?;
            nfs::nfsstat3::NFS3_OK.serialize(output)?;
            wcc_res.serialize(output)?;
        }
        Err(e) => {
            error!("remove error {:?} --> {:?}", xid, e);
            // serialize CREATE3resfail
            make_success_reply(xid).serialize(output)?;
            e.serialize(output)?;
            wcc_res.serialize(output)?;
        }
    }

    Ok(())
}

/*
 RENAME3res NFSPROC3_RENAME(RENAME3args) = 14;

      struct RENAME3args {
           diropargs3   from;
           diropargs3   to;
      };

      struct RENAME3resok {
           wcc_data     fromdir_wcc;
           wcc_data     todir_wcc;
      };

      struct RENAME3resfail {
           wcc_data     fromdir_wcc;
           wcc_data     todir_wcc;
      };

      union RENAME3res switch (nfsstat3 status) {
      case NFS3_OK:
           RENAME3resok   resok;
      default:
           RENAME3resfail resfail;
      };
*/

pub async fn nfsproc3_rename(
    xid: u32,
    input: &mut impl Read,
    output: &mut impl Write,
    context: &RPCContext,
) -> Result<(), anyhow::Error> {
    // if we do not have write capabilities
    if !matches!(context.vfs.capabilities(), VFSCapabilities::ReadWrite) {
        warn!("No write capabilities.");
        make_success_reply(xid).serialize(output)?;
        nfs::nfsstat3::NFS3ERR_ROFS.serialize(output)?;
        nfs::wcc_data::default().serialize(output)?;
        return Ok(());
    }

    let mut fromdirops = nfs::diropargs3::default();
    let mut todirops = nfs::diropargs3::default();
    fromdirops.deserialize(input)?;
    todirops.deserialize(input)?;

    debug!(
        "nfsproc3_rename({:?}, {:?}, {:?}) ",
        xid, fromdirops, todirops
    );

    // find the from directory
    let from_dirid = context.vfs.fh_to_id(&fromdirops.dir);
    if let Err(stat) = from_dirid {
        // directory does not exist
        make_success_reply(xid).serialize(output)?;
        stat.serialize(output)?;
        nfs::wcc_data::default().serialize(output)?;
        error!("Directory does not exist");
        return Ok(());
    }

    // find the to directory
    let to_dirid = context.vfs.fh_to_id(&todirops.dir);
    if let Err(stat) = to_dirid {
        // directory does not exist
        make_success_reply(xid).serialize(output)?;
        stat.serialize(output)?;
        nfs::wcc_data::default().serialize(output)?;
        error!("Directory does not exist");
        return Ok(());
    }

    // found the directory, get the attributes
    let from_dirid = from_dirid.unwrap();
    let to_dirid = to_dirid.unwrap();

    // get the object attributes before the write
    let pre_from_dir_attr = match context
        .vfs
        .getattr(&auth_from_context(context), from_dirid)
        .await
    {
        Ok(v) => {
            let wccattr = nfs::wcc_attr {
                size: v.size,
                mtime: v.mtime,
                ctime: v.ctime,
            };
            nfs::pre_op_attr::attributes(wccattr)
        }
        Err(stat) => {
            error!("Cannot stat directory");
            make_success_reply(xid).serialize(output)?;
            stat.serialize(output)?;
            nfs::wcc_data::default().serialize(output)?;
            return Ok(());
        }
    };

    // get the object attributes before the write
    let pre_to_dir_attr = match context
        .vfs
        .getattr(&auth_from_context(context), to_dirid)
        .await
    {
        Ok(v) => {
            let wccattr = nfs::wcc_attr {
                size: v.size,
                mtime: v.mtime,
                ctime: v.ctime,
            };
            nfs::pre_op_attr::attributes(wccattr)
        }
        Err(stat) => {
            error!("Cannot stat directory");
            make_success_reply(xid).serialize(output)?;
            stat.serialize(output)?;
            nfs::wcc_data::default().serialize(output)?;
            return Ok(());
        }
    };

    // rename!
    let res = context
        .vfs
        .rename(
            &auth_from_context(context),
            from_dirid,
            &fromdirops.name,
            to_dirid,
            &todirops.name,
        )
        .await;

    // Re-read dir attributes for post op attr
    let post_from_dir_attr = match context
        .vfs
        .getattr(&auth_from_context(context), from_dirid)
        .await
    {
        Ok(v) => nfs::post_op_attr::attributes(v),
        Err(_) => nfs::post_op_attr::Void,
    };
    let post_to_dir_attr = match context
        .vfs
        .getattr(&auth_from_context(context), to_dirid)
        .await
    {
        Ok(v) => nfs::post_op_attr::attributes(v),
        Err(_) => nfs::post_op_attr::Void,
    };
    let from_wcc_res = nfs::wcc_data {
        before: pre_from_dir_attr,
        after: post_from_dir_attr,
    };

    let to_wcc_res = nfs::wcc_data {
        before: pre_to_dir_attr,
        after: post_to_dir_attr,
    };

    match res {
        Ok(()) => {
            debug!("rename success");
            make_success_reply(xid).serialize(output)?;
            nfs::nfsstat3::NFS3_OK.serialize(output)?;
            from_wcc_res.serialize(output)?;
            to_wcc_res.serialize(output)?;
        }
        Err(e) => {
            error!("rename error {:?} --> {:?}", xid, e);
            // serialize CREATE3resfail
            make_success_reply(xid).serialize(output)?;
            e.serialize(output)?;
            from_wcc_res.serialize(output)?;
            to_wcc_res.serialize(output)?;
        }
    }

    Ok(())
}

/*
     MKDIR3res NFSPROC3_MKDIR(MKDIR3args) = 9;

     struct MKDIR3args {
          diropargs3   where;
          sattr3       attributes;
     };

     struct MKDIR3resok {
          post_op_fh3   obj;
          post_op_attr  obj_attributes;
          wcc_data      dir_wcc;
     };

     struct MKDIR3resfail {
          wcc_data      dir_wcc;
     };

     union MKDIR3res switch (nfsstat3 status) {
     case NFS3_OK:
          MKDIR3resok   resok;
     default:
          MKDIR3resfail resfail;
     };

*/

#[allow(non_camel_case_types)]
#[derive(Debug, Default)]
struct MKDIR3args {
    dirops: nfs::diropargs3,
    attributes: nfs::sattr3,
}
XDRStruct!(MKDIR3args, dirops, attributes);

pub async fn nfsproc3_mkdir(
    xid: u32,
    input: &mut impl Read,
    output: &mut impl Write,
    context: &RPCContext,
) -> Result<(), anyhow::Error> {
    // if we do not have write capabilities
    if !matches!(context.vfs.capabilities(), VFSCapabilities::ReadWrite) {
        warn!("No write capabilities.");
        make_success_reply(xid).serialize(output)?;
        nfs::nfsstat3::NFS3ERR_ROFS.serialize(output)?;
        nfs::wcc_data::default().serialize(output)?;
        return Ok(());
    }
    let mut args = MKDIR3args::default();
    args.deserialize(input)?;

    debug!("nfsproc3_mkdir({:?}, {:?}) ", xid, args);

    // find the directory we are supposed to create the
    // new file in
    let dirid = context.vfs.fh_to_id(&args.dirops.dir);
    if let Err(stat) = dirid {
        // directory does not exist
        make_success_reply(xid).serialize(output)?;
        stat.serialize(output)?;
        nfs::wcc_data::default().serialize(output)?;
        error!("Directory does not exist");
        return Ok(());
    }
    // found the directory, get the attributes
    let dirid = dirid.unwrap();

    // get the object attributes before the write
    let pre_dir_attr = match context
        .vfs
        .getattr(&auth_from_context(context), dirid)
        .await
    {
        Ok(v) => {
            let wccattr = nfs::wcc_attr {
                size: v.size,
                mtime: v.mtime,
                ctime: v.ctime,
            };
            nfs::pre_op_attr::attributes(wccattr)
        }
        Err(stat) => {
            error!("Cannot stat directory");
            make_success_reply(xid).serialize(output)?;
            stat.serialize(output)?;
            nfs::wcc_data::default().serialize(output)?;
            return Ok(());
        }
    };

    let res = context
        .vfs
        .mkdir(
            &auth_from_context(context),
            dirid,
            &args.dirops.name,
            &args.attributes,
        )
        .await;

    // Re-read dir attributes for post op attr
    let post_dir_attr = match context
        .vfs
        .getattr(&auth_from_context(context), dirid)
        .await
    {
        Ok(v) => nfs::post_op_attr::attributes(v),
        Err(_) => nfs::post_op_attr::Void,
    };
    let wcc_res = nfs::wcc_data {
        before: pre_dir_attr,
        after: post_dir_attr,
    };

    match res {
        Ok((fid, fattr)) => {
            debug!("mkdir success --> {:?}, {:?}", fid, fattr);
            make_success_reply(xid).serialize(output)?;
            nfs::nfsstat3::NFS3_OK.serialize(output)?;
            // serialize CREATE3resok
            let fh = context.vfs.id_to_fh(fid);
            nfs::post_op_fh3::handle(fh).serialize(output)?;
            nfs::post_op_attr::attributes(fattr).serialize(output)?;
            wcc_res.serialize(output)?;
        }
        Err(e) => {
            debug!("mkdir error {:?} --> {:?}", xid, e);
            // serialize CREATE3resfail
            make_success_reply(xid).serialize(output)?;
            e.serialize(output)?;
            wcc_res.serialize(output)?;
        }
    }

    Ok(())
}

/*
      SYMLINK3res NFSPROC3_SYMLINK(SYMLINK3args) = 10;

      struct symlinkdata3 {
           sattr3    symlink_attributes;
           nfspath3  symlink_data;
      };

      struct SYMLINK3args {
           diropargs3    where;
           symlinkdata3  symlink;
      };

      struct SYMLINK3resok {
           post_op_fh3   obj;
           post_op_attr  obj_attributes;
           wcc_data      dir_wcc;
      };

      struct SYMLINK3resfail {
           wcc_data      dir_wcc;
      };

      union SYMLINK3res switch (nfsstat3 status) {
      case NFS3_OK:
           SYMLINK3resok   resok;
      default:
           SYMLINK3resfail resfail;
      };
*/

#[allow(non_camel_case_types)]
#[derive(Debug, Default)]
struct SYMLINK3args {
    dirops: nfs::diropargs3,
    symlink: nfs::symlinkdata3,
}
XDRStruct!(SYMLINK3args, dirops, symlink);

pub async fn nfsproc3_symlink(
    xid: u32,
    input: &mut impl Read,
    output: &mut impl Write,
    context: &RPCContext,
) -> Result<(), anyhow::Error> {
    // if we do not have write capabilities
    if !matches!(context.vfs.capabilities(), VFSCapabilities::ReadWrite) {
        warn!("No write capabilities.");
        make_success_reply(xid).serialize(output)?;
        nfs::nfsstat3::NFS3ERR_ROFS.serialize(output)?;
        nfs::wcc_data::default().serialize(output)?;
        return Ok(());
    }
    let mut args = SYMLINK3args::default();
    args.deserialize(input)?;

    debug!("nfsproc3_symlink({:?}, {:?}) ", xid, args);

    // find the directory we are supposed to create the
    // new file in
    let dirid = context.vfs.fh_to_id(&args.dirops.dir);
    if let Err(stat) = dirid {
        // directory does not exist
        make_success_reply(xid).serialize(output)?;
        stat.serialize(output)?;
        nfs::wcc_data::default().serialize(output)?;
        error!("Directory does not exist");
        return Ok(());
    }
    // found the directory, get the attributes
    let dirid = dirid.unwrap();

    // get the object attributes before the write
    let pre_dir_attr = match context
        .vfs
        .getattr(&auth_from_context(context), dirid)
        .await
    {
        Ok(v) => {
            let wccattr = nfs::wcc_attr {
                size: v.size,
                mtime: v.mtime,
                ctime: v.ctime,
            };
            nfs::pre_op_attr::attributes(wccattr)
        }
        Err(stat) => {
            error!("Cannot stat directory");
            make_success_reply(xid).serialize(output)?;
            stat.serialize(output)?;
            nfs::wcc_data::default().serialize(output)?;
            return Ok(());
        }
    };

    let res = context
        .vfs
        .symlink(
            &auth_from_context(context),
            dirid,
            &args.dirops.name,
            &args.symlink.symlink_data,
            &args.symlink.symlink_attributes,
        )
        .await;

    // Re-read dir attributes for post op attr
    let post_dir_attr = match context
        .vfs
        .getattr(&auth_from_context(context), dirid)
        .await
    {
        Ok(v) => nfs::post_op_attr::attributes(v),
        Err(_) => nfs::post_op_attr::Void,
    };
    let wcc_res = nfs::wcc_data {
        before: pre_dir_attr,
        after: post_dir_attr,
    };

    match res {
        Ok((fid, fattr)) => {
            debug!("symlink success --> {:?}, {:?}", fid, fattr);
            make_success_reply(xid).serialize(output)?;
            nfs::nfsstat3::NFS3_OK.serialize(output)?;
            // serialize CREATE3resok
            let fh = context.vfs.id_to_fh(fid);
            nfs::post_op_fh3::handle(fh).serialize(output)?;
            nfs::post_op_attr::attributes(fattr).serialize(output)?;
            wcc_res.serialize(output)?;
        }
        Err(e) => {
            debug!("symlink error --> {:?}", e);
            // serialize CREATE3resfail
            make_success_reply(xid).serialize(output)?;
            e.serialize(output)?;
            wcc_res.serialize(output)?;
        }
    }

    Ok(())
}

/*

 READLINK3res NFSPROC3_READLINK(READLINK3args) = 5;

 struct READLINK3args {
      nfs_fh3  symlink;
 };

 struct READLINK3resok {
      post_op_attr   symlink_attributes;
      nfspath3       data;
 };

 struct READLINK3resfail {
      post_op_attr   symlink_attributes;
 };

 union READLINK3res switch (nfsstat3 status) {
 case NFS3_OK:
      READLINK3resok   resok;
 default:
      READLINK3resfail resfail;
 };
*/
pub async fn nfsproc3_readlink(
    xid: u32,
    input: &mut impl Read,
    output: &mut impl Write,
    context: &RPCContext,
) -> Result<(), anyhow::Error> {
    let mut handle = nfs::nfs_fh3::default();
    handle.deserialize(input)?;
    debug!("nfsproc3_readlink({:?},{:?}) ", xid, handle);

    let id = context.vfs.fh_to_id(&handle);
    // fail if unable to convert file handle
    if let Err(stat) = id {
        make_success_reply(xid).serialize(output)?;
        stat.serialize(output)?;
        return Ok(());
    }
    let id = id.unwrap();
    // if the id does not exist, we fail
    let symlink_attr = match context.vfs.getattr(&auth_from_context(context), id).await {
        Ok(v) => nfs::post_op_attr::attributes(v),
        Err(stat) => {
            make_success_reply(xid).serialize(output)?;
            stat.serialize(output)?;
            nfs::post_op_attr::Void.serialize(output)?;
            return Ok(());
        }
    };
    match context.vfs.readlink(&auth_from_context(context), id).await {
        Ok(path) => {
            debug!(" {:?} --> {:?}", xid, path);
            make_success_reply(xid).serialize(output)?;
            nfs::nfsstat3::NFS3_OK.serialize(output)?;
            symlink_attr.serialize(output)?;
            path.serialize(output)?;
        }
        Err(stat) => {
            // failed to read link
            // retry with failure and the post_op_attr
            make_success_reply(xid).serialize(output)?;
            stat.serialize(output)?;
            symlink_attr.serialize(output)?;
        }
    }
    Ok(())
}

pub async fn nfsproc3_mknod<W: Write>(
    xid: u32,
    input: &mut impl Read,
    output: &mut W,
    context: &RPCContext,
) -> Result<(), anyhow::Error> {
    debug!("mknod {:?}", xid);
    let mut args = nfs::MKNOD3args {
        where_: nfs::diropargs3::default(),
        what: nfs::mknoddata3::NF3REG,
    };
    args.deserialize(input)?;

    // Get the parent directory id
    let parent_id = match context.vfs.fh_to_id(&args.where_.dir) {
        Ok(id) => id,
        Err(_) => {
            let result = nfs::MKNOD3res::Error(
                nfs::nfsstat3::NFS3ERR_STALE,
                nfs::MKNOD3resfail {
                    dir_wcc: nfs::wcc_data::default(),
                },
            );
            make_success_reply(xid).serialize(output)?;
            result.serialize(output)?;
            return Ok(());
        }
    };

    // Get pre-operation attributes for parent directory
    let pre_op_attr = context
        .vfs
        .getattr(&auth_from_context(context), parent_id)
        .await
        .ok()
        .map(|attr| {
            nfs::pre_op_attr::attributes(nfs::wcc_attr {
                size: attr.size,
                mtime: attr.mtime,
                ctime: attr.ctime,
            })
        })
        .unwrap_or(nfs::pre_op_attr::Void);

    // Helper to create wcc_data for the parent directory
    let get_post_op_attr = || async {
        context
            .vfs
            .getattr(&auth_from_context(context), parent_id)
            .await
            .ok()
            .map(nfs::post_op_attr::attributes)
            .unwrap_or(nfs::post_op_attr::Void)
    };

    // Extract file type, attributes, and device spec
    let (ftype, sattr, spec) = match &args.what {
        nfs::mknoddata3::NF3CHR(dev) => (nfs::ftype3::NF3CHR, &dev.dev_attributes, Some(&dev.spec)),
        nfs::mknoddata3::NF3BLK(dev) => (nfs::ftype3::NF3BLK, &dev.dev_attributes, Some(&dev.spec)),
        nfs::mknoddata3::NF3SOCK(attr) => (nfs::ftype3::NF3SOCK, attr, None),
        nfs::mknoddata3::NF3FIFO(attr) => (nfs::ftype3::NF3FIFO, attr, None),
        _ => {
            // Invalid file type for MKNOD
            let result = nfs::MKNOD3res::Error(
                nfs::nfsstat3::NFS3ERR_BADTYPE,
                nfs::MKNOD3resfail {
                    dir_wcc: nfs::wcc_data {
                        before: pre_op_attr,
                        after: get_post_op_attr().await,
                    },
                },
            );
            make_success_reply(xid).serialize(output)?;
            result.serialize(output)?;
            return Ok(());
        }
    };

    // Create the special file
    match context
        .vfs
        .mknod(
            &auth_from_context(context),
            parent_id,
            &args.where_.name,
            ftype,
            sattr,
            spec,
        )
        .await
    {
        Ok((id, attr)) => {
            let handle = context.vfs.id_to_fh(id);
            let result = nfs::MKNOD3res::NFS3_OK(nfs::MKNOD3resok {
                obj: nfs::post_op_fh3::handle(handle),
                obj_attributes: nfs::post_op_attr::attributes(attr),
                dir_wcc: nfs::wcc_data {
                    before: pre_op_attr,
                    after: get_post_op_attr().await,
                },
            });
            make_success_reply(xid).serialize(output)?;
            result.serialize(output)?;
        }
        Err(stat) => {
            let result = nfs::MKNOD3res::Error(
                stat,
                nfs::MKNOD3resfail {
                    dir_wcc: nfs::wcc_data {
                        before: pre_op_attr,
                        after: get_post_op_attr().await,
                    },
                },
            );
            make_success_reply(xid).serialize(output)?;
            result.serialize(output)?;
        }
    }

    Ok(())
}

pub async fn nfsproc3_link<W: Write>(
    xid: u32,
    input: &mut impl Read,
    output: &mut W,
    context: &RPCContext,
) -> Result<(), anyhow::Error> {
    debug!("link {:?}", xid);
    let mut args = nfs::LINK3args {
        file: nfs::nfs_fh3::default(),
        link: nfs::diropargs3::default(),
    };
    args.deserialize(input)?;

    // Get the file id
    let file_id = match context.vfs.fh_to_id(&args.file) {
        Ok(id) => id,
        Err(_) => {
            let result =
                nfs::LINK3res::Error(nfs::nfsstat3::NFS3ERR_STALE, nfs::LINK3resfail::default());
            make_success_reply(xid).serialize(output)?;
            result.serialize(output)?;
            return Ok(());
        }
    };

    // Get the link directory id
    let link_dir_id = match context.vfs.fh_to_id(&args.link.dir) {
        Ok(id) => id,
        Err(_) => {
            let result =
                nfs::LINK3res::Error(nfs::nfsstat3::NFS3ERR_STALE, nfs::LINK3resfail::default());
            make_success_reply(xid).serialize(output)?;
            result.serialize(output)?;
            return Ok(());
        }
    };

    // Get pre-operation attributes
    let file_pre_attr = context
        .vfs
        .getattr(&auth_from_context(context), file_id)
        .await
        .ok()
        .map(nfs::post_op_attr::attributes)
        .unwrap_or(nfs::post_op_attr::Void);

    let linkdir_pre_attr = context
        .vfs
        .getattr(&auth_from_context(context), link_dir_id)
        .await
        .ok()
        .map(|attr| {
            nfs::pre_op_attr::attributes(nfs::wcc_attr {
                size: attr.size,
                mtime: attr.mtime,
                ctime: attr.ctime,
            })
        })
        .unwrap_or(nfs::pre_op_attr::Void);

    // Helper to get post-operation attributes
    let get_file_post_attr = || async {
        context
            .vfs
            .getattr(&auth_from_context(context), file_id)
            .await
            .ok()
            .map(nfs::post_op_attr::attributes)
            .unwrap_or(nfs::post_op_attr::Void)
    };

    let get_linkdir_post_attr = || async {
        context
            .vfs
            .getattr(&auth_from_context(context), link_dir_id)
            .await
            .ok()
            .map(nfs::post_op_attr::attributes)
            .unwrap_or(nfs::post_op_attr::Void)
    };

    // Create the hard link
    match context
        .vfs
        .link(
            &auth_from_context(context),
            file_id,
            link_dir_id,
            &args.link.name,
        )
        .await
    {
        Ok(()) => {
            let result = nfs::LINK3res::NFS3_OK(nfs::LINK3resok {
                file_attributes: get_file_post_attr().await,
                linkdir_wcc: nfs::wcc_data {
                    before: linkdir_pre_attr,
                    after: get_linkdir_post_attr().await,
                },
            });
            make_success_reply(xid).serialize(output)?;
            result.serialize(output)?;
        }
        Err(stat) => {
            let result = nfs::LINK3res::Error(
                stat,
                nfs::LINK3resfail {
                    file_attributes: file_pre_attr,
                    linkdir_wcc: nfs::wcc_data {
                        before: linkdir_pre_attr,
                        after: get_linkdir_post_attr().await,
                    },
                },
            );
            make_success_reply(xid).serialize(output)?;
            result.serialize(output)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction_tracker::TransactionTracker;
    use crate::vfs::test_support::ContextRecordingFs;
    use crate::vfs::NFSFileSystem;
    use std::io::Cursor;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::time::Duration;

    fn test_context(fs: Arc<ContextRecordingFs>) -> RPCContext {
        RPCContext {
            local_port: 2049,
            client_addr: "127.0.0.1:51000".to_string(),
            auth: auth_unix {
                stamp: 0,
                machinename: b"testhost".to_vec(),
                uid: 1000,
                gid: 100,
                gids: vec![100, 20],
            },
            vfs: fs,
            mount_signal: None,
            export_name: Arc::new("/".to_string()),
            transaction_tracker: Arc::new(TransactionTracker::new(Duration::from_secs(60))),
        }
    }

    #[tokio::test]
    async fn write_forwards_context_and_result_reaches_the_wire() {
        let verifier: nfs::writeverf3 = [9, 8, 7, 6, 5, 4, 3, 2];
        let fs = Arc::new(ContextRecordingFs::new(stable_how::UNSTABLE, verifier));
        let context = test_context(fs.clone());
        let xid = 0xabcd;
        let incarnation = 77;
        let fileid: nfs::fileid3 = 42;
        let data = b"some bytes".to_vec();

        let args = WRITE3args {
            file: fs.id_to_fh(fileid),
            offset: 4096,
            count: data.len() as u32,
            stable: stable_how::DATA_SYNC as u32,
            data: data.clone(),
        };
        let mut request = Vec::new();
        args.serialize(&mut request).unwrap();

        let mut output = Vec::new();
        nfsproc3_write(
            xid,
            &mut Cursor::new(request),
            &mut output,
            &context,
            incarnation,
        )
        .await
        .unwrap();

        {
            let writes = fs.writes.lock().unwrap();
            assert_eq!(writes.len(), 1);
            let captured = &writes[0];
            assert_eq!(captured.xid, xid);
            assert_eq!(captured.client_addr, context.client_addr);
            assert_eq!(captured.connection_incarnation, incarnation);
            assert_eq!(captured.requested_stability, stable_how::DATA_SYNC);
            assert_eq!(captured.auth.uid, 1000);
            assert_eq!(captured.auth.gid, 100);
            assert_eq!(captured.auth.gids, vec![100, 20]);
            assert_eq!(captured.id, fileid);
            assert_eq!(captured.offset, 4096);
            assert_eq!(captured.data, data);
        }
        // the handler must not also invoke the legacy path
        assert_eq!(fs.legacy_write_calls.load(Ordering::SeqCst), 0);

        // the returned committed level and verifier must reach the wire
        let pre = ContextRecordingFs::attr(fileid, 512);
        let mut expected = Vec::new();
        make_success_reply(xid).serialize(&mut expected).unwrap();
        nfs::nfsstat3::NFS3_OK.serialize(&mut expected).unwrap();
        WRITE3resok {
            file_wcc: nfs::wcc_data {
                before: nfs::pre_op_attr::attributes(nfs::wcc_attr {
                    size: pre.size,
                    mtime: pre.mtime,
                    ctime: pre.ctime,
                }),
                after: nfs::post_op_attr::attributes(ContextRecordingFs::attr(
                    fileid,
                    4096 + data.len() as u64,
                )),
            },
            count: data.len() as u32,
            committed: stable_how::UNSTABLE,
            verf: verifier,
        }
        .serialize(&mut expected)
        .unwrap();
        assert_eq!(output, expected);
    }

    #[tokio::test]
    async fn write_with_invalid_stable_how_returns_garbage_args() {
        let fs = Arc::new(ContextRecordingFs::new(
            stable_how::FILE_SYNC,
            [0u8; nfs::NFS3_WRITEVERFSIZE as usize],
        ));
        let context = test_context(fs.clone());
        let xid = 99;
        let data = b"abc".to_vec();

        let args = WRITE3args {
            file: fs.id_to_fh(7),
            offset: 0,
            count: data.len() as u32,
            stable: 3, // not a valid stable_how value
            data,
        };
        let mut request = Vec::new();
        args.serialize(&mut request).unwrap();

        let mut output = Vec::new();
        nfsproc3_write(xid, &mut Cursor::new(request), &mut output, &context, 1)
            .await
            .unwrap();

        assert!(fs.writes.lock().unwrap().is_empty());
        assert_eq!(fs.legacy_write_calls.load(Ordering::SeqCst), 0);

        let mut expected = Vec::new();
        garbage_args_reply_message(xid)
            .serialize(&mut expected)
            .unwrap();
        assert_eq!(output, expected);
    }

    #[tokio::test]
    async fn commit_forwards_context_and_verifier_reaches_the_wire() {
        let verifier: nfs::writeverf3 = [1, 2, 3, 4, 5, 6, 7, 8];
        let fs = Arc::new(ContextRecordingFs::new(stable_how::FILE_SYNC, verifier));
        let context = test_context(fs.clone());
        let xid = 0x1234;
        let incarnation = 5;
        let fileid: nfs::fileid3 = 8;

        let args = COMMIT3args {
            file: fs.id_to_fh(fileid),
            offset: 100,
            count: 200,
        };
        let mut request = Vec::new();
        args.serialize(&mut request).unwrap();

        let mut output = Vec::new();
        nfsproc3_commit(
            xid,
            &mut Cursor::new(request),
            &mut output,
            &context,
            incarnation,
        )
        .await
        .unwrap();

        {
            let commits = fs.commits.lock().unwrap();
            assert_eq!(commits.len(), 1);
            let captured = &commits[0];
            assert_eq!(captured.xid, xid);
            assert_eq!(captured.client_addr, context.client_addr);
            assert_eq!(captured.connection_incarnation, incarnation);
            assert_eq!(captured.auth.uid, 1000);
            assert_eq!(captured.auth.gid, 100);
            assert_eq!(captured.auth.gids, vec![100, 20]);
            assert_eq!(captured.fileid, fileid);
            assert_eq!(captured.offset, 100);
            assert_eq!(captured.count, 200);
        }
        // the handler must not also invoke the legacy path
        assert_eq!(fs.legacy_commit_calls.load(Ordering::SeqCst), 0);

        let attr = ContextRecordingFs::attr(fileid, 512);
        let mut expected = Vec::new();
        make_success_reply(xid).serialize(&mut expected).unwrap();
        nfs::nfsstat3::NFS3_OK.serialize(&mut expected).unwrap();
        COMMIT3resok {
            file_wcc: nfs::wcc_data {
                before: nfs::pre_op_attr::attributes(nfs::wcc_attr {
                    size: attr.size,
                    mtime: attr.mtime,
                    ctime: attr.ctime,
                }),
                after: nfs::post_op_attr::attributes(attr),
            },
            verf: verifier,
        }
        .serialize(&mut expected)
        .unwrap();
        assert_eq!(output, expected);
    }
}
