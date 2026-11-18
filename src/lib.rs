#![cfg_attr(feature = "strict", deny(warnings))]

mod context;
mod rpc;
mod rpcwire;
pub mod xdr;

mod mount;
mod mount_handlers;

mod portmap;
mod portmap_handlers;

pub mod nfs;
mod nfs_handlers;

#[cfg(not(target_os = "windows"))]
pub mod fs_util;

pub mod tcp;
mod transaction_tracker;
pub mod vfs;

pub use crate::{xdr_bool_union as XDRBoolUnion, xdr_enum_serde as XDREnumSerde, xdr_struct as XDRStruct};
