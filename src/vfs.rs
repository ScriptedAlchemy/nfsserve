use std::cmp::Ordering;

use async_trait::async_trait;

use crate::nfs;
use crate::nfs::*;

/// Authentication context passed to filesystem operations
#[derive(Clone, Debug)]
pub struct AuthContext {
    /// User ID of the caller
    pub uid: u32,
    /// Primary group ID of the caller
    pub gid: u32,
    /// Additional group IDs the user belongs to
    pub gids: Vec<u32>,
}

impl AuthContext {
    /// Create a new AuthContext from RPC auth_unix
    pub fn from_rpc_auth(auth: &crate::rpc::auth_unix) -> Self {
        AuthContext {
            uid: auth.uid,
            gid: auth.gid,
            gids: auth.gids.clone(),
        }
    }

    /// Check if the user belongs to a specific group
    pub fn is_member_of_group(&self, gid: u32) -> bool {
        self.gid == gid || self.gids.contains(&gid)
    }
}
#[derive(Default, Debug)]
pub struct DirEntrySimple {
    pub fileid: fileid3,
    pub name: filename3,
    pub cookie: cookie3,
}
#[derive(Default, Debug)]
pub struct ReadDirSimpleResult {
    pub entries: Vec<DirEntrySimple>,
    pub end: bool,
}

#[derive(Default, Debug)]
pub struct DirEntry {
    pub fileid: fileid3,
    pub name: filename3,
    pub attr: fattr3,
    pub cookie: cookie3,
}
#[derive(Default, Debug)]
pub struct ReadDirResult {
    pub entries: Vec<DirEntry>,
    pub end: bool,
}

impl ReadDirSimpleResult {
    fn from_readdir_result(result: &ReadDirResult) -> ReadDirSimpleResult {
        let entries: Vec<DirEntrySimple> = result
            .entries
            .iter()
            .map(|e| DirEntrySimple {
                fileid: e.fileid,
                name: e.name.clone(),
                cookie: e.cookie,
            })
            .collect();
        ReadDirSimpleResult {
            entries,
            end: result.end,
        }
    }
}

static GENERATION_NUMBER: u64 = 0;

/// What capabilities are supported
pub enum VFSCapabilities {
    ReadOnly,
    ReadWrite,
}

/// Result of checking the caller's NFSv3 ACCESS permissions.
#[derive(Clone, Debug)]
pub struct AccessResult {
    /// Attributes from the same filesystem state used for the access check.
    pub attributes: fattr3,
    /// The subset of requested [`ACCESS3_ALL`] permissions that is allowed.
    pub access: u32,
}

/// Unix mode-bit fallback for filesystems without ACLs or identity remapping.
fn mode_access(auth: &AuthContext, attributes: &fattr3, requested: u32, capabilities: VFSCapabilities) -> u32 {
    let is_directory = matches!(attributes.ftype, ftype3::NF3DIR);
    let permissions = if auth.uid == 0 {
        // Root can search directories, but may only execute a regular file
        // if at least one execute bit is set.
        0o6 | u32::from(is_directory || attributes.mode & 0o111 != 0)
    } else if auth.uid == attributes.uid {
        (attributes.mode >> 6) & 0o7
    } else if auth.is_member_of_group(attributes.gid) {
        (attributes.mode >> 3) & 0o7
    } else {
        attributes.mode & 0o7
    };

    let mut access = 0;
    if permissions & 0o4 != 0 {
        access |= ACCESS3_READ;
    }
    if permissions & 0o1 != 0 {
        access |= if is_directory { ACCESS3_LOOKUP } else { ACCESS3_EXECUTE };
    }
    if matches!(capabilities, VFSCapabilities::ReadWrite) {
        if is_directory {
            // Each directory mutation requires write AND search permission.
            if permissions & 0o3 == 0o3 {
                access |= ACCESS3_MODIFY | ACCESS3_EXTEND | ACCESS3_DELETE;
            }
        } else if permissions & 0o2 != 0 {
            access |= ACCESS3_MODIFY | ACCESS3_EXTEND;
        }
    }
    access & requested
}

/// Transport-level metadata describing the RPC request being served
#[derive(Clone, Debug)]
pub struct RpcRequestContext {
    /// RPC transaction id of the request
    pub xid: u32,
    /// Address of the client that sent the request
    pub client_addr: String,
    /// Server-minted identifier that is unique per accepted transport
    /// connection. A client reconnecting from the same address observes
    /// a fresh incarnation.
    pub connection_incarnation: u64,
}

/// Request metadata passed to [`NFSFileSystem::write_with_context`]
#[derive(Clone, Debug)]
pub struct WriteRequestContext {
    /// Transport-level request metadata
    pub rpc: RpcRequestContext,
    /// Stability level the client requested for this write
    pub requested_stability: stable_how,
}

/// Result of a contextual write, echoed back on the wire
#[derive(Clone, Debug)]
pub struct WriteResult {
    /// Post-write attributes of the file
    pub attributes: fattr3,
    /// Stability level the server actually honored
    pub committed: stable_how,
    /// Write verifier the client uses to detect server restarts
    pub verifier: writeverf3,
}

/// Request metadata passed to [`NFSFileSystem::commit_with_context`]
#[derive(Clone, Debug)]
pub struct CommitRequestContext {
    /// Transport-level request metadata
    pub rpc: RpcRequestContext,
}

/// Result of a contextual commit, echoed back on the wire
#[derive(Clone, Debug)]
pub struct CommitResult {
    /// Write verifier the client uses to detect server restarts
    pub verifier: writeverf3,
}

/// The basic API to implement to provide an NFS file system
///
/// Opaque FH
/// ---------
/// Files are only uniquely identified by a 64-bit file id. (basically an inode number)
/// We automatically produce internally the opaque filehandle which is comprised of
///  - A 64-bit generation number derived from the server startup time
///   (i.e. so the opaque file handle expires when the NFS server restarts)
///  - The 64-bit file id
//
/// readdir pagination
/// ------------------
/// We do not use cookie verifier. We just use the start_after.  The
/// implementation should allow startat to start at any position. That is,
/// the next query to readdir may be the last entry in the previous readdir
/// response.
//
/// There is a wierd annoying thing about readdir that limits the number
/// of bytes in the response (instead of the number of entries). The caller
/// will have to truncate the readdir response / issue more calls to readdir
/// accordingly to fill up the expected number of bytes without exceeding it.
//
/// Other requirements
/// ------------------
///  getattr needs to be fast. NFS uses that a lot
//
///  The 0 fileid is reserved and should not be used
#[async_trait]
pub trait NFSFileSystem: Sync {
    /// Returns the set of capabilities supported
    fn capabilities(&self) -> VFSCapabilities;
    /// Maximum length of a filename component in bytes, reported by NFSv3 PATHCONF.
    fn name_max(&self) -> u32 {
        255
    }
    /// Whether filename lookup ignores case on this filesystem (NFSv3 PATHCONF).
    fn case_insensitive(&self) -> bool {
        false
    }
    /// Returns the ID the of the root directory "/"
    fn root_dir(&self) -> fileid3;
    /// Look up the id of a path in a directory
    ///
    /// i.e. given a directory dir/ containing a file a.txt
    /// this may call lookup(id_of("dir/"), "a.txt")
    /// and this should return the id of the file "dir/a.txt"
    ///
    /// This method should be fast as it is used very frequently.
    async fn lookup(&self, auth: &AuthContext, dirid: fileid3, filename: &filename3) -> Result<fileid3, nfsstat3>;

    /// Returns the attributes of an id.
    /// This method should be fast as it is used very frequently.
    async fn getattr(&self, auth: &AuthContext, id: fileid3) -> Result<fattr3, nfsstat3>;

    /// Check the caller's permissions for an object (NFSv3 ACCESS).
    ///
    /// Report each requested `ACCESS3_*` permission independently and leave
    /// denied permissions unset; a normal denial is `Ok` with no corresponding
    /// bit, not an error. Return errors for failures such as a stale handle or
    /// unavailable storage. Attributes and permissions should describe the same
    /// filesystem state.
    ///
    /// The default checks Unix owner/group/other mode bits using [`Self::getattr`]
    /// and treats uid 0 as privileged. Filesystems with ACLs, identity mapping,
    /// root squashing, or other access restrictions MUST override this method
    /// with their authoritative permission checks. Clients can use ACCESS to
    /// authorize opening data already in their local cache, without a new READ
    /// request reaching the server.
    async fn access(&self, auth: &AuthContext, id: fileid3, requested: u32) -> Result<AccessResult, nfsstat3> {
        let attributes = self.getattr(auth, id).await?;
        let access = mode_access(auth, &attributes, requested, self.capabilities());
        Ok(AccessResult { attributes, access })
    }

    /// Sets the attributes of an id
    /// this should return Err(nfsstat3::NFS3ERR_ROFS) if readonly
    async fn setattr(&self, auth: &AuthContext, id: fileid3, setattr: sattr3) -> Result<fattr3, nfsstat3>;

    /// Reads the contents of a file returning (bytes, EOF)
    /// Note that offset/count may go past the end of the file and that
    /// in that case, all bytes till the end of file are returned.
    /// EOF must be flagged if the end of the file is reached by the read.
    async fn read(&self, auth: &AuthContext, id: fileid3, offset: u64, count: u32)
        -> Result<(Vec<u8>, bool), nfsstat3>;

    /// Writes the contents of a file returning (bytes, EOF)
    /// Note that offset/count may go past the end of the file and that
    /// in that case, the file is extended.
    /// If not supported due to readonly file system
    /// this should return Err(nfsstat3::NFS3ERR_ROFS)
    async fn write(&self, auth: &AuthContext, id: fileid3, offset: u64, data: &[u8]) -> Result<fattr3, nfsstat3>;

    /// Writes the contents of a file, with access to the request context.
    /// The default implementation delegates to [`NFSFileSystem::write`]
    /// and reports the write as FILE_SYNC, matching the legacy behavior.
    /// Implementations that support unstable writes should override this
    /// to honor `context.requested_stability`.
    async fn write_with_context(
        &self,
        context: &WriteRequestContext,
        auth: &AuthContext,
        id: fileid3,
        offset: u64,
        data: &[u8],
    ) -> Result<WriteResult, nfsstat3> {
        let _ = context;
        let attributes = self.write(auth, id, offset, data).await?;
        Ok(WriteResult {
            attributes,
            committed: stable_how::FILE_SYNC,
            verifier: self.get_write_verf(),
        })
    }

    /// Creates a file with the following attributes.
    /// If not supported due to readonly file system
    /// this should return Err(nfsstat3::NFS3ERR_ROFS)
    async fn create(
        &self,
        auth: &AuthContext,
        dirid: fileid3,
        filename: &filename3,
        attr: sattr3,
    ) -> Result<(fileid3, fattr3), nfsstat3>;

    /// Creates a file if it does not already exist
    /// this should return Err(nfsstat3::NFS3ERR_ROFS)
    async fn create_exclusive(
        &self,
        auth: &AuthContext,
        dirid: fileid3,
        filename: &filename3,
    ) -> Result<fileid3, nfsstat3>;

    /// Makes a directory with the following attributes.
    /// If not supported dur to readonly file system
    /// this should return Err(nfsstat3::NFS3ERR_ROFS)
    async fn mkdir(
        &self,
        auth: &AuthContext,
        dirid: fileid3,
        dirname: &filename3,
        attrs: &sattr3,
    ) -> Result<(fileid3, fattr3), nfsstat3>;

    /// Removes a file.
    /// If not supported due to readonly file system
    /// this should return Err(nfsstat3::NFS3ERR_ROFS)
    async fn remove(&self, auth: &AuthContext, dirid: fileid3, filename: &filename3) -> Result<(), nfsstat3>;

    /// Renames a file.
    /// If not supported due to readonly file system
    /// this should return Err(nfsstat3::NFS3ERR_ROFS)
    async fn rename(
        &self,
        auth: &AuthContext,
        from_dirid: fileid3,
        from_filename: &filename3,
        to_dirid: fileid3,
        to_filename: &filename3,
    ) -> Result<(), nfsstat3>;

    /// Returns the contents of a directory with pagination.
    /// Directory listing should be deterministic.
    /// Up to max_entries may be returned, and start_after is used
    /// to determine where to start returning entries from.
    ///
    /// For instance if the directory has entry with ids [1,6,2,11,8,9]
    /// and start_after=6, readdir should returning 2,11,8,...
    //
    async fn readdir(
        &self,
        auth: &AuthContext,
        dirid: fileid3,
        start_after: fileid3,
        max_entries: usize,
    ) -> Result<ReadDirResult, nfsstat3>;

    /// Simple version of readdir.
    /// Only need to return filename and id
    async fn readdir_simple(
        &self,
        auth: &AuthContext,
        dirid: fileid3,
        count: usize,
    ) -> Result<ReadDirSimpleResult, nfsstat3> {
        Ok(ReadDirSimpleResult::from_readdir_result(&self.readdir(auth, dirid, 0, count).await?))
    }

    /// Makes a symlink with the following attributes.
    /// If not supported due to readonly file system
    /// this should return Err(nfsstat3::NFS3ERR_ROFS)
    async fn symlink(
        &self,
        auth: &AuthContext,
        dirid: fileid3,
        linkname: &filename3,
        symlink: &nfspath3,
        attr: &sattr3,
    ) -> Result<(fileid3, fattr3), nfsstat3>;

    /// Reads a symlink
    async fn readlink(&self, auth: &AuthContext, id: fileid3) -> Result<nfspath3, nfsstat3>;

    /// Creates a special file (block device, character device, socket, or FIFO)
    /// If not supported due to readonly file system
    /// this should return Err(nfsstat3::NFS3ERR_ROFS)
    /// For character and block devices, spec contains the major/minor device numbers
    async fn mknod(
        &self,
        auth: &AuthContext,
        dirid: fileid3,
        filename: &filename3,
        ftype: ftype3,
        attr: &sattr3,
        spec: Option<&specdata3>,
    ) -> Result<(fileid3, fattr3), nfsstat3>;

    /// Creates a hard link to an existing file
    /// If not supported due to readonly file system
    /// this should return Err(nfsstat3::NFS3ERR_ROFS)
    async fn link(
        &self,
        auth: &AuthContext,
        fileid: fileid3,
        linkdirid: fileid3,
        linkname: &filename3,
    ) -> Result<(), nfsstat3>;

    /// Commit pending writes to stable storage
    /// Returns a write verifier that can be used to detect server restarts
    async fn commit(
        &self,
        _auth: &AuthContext,
        _fileid: fileid3,
        _offset: u64,
        _count: u32,
    ) -> Result<writeverf3, nfsstat3> {
        // Default implementation: since writes are synchronous (FILE_SYNC),
        // commit is a no-op that just returns the write verifier
        Ok(self.get_write_verf())
    }

    /// Commit pending writes to stable storage, with access to the request
    /// context. The default implementation delegates to
    /// [`NFSFileSystem::commit`].
    async fn commit_with_context(
        &self,
        context: &CommitRequestContext,
        auth: &AuthContext,
        fileid: fileid3,
        offset: u64,
        count: u32,
    ) -> Result<CommitResult, nfsstat3> {
        let _ = context;
        Ok(CommitResult {
            verifier: self.commit(auth, fileid, offset, count).await?,
        })
    }

    /// Get the current write verifier for this filesystem
    fn get_write_verf(&self) -> writeverf3 {
        // Default implementation returns a static verifier
        // Real implementations should generate this based on boot time or similar
        [0u8; NFS3_WRITEVERFSIZE as usize]
    }

    /// Get static file system Information
    async fn fsinfo(&self, auth: &AuthContext, root_fileid: fileid3) -> Result<fsinfo3, nfsstat3> {
        let dir_attr: nfs::post_op_attr = match self.getattr(auth, root_fileid).await {
            Ok(v) => nfs::post_op_attr::attributes(v),
            Err(_) => nfs::post_op_attr::Void,
        };

        let res = fsinfo3 {
            obj_attributes: dir_attr,
            rtmax: 1024 * 1024,
            rtpref: 1024 * 124,
            rtmult: 1024 * 1024,
            wtmax: 1024 * 1024,
            wtpref: 1024 * 1024,
            wtmult: 1024 * 1024,
            dtpref: 1024 * 1024,
            maxfilesize: 128 * 1024 * 1024 * 1024,
            time_delta: nfs::nfstime3 {
                seconds: 0,
                nseconds: 1000000,
            },
            properties: nfs::FSF_SYMLINK | nfs::FSF_HOMOGENEOUS | nfs::FSF_CANSETTIME,
        };
        Ok(res)
    }

    /// Get file system statistics
    async fn fsstat(&self, auth: &AuthContext, fileid: fileid3) -> Result<fsstat3, nfsstat3> {
        let obj_attr = match self.getattr(auth, fileid).await {
            Ok(v) => nfs::post_op_attr::attributes(v),
            Err(_) => nfs::post_op_attr::Void,
        };

        let res = fsstat3 {
            obj_attributes: obj_attr,
            tbytes: 1024 * 1024 * 1024 * 1024,
            fbytes: 1024 * 1024 * 1024 * 1024,
            abytes: 1024 * 1024 * 1024 * 1024,
            tfiles: 1024 * 1024 * 1024,
            ffiles: 1024 * 1024 * 1024,
            afiles: 1024 * 1024 * 1024,
            invarsec: 0,
        };
        Ok(res)
    }

    /// Converts the fileid to an opaque NFS file handle. Optional.
    fn id_to_fh(&self, id: fileid3) -> nfs_fh3 {
        let gennum = GENERATION_NUMBER;
        let mut ret: Vec<u8> = Vec::new();
        ret.extend_from_slice(&gennum.to_le_bytes());
        ret.extend_from_slice(&id.to_le_bytes());
        nfs_fh3 { data: ret }
    }
    /// Converts an opaque NFS file handle to a fileid.  Optional.
    fn fh_to_id(&self, id: &nfs_fh3) -> Result<fileid3, nfsstat3> {
        if id.data.len() != 16 {
            return Err(nfsstat3::NFS3ERR_BADHANDLE);
        }
        let gen = u64::from_le_bytes(id.data[0..8].try_into().unwrap());
        let id = u64::from_le_bytes(id.data[8..16].try_into().unwrap());
        match gen.cmp(&GENERATION_NUMBER) {
            Ordering::Less => Err(nfsstat3::NFS3ERR_STALE),
            Ordering::Greater => Err(nfsstat3::NFS3ERR_BADHANDLE),
            Ordering::Equal => Ok(id),
        }
    }
    /// Converts a complete path to a fileid.  Optional.
    /// The default implementation walks the directory structure with lookup()
    async fn path_to_id(&self, auth: &AuthContext, path: &[u8]) -> Result<fileid3, nfsstat3> {
        let splits = path.split(|&r| r == b'/');
        let mut fid = self.root_dir();
        for component in splits {
            if component.is_empty() {
                continue;
            }
            fid = self.lookup(auth, fid, &component.into()).await?;
        }
        Ok(fid)
    }

    fn serverid(&self) -> cookieverf3 {
        GENERATION_NUMBER.to_le_bytes()
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Clone, Debug)]
    pub(crate) struct CapturedWrite {
        pub(crate) xid: u32,
        pub(crate) client_addr: String,
        pub(crate) connection_incarnation: u64,
        pub(crate) requested_stability: stable_how,
        pub(crate) auth: AuthContext,
        pub(crate) id: fileid3,
        pub(crate) offset: u64,
        pub(crate) data: Vec<u8>,
    }

    #[derive(Clone, Debug)]
    pub(crate) struct CapturedCommit {
        pub(crate) xid: u32,
        pub(crate) client_addr: String,
        pub(crate) connection_incarnation: u64,
        pub(crate) auth: AuthContext,
        pub(crate) fileid: fileid3,
        pub(crate) offset: u64,
        pub(crate) count: u32,
    }

    #[derive(Clone, Debug)]
    pub(crate) struct CapturedAccess {
        pub(crate) auth: AuthContext,
        pub(crate) id: fileid3,
        pub(crate) requested: u32,
    }

    /// Test filesystem that records access/write/commit calls and returns
    /// configurable access and durability results.
    pub(crate) struct ContextRecordingFs {
        pub(crate) getattr_error: Option<nfsstat3>,
        pub(crate) getattr_calls: AtomicUsize,
        pub(crate) read_only: bool,
        pub(crate) access_result: Option<Result<AccessResult, nfsstat3>>,
        pub(crate) accesses: Mutex<Vec<CapturedAccess>>,
        pub(crate) committed: stable_how,
        pub(crate) verifier: writeverf3,
        pub(crate) writes: Arc<Mutex<Vec<CapturedWrite>>>,
        pub(crate) commits: Arc<Mutex<Vec<CapturedCommit>>>,
        pub(crate) legacy_write_calls: Arc<AtomicUsize>,
        pub(crate) legacy_commit_calls: Arc<AtomicUsize>,
    }

    impl ContextRecordingFs {
        pub(crate) fn new(committed: stable_how, verifier: writeverf3) -> ContextRecordingFs {
            ContextRecordingFs {
                getattr_error: None,
                getattr_calls: AtomicUsize::new(0),
                read_only: false,
                access_result: None,
                accesses: Mutex::new(Vec::new()),
                committed,
                verifier,
                writes: Arc::new(Mutex::new(Vec::new())),
                commits: Arc::new(Mutex::new(Vec::new())),
                legacy_write_calls: Arc::new(AtomicUsize::new(0)),
                legacy_commit_calls: Arc::new(AtomicUsize::new(0)),
            }
        }

        pub(crate) fn attr(id: fileid3, size: u64) -> fattr3 {
            fattr3 {
                fileid: id,
                size,
                mtime: nfs::nfstime3 {
                    seconds: 90,
                    nseconds: 100,
                },
                ctime: nfs::nfstime3 {
                    seconds: 90,
                    nseconds: 101,
                },
                ..Default::default()
            }
        }
    }

    #[async_trait]
    impl NFSFileSystem for ContextRecordingFs {
        fn name_max(&self) -> u32 {
            1023
        }
        fn capabilities(&self) -> VFSCapabilities {
            if self.read_only {
                VFSCapabilities::ReadOnly
            } else {
                VFSCapabilities::ReadWrite
            }
        }
        fn root_dir(&self) -> fileid3 {
            1
        }
        async fn lookup(
            &self,
            _auth: &AuthContext,
            _dirid: fileid3,
            _filename: &filename3,
        ) -> Result<fileid3, nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn getattr(&self, _auth: &AuthContext, id: fileid3) -> Result<fattr3, nfsstat3> {
            self.getattr_calls.fetch_add(1, Ordering::SeqCst);
            match self.getattr_error {
                Some(status) => Err(status),
                None => Ok(Self::attr(id, 512)),
            }
        }
        async fn access(&self, auth: &AuthContext, id: fileid3, requested: u32) -> Result<AccessResult, nfsstat3> {
            self.accesses.lock().unwrap().push(CapturedAccess {
                auth: auth.clone(),
                id,
                requested,
            });
            match &self.access_result {
                Some(result) => result.clone(),
                None => Err(nfsstat3::NFS3ERR_NOTSUPP),
            }
        }
        async fn setattr(&self, _auth: &AuthContext, _id: fileid3, _setattr: sattr3) -> Result<fattr3, nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn read(
            &self,
            _auth: &AuthContext,
            _id: fileid3,
            _offset: u64,
            _count: u32,
        ) -> Result<(Vec<u8>, bool), nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn write(
            &self,
            _auth: &AuthContext,
            _id: fileid3,
            _offset: u64,
            _data: &[u8],
        ) -> Result<fattr3, nfsstat3> {
            self.legacy_write_calls.fetch_add(1, Ordering::SeqCst);
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn write_with_context(
            &self,
            context: &WriteRequestContext,
            auth: &AuthContext,
            id: fileid3,
            offset: u64,
            data: &[u8],
        ) -> Result<WriteResult, nfsstat3> {
            self.writes.lock().unwrap().push(CapturedWrite {
                xid: context.rpc.xid,
                client_addr: context.rpc.client_addr.clone(),
                connection_incarnation: context.rpc.connection_incarnation,
                requested_stability: context.requested_stability,
                auth: auth.clone(),
                id,
                offset,
                data: data.to_vec(),
            });
            Ok(WriteResult {
                attributes: Self::attr(id, offset + data.len() as u64),
                committed: self.committed,
                verifier: self.verifier,
            })
        }
        async fn create(
            &self,
            _auth: &AuthContext,
            _dirid: fileid3,
            _filename: &filename3,
            _attr: sattr3,
        ) -> Result<(fileid3, fattr3), nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn create_exclusive(
            &self,
            _auth: &AuthContext,
            _dirid: fileid3,
            _filename: &filename3,
        ) -> Result<fileid3, nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn mkdir(
            &self,
            _auth: &AuthContext,
            _dirid: fileid3,
            _dirname: &filename3,
            _attrs: &sattr3,
        ) -> Result<(fileid3, fattr3), nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn remove(&self, _auth: &AuthContext, _dirid: fileid3, _filename: &filename3) -> Result<(), nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn rename(
            &self,
            _auth: &AuthContext,
            _from_dirid: fileid3,
            _from_filename: &filename3,
            _to_dirid: fileid3,
            _to_filename: &filename3,
        ) -> Result<(), nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn readdir(
            &self,
            _auth: &AuthContext,
            _dirid: fileid3,
            _start_after: fileid3,
            _max_entries: usize,
        ) -> Result<ReadDirResult, nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn symlink(
            &self,
            _auth: &AuthContext,
            _dirid: fileid3,
            _linkname: &filename3,
            _symlink: &nfspath3,
            _attr: &sattr3,
        ) -> Result<(fileid3, fattr3), nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn readlink(&self, _auth: &AuthContext, _id: fileid3) -> Result<nfspath3, nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn mknod(
            &self,
            _auth: &AuthContext,
            _dirid: fileid3,
            _filename: &filename3,
            _ftype: ftype3,
            _attr: &sattr3,
            _spec: Option<&specdata3>,
        ) -> Result<(fileid3, fattr3), nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn link(
            &self,
            _auth: &AuthContext,
            _fileid: fileid3,
            _linkdirid: fileid3,
            _linkname: &filename3,
        ) -> Result<(), nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn commit(
            &self,
            _auth: &AuthContext,
            _fileid: fileid3,
            _offset: u64,
            _count: u32,
        ) -> Result<writeverf3, nfsstat3> {
            self.legacy_commit_calls.fetch_add(1, Ordering::SeqCst);
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn commit_with_context(
            &self,
            context: &CommitRequestContext,
            auth: &AuthContext,
            fileid: fileid3,
            offset: u64,
            count: u32,
        ) -> Result<CommitResult, nfsstat3> {
            self.commits.lock().unwrap().push(CapturedCommit {
                xid: context.rpc.xid,
                client_addr: context.rpc.client_addr.clone(),
                connection_incarnation: context.rpc.connection_incarnation,
                auth: auth.clone(),
                fileid,
                offset,
                count,
            });
            Ok(CommitResult {
                verifier: self.verifier,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    fn rpc_context() -> RpcRequestContext {
        RpcRequestContext {
            xid: 7,
            client_addr: "127.0.0.1:1048".to_string(),
            connection_incarnation: 42,
        }
    }

    fn auth() -> AuthContext {
        AuthContext {
            uid: 1000,
            gid: 100,
            gids: vec![100, 20],
        }
    }

    /// Legacy implementor that overrides write/commit/get_write_verf and
    /// counts how often each legacy method is called.
    struct RecordingFs {
        write_calls: AtomicUsize,
        commit_calls: AtomicUsize,
        attributes: Option<fattr3>,
        read_only: bool,
    }

    impl RecordingFs {
        fn new() -> RecordingFs {
            RecordingFs {
                write_calls: AtomicUsize::new(0),
                commit_calls: AtomicUsize::new(0),
                attributes: None,
                read_only: false,
            }
        }
    }

    fn access_fs(ftype: ftype3, mode: u32) -> RecordingFs {
        let mut fs = RecordingFs::new();
        fs.attributes = Some(fattr3 {
            ftype,
            mode,
            fileid: 42,
            uid: 1000,
            gid: 100,
            ..Default::default()
        });
        fs
    }

    #[tokio::test]
    async fn default_access_uses_owner_group_and_other_permissions() {
        let fs = access_fs(ftype3::NF3REG, 0o641);
        let cases = [
            (auth(), ACCESS3_READ | ACCESS3_MODIFY | ACCESS3_EXTEND),
            (
                AuthContext {
                    uid: 2000,
                    gid: 100,
                    gids: vec![],
                },
                ACCESS3_READ,
            ),
            (
                AuthContext {
                    uid: 2000,
                    gid: 200,
                    gids: vec![100],
                },
                ACCESS3_READ,
            ),
            (
                AuthContext {
                    uid: 2000,
                    gid: 200,
                    gids: vec![],
                },
                ACCESS3_EXECUTE,
            ),
        ];
        for (auth, expected) in cases {
            let result = fs.access(&auth, 42, ACCESS3_ALL).await.unwrap();
            assert_eq!(result.access, expected, "{auth:?}");
            assert_eq!(result.attributes.fileid, 42);
            assert_eq!(result.attributes.mode, 0o641);
            assert_eq!(result.attributes.uid, 1000);
        }
    }

    #[tokio::test]
    async fn default_access_does_not_fall_back_from_owner_or_group_to_other() {
        let owner_fs = access_fs(ftype3::NF3REG, 0o077);
        assert_eq!(owner_fs.access(&auth(), 42, ACCESS3_ALL).await.unwrap().access, 0);

        let group_fs = access_fs(ftype3::NF3REG, 0o707);
        let group = AuthContext {
            uid: 2000,
            gid: 100,
            gids: vec![],
        };
        assert_eq!(group_fs.access(&group, 42, ACCESS3_ALL).await.unwrap().access, 0);
    }

    #[tokio::test]
    async fn default_access_requires_write_and_search_for_directory_mutations() {
        let cases = [
            (0o200, 0),
            (0o100, ACCESS3_LOOKUP),
            (0o400, ACCESS3_READ),
            (0o700, ACCESS3_READ | ACCESS3_LOOKUP | ACCESS3_MODIFY | ACCESS3_EXTEND | ACCESS3_DELETE),
        ];
        for (mode, expected) in cases {
            let fs = access_fs(ftype3::NF3DIR, mode);
            assert_eq!(fs.access(&auth(), 42, ACCESS3_ALL).await.unwrap().access, expected, "mode {mode:o}");
        }
        let fs = access_fs(ftype3::NF3REG, 0o777);
        assert_eq!(fs.access(&auth(), 42, ACCESS3_LOOKUP | ACCESS3_DELETE).await.unwrap().access, 0);
    }

    #[tokio::test]
    async fn default_access_retains_execute_and_lookup_on_read_only_filesystems() {
        for (ftype, expected) in [
            (ftype3::NF3REG, ACCESS3_READ | ACCESS3_EXECUTE),
            (ftype3::NF3DIR, ACCESS3_READ | ACCESS3_LOOKUP),
        ] {
            let mut fs = access_fs(ftype, 0o777);
            fs.read_only = true;
            assert_eq!(fs.access(&auth(), 42, ACCESS3_ALL).await.unwrap().access, expected);
        }
    }

    #[tokio::test]
    async fn default_access_root_requires_an_execute_bit_on_non_directories() {
        let root = AuthContext {
            uid: 0,
            gid: 0,
            gids: vec![],
        };
        let cases = [
            (ftype3::NF3REG, 0o000, ACCESS3_READ | ACCESS3_MODIFY | ACCESS3_EXTEND),
            (ftype3::NF3REG, 0o001, ACCESS3_READ | ACCESS3_MODIFY | ACCESS3_EXTEND | ACCESS3_EXECUTE),
            (
                ftype3::NF3DIR,
                0o000,
                ACCESS3_READ | ACCESS3_LOOKUP | ACCESS3_MODIFY | ACCESS3_EXTEND | ACCESS3_DELETE,
            ),
        ];
        for (ftype, mode, expected) in cases {
            let fs = access_fs(ftype, mode);
            assert_eq!(fs.access(&root, 42, ACCESS3_ALL).await.unwrap().access, expected);
        }
    }

    #[tokio::test]
    async fn default_access_only_reports_supported_requested_permissions() {
        let fs = access_fs(ftype3::NF3REG, 0o777);
        assert_eq!(fs.access(&auth(), 42, ACCESS3_READ | (1 << 31)).await.unwrap().access, ACCESS3_READ);
        assert_eq!(fs.access(&auth(), 42, 0).await.unwrap().access, 0);
    }

    #[tokio::test]
    async fn default_access_propagates_getattr_errors() {
        assert!(matches!(RecordingFs::new().access(&auth(), 42, ACCESS3_ALL).await, Err(nfsstat3::NFS3ERR_NOTSUPP)));
    }

    #[async_trait]
    impl NFSFileSystem for RecordingFs {
        fn capabilities(&self) -> VFSCapabilities {
            if self.read_only {
                VFSCapabilities::ReadOnly
            } else {
                VFSCapabilities::ReadWrite
            }
        }
        fn root_dir(&self) -> fileid3 {
            1
        }
        async fn lookup(
            &self,
            _auth: &AuthContext,
            _dirid: fileid3,
            _filename: &filename3,
        ) -> Result<fileid3, nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn getattr(&self, _auth: &AuthContext, _id: fileid3) -> Result<fattr3, nfsstat3> {
            self.attributes.ok_or(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn setattr(&self, _auth: &AuthContext, _id: fileid3, _setattr: sattr3) -> Result<fattr3, nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn read(
            &self,
            _auth: &AuthContext,
            _id: fileid3,
            _offset: u64,
            _count: u32,
        ) -> Result<(Vec<u8>, bool), nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn write(&self, _auth: &AuthContext, id: fileid3, offset: u64, data: &[u8]) -> Result<fattr3, nfsstat3> {
            self.write_calls.fetch_add(1, Ordering::SeqCst);
            Ok(fattr3 {
                fileid: id,
                size: offset + data.len() as u64,
                ..Default::default()
            })
        }
        async fn create(
            &self,
            _auth: &AuthContext,
            _dirid: fileid3,
            _filename: &filename3,
            _attr: sattr3,
        ) -> Result<(fileid3, fattr3), nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn create_exclusive(
            &self,
            _auth: &AuthContext,
            _dirid: fileid3,
            _filename: &filename3,
        ) -> Result<fileid3, nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn mkdir(
            &self,
            _auth: &AuthContext,
            _dirid: fileid3,
            _dirname: &filename3,
            _attrs: &sattr3,
        ) -> Result<(fileid3, fattr3), nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn remove(&self, _auth: &AuthContext, _dirid: fileid3, _filename: &filename3) -> Result<(), nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn rename(
            &self,
            _auth: &AuthContext,
            _from_dirid: fileid3,
            _from_filename: &filename3,
            _to_dirid: fileid3,
            _to_filename: &filename3,
        ) -> Result<(), nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn readdir(
            &self,
            _auth: &AuthContext,
            _dirid: fileid3,
            _start_after: fileid3,
            _max_entries: usize,
        ) -> Result<ReadDirResult, nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn symlink(
            &self,
            _auth: &AuthContext,
            _dirid: fileid3,
            _linkname: &filename3,
            _symlink: &nfspath3,
            _attr: &sattr3,
        ) -> Result<(fileid3, fattr3), nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn readlink(&self, _auth: &AuthContext, _id: fileid3) -> Result<nfspath3, nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn mknod(
            &self,
            _auth: &AuthContext,
            _dirid: fileid3,
            _filename: &filename3,
            _ftype: ftype3,
            _attr: &sattr3,
            _spec: Option<&specdata3>,
        ) -> Result<(fileid3, fattr3), nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn link(
            &self,
            _auth: &AuthContext,
            _fileid: fileid3,
            _linkdirid: fileid3,
            _linkname: &filename3,
        ) -> Result<(), nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn commit(
            &self,
            _auth: &AuthContext,
            _fileid: fileid3,
            _offset: u64,
            _count: u32,
        ) -> Result<writeverf3, nfsstat3> {
            self.commit_calls.fetch_add(1, Ordering::SeqCst);
            Ok([7u8; NFS3_WRITEVERFSIZE as usize])
        }
        fn get_write_verf(&self) -> writeverf3 {
            [7u8; NFS3_WRITEVERFSIZE as usize]
        }
    }

    /// Legacy implementor that omits commit and get_write_verf entirely.
    struct LegacyFs;

    #[test]
    fn pathconf_default_name_limit_is_255_bytes() {
        assert_eq!(LegacyFs.name_max(), 255);
    }

    #[async_trait]
    impl NFSFileSystem for LegacyFs {
        fn capabilities(&self) -> VFSCapabilities {
            VFSCapabilities::ReadWrite
        }
        fn root_dir(&self) -> fileid3 {
            1
        }
        async fn lookup(
            &self,
            _auth: &AuthContext,
            _dirid: fileid3,
            _filename: &filename3,
        ) -> Result<fileid3, nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn getattr(&self, _auth: &AuthContext, _id: fileid3) -> Result<fattr3, nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn setattr(&self, _auth: &AuthContext, _id: fileid3, _setattr: sattr3) -> Result<fattr3, nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn read(
            &self,
            _auth: &AuthContext,
            _id: fileid3,
            _offset: u64,
            _count: u32,
        ) -> Result<(Vec<u8>, bool), nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn write(
            &self,
            _auth: &AuthContext,
            _id: fileid3,
            _offset: u64,
            _data: &[u8],
        ) -> Result<fattr3, nfsstat3> {
            Ok(fattr3::default())
        }
        async fn create(
            &self,
            _auth: &AuthContext,
            _dirid: fileid3,
            _filename: &filename3,
            _attr: sattr3,
        ) -> Result<(fileid3, fattr3), nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn create_exclusive(
            &self,
            _auth: &AuthContext,
            _dirid: fileid3,
            _filename: &filename3,
        ) -> Result<fileid3, nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn mkdir(
            &self,
            _auth: &AuthContext,
            _dirid: fileid3,
            _dirname: &filename3,
            _attrs: &sattr3,
        ) -> Result<(fileid3, fattr3), nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn remove(&self, _auth: &AuthContext, _dirid: fileid3, _filename: &filename3) -> Result<(), nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn rename(
            &self,
            _auth: &AuthContext,
            _from_dirid: fileid3,
            _from_filename: &filename3,
            _to_dirid: fileid3,
            _to_filename: &filename3,
        ) -> Result<(), nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn readdir(
            &self,
            _auth: &AuthContext,
            _dirid: fileid3,
            _start_after: fileid3,
            _max_entries: usize,
        ) -> Result<ReadDirResult, nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn symlink(
            &self,
            _auth: &AuthContext,
            _dirid: fileid3,
            _linkname: &filename3,
            _symlink: &nfspath3,
            _attr: &sattr3,
        ) -> Result<(fileid3, fattr3), nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn readlink(&self, _auth: &AuthContext, _id: fileid3) -> Result<nfspath3, nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn mknod(
            &self,
            _auth: &AuthContext,
            _dirid: fileid3,
            _filename: &filename3,
            _ftype: ftype3,
            _attr: &sattr3,
            _spec: Option<&specdata3>,
        ) -> Result<(fileid3, fattr3), nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn link(
            &self,
            _auth: &AuthContext,
            _fileid: fileid3,
            _linkdirid: fileid3,
            _linkname: &filename3,
        ) -> Result<(), nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
    }

    /// Marker that keeps a type `Sync` while making it `!Send`.
    struct NotSendMarker(PhantomData<*const ()>);
    unsafe impl Sync for NotSendMarker {}

    /// A `Sync` but not `Send` legacy implementor. The `NFSFileSystem`
    /// trait bound is exactly `Sync`, so this must keep compiling.
    struct SyncNotSendFs {
        _marker: NotSendMarker,
        write_calls: AtomicUsize,
    }

    impl SyncNotSendFs {
        fn new() -> SyncNotSendFs {
            SyncNotSendFs {
                _marker: NotSendMarker(PhantomData),
                write_calls: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl NFSFileSystem for SyncNotSendFs {
        fn capabilities(&self) -> VFSCapabilities {
            VFSCapabilities::ReadWrite
        }
        fn root_dir(&self) -> fileid3 {
            1
        }
        async fn lookup(
            &self,
            _auth: &AuthContext,
            _dirid: fileid3,
            _filename: &filename3,
        ) -> Result<fileid3, nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn getattr(&self, _auth: &AuthContext, _id: fileid3) -> Result<fattr3, nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn setattr(&self, _auth: &AuthContext, _id: fileid3, _setattr: sattr3) -> Result<fattr3, nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn read(
            &self,
            _auth: &AuthContext,
            _id: fileid3,
            _offset: u64,
            _count: u32,
        ) -> Result<(Vec<u8>, bool), nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn write(
            &self,
            _auth: &AuthContext,
            _id: fileid3,
            _offset: u64,
            _data: &[u8],
        ) -> Result<fattr3, nfsstat3> {
            self.write_calls.fetch_add(1, Ordering::SeqCst);
            Ok(fattr3::default())
        }
        async fn create(
            &self,
            _auth: &AuthContext,
            _dirid: fileid3,
            _filename: &filename3,
            _attr: sattr3,
        ) -> Result<(fileid3, fattr3), nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn create_exclusive(
            &self,
            _auth: &AuthContext,
            _dirid: fileid3,
            _filename: &filename3,
        ) -> Result<fileid3, nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn mkdir(
            &self,
            _auth: &AuthContext,
            _dirid: fileid3,
            _dirname: &filename3,
            _attrs: &sattr3,
        ) -> Result<(fileid3, fattr3), nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn remove(&self, _auth: &AuthContext, _dirid: fileid3, _filename: &filename3) -> Result<(), nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn rename(
            &self,
            _auth: &AuthContext,
            _from_dirid: fileid3,
            _from_filename: &filename3,
            _to_dirid: fileid3,
            _to_filename: &filename3,
        ) -> Result<(), nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn readdir(
            &self,
            _auth: &AuthContext,
            _dirid: fileid3,
            _start_after: fileid3,
            _max_entries: usize,
        ) -> Result<ReadDirResult, nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn symlink(
            &self,
            _auth: &AuthContext,
            _dirid: fileid3,
            _linkname: &filename3,
            _symlink: &nfspath3,
            _attr: &sattr3,
        ) -> Result<(fileid3, fattr3), nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn readlink(&self, _auth: &AuthContext, _id: fileid3) -> Result<nfspath3, nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn mknod(
            &self,
            _auth: &AuthContext,
            _dirid: fileid3,
            _filename: &filename3,
            _ftype: ftype3,
            _attr: &sattr3,
            _spec: Option<&specdata3>,
        ) -> Result<(fileid3, fattr3), nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn link(
            &self,
            _auth: &AuthContext,
            _fileid: fileid3,
            _linkdirid: fileid3,
            _linkname: &filename3,
        ) -> Result<(), nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
    }

    #[tokio::test]
    async fn write_with_context_delegates_to_write_exactly_once() {
        let fs = RecordingFs::new();
        let context = WriteRequestContext {
            rpc: rpc_context(),
            requested_stability: stable_how::UNSTABLE,
        };
        let result = fs.write_with_context(&context, &auth(), 3, 10, b"hello").await.unwrap();
        assert_eq!(fs.write_calls.load(Ordering::SeqCst), 1);
        assert_eq!(fs.commit_calls.load(Ordering::SeqCst), 0);
        assert_eq!(result.committed, stable_how::FILE_SYNC);
        assert_eq!(result.verifier, [7u8; NFS3_WRITEVERFSIZE as usize]);
        assert_eq!(result.attributes.size, 15);
    }

    #[tokio::test]
    async fn commit_with_context_delegates_to_commit_exactly_once() {
        let fs = RecordingFs::new();
        let context = CommitRequestContext { rpc: rpc_context() };
        let result = fs.commit_with_context(&context, &auth(), 3, 0, 100).await.unwrap();
        assert_eq!(fs.commit_calls.load(Ordering::SeqCst), 1);
        assert_eq!(fs.write_calls.load(Ordering::SeqCst), 0);
        assert_eq!(result.verifier, [7u8; NFS3_WRITEVERFSIZE as usize]);
    }

    #[tokio::test]
    async fn legacy_implementor_without_commit_gets_defaults() {
        let fs = LegacyFs;
        let zero = [0u8; NFS3_WRITEVERFSIZE as usize];
        assert_eq!(fs.get_write_verf(), zero);
        assert_eq!(fs.commit(&auth(), 1, 0, 0).await.unwrap(), zero);
        let write = fs
            .write_with_context(
                &WriteRequestContext {
                    rpc: rpc_context(),
                    requested_stability: stable_how::DATA_SYNC,
                },
                &auth(),
                1,
                0,
                b"x",
            )
            .await
            .unwrap();
        assert_eq!(write.committed, stable_how::FILE_SYNC);
        assert_eq!(write.verifier, zero);
        let commit = fs
            .commit_with_context(&CommitRequestContext { rpc: rpc_context() }, &auth(), 1, 0, 0)
            .await
            .unwrap();
        assert_eq!(commit.verifier, zero);
    }

    #[test]
    fn sync_but_not_send_implementor_compiles() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<SyncNotSendFs>();

        let fs = SyncNotSendFs::new();
        let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let context = WriteRequestContext {
            rpc: rpc_context(),
            requested_stability: stable_how::UNSTABLE,
        };
        let result = runtime.block_on(fs.write_with_context(&context, &auth(), 1, 0, b"hi")).unwrap();
        assert_eq!(fs.write_calls.load(Ordering::SeqCst), 1);
        assert_eq!(result.committed, stable_how::FILE_SYNC);
    }
}
