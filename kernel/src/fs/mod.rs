use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::error::Error;
use core::fmt;
use spin::RwLock;

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn serial_out(byte: u8) {
    core::arch::asm!(
        "out dx, al",
        in("al") byte,
        in("dx") 0x3F8u16,
        options(nostack, preserves_flags)
    );
}

pub mod vfs;

pub use vfs::{VirtualFileSystem, FileNode, FileType, FileSystem, FileStat};

/// Global virtual filesystem instance
static VFS: RwLock<Option<VirtualFileSystem>> = RwLock::new(None);

/// Initialize the filesystem
pub fn init() -> crate::Result<()> {
    // probe: 'S' entering fs::init
    #[cfg(target_arch = "x86_64")]
    unsafe { serial_out(b'S'); }

    let mut vfs_guard = VFS.write();
    let mut vfs = VirtualFileSystem::new();

    vfs.mkdir("/bin")?;
    vfs.mkdir("/dev")?;
    vfs.mkdir("/etc")?;
    vfs.mkdir("/home")?;
    vfs.mkdir("/lib")?;
    vfs.mkdir("/proc")?;
    vfs.mkdir("/sys")?;
    vfs.mkdir("/tmp")?;
    vfs.mkdir("/usr")?;
    vfs.mkdir("/var")?;
    // probe: 'M' after mkdirs
    #[cfg(target_arch = "x86_64")]
    unsafe { serial_out(b'M'); }

    // Create some basic files
    vfs.create_file("/etc/hostname", b"k23\n")?;
    vfs.create_file("/etc/passwd", b"root:x:0:0:root:/root:/bin/sh\n")?;
    vfs.create_file("/etc/group", b"root:x:0:root\n")?;
    vfs.create_file("/proc/version", b"k23 version 0.1.0\n")?;
    vfs.create_file("/proc/cmdline", b"console=ttyS0\n")?;
    // probe: 'C' after create_file batch
    #[cfg(target_arch = "x86_64")]
    unsafe { serial_out(b'C'); }
    *vfs_guard = Some(vfs);
    // probe: 's' stored VFS
    #[cfg(target_arch = "x86_64")]
    unsafe { serial_out(b's'); }
    Ok(())
}

/// Get a reference to the global VFS
pub fn with_vfs<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&VirtualFileSystem) -> R,
{
    let vfs_guard = VFS.read();
    vfs_guard.as_ref().map(f)
}

/// Get a mutable reference to the global VFS
pub fn with_vfs_mut<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut VirtualFileSystem) -> R,
{
    let mut vfs_guard = VFS.write();
    vfs_guard.as_mut().map(f)
}

/// Filesystem error types
#[derive(Debug)]
pub enum FsError {
    NotFound,
    AlreadyExists,
    NotDirectory,
    NotFile,
    InvalidPath,
    PermissionDenied,
    IoError(String),
}
impl Error for FsError {}
impl fmt::Display for FsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FsError::NotFound => write!(f, "No such file or directory"),
            FsError::AlreadyExists => write!(f, "File or directory already exists"),
            FsError::NotDirectory => write!(f, "Not a directory"),
            FsError::NotFile => write!(f, "Not a file"),
            FsError::InvalidPath => write!(f, "Invalid path"),
            FsError::PermissionDenied => write!(f, "Permission denied"),
            FsError::IoError(msg) => write!(f, "I/O error: {}", msg),
        }
    }
}

impl From<FsError> for crate::Result<()> {
    fn from(err: FsError) -> Self {
        Err(anyhow::anyhow!("Filesystem error: {}", err))
    }
}
