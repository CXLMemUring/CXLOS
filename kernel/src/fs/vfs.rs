use super::FsError;
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

/// File type enumeration
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FileType {
    Regular,
    Directory,
    Device,
    Link,
}

/// File statistics
#[derive(Debug, Clone)]
pub struct FileStat {
    pub size: usize,
    pub file_type: FileType,
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
}

/// A file node in the filesystem
#[derive(Debug, Clone)]
pub struct FileNode {
    pub name: String,
    pub file_type: FileType,
    pub data: Vec<u8>,
    // Use a simple Vec-based map to reduce allocator complexity during bootstrap.
    // This avoids deeper BTreeMap node allocations which may trigger OOM/fragmentation
    // on early boot in constrained environments.
    pub children: Vec<(String, Box<FileNode>)>,
    pub stat: FileStat,
}

impl FileNode {
    /// Create a new directory node
    pub fn new_dir(name: String) -> Self {
        Self {
            name,
            file_type: FileType::Directory,
            data: Vec::new(),
            children: Vec::new(),
            stat: FileStat {
                size: 0,
                file_type: FileType::Directory,
                mode: 0o755,
                uid: 0,
                gid: 0,
            },
        }
    }

    /// Create a new file node
    pub fn new_file(name: String, data: Vec<u8>) -> Self {
        let size = data.len();
        Self {
            name,
            file_type: FileType::Regular,
            data,
            children: Vec::new(),
            stat: FileStat {
                size,
                file_type: FileType::Regular,
                mode: 0o644,
                uid: 0,
                gid: 0,
            },
        }
    }
}

/// Virtual filesystem implementation
pub struct VirtualFileSystem {
    root: FileNode,
}

impl VirtualFileSystem {
    /// Create a new VFS with root directory
    pub fn new() -> Self {
        Self {
            root: FileNode::new_dir("/".to_string()),
        }
    }

    /// Parse a path into components
    fn parse_path(path: &str) -> Result<Vec<String>, FsError> {
        if !path.starts_with('/') {
            return Err(FsError::InvalidPath);
        }

        let components: Vec<String> = path
            .split('/')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();

        Ok(components)
    }

    /// Navigate to a node by path
    fn navigate_to(&self, path: &str) -> Result<&FileNode, FsError> {
        if path == "/" {
            return Ok(&self.root);
        }

        let components = Self::parse_path(path)?;
        let mut current = &self.root;

        for component in components {
            if current.file_type != FileType::Directory {
                return Err(FsError::NotDirectory);
            }

            // linear search over children
            let mut next: Option<&FileNode> = None;
            for (name, child) in &current.children {
                if name == &component {
                    next = Some(child);
                    break;
                }
            }
            current = next.ok_or(FsError::NotFound)?;
        }

        Ok(current)
    }

    /// Navigate to a node by path (mutable)
    fn navigate_to_mut(&mut self, path: &str) -> Result<&mut FileNode, FsError> {
        if path == "/" {
            return Ok(&mut self.root);
        }

        let components = Self::parse_path(path)?;
        let mut current = &mut self.root;

        for component in components {
            if current.file_type != FileType::Directory {
                return Err(FsError::NotDirectory);
            }

            // linear search over children (mutable)
            let mut next: Option<&mut FileNode> = None;
            for (name, child) in &mut current.children {
                if name == &component {
                    next = Some(child);
                    break;
                }
            }
            current = next.ok_or(FsError::NotFound)?;
        }

        Ok(current)
    }

    /// Navigate to parent directory
    fn navigate_to_parent_mut(&mut self, path: &str) -> Result<(&mut FileNode, String), FsError> {
        let components = Self::parse_path(path)?;
        if components.is_empty() {
            return Err(FsError::InvalidPath);
        }

        let filename = components.last().unwrap().clone();
        let parent_components = &components[..components.len() - 1];

        let mut current = &mut self.root;
        for component in parent_components {
            if current.file_type != FileType::Directory {
                return Err(FsError::NotDirectory);
            }

            // linear search over children (mutable)
            let mut next: Option<&mut FileNode> = None;
            for (name, child) in &mut current.children {
                if name == component {
                    next = Some(child);
                    break;
                }
            }
            current = next.ok_or(FsError::NotFound)?;
        }

        Ok((current, filename))
    }

    /// Create a directory
    pub fn mkdir(&mut self, path: &str) -> Result<(), FsError> {
        let (parent, dirname) = self.navigate_to_parent_mut(path)?;

        if parent.children.iter().any(|(n, _)| n == &dirname) {
            return Err(FsError::AlreadyExists);
        }

        parent
            .children
            .push((dirname.clone(), Box::new(FileNode::new_dir(dirname))));

        Ok(())
    }

    /// Create a file with content
    pub fn create_file(&mut self, path: &str, content: &[u8]) -> Result<(), FsError> {
        let (parent, filename) = self.navigate_to_parent_mut(path)?;

        if parent.children.iter().any(|(n, _)| n == &filename) {
            return Err(FsError::AlreadyExists);
        }

        parent
            .children
            .push((filename.clone(), Box::new(FileNode::new_file(filename, content.to_vec()))));

        Ok(())
    }

    /// Read file content
    pub fn read_file(&self, path: &str) -> Result<Vec<u8>, FsError> {
        let node = self.navigate_to(path)?;

        if node.file_type != FileType::Regular {
            return Err(FsError::NotFile);
        }

        Ok(node.data.clone())
    }

    /// Write to a file (overwrite)
    pub fn write_file(&mut self, path: &str, content: &[u8]) -> Result<(), FsError> {
        let node = self.navigate_to_mut(path)?;

        if node.file_type != FileType::Regular {
            return Err(FsError::NotFile);
        }

        node.data = content.to_vec();
        node.stat.size = content.len();

        Ok(())
    }

    /// Append to a file
    pub fn append_file(&mut self, path: &str, content: &[u8]) -> Result<(), FsError> {
        let node = self.navigate_to_mut(path)?;

        if node.file_type != FileType::Regular {
            return Err(FsError::NotFile);
        }

        node.data.extend_from_slice(content);
        node.stat.size = node.data.len();

        Ok(())
    }

    /// List directory contents
    pub fn list_dir(&self, path: &str) -> Result<Vec<String>, FsError> {
        let node = self.navigate_to(path)?;

        if node.file_type != FileType::Directory {
            return Err(FsError::NotDirectory);
        }

        let entries: Vec<String> = node.children.iter().map(|(n, _)| n.clone()).collect();
        Ok(entries)
    }

    /// Get file statistics
    pub fn stat(&self, path: &str) -> Result<FileStat, FsError> {
        let node = self.navigate_to(path)?;
        Ok(node.stat.clone())
    }

    /// Check if path exists
    pub fn exists(&self, path: &str) -> bool {
        self.navigate_to(path).is_ok()
    }

    /// Remove a file
    pub fn remove_file(&mut self, path: &str) -> Result<(), FsError> {
        let (parent, filename) = self.navigate_to_parent_mut(path)?;

        let idx = parent
            .children
            .iter()
            .position(|(n, _)| n == &filename)
            .ok_or(FsError::NotFound)?;
        let node = &parent.children[idx].1;

        if node.file_type != FileType::Regular {
            return Err(FsError::NotFile);
        }

        parent.children.remove(idx);
        Ok(())
    }

    /// Remove a directory (must be empty)
    pub fn remove_dir(&mut self, path: &str) -> Result<(), FsError> {
        let (parent, dirname) = self.navigate_to_parent_mut(path)?;

        let idx = parent
            .children
            .iter()
            .position(|(n, _)| n == &dirname)
            .ok_or(FsError::NotFound)?;
        let node = &parent.children[idx].1;

        if node.file_type != FileType::Directory {
            return Err(FsError::NotDirectory);
        }

        if !node.children.is_empty() {
            return Err(FsError::IoError("Directory not empty".to_string()));
        }

        parent.children.remove(idx);
        Ok(())
    }
}

/// Trait for filesystem operations
pub trait FileSystem {
    fn open(&self, path: &str, flags: u32) -> Result<usize, FsError>;
    fn close(&self, fd: usize) -> Result<(), FsError>;
    fn read(&self, fd: usize, buf: &mut [u8]) -> Result<usize, FsError>;
    fn write(&self, fd: usize, buf: &[u8]) -> Result<usize, FsError>;
    fn seek(&self, fd: usize, offset: i64, whence: u32) -> Result<usize, FsError>;
}

impl fmt::Display for FileType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FileType::Regular => write!(f, "-"),
            FileType::Directory => write!(f, "d"),
            FileType::Device => write!(f, "c"),
            FileType::Link => write!(f, "l"),
        }
    }
}
