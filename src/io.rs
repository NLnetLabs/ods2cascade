//! I/O utilities.
use std::{
    io::{Read, Write},
    path::Path,
};

/// Export either the normal or simulated impls of IoUtil defined below..
// TODO: Find a better name than IoUtilImpl...
pub use inner::Fs;

//--- FsOps ------------------------------------------------------------------

/// Trait for performing I/O.
///
/// Enables real file I/O to be swapped out in tests for simulated I/O.
pub trait FsOps {
    /// A type which offers an interface for writing for use with the write!
    /// and similar macros.
    type F: Read + Write;

    /// Construct an IoUtil impl.
    ///
    /// Allows a test impl to have state and configuration.
    fn new() -> Self;

    /// Opens a file in write-only mode.
    ///
    /// Modelled after std::fs::create() but returns something which can be
    /// written to rather than a std::io::File object.
    ///
    /// This function will create a file if it does not exist, and will
    /// truncate it if it does.
    fn create<P: AsRef<Path>>(&self, path: P) -> std::io::Result<Self::F>;

    /// Create a directory.
    ///
    /// Modelled after std::fs::create_dir().
    fn create_dir<P: AsRef<Path>>(&self, pathi: P) -> std::io::Result<()>;

    /// Reads the entire contents of a file into a string.
    fn read_to_string<P: AsRef<Path>>(&self, path: P) -> std::io::Result<String>;

    /// Returns Ok(true) if the path points at an existing entity.
    fn exists<P: AsRef<Path>>(&self, path: P) -> std::io::Result<bool>;

    /// Print a pretty debug representation of an object to a file.
    fn dbg_to_file<T: std::fmt::Debug>(
        &self,
        v: T,
        name: &str,
        dbg_dir: &str,
    ) -> std::io::Result<()>;

    /// Get the owner of a file.
    fn owner<P: AsRef<Path>>(&self, path: P) -> std::io::Result<Option<String>>;
}

//--- Actual I/O impl of IoUtil ----------------------------------------------

/// Actual I/O.
#[cfg(not(test))]
mod inner {
    use std::io::Write;
    use std::path::Path;

    use fs_err::File;

    use crate::io::FsOps;

    //--- IoUtilImpl ---------------------------------------------------------

    /// An implementation of IoUtil that uses real I/O.
    pub struct Fs;

    impl FsOps for Fs {
        type F = File;

        fn new() -> Self {
            Self
        }

        fn create<P: AsRef<Path>>(&self, path: P) -> std::io::Result<Self::F> {
            fs_err::File::create(path.as_ref().to_path_buf())
        }

        fn create_dir<P: AsRef<Path>>(&self, path: P) -> std::io::Result<()> {
            fs_err::create_dir(&path)
        }

        fn read_to_string<P: AsRef<Path>>(&self, path: P) -> std::io::Result<String> {
            fs_err::read_to_string(&path)
        }

        fn exists<P: AsRef<Path>>(&self, path: P) -> std::io::Result<bool> {
            fs_err::exists(path)
        }

        fn dbg_to_file<T: std::fmt::Debug>(
            &self,
            v: T,
            name: &str,
            dbg_dir: &str,
        ) -> std::io::Result<()> {
            let mut f = self.create(format!("{dbg_dir}/{name}"))?;
            write!(f, "{:#?}", v)?;
            Ok(())
        }

        fn owner<P: AsRef<Path>>(&self, path: P) -> std::io::Result<Option<String>> {
            use file_owner::PathExt;
            path.owner().and_then(|owner| owner.name()).map_err(|err| {
                std::io::Error::other(format!(
                    "File ownership for '{}' could not be determined: {err}",
                    path.as_ref().display()
                ))
            })
        }
    }
}

//--- Simulated I/O impl of IoUtil -------------------------------------------

/// Simulated I/O for use by tests.
#[cfg(test)]
mod inner {
    use std::{
        collections::{HashMap, HashSet, hash_map::Entry},
        path::{Path, PathBuf},
        sync::{Arc, Mutex},
    };

    use crate::io::FsOps;

    //--- SimulatedFsEntries -------------------------------------------------

    /// A type that stores information about files in the simulated
    /// filesystem.
    type SimulatedFsEntries = Arc<Mutex<HashMap<PathBuf, SimulatedFsEntry>>>;

    //--- SimulatedFs --------------------------------------------------------

    /// An implementation of IoUtil that uses simulated I/O.
    #[derive(Debug)]
    pub struct Fs {
        /// A collection of simulated files.
        ///
        /// Each entry is a filename and associated content.
        ///
        /// Calls to [`Self::read_to_string()`] will read from these "files".
        fs: SimulatedFsEntries,
    }

    //--- impl IoUtil

    impl Fs {
        /// Add a file to the simulated filesystem.
        pub fn register_file<P: Into<PathBuf>, S: Into<String>>(&self, path: P, content: S) {
            let path = path.into();
            self.fs.lock().unwrap().insert(
                path.clone(),
                SimulatedFsEntry::new_file(path, content.into()),
            );
        }

        /// Add a simulated directory to the simulated filesystem.
        pub fn register_dir<P: Into<PathBuf>>(&self, path: P) {
            let path = path.into();
            self.fs
                .lock()
                .unwrap()
                .insert(path.clone(), SimulatedFsEntry::new_dir(path));
        }

        pub fn file_paths(&self) -> HashSet<PathBuf> {
            self.fs
                .lock()
                .unwrap()
                .iter()
                .filter_map(|(k, v)| if v.is_dir { None } else { Some(k) })
                .cloned()
                .collect::<HashSet<_>>()
        }
    }

    //--- impl IoUtil

    impl FsOps for Fs {
        type F = SimulatedFile;

        fn new() -> Self {
            Self {
                fs: Default::default(),
            }
        }

        fn create<P: AsRef<Path>>(&self, path: P) -> std::io::Result<Self::F> {
            Ok(SimulatedFile::new(
                self.fs.clone(),
                path.as_ref().to_path_buf(),
            ))
        }

        fn create_dir<P: AsRef<Path>>(&self, path: P) -> std::io::Result<()> {
            let path = path.as_ref().to_path_buf();
            match self.fs.lock().unwrap().entry(path.clone()) {
                Entry::Occupied(_) => Err(std::io::ErrorKind::AlreadyExists.into()),
                Entry::Vacant(e) => {
                    e.insert(SimulatedFsEntry::new_dir(path));
                    Ok(())
                }
            }
        }

        fn read_to_string<P: AsRef<Path>>(&self, path: P) -> std::io::Result<String> {
            self.fs
                .lock()
                .unwrap()
                .get(&path.as_ref().to_path_buf())
                .ok_or(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("Test data file '{}' not found", path.as_ref().display()),
                ))
                .and_then(|file| {
                    // Behave the same way as std::io::read_to_string()
                    String::from_utf8(file.content.clone()).map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "stream did not contain valid UTF-8",
                        )
                    })
                })
        }

        fn exists<P: AsRef<Path>>(&self, path: P) -> std::io::Result<bool> {
            Ok(self
                .fs
                .lock()
                .unwrap()
                .contains_key(&path.as_ref().to_path_buf()))
        }

        fn dbg_to_file<T: std::fmt::Debug>(
            &self,
            _v: T,
            _name: &str,
            _dbg_dir: &str,
        ) -> std::io::Result<()> {
            // Do nothing as we don't need the debug files during tests.
            Ok(())
        }

        fn owner<P: AsRef<Path>>(&self, _path: P) -> std::io::Result<Option<String>> {
            Ok(Some("test".to_string()))
        }
    }

    //--- SimulatedFsEntry ---------------------------------------------------

    /// A file or directory entry in the simulated filesystem.
    pub struct SimulatedFsEntry {
        path: PathBuf,
        content: Vec<u8>,
        is_dir: bool,
    }

    impl SimulatedFsEntry {
        /// Creates a new test file.
        pub fn new_file<P: Into<PathBuf>, C: Into<Vec<u8>>>(path: P, content: C) -> Self {
            Self {
                path: path.into(),
                content: content.into(),
                is_dir: false,
            }
        }

        /// Creates a new test directory.
        pub fn new_dir<P: Into<PathBuf>>(path: P) -> Self {
            Self {
                path: path.into(),
                content: vec![],
                is_dir: true,
            }
        }

        /// Get the length of the filesystem entry.
        ///
        /// Directories have zero length.
        pub fn len(&self) -> usize {
            self.content.len()
        }

        /// Clears the filesystem entry.
        ///
        /// Clears the content stored for a simulated file.
        ///
        /// Has no effect on simulated directories.
        pub fn clear(&mut self) {
            self.content.clear();
        }
    }

    //--- impl Debug

    /// Debug impl that assumes that file contains text.
    ///
    /// The default Debug impl would print the file content as a sequence of
    /// integer byte values which is unhelpful when debugging.
    impl std::fmt::Debug for SimulatedFsEntry {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("TestFile")
                .field("path", &self.path)
                .field("is_dir", &self.is_dir)
                .field("content", &String::from_utf8_lossy(&self.content))
                .finish()
        }
    }

    //--- SimulatedFile ------------------------------------------------------

    /// Simulated read/write access to a simulated file.
    ///
    /// No actual filesystem reads or writes will be done when working with
    /// this file.
    pub struct SimulatedFile {
        files: SimulatedFsEntries,
        path: PathBuf,
        read_pos: usize,
    }

    impl SimulatedFile {
        /// Creates a new read-write test file.
        ///
        /// This function will create a test file if it does not exist, and
        /// will truncate it if it does.
        pub fn new<P: Into<PathBuf>>(files: SimulatedFsEntries, path: P) -> Self {
            let path = path.into();
            {
                let mut locked = files.lock().unwrap();
                locked
                    .entry(path.clone())
                    .and_modify(|file| file.clear())
                    .or_insert_with_key(|path| SimulatedFsEntry::new_file(path, String::new()));
            }
            Self {
                files,
                path,
                read_pos: 0,
            }
        }
    }

    //--- impl Write

    impl std::io::Write for SimulatedFile {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let mut files = self.files.lock().unwrap();
            let file = files.get_mut(&self.path).unwrap();
            file.content.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            // No flush needed on a Vec<u8>.
            Ok(())
        }
    }

    //--- impl Read

    impl std::io::Read for SimulatedFile {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let files = self.files.lock().unwrap();
            let file = files.get(&self.path).unwrap();

            let bytes_remaining = file
                .len()
                .checked_sub(self.read_pos)
                .ok_or(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?;

            // Read as many bytes as will fit in the buffer, or less if fewer
            // bytes than that remain to be read.
            let bytes_to_read = std::cmp::min(buf.len(), bytes_remaining);
            buf[0..bytes_to_read]
                .copy_from_slice(&file.content[self.read_pos..self.read_pos + bytes_to_read]);

            // Advance the read cursor ready for the next read.
            self.read_pos += bytes_to_read;

            // Return the number of bytes read.
            Ok(bytes_to_read)
        }
    }
}
