//! I/O utilities.
use std::{
    io::{Read, Write},
    path::Path,
};

/// Export either the normal or simulated impls of IoUtil defined below..
// TODO: Find a better name than IoUtilImpl...
pub use inner::IoUtilImpl;

//--- IoUtil -----------------------------------------------------------------

/// Trait for performing I/O.
///
/// Enables real file I/O to be swapped out in tests for simulated I/O.
pub trait IoUtil {
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
}

//--- Actual I/O impl of IoUtil ----------------------------------------------

/// Actual I/O.
#[cfg(not(test))]
mod inner {
    use std::io::Write;
    use std::path::Path;

    use fs_err::File;

    use crate::io::IoUtil;

    //--- IoUtilImpl ---------------------------------------------------------

    /// An implementation of IoUtil that uses real I/O.
    pub struct IoUtilImpl;

    impl IoUtil for IoUtilImpl {
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
            write!(f, "{:#?}", &v)?;
            Ok(())
        }
    }
}

//--- Simulated I/O impl of IoUtil -------------------------------------------

/// Simulated I/O for use by tests.
#[cfg(test)]
mod inner {
    use std::{
        collections::{HashMap, hash_map::Entry},
        path::{Path, PathBuf},
        sync::{Arc, Mutex},
    };

    use crate::io::IoUtil;

    //--- TestFileSystem -----------------------------------------------------

    /// A type that stores information about files in the simulated
    /// filesystem.
    type SimulatedFs = Arc<Mutex<HashMap<PathBuf, SimulatedFsEntry>>>;

    //--- IoUtilImpl ---------------------------------------------------------

    /// An implementation of IoUtil that uses simulated I/O.
    #[derive(Debug)]
    pub struct IoUtilImpl {
        /// A collection of simulated files.
        ///
        /// Each entry is a filename and associated content.
        ///
        /// Calls to [`Self::read_to_string()`] will read from these "files".
        fs: SimulatedFs,
    }

    //--- impl IoUtil

    impl IoUtilImpl {
        /// Add a read-only simulated file to the simulated filesystem.
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

        /// Returns true if the given path is an existing directory in the
        /// simulated filesystem.
        pub fn exists_dir<P: Into<PathBuf>>(&self, path: P) -> bool {
            let path = path.into();
            let files = self.fs.lock().unwrap();
            let Some(entry) = files.get(&path) else {
                return false;
            };
            entry.is_dir
        }
    }

    //--- impl IoUtil

    impl IoUtil for IoUtilImpl {
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
                .map(|file| String::from_utf8_lossy(&file.content).into_owned())
                .ok_or(std::io::Error::other(format!(
                    "File '{}' not found in simulated test filesystem",
                    path.as_ref().display()
                )))
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
    }

    //--- SimulatedFsEntry ---------------------------------------------------

    /// A file or directory entry in the simulated filesystem.
    pub struct SimulatedFsEntry {
        path: PathBuf,
        content: Vec<u8>,
        is_dir: bool,
        read_only: bool, // Only relevant for files
    }

    impl SimulatedFsEntry {
        /// Creates a new read-only test file.
        pub fn new_file<P: Into<PathBuf>, C: Into<Vec<u8>>>(path: P, content: C) -> Self {
            Self {
                path: path.into(),
                content: content.into(),
                is_dir: false,
                read_only: true,
            }
        }

        /// Creates a new read-only test directory.
        pub fn new_dir<P: Into<PathBuf>>(path: P) -> Self {
            Self {
                path: path.into(),
                content: vec![],
                is_dir: true,
                read_only: false,
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
        ///
        /// # Panics
        ///
        /// Panics if the file is read-only.
        pub fn clear(&mut self) {
            if self.read_only {
                panic!(
                    "Cannot modify read-only test file '{}'",
                    self.path.display()
                )
            }
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
                .field("read_only", &self.read_only)
                .field("content", &String::from_utf8_lossy(&self.content))
                .finish()
        }
    }

    //--- SimulatedFile ------------------------------------------------------

    /// Simulated read/write access to a simulated filesystem entry.
    ///
    /// No actual filesystem reads or writes will be done when working with
    /// this file.
    pub struct SimulatedFile {
        files: SimulatedFs,
        path: PathBuf,
        read_pos: usize,
    }

    impl SimulatedFile {
        /// Creates a new read-write test file.
        ///
        /// This function will create a test file if it does not exist, and
        /// will truncate it if it does.
        ///
        /// # Panics
        ///
        /// This function will panic if the test file exists and is marked
        /// read-only.
        pub fn new<P: Into<PathBuf>>(files: SimulatedFs, path: P) -> Self {
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
            let len = std::cmp::min(buf.len(), file.len() - self.read_pos);
            buf[0..len].clone_from_slice(&file.content[self.read_pos..self.read_pos + len]);
            self.read_pos += len;
            Ok(len)
        }
    }
}
