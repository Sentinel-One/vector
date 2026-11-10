#![deny(warnings)]
#![deny(clippy::all)]

#[macro_use]
extern crate scan_fmt;

pub mod buffer;
mod checkpointer;
mod file_server;
mod file_watcher;
mod fingerprinter;
mod internal_events;
mod metadata_ext;
pub mod paths_provider;

pub use self::{
    checkpointer::{Checkpointer, CheckpointsView, CHECKPOINT_FILE_NAME},
    file_server::{calculate_ignore_before, FileServer, Line, Shutdown as FileServerShutdown},
    fingerprinter::{FileFingerprint, FingerprintStrategy, Fingerprinter},
    internal_events::FileSourceInternalEvents,
};
use std::{fs::File, io, path::Path};

use vector_config::configurable_component;

pub type FilePosition = u64;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum ReadFrom {
    #[default]
    Beginning,
    End,
    Checkpoint(FilePosition),
}

/// File position to use when reading a new file.
#[configurable_component]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReadFromConfig {
    /// Read from the beginning of the file.
    Beginning,

    /// Start reading from the current end of the file.
    End,
}

impl From<ReadFromConfig> for ReadFrom {
    fn from(rfc: ReadFromConfig) -> Self {
        match rfc {
            ReadFromConfig::Beginning => ReadFrom::Beginning,
            ReadFromConfig::End => ReadFrom::End,
        }
    }
}

/// How the file source treats symbolic links.
#[configurable_component]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SymlinkPolicy {
    /// Follow symbolic links.
    #[default]
    Follow,

    /// Skip symbolic links and never open a file through one.
    Deny,

    /// Follow symbolic links only if the real path stays inside the literal directory prefix of the include pattern that matched.
    WithinRoot,
}

impl SymlinkPolicy {
    /// Opens `path` for reading, honoring the policy.
    pub(crate) fn open(self, path: &Path) -> io::Result<File> {
        match self {
            Self::Follow => File::open(path),
            Self::Deny => open_nofollow(path),
            // Open the resolved path so a legit in-root symlink still works.
            Self::WithinRoot => open_nofollow(&path.canonicalize()?),
        }
    }
}

#[cfg(unix)]
fn open_nofollow(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
fn open_nofollow(path: &Path) -> io::Result<File> {
    if std::fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(io::Error::other("symbolic links are not allowed"));
    }
    File::open(path)
}

#[cfg(test)]
mod symlink_tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn open_policies() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real.log");
        std::fs::write(&target, "x").unwrap();
        let link = dir.path().join("link.log");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        assert!(SymlinkPolicy::Follow.open(&link).is_ok());
        assert!(SymlinkPolicy::Deny.open(&link).is_err());
        assert!(SymlinkPolicy::Deny.open(&target).is_ok());
        assert!(SymlinkPolicy::WithinRoot.open(&link).is_ok());
    }
}
