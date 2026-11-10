//! [`Glob`] paths provider.

use std::{
    io,
    path::{Path, PathBuf},
};

pub use glob::MatchOptions;
use glob::Pattern;

use super::PathsProvider;
use crate::{FileSourceInternalEvents, SymlinkPolicy};

/// A glob-based path provider.
///
/// Provides the paths to the files on the file system that match include
/// patterns and don't match the exclude patterns.
pub struct Glob<E: FileSourceInternalEvents> {
    include_patterns: Vec<String>,
    exclude_patterns: Vec<Pattern>,
    glob_match_options: MatchOptions,
    symlink_policy: SymlinkPolicy,
    emitter: E,
}

impl<E: FileSourceInternalEvents> Glob<E> {
    /// Create a new [`Glob`].
    ///
    /// Returns `None` if patterns aren't valid.
    pub fn new(
        include_patterns: &[PathBuf],
        exclude_patterns: &[PathBuf],
        glob_match_options: MatchOptions,
        symlink_policy: SymlinkPolicy,
        emitter: E,
    ) -> Option<Self> {
        let include_patterns = include_patterns
            .iter()
            .map(|path| path.to_str().map(ToOwned::to_owned))
            .collect::<Option<_>>()?;

        let exclude_patterns = exclude_patterns
            .iter()
            .filter_map(|path| path.to_str().map(|path| Pattern::new(path).ok()))
            .collect::<Option<Vec<_>>>()?;

        Some(Self {
            include_patterns,
            exclude_patterns,
            glob_match_options,
            symlink_policy,
            emitter,
        })
    }
}

impl<E: FileSourceInternalEvents> Glob<E> {
    // Returns false (and reports) when the symlink policy rejects the path.
    fn allowed_by_policy(&self, include_pattern: &str, path: &Path) -> bool {
        let result = match self.symlink_policy {
            SymlinkPolicy::Follow => return true,
            SymlinkPolicy::Deny => deny_symlink(path),
            SymlinkPolicy::WithinRoot => within_root(include_pattern, path),
        };
        match result {
            Ok(()) => true,
            Err(error) => {
                self.emitter.emit_path_globbing_failed(path, &error);
                false
            }
        }
    }
}

fn deny_symlink(path: &Path) -> io::Result<()> {
    if std::fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(io::Error::other("symbolic links are not allowed"));
    }
    Ok(())
}

// Literal directory prefix of a glob pattern (components before the first wildcard).
fn literal_root(pattern: &str) -> PathBuf {
    let path = Path::new(pattern);
    let mut root = PathBuf::new();
    for component in path.components() {
        if component
            .as_os_str()
            .to_string_lossy()
            .contains(['*', '?', '['])
        {
            return root;
        }
        root.push(component);
    }
    // No wildcard: the pattern is a file, so its directory is the root.
    root.parent().map(Path::to_path_buf).unwrap_or(root)
}

fn within_root(include_pattern: &str, path: &Path) -> io::Result<()> {
    let root = literal_root(include_pattern);
    let root = if root.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        root
    }
    .canonicalize()?;
    if path.canonicalize()?.starts_with(&root) {
        Ok(())
    } else {
        Err(io::Error::other("path resolves outside the include root"))
    }
}

impl<E: FileSourceInternalEvents> PathsProvider for Glob<E> {
    type IntoIter = Vec<PathBuf>;

    fn paths(&self) -> Self::IntoIter {
        self.include_patterns
            .iter()
            .flat_map(|include_pattern| {
                glob::glob_with(include_pattern.as_str(), self.glob_match_options)
                    .expect("failed to read glob pattern")
                    .filter_map(|val| {
                        val.map_err(|error| {
                            self.emitter
                                .emit_path_globbing_failed(error.path(), error.error())
                        })
                        .ok()
                    })
                    .filter(move |path| self.allowed_by_policy(include_pattern, path))
            })
            .filter(|candidate_path: &PathBuf| -> bool {
                !self.exclude_patterns.iter().any(|exclude_pattern| {
                    let candidate_path_str = candidate_path.to_str().unwrap();
                    exclude_pattern.matches(candidate_path_str)
                })
            })
            .collect()
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::{os::unix::fs::symlink, time::Duration};

    use super::*;

    #[derive(Clone)]
    struct NoopEmitter;

    impl FileSourceInternalEvents for NoopEmitter {
        fn emit_file_added(&self, _: &Path) {}
        fn emit_file_resumed(&self, _: &Path, _: u64) {}
        fn emit_file_watch_error(&self, _: &Path, _: io::Error) {}
        fn emit_file_unwatched(&self, _: &Path, _: bool) {}
        fn emit_file_deleted(&self, _: &Path) {}
        fn emit_file_delete_error(&self, _: &Path, _: io::Error) {}
        fn emit_file_fingerprint_read_error(&self, _: &Path, _: io::Error) {}
        fn emit_file_checkpointed(&self, _: usize, _: Duration) {}
        fn emit_file_checksum_failed(&self, _: &Path) {}
        fn emit_file_checkpoint_write_error(&self, _: io::Error) {}
        fn emit_files_open(&self, _: usize) {}
        fn emit_path_globbing_failed(&self, _: &Path, _: &io::Error) {}
    }

    // root/real.log, root/in.log -> real.log, root/out.log -> outside secret.
    fn setup() -> (tempfile::TempDir, tempfile::TempDir, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let secret = outside.path().join("secret");
        std::fs::write(&secret, "s").unwrap();
        std::fs::write(root.path().join("real.log"), "r").unwrap();
        symlink(root.path().join("real.log"), root.path().join("in.log")).unwrap();
        symlink(&secret, root.path().join("out.log")).unwrap();
        (root, outside, secret)
    }

    fn names(root: &Path, policy: SymlinkPolicy) -> Vec<String> {
        let glob = Glob::new(
            &[root.join("*.log")],
            &[],
            MatchOptions::default(),
            policy,
            NoopEmitter,
        )
        .unwrap();
        let mut names: Vec<_> = glob
            .paths()
            .into_iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn follow_returns_all() {
        let (root, _outside, _) = setup();
        assert_eq!(
            names(root.path(), SymlinkPolicy::Follow),
            ["in.log", "out.log", "real.log"]
        );
    }

    #[test]
    fn deny_drops_symlinks() {
        let (root, _outside, _) = setup();
        assert_eq!(names(root.path(), SymlinkPolicy::Deny), ["real.log"]);
    }

    #[test]
    fn within_root_drops_only_escaping_symlinks() {
        let (root, _outside, _) = setup();
        assert_eq!(
            names(root.path(), SymlinkPolicy::WithinRoot),
            ["in.log", "real.log"]
        );
    }
}
