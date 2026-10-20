//! The private files of the store: their creation, atomic replacement, and removal.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

use crate::error::{Error, Result};

/// Builds an error mapper that keeps an I/O source under `context`.
pub(super) fn io_error(context: String) -> impl FnOnce(io::Error) -> Error {
    move |error| Error::io(context).with_source(error)
}

/// Returns options that create a file readable only by the current user (mode 0600 on Unix)
/// and that open no link that its path names on Unix.
pub(super) fn private_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options
            .mode(0o600)
            .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits());
    }
    options
}

/// Creates the file at `path`, which must not exist, readable only by the current user.
pub(super) fn create_new(path: &Path) -> io::Result<File> {
    private_options().create_new(true).open(path)
}

/// Atomically replaces `path` with `contents`, readable only by the current user.
///
/// The contents go to a fresh temporary file beside `path`, which is flushed to disk and then
/// renamed over it, so a reader sees the old contents or the new ones, and a crash leaves at most
/// the temporary file.
pub(super) fn write_private(path: &Path, contents: &[u8]) -> Result<()> {
    let mut suffix = [0u8; 8];
    getrandom::fill(&mut suffix)
        .map_err(|error| Error::other("cannot name a temporary file").with_source(error))?;
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let temporary = path.with_file_name(format!(".{name}.{}.tmp", u64::from_le_bytes(suffix)));
    let written = (|| -> io::Result<()> {
        let mut file = create_new(&temporary)?;
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)
    })();
    if written.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    written.map_err(io_error(format!("cannot write {}", path.display())))
}

/// Removes the file at `path` if it exists.
pub(super) fn remove_if_present(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => {
            Err(io_error(format!("cannot remove {}", path.display()))(error))
        }
        _ => Ok(()),
    }
}
