#![warn(rust_2018_idioms, missing_docs)]
//! ipfs-unixfs: UnixFs tree support in Rust.
//!
//! The crate aims to provide a blockstore implementation independent of the UnixFs implementation by
//! working on slices and not doing any IO operations.
//!
//! The main entry point for extracting information and/or data out of UnixFs trees is
//! `ipfs_unixfs::walk::Walker`. To resolve `IpfsPath` segments over dag-pb nodes,
//! `ipfs_unixfs::resolve` should be used.

extern crate alloc;

use alloc::borrow::Cow;
use core::fmt;

/// File support.
pub mod file;

/// Symlink creation support
pub mod symlink;

/// Directory and directory tree support
pub mod dir;
pub use dir::{resolve, LookupError, MaybeResolved, ResolveError};

mod pb;
use pb::{UnixFs, UnixFsType};

/// Support operations for the dag-pb, the outer shell of UnixFS
pub mod dagpb;

/// Support for walking over all UnixFs trees
pub mod walk;

#[cfg(test)]
pub(crate) mod test_support;

/// A link could not be transformed into a Cid.
#[derive(Debug)]
pub struct InvalidCidInLink {
    /// The index of this link, from zero
    pub nth: usize,
    /// Hash which could not be turned into a `Cid`
    pub hash: Cow<'static, [u8]>,
    /// Name of the link, most likely empty when this originates from a file, most likely non-empty
    /// for other kinds.
    pub name: Cow<'static, str>,
    /// Error from the attempted conversion
    pub source: cid::Error,
    /// This is to deny creating these outside of the crate
    hidden: (),
}

impl<'a> From<(usize, pb::PBLink<'a>, cid::Error)> for InvalidCidInLink {
    fn from((nth, link, source): (usize, pb::PBLink<'a>, cid::Error)) -> Self {
        let hash = match link.Hash {
            Some(Cow::Borrowed(x)) if !x.is_empty() => Cow::Owned(x.to_vec()),
            Some(Cow::Borrowed(_)) | None => Cow::Borrowed(&[][..]),
            Some(Cow::Owned(x)) => Cow::Owned(x),
        };

        let name = match link.Name {
            Some(Cow::Borrowed(x)) if !x.is_empty() => Cow::Owned(x.to_string()),
            Some(Cow::Borrowed(_)) | None => Cow::Borrowed(""),
            Some(Cow::Owned(x)) => Cow::Owned(x),
        };

        InvalidCidInLink {
            nth,
            hash,
            name,
            source,
            hidden: (),
        }
    }
}

impl fmt::Display for InvalidCidInLink {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            fmt,
            "failed to convert link #{} ({:?}) to Cid: {}",
            self.nth, self.name, self.source
        )
    }
}

impl std::error::Error for InvalidCidInLink {}

/// Wrapper around the unexpected UnixFs node type, allowing access to querying what is known about
/// the type.
pub struct UnexpectedNodeType(i32);

impl fmt::Debug for UnexpectedNodeType {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        let converted = UnixFsType::from(self.0);
        // the conversion defaults to Raw
        if converted == UnixFsType::Raw && self.0 != 0 {
            write!(fmt, "{} or <unknown>", self.0)
        } else {
            write!(fmt, "{} or {:?}", self.0, converted)
        }
    }
}

impl From<UnixFsType> for UnexpectedNodeType {
    fn from(t: UnixFsType) -> UnexpectedNodeType {
        UnexpectedNodeType(t.into())
    }
}

impl UnexpectedNodeType {
    /// Returns `true` if the type represents some directory
    pub fn is_directory(&self) -> bool {
        matches!(
            UnixFsType::from(self.0),
            UnixFsType::Directory | UnixFsType::HAMTShard
        )
    }

    /// Returns `true` if the type represents a `File`
    pub fn is_file(&self) -> bool {
        matches!(UnixFsType::from(self.0), UnixFsType::File)
    }
}

/// A container for the UnixFs metadata, which can be present at the root of the file, directory, or symlink trees.
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct Metadata {
    mode: Option<u32>,
    mtime: Option<(i64, u32)>,
}

impl Metadata {
    /// Returns the full file mode, if one has been specified.
    ///
    /// The full file mode is originally read through `st_mode` field of `stat` struct defined in
    /// `sys/stat.h` and its defining OpenGroup standard. The lowest 3 bytes correspond to read,
    /// write, and execute rights per user, group, and other, while the 4th byte determines sticky bits,
    /// set user id or set group id. The following two bytes correspond to the different file types, as
    /// defined by the same OpenGroup standard:
    /// https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/sys_stat.h.html
    pub fn mode(&self) -> Option<u32> {
        self.mode
    }

    /// Returns the raw timestamp of last modification time, if specified.
    ///
    /// The timestamp is `(seconds, nanos)` - similar to `core::time::Duration`, with the exception of
    /// allowing seconds to be negative. The seconds are calculated from `1970-01-01 00:00:00` or
    /// the common "unix epoch".
    pub fn mtime(&self) -> Option<(i64, u32)> {
        self.mtime
    }

    /// Returns the mtime metadata as a `FileTime`. Enabled only in the `filetime` feature.
    #[cfg(feature = "filetime")]
    pub fn mtime_as_filetime(&self) -> Option<filetime::FileTime> {
        self.mtime()
            .map(|(seconds, nanos)| filetime::FileTime::from_unix_time(seconds, nanos))
    }
}

impl<'a> From<&'a UnixFs<'_>> for Metadata {
    fn from(data: &'a UnixFs<'_>) -> Self {
        let mode = data.mode;
        let mtime = data
            .mtime
            .clone()
            .map(|ut| (ut.Seconds, ut.FractionalNanoseconds.unwrap_or(0)));

        Metadata { mode, mtime }
    }
}
