use crate::io;
use crate::path::Path;

/// Creates a new symbolic link on the filesystem.
///
/// The `link` path will be a symbolic link pointing to the `original` path.
#[stable(feature = "toyos_ext", since = "1.0.0")]
pub fn symlink<P: AsRef<Path>, Q: AsRef<Path>>(original: P, link: Q) -> io::Result<()> {
    crate::sys::fs::symlink(original.as_ref(), link.as_ref())
}

/// Resolve this process's files through `namespace`, a namespace handle it
/// owns and gives up here.
///
/// For the one process no parent endows a namespace: init builds the machine's
/// directory capabilities itself. Refused, and the handle closed, when this
/// process already resolves through one.
#[stable(feature = "toyos_ext", since = "1.0.0")]
pub fn adopt_namespace(namespace: u32) -> io::Result<()> {
    // SAFETY: the caller gives up a namespace handle it owns.
    let ns = unsafe { toyos::namespace::Namespace::from_raw(toyos_abi::RawHandle(namespace)) };
    toyos::endow::adopt_namespace(ns)
        .map_err(|_| io::const_error!(io::ErrorKind::AlreadyExists, "this process already has a namespace"))
}
