use std::io::Read;
use std::os::fd::{FromRawFd, RawFd};

use syscall::CallerCtx;
use syscall::error::{Error, Result};
use syscall::error::{EINVAL, ENOENT};
use syscall::flag::{O_RDWR, O_CLOEXEC};
use syscall::scheme::{OpenResult, SchemeMut};

pub fn cross_scheme_link() -> anyhow::Result<()> {
    inner().unwrap();
    Ok(())
}
struct RedirectScheme;

impl SchemeMut for RedirectScheme {
    fn xopen(&mut self, path: &str, flags: usize, _ctx: &CallerCtx) -> Result<OpenResult> {
        syscall::open(path, flags | O_CLOEXEC).map(|fd| OpenResult::OtherScheme { fd })
    }
}
struct DupScheme;
impl SchemeMut for DupScheme {
    fn open(&mut self, path: &str, _flags: usize, _uid: u32, _gid: u32) -> Result<usize> {
        if !path.is_empty() {
            return Err(Error::new(ENOENT));
        }
        Ok(0)
    }
    fn xdup(&mut self, _old_id: usize, buf: &[u8], _ctx: &CallerCtx) -> Result<OpenResult> {
        syscall::open(std::str::from_utf8(buf).map_err(|_| Error::new(EINVAL))?, O_RDWR).map(|fd| OpenResult::OtherScheme { fd })
    }
    fn close(&mut self, _id: usize) -> Result<usize> {
        Ok(0)
    }
}

fn inner() -> Result<()> {
    println!("Testing cross scheme links");
    crate::daemon::scheme("cross_scheme_link_redirect", "redirect", RedirectScheme).unwrap();
    crate::daemon::scheme("cross_scheme_link_dup", "dup", DupScheme).unwrap();
    println!("Started scheme daemons");

    // Open an event queue through the redirect scheme. Unless the kernel is trying to trick us by
    // renaming `event:`, it will never work without cross scheme links;

    let path = "file:/tmp/cross_scheme_link.tmp";
    let data = "some data";

    std::fs::write(path, data).unwrap();

    let mut file2 = unsafe { std::fs::File::from_raw_fd(syscall::open(format!("redirect:{path}"), O_RDWR | O_CLOEXEC)? as RawFd) };
    let mut file3 = unsafe {
        let dup_handle = syscall::open("dup:", O_CLOEXEC)?;
        let fd = syscall::dup(dup_handle, path.as_bytes())?;
        let _ = syscall::close(dup_handle);
        std::fs::File::from_raw_fd(fd as RawFd)
    };
    let mut buf1 = String::new();
    let mut buf2 = String::new();
    file2.read_to_string(&mut buf1).unwrap();
    file3.read_to_string(&mut buf2).unwrap();

    assert_eq!(buf1, data);
    assert_eq!(buf2, data);

    let _ = syscall::unlink(":redirect");
    let _ = syscall::unlink(":dup");

    Ok(())
}
