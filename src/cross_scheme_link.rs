use syscall::CallerCtx;
use syscall::data::Event;
use syscall::error::{Error, Result};
use syscall::error::{EINVAL, ENOENT};
use syscall::flag::{EventFlags, O_RDWR, O_CLOEXEC};
use syscall::scheme::{OpenResult, SchemeMut};

pub fn cross_scheme_link() -> Result<(), String> {
    inner().map_err(|e| e.to_string())
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

fn test_event_queue(eq: usize) -> Result<()> {
    let mut fds = [0_usize; 2];
    syscall::pipe2(&mut fds, O_CLOEXEC)?;
    let [read, write] = fds;

    let event = Event {
        id: read,
        flags: EventFlags::EVENT_READ,
        data: 0,
    };
    syscall::write(eq, &event).unwrap();

    syscall::write(write, b"(unused)")?;

    let mut read_event = Event::default();
    syscall::read(eq, &mut read_event)?;
    assert_eq!(read_event.id, event.id);
    assert_eq!(read_event.flags, event.flags);
    assert_eq!(read_event.data, event.data);

    Ok(())
}

fn inner() -> Result<()> {
    println!("Testing cross scheme links");
    crate::daemon::scheme("cross_scheme_link_redirect", "redirect", RedirectScheme).unwrap();
    crate::daemon::scheme("cross_scheme_link_dup", "dup", DupScheme).unwrap();
    println!("Started scheme daemons");

    // Open an event queue through the redirect scheme. Unless the kernel is trying to trick us by
    // renaming `event:`, it will never work without cross scheme links;

    let eq1 = syscall::open("redirect:event:", O_RDWR | O_CLOEXEC)?;
    let eq2 = {
        let dup_handle = syscall::open("dup:", O_CLOEXEC)?;
        let queue = syscall::dup(dup_handle, b"event:")?;
        let _ = syscall::close(dup_handle);
        queue
    };

    test_event_queue(eq1).unwrap();
    test_event_queue(eq2).unwrap();

    let _ = syscall::unlink(":redirect");
    let _ = syscall::unlink(":dup");

    Ok(())
}
