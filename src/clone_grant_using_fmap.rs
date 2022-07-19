// TODO: This is no longer implemented by the kernel. Should it be moved to resist?

use syscall::data::{Map, Packet};
use syscall::error::{Error, Result, EFAULT, EINVAL};
use syscall::flag::{CloneFlags, MapFlags, O_CREAT, O_RDONLY, O_RDWR, O_CLOEXEC, WaitFlags};
use syscall::scheme::SchemeMut;

// Start of code copied from syscall.
use std::convert::Infallible;

use syscall::{
    clone,
    close,
    EIO,
    exit,
    pipe2,
    read,
    write,
};

#[must_use = "Daemon::ready must be called"]
pub struct Daemon {
    write_pipe: usize,
}

impl Daemon {
    pub fn new<F: FnOnce(Daemon) -> Infallible>(f: F) -> Result<u8> {
        let mut pipes = [0; 2];
        pipe2(&mut pipes, 0)?;

        let [read_pipe, write_pipe] = pipes;

        let result = unsafe { libc::fork() };

        if result == 0 {
            let _ = close(read_pipe);

            f(Daemon {
                write_pipe,
            });
            // TODO: Replace Infallible with the never type once it is stabilized.
            unreachable!();
        } else if result > 0 {
            let _ = close(write_pipe);

            let mut data = [0];
            let res = read(read_pipe, &mut data);
            let _ = close(read_pipe);

            if res? == 1 {
                //exit(data[0] as usize)?;
                //unreachable!();
                Ok(data[0])
            } else {
                Err(Error::new(EIO))
            }
        } else {
            return Err(Error::new(std::io::Error::last_os_error().raw_os_error().unwrap_or(EINVAL)));
        }
    }

    pub fn ready(self) -> Result<()> {
        let res = write(self.write_pipe, &[0]);
        let _ = close(self.write_pipe);

        if res? == 1 {
            Ok(())
        } else {
            Err(Error::new(EIO))
        }
    }
}

// End of code copied from syscall

struct TestScheme(bool);

impl SchemeMut for TestScheme {
    fn open(&mut self, _path: &str, _flags: usize, _uid: u32, _gid: u32) -> Result<usize> { Ok(0) }
    fn close(&mut self, _id: usize) -> Result<usize> { Ok(0) }
    fn fmap(&mut self, id: usize, map: &Map) -> Result<usize> {
        if map.size != PAGE_SIZE { return Err(Error::new(EINVAL)); }

        let addr = unsafe { syscall::fmap(!0, &Map { offset: 0, size: PAGE_SIZE, flags: MapFlags::MAP_SHARED | MapFlags::PROT_WRITE, address: 0 })? };
        if self.0 { unsafe { (addr as *mut u8).write(42); } }

        Ok(addr)
    }
}

const SCHEME_NAME: &str = "acid_clone_grant_using_fmap";
const PAGE_SIZE: usize = 4096;

fn inner(readonly: bool) -> Result<()> {
    println!("Testing - {}", if readonly { "readonly" } else { "writable" });
    Daemon::new(move |daemon: Daemon| -> std::convert::Infallible {
        let e = |r| {
            match r {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("error in clone_grant_using_fmap daemon: {}", e);
                    std::process::exit(1);
                }
            }
        };

        let socket = e(syscall::open(format!(":{}{}", SCHEME_NAME, readonly), O_CREAT | O_RDWR | O_CLOEXEC));

        daemon.ready();

        let mut packet = Packet::default();
        let mut scheme = TestScheme(readonly);

        loop {
            if e(syscall::read(socket, &mut packet)) == 0 { break };
            scheme.handle(&mut packet);
            if e(syscall::write(socket, &packet)) == 0 { break }
        }
        let _ = syscall::close(socket);

        std::process::exit(0);
    })?;
    println!("Started scheme daemon");
    let fd = syscall::open(format!("{}{}:", SCHEME_NAME, readonly), O_CLOEXEC | O_RDONLY)?;

    let ptr = unsafe { syscall::fmap(fd, &Map { offset: 0, size: PAGE_SIZE, flags: MapFlags::MAP_PRIVATE | MapFlags::PROT_READ | MapFlags::PROT_WRITE, address: 0 })? as *mut u8 };

    println!("Obtained pointer {:p}", ptr);

    // TODO: Prevent optimizations which may cancel out this type of checking. Volatile will most
    // likely be adequate.

    if !readonly {
        unsafe {
            ptr.write_volatile(0x42);
        }
    }

    let pid;
    unsafe {
        pid = libc::fork() as usize;

        assert_ne!(pid, (-1_isize) as usize);

        println!("Fork was successful, for the {} process", if pid == 0 { "child" } else { "parent" });

        if pid == 0 {
            println!("Child process: checking...");

            // We are the child process. Hopefully relibc copied the grant properly and without
            // aliasing.
            if readonly {
                assert_eq!(ptr.read_volatile(), 42);
            } else {
                assert_eq!(ptr.read_volatile(), 0);
                ptr.write_volatile(0x43);
                assert_eq!(ptr.read_volatile(), 0x43);
            }
            println!("Child process: obtained correct page");
            std::process::exit(0);
        }
    }

    println!("Waiting...");
    syscall::waitpid(pid, &mut 0, WaitFlags::empty())?;

    unsafe { assert_eq!(ptr.read_volatile(), if readonly { 42 } else { 0x42 }); }

    println!("It worked!");

    let _ = unsafe { syscall::funmap(ptr as usize, PAGE_SIZE) };

    syscall::unlink(format!(":{}{}", SCHEME_NAME, readonly))?;

    Ok(())
}

pub fn clone_grant_using_fmap() -> Result<(), String> {
    inner(false).map_err(|e| e.to_string())?;
    inner(true).map_err(|e| e.to_string())?;
    Ok(())
}
