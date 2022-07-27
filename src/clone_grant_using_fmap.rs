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

#[derive(Debug, Eq, PartialEq)]
struct Perms { r: bool, w: bool, x: bool, b: bool }
#[derive(Debug, Eq, PartialEq)]
struct Mapping {
    addr: usize,
    len: usize,
    offset: usize,
    perms: Perms,
}
fn read_addr_space() -> Result<Box<[Mapping]>, String> {
    use std::fs::File;
    use std::io::{BufReader, prelude::*};

    let mut mappings = Vec::new();

    let mut buf = vec! [0_u8; 4096];
    let mut file = File::open("thisproc:current/addrspace").map_err(|err| format!("failed to open current address space: {}", err))?;

    loop {
        const RECORD_SIZE: usize = 4 * std::mem::size_of::<usize>();
        let read = file.read(&mut buf).map_err(|err| format!("failed to read from address space: {}", err))? / RECORD_SIZE;

        for chunks in buf[..read].array_chunks::<RECORD_SIZE>() {
            let mut nums = chunks.array_chunks::<{std::mem::size_of::<usize>()}>().copied().map(usize::from_ne_bytes);

            mappings.push(Mapping {
                addr: nums.next().unwrap(),
                len: nums.next().unwrap(),
                perms: {
                    let raw = nums.next().unwrap();
                    let flags = MapFlags::from_bits(raw & !0x8000_0000).unwrap();

                    Perms {
                        r: true,
                        w: flags.contains(MapFlags::PROT_WRITE),
                        x: flags.contains(MapFlags::PROT_EXEC),
                        b: raw & 0x8000_0000 != 0,
                    }
                },
                offset: nums.next().unwrap(),
            });
        }

        if read < buf.len() { break }
    }

    Ok(mappings.into_boxed_slice())
}

// Exec is harder and more unreliable to check, but kernel debug looks good enough for now.
pub fn check_clone_leak() -> Result<(), String> {
    // TODO: Check sigaction?

    let prev_addr_space = read_addr_space()?;

    let prev_number = syscall::open("memory:", 0).map_err(|_| format!("failed to open dummy file descriptor 1st time"))?;
    let _ = syscall::close(prev_number);

    unsafe { libc::fork(); }

    let next_addr_space = read_addr_space()?;

    let next_number = syscall::open("memory:", 0).map_err(|_| format!("failed to open dummy file descriptor 2nd time"))?;
    let _ = syscall::close(next_number);

    assert_eq!(prev_number, next_number, "file descriptor leak");
    assert_eq!(prev_addr_space, next_addr_space);

    Ok(())
}
