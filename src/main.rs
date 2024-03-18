//!Acid testing program
#![feature(array_chunks, asm_const, core_intrinsics, thread_local)]

use std::{env, process};
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::Hasher;
use std::os::unix::thread::JoinHandleExt;
use std::sync::Barrier;
use std::thread;
use std::time::{Duration, Instant};
use std::sync::atomic::{AtomicUsize, Ordering, compiler_fence};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::fd::{IntoRawFd, FromRawFd, RawFd, AsRawFd};
use std::process::Command;
use std::net::TcpStream;

use syscall::{O_CLOEXEC, Map, MapFlags, ADDRSPACE_OP_MMAP, ADDRSPACE_OP_MUNMAP};
use syscall::O_RDONLY;
use syscall::PAGE_SIZE;

use anyhow::{bail, Result};

mod cross_scheme_link;
mod daemon;
mod scheme_data_leak;
mod relibc_leak;
mod eintr;
mod syscall_bench;

#[cfg(target_arch = "x86_64")]
fn avx2_test() -> Result<()> {
    let mut a: [u8; 32] = [0x41; 32];
    let mut b: [u8; 32] = [0x42; 32];
    unsafe {
        core::arch::asm!("
            vpxor ymm0, ymm0, ymm0
            vpcmpeqb ymm1, ymm1, ymm1

            mov eax, {SYS_YIELD}
            syscall

            vmovdqu [r12], ymm0
            vmovdqu [r13], ymm1
        ", in("r12") a.as_mut_ptr(), in("r13") b.as_mut_ptr(), out("ymm0") _, out("ymm1") _, SYS_YIELD = const syscall::SYS_YIELD);
    }
    assert_eq!(a, [0x00; 32]);
    assert_eq!(b, [0xff; 32]);
    Ok(())
}

fn create_test() -> Result<()> {
    use std::fs;
    use std::io::{self, Read};
    use std::path::PathBuf;

    let mut test_dir = PathBuf::new();
    test_dir.push("test_dir");

    let mut test_file = test_dir.clone();
    test_file.push("test_file");
    let test_file_err = fs::File::create(&test_file).err().map(|err| err.kind());
    if test_file_err != Some(io::ErrorKind::NotFound) {
        bail!("Incorrect open error: {:?}, should be NotFound", test_file_err);
    }

    fs::create_dir(&test_dir)?;

    let test_data = "Test data";
    {
        let mut file = fs::File::create(&test_file)?;
        file.write(test_data.as_bytes())?;
    }

    {
        let mut file = fs::File::open(&test_file)?;
        let mut buffer: Vec<u8> = Vec::new();
        file.read_to_end(&mut buffer)?;
        assert_eq!(buffer.len(), test_data.len());
        for (&a, b) in buffer.iter().zip(test_data.bytes()) {
            if a != b {
                bail!("{} did not contain the correct data", test_file.display());
            }
        }
    }

    Ok(())
}
fn clone_grant_using_fmap_test() -> Result<()> {
    clone_grant_using_fmap_test_inner(false)
}
fn clone_grant_using_fmap_lazy_test() -> Result<()> {
    clone_grant_using_fmap_test_inner(true)
}

fn test_shared_ref(shared_ref: &AtomicUsize) {
    let mut fds = [0 as libc::c_int; 2];
    assert!(unsafe { libc::pipe(fds.as_mut_ptr()) } >= 0);
    let read_fd1 = fds[0] as usize;
    let write_fd1 = fds[1] as usize;

    assert!(unsafe { libc::pipe(fds.as_mut_ptr()) } >= 0);
    let read_fd2 = fds[0] as usize;
    let write_fd2 = fds[1] as usize;

    let fork_res = unsafe { libc::fork() };
    assert!(fork_res >= 0);

    if fork_res == 0 {
        shared_ref.store(0xDEADBEEF, Ordering::SeqCst);
        let _ = syscall::write(write_fd1, &[0]).unwrap();
        let _ = syscall::read(read_fd2, &mut [0]).unwrap();
        assert_eq!(shared_ref.load(Ordering::SeqCst), 2);
    } else {
        let _ = syscall::read(read_fd1, &mut [0]).unwrap();
        assert_eq!(shared_ref.compare_exchange(0xDEADBEEF, 2, Ordering::SeqCst, Ordering::SeqCst), Ok(0xDEADBEEF));
        let _ = syscall::write(write_fd2, &[0]).unwrap();
    }
}

fn clone_grant_using_fmap_test_inner(lazy: bool) -> Result<()> {
    let lazy_flag = if lazy { MapFlags::MAP_LAZY } else { MapFlags::empty() };

    let mem = syscall::open("shm:clone_grant_using_fmap_test", O_CLOEXEC).unwrap();
    let base_ptr = unsafe { syscall::fmap(mem, &Map { address: 0, size: PAGE_SIZE, flags: MapFlags::PROT_READ | MapFlags::PROT_WRITE | MapFlags::MAP_SHARED | lazy_flag, offset: 0 }).unwrap() };
    let shared_ref: &'static AtomicUsize = unsafe { &*(base_ptr as *const AtomicUsize) };

    test_shared_ref(shared_ref);

    Ok(())
}

fn redoxfs_range_bookkeeping() -> Result<()> {
    // Number of pages
    const P: usize = 128;

    let mut chunks = vec! [false; P];

    // Number of operations
    const N: usize = 10000;

    let file = OpenOptions::new().create(true).write(true).read(true).open("tmp").unwrap();
    file.set_len((P * PAGE_SIZE) as u64).unwrap();
    let fd = file.into_raw_fd() as usize;

    println!("Created file");

    fn rand() -> usize {
        let ret: usize;
        unsafe { core::arch::asm!("rdrand {}", out(reg) ret); }
        ret
    }

    for _ in 0..N {
        let n = rand();
        let insert_not_remove = n & (1 << (usize::BITS - 1)) != 0;
        let idx = n % P;

        if insert_not_remove {
            let Some((first_unused, _)) = chunks.iter().copied().enumerate().filter(|&(_, c)| !c).nth(idx) else {
                continue;
            };
            chunks[first_unused] = true;

            println!("INS {}", first_unused);

            unsafe {
                let _ = syscall::fmap(fd, &Map {
                    address: 0xDEADB000 + first_unused * PAGE_SIZE,
                    offset: first_unused * PAGE_SIZE,
                    flags: MapFlags::PROT_READ | MapFlags::PROT_WRITE | MapFlags::MAP_SHARED | MapFlags::MAP_FIXED,
                    size: PAGE_SIZE,
                }).expect("failed to fmap");
            }
        } else {
            let Some((first_used, _)) = chunks.iter().copied().enumerate().filter(|&(_, c)| c).nth(idx) else {
                continue;
            };
            chunks[first_used] = false;

            println!("REM {}", first_used);

            unsafe {
                syscall::funmap(0xDEADB000 + first_used * PAGE_SIZE, PAGE_SIZE).expect("failed to funmap");
            }
        }
    }

    Ok(())
}

fn file_mmap_test() -> Result<()> {
    let file = OpenOptions::new().read(true).write(true).create(true).open("acid_tmp_file").unwrap();
    let fd = file.into_raw_fd() as usize;

    let buf = unsafe {
        let ptr = syscall::fmap(fd, &Map { address: 0, size: 16384 + 127, flags: MapFlags::PROT_READ | MapFlags::PROT_WRITE | MapFlags::MAP_SHARED, offset: 0 }).unwrap();
        core::slice::from_raw_parts_mut(ptr as *mut u8, 16384 + 127)
    };
    let buf2 = unsafe {
        let ptr = syscall::fmap(fd, &Map { address: 0, size: 1337, flags: MapFlags::PROT_READ | MapFlags::PROT_WRITE | MapFlags::MAP_SHARED, offset: 3 * 4096 }).unwrap();
        core::slice::from_raw_parts_mut(ptr as *mut u8, 1337)
    };

    for (i, byte) in buf.iter_mut().enumerate() {
        *byte = i as u8;
    }
    for (i, byte) in buf2.iter_mut().enumerate() {
        *byte = (i as u8).wrapping_mul(57);
    }

    let functions: [unsafe fn(&mut [u8]) -> (); 3] = [
        |buf| unsafe {
            let buf = &mut buf[12288..];
            syscall::funmap(buf.as_mut_ptr() as usize, buf.len()).unwrap();
        },
        |buf| unsafe {
            let buf = &mut buf[..8192];
            syscall::funmap(buf.as_mut_ptr() as usize, buf.len()).unwrap();
        },
        |buf| unsafe {
            let buf = &mut buf[8192..][..4096];
            syscall::funmap(buf.as_mut_ptr() as usize, buf.len()).unwrap();
        },
    ];

    // TODO: Run the test repeatedly in a different order each time.
    let order = [2, 1, 0];
    unsafe {
        let [i, j, k] = order;
        dbg!(i, j, k);
        functions[i](buf);
        functions[j](buf);
        functions[k](buf);
    }


    let parent_memory = File::open("thisproc:current/addrspace").unwrap();

    unsafe {
        let mut pipes1 = [0; 2];
        let mut pipes2 = [0; 2];
        assert_eq!(libc::pipe(pipes1.as_mut_ptr()), 0);
        assert_eq!(libc::pipe(pipes2.as_mut_ptr()), 0);

        let child = libc::fork();
        assert_ne!(child, -1);

        if child == 0 {
            let mut child_memory = File::open("thisproc:current/addrspace").unwrap();

            let words = [
                ADDRSPACE_OP_MMAP,
                parent_memory.as_raw_fd() as usize,
                buf2.as_ptr() as usize,
                0xDEADB000,
                4096,
                (MapFlags::PROT_READ | MapFlags::PROT_WRITE | MapFlags::MAP_FIXED_NOREPLACE).bits(),
            ];

            dbg!();
            child_memory.write(core::slice::from_raw_parts(words.as_ptr().cast(), words.len() * core::mem::size_of::<usize>())).unwrap();
            dbg!();

            let _ = syscall::write(pipes1[1] as usize, &[1]).unwrap();
            dbg!();

            let words = [
                ADDRSPACE_OP_MUNMAP,
                0xDEADB000,
                4096,
            ];
            child_memory.write(core::slice::from_raw_parts(words.as_ptr().cast(), words.len() * core::mem::size_of::<usize>())).unwrap();

            let _ = syscall::write(pipes2[1] as usize, &[1]).unwrap();
            dbg!();

            std::process::exit(0);
        } else {
            dbg!();
            let _ = syscall::read(pipes1[0] as usize, &mut [0]).unwrap();
            assert_eq!(syscall::funmap(buf2.as_ptr() as usize, 4096), Err(syscall::Error::new(syscall::EBUSY)));
            dbg!();
            let _ = syscall::read(pipes2[0] as usize, &mut [0]).unwrap();
            assert_eq!(syscall::funmap(buf2.as_ptr() as usize, 4096), Ok(0));
            dbg!();
        }
    }

    drop(unsafe { File::from_raw_fd(fd as RawFd) });

    let data = std::fs::read("acid_tmp_file").unwrap();
    for (i, byte) in data.iter().enumerate().skip(4096).take(4096) {
        assert_eq!(i % 256, usize::from(*byte));
    }

    std::fs::remove_file("acid_tmp_file").unwrap();

    Ok(())
}

fn anonymous_map_shared() -> Result<()> {
    let base_ptr = unsafe { syscall::fmap(!0, &Map { address: 0, size: PAGE_SIZE, flags: MapFlags::PROT_READ | MapFlags::PROT_WRITE | MapFlags::MAP_SHARED, offset: 0 }).unwrap() };
    let shared_ref: &'static AtomicUsize = unsafe { &*(base_ptr as *const AtomicUsize) };

    test_shared_ref(shared_ref);

    Ok(())
}

#[cfg(target_arch = "x86_64")]
fn direction_flag_interrupt_test() -> Result<()> {
    let thread = std::thread::spawn(|| {
        unsafe {
            core::arch::asm!("
                std
            2:
                pause
                jmp 2b
            ", options(noreturn));
        }
    });

    std::thread::sleep(Duration::from_secs(1));

    let pthread: libc::pthread_t = thread.into_pthread_t();

    unsafe {
        assert_eq!(libc::pthread_detach(pthread), 0);
        assert_eq!(libc::pthread_kill(pthread, libc::SIGKILL), 0);
    }

    Ok(())
}

#[cfg(target_arch = "x86_64")]
fn direction_flag_syscall_test() -> Result<()> {
    let path = *b"sys:context";

    let result: usize;

    unsafe {
        core::arch::asm!("
            std
            syscall
            cld
        ", inout("rax") syscall::SYS_OPEN => result, in("rdi") path.as_ptr(), in("rsi") path.len(), in("rdx") syscall::O_RDONLY, out("rcx") _, out("r11") _);
    }

    let file = syscall::Error::demux(result).unwrap();

    let mut buf = [0_u8; 4096];

    let result: usize;

    unsafe {
        core::arch::asm!("
            std
            syscall
            cld
        ", inout("rax") syscall::SYS_READ => result, in("rdi") file, in("rsi") buf.as_mut_ptr(), in("rdx") buf.len(), out("rcx") _, out("r11") _);
    }

    syscall::Error::demux(result).unwrap();

    Ok(())
}
fn pipe_test() -> Result<()> {
    let read_fd = syscall::open("pipe:", O_RDONLY).expect("failed to open pipe:");
    let write_fd = syscall::dup(read_fd, b"write").expect("failed to obtain write pipe");

    let barrier = Barrier::new(2);

    let mut initial_buf = vec! [0_u8; 131768];

    for idx in 0..131768 {
        let mut hasher = DefaultHasher::new();
        hasher.write_usize(131768);
        hasher.write_usize(idx);
        hasher.write(&initial_buf[..idx]);
        initial_buf[idx] = hasher.finish() as u8;
    }

    thread::scope(|scope| {
        let thread = scope.spawn(|| {
            // Saturate queue.
            let bytes_written = syscall::write(write_fd, &vec! [0_u8; 65537]).expect("failed to write to pipe");
            assert_eq!(bytes_written, 65536);

            barrier.wait();

            // Then try writing again.
            let bytes_written = syscall::write(write_fd, &[0_u8]).expect("failed to write to pipe");
            assert_eq!(bytes_written, 1);

            barrier.wait();

            let mut buf = vec! [0_u8; 131768];

            for i in 0..131768 {
                buf.copy_from_slice(&initial_buf);
                for byte in &mut buf {
                    *byte = byte.wrapping_add(i as u8);
                }

                let mut bytes_written = 0;

                while bytes_written < i {
                    bytes_written += syscall::write(write_fd, &buf[bytes_written..i]).expect("failed to write to pipe");
                }
            }
        });

        barrier.wait();

        let bytes_read = syscall::read(read_fd, &mut vec! [0_u8; 65537]).expect("failed to read from pipe");
        assert_eq!(bytes_read, 65536);

        let bytes_read = syscall::read(read_fd, &mut [0_u8]).expect("failed to read from pipe");
        assert_eq!(bytes_read, 1);

        barrier.wait();

        let mut buf = vec! [0_u8; 131768];

        for i in 0..131768 {
            let mut bytes_read = 0;

            while bytes_read < i {
                bytes_read += syscall::read(read_fd, &mut buf[bytes_read..i]).expect("failed to read from pipe");
            }

            assert!(buf[..i].iter().copied().enumerate().all(|(idx, byte)| byte == initial_buf[idx].wrapping_add(i as u8)));
        }

        thread.join().unwrap();
    });

    Ok(())
}

fn page_fault_test() -> Result<()> {
    use syscall::flag::{SigActionFlags, SIGSEGV};
    use syscall::data::SigAction;

    const ADDR: usize = 0xDEADC0DE;
    const ALIGNED_ADDR: usize = ADDR / PAGE_SIZE * PAGE_SIZE;
    static STATE: AtomicUsize = AtomicUsize::new(0);

    fn map(value: u8) {
        unsafe {
            let _ = syscall::fmap(!0, &Map { offset: 0, address: ALIGNED_ADDR, size: PAGE_SIZE, flags: MapFlags::MAP_FIXED_NOREPLACE | MapFlags::MAP_PRIVATE | MapFlags::PROT_READ | MapFlags::PROT_WRITE }).expect("[signal handler]: failed to re-map address");
            (ADDR as *mut u8).write_volatile(value);
        }
    }
    extern "C" fn page_fault_handler(_signo: usize) {
        std::panic::catch_unwind(|| {
            let prev_state = STATE.fetch_add(1, Ordering::Relaxed);
            compiler_fence(Ordering::SeqCst);

            match prev_state {
                0 => {
                    println!("[signal handler]: Mapping to fix page fault...");
                    map(42);
                }
                1 => {
                    println!("[signal handler]: Remapping to finish main process...");
                    map(43);
                }
                _ => unreachable!("[signal handler]: Page fault should NOT occur more than twice! What went wrong?"),
            }

            syscall::sigreturn().expect("[signal handler]: expected sigreturn to work")
        }).unwrap_or_else(|_| std::intrinsics::abort());
    }

    let new_sigaction = SigAction {
        sa_handler: Some(page_fault_handler),
        // I think this is currently ignored by the kernel. TODO
        sa_mask: [0; 2],
        sa_flags: SigActionFlags::empty(),
    };
    syscall::sigaction(SIGSEGV, Some(&new_sigaction), None).unwrap();

    for i in 0..2 {
        println!("Reading {} time:", if i == 0 { "first" } else if i == 1 { "second" } else { unreachable!() });
        println!("value {}", unsafe { (ADDR as *const u8).read_volatile() });
        if i == 0 {
            println!("Unmapping to test TLB flush...");
        }
        let _ = unsafe { syscall::funmap(ALIGNED_ADDR, PAGE_SIZE).expect("failed to unmap") };
    }

    compiler_fence(Ordering::SeqCst);
    match STATE.load(Ordering::Relaxed) {
        0 => panic!("failed: no page fault was caught, maybe 0xDEADC0DE was already mapped?"),
        1 => panic!("failed: unmap was unsuccessful"),
        2 => (),

        _ => unreachable!(),
    }

    Ok(())
}

fn tlb_test() -> Result<()> {
    struct Inner {
        counter: usize,
        page: *mut usize,
    }
    unsafe impl Send for Inner {}

    let mutex = spin::Mutex::new(Inner {
        counter: 0,
        page: unsafe {
            syscall::fmap(!0, &Map {
                address: 0, offset: 0, flags: MapFlags::PROT_READ | MapFlags::PROT_WRITE | MapFlags::MAP_PRIVATE, size: PAGE_SIZE
            }).unwrap() as *mut usize
        },
    });

    const N: usize = 1024 * 32;
    const THREAD_COUNT: usize = 4;

    std::thread::scope(|scope| {
        let mut threads = Vec::new();
        for _ in 0..THREAD_COUNT {
            threads.push(scope.spawn(|| unsafe {
                for _ in 0..N {
                    let new_page = syscall::fmap(!0, &Map {
                        address: 0,
                        offset: 0,
                        flags: MapFlags::PROT_READ | MapFlags::PROT_WRITE | MapFlags::MAP_PRIVATE,
                        size: PAGE_SIZE,
                    }).unwrap() as *mut usize;

                    let mut guard = mutex.lock();
                    let stored_value = guard.page.read_volatile();

                    assert_eq!(stored_value, guard.counter);

                    guard.counter += 1;
                    new_page.write_volatile(guard.counter);

                    /*
                    guard.page = syscall::fmap(!0, &Map {
                        address: guard.page as usize,
                        size: PAGE_SIZE,
                        flags: MapFlags::PROT_READ | MapFlags::PROT_WRITE | MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
                        offset: 0,
                    }).unwrap() as *mut usize;
                    */
                    assert_eq!(syscall::syscall5(syscall::SYS_MREMAP, new_page as usize, PAGE_SIZE, guard.page as usize, PAGE_SIZE, syscall::MremapFlags::FIXED_REPLACE.bits()).unwrap(), guard.page as usize);
                }
            }));
        }

        // Use this thread to prevent the same physical address from being reused.
        //
        // Unsure if it makes a difference, but I was able to successfully get the test to fail
        // (lol) using it.
        threads.push(scope.spawn(|| unsafe {
            const KEEP_BUSY_PAGE_COUNT: usize = 1024;

            let mut frames = vec! [0; KEEP_BUSY_PAGE_COUNT];

            for _ in 0..256 {
                for i in 0..KEEP_BUSY_PAGE_COUNT {
                    frames[i] = syscall::physalloc(PAGE_SIZE).unwrap();
                }
                for i in 0..KEEP_BUSY_PAGE_COUNT {
                    syscall::physfree(frames[i], PAGE_SIZE).unwrap();
                }
            }
        }));
        for thread in threads {
            thread.join().unwrap();
        }
    });

    assert_eq!(mutex.into_inner().counter, N * THREAD_COUNT);

    Ok(())
}

#[cfg(target_arch = "x86_64")]
fn switch_test() -> Result<()> {
    use x86::time::rdtscp;

    let tsc = unsafe { rdtscp() };

    let switch_thread = thread::spawn(|| -> usize {
        let mut j = 0;
        while j < 500 {
            thread::yield_now();
            j += 1;
        }
        j
    });

    let mut i = 0;
    while i < 500 {
        thread::yield_now();
        i += 1;
    }

    let j = switch_thread.join().unwrap();

    let dtsc = unsafe { rdtscp() } - tsc;
    println!("P {} C {} T {}", i, j, dtsc);

    Ok(())
}

fn tcp_fin_test() -> Result<()> {
    let mut conn = TcpStream::connect("static.redox-os.org:80")?;
    conn.write(b"TEST")?;
    drop(conn);

    Ok(())
}

fn thread_test() -> Result<()> {
    println!("Trying to stop kernel...");

    let start = Instant::now();
    while start.elapsed().as_secs() == 0 {}

    println!("Kernel preempted!");

    println!("Trying to kill kernel...");

    let mut threads = Vec::new();
    for i in 0..10 {
        threads.push(thread::spawn(move || {
            let mut sub_threads = Vec::new();
            for j in 0..10 {
                sub_threads.push(thread::spawn(move || {
                    Command::new("ion")
                        .arg("-c")
                        .arg(&format!("echo {}:{}", i, j))
                        .spawn().unwrap()
                        .wait().unwrap();
                }));
            }

            Command::new("ion")
                .arg("-c")
                .arg(&format!("echo {}", i))
                .spawn().unwrap()
                .wait().unwrap();

            for sub_thread in sub_threads {
                let _ = sub_thread.join();
            }
        }));
    }

    for thread in threads {
        let _ = thread.join();
    }

    println!("Kernel survived thread test!");

    Ok(())
}

/// Test of zero values in thread BSS
#[thread_local]
static mut TBSS_TEST_ZERO: usize = 0;
/// Test of non-zero values in thread data.
#[thread_local]
static mut TDATA_TEST_NONZERO: usize = usize::max_value();

fn tls_test() -> Result<()> {
    thread::spawn(|| {
        unsafe {
            assert_eq!(TBSS_TEST_ZERO, 0);
            TBSS_TEST_ZERO += 1;
            assert_eq!(TBSS_TEST_ZERO, 1);
            assert_eq!(TDATA_TEST_NONZERO, usize::max_value());
            TDATA_TEST_NONZERO -= 1;
            assert_eq!(TDATA_TEST_NONZERO, usize::max_value() - 1);
        }
    }).join().unwrap();

    unsafe {
        assert_eq!(TBSS_TEST_ZERO, 0);
        TBSS_TEST_ZERO += 1;
        assert_eq!(TBSS_TEST_ZERO, 1);
        assert_eq!(TDATA_TEST_NONZERO, usize::max_value());
        TDATA_TEST_NONZERO -= 1;
        assert_eq!(TDATA_TEST_NONZERO, usize::max_value() - 1);
    }

    Ok(())
}
fn efault_test() -> Result<()> {
    use syscall::*;

    let ret = unsafe {
        syscall3(SYS_WRITE, 1, 0xdeadbeef, 0xfeedface)
    };
    assert_eq!(ret, Err(Error::new(EFAULT)));

    Ok(())
}

fn main() {

    let mut tests: HashMap<&'static str, fn() -> Result<()>> = HashMap::new();
    #[cfg(target_arch = "x86_64")]
    tests.insert("avx2", avx2_test);
    tests.insert("create_test", create_test);
    tests.insert("page_fault", page_fault_test);
    #[cfg(target_arch = "x86_64")]
    tests.insert("switch", switch_test);
    tests.insert("tcp_fin", tcp_fin_test);
    tests.insert("thread", thread_test);
    tests.insert("tls", tls_test);
    tests.insert("cross_scheme_link", cross_scheme_link::cross_scheme_link);
    tests.insert("efault", efault_test);
    #[cfg(target_arch = "x86_64")]
    tests.insert("direction_flag_sc", direction_flag_syscall_test);
    #[cfg(target_arch = "x86_64")]
    tests.insert("direction_flag_int", direction_flag_interrupt_test);
    tests.insert("pipe", pipe_test);
    tests.insert("scheme_data_leak", scheme_data_leak::scheme_data_leak_test);
    tests.insert("relibc_leak", relibc_leak::test);
    tests.insert("clone_grant_using_fmap", clone_grant_using_fmap_test);
    tests.insert("clone_grant_using_fmap_lazy", clone_grant_using_fmap_lazy_test);
    tests.insert("anonymous_map_shared", anonymous_map_shared);
    tests.insert("tlb", tlb_test);
    tests.insert("file_mmap", file_mmap_test);
    tests.insert("redoxfs_range_bookkeeping", redoxfs_range_bookkeeping);
    tests.insert("eintr", eintr::eintr);
    tests.insert("syscall_bench", syscall_bench::bench);

    let mut ran_test = false;
    for arg in env::args().skip(1) {
        if let Some(test) = tests.get(&arg.as_str()) {
            ran_test = true;

            let time = Instant::now();
            let res = test();
            let elapsed = time.elapsed();
            match res {
                Ok(_) => {
                    println!("acid: {}: passed: {} ns", arg, elapsed.as_secs() * 1000000000 + elapsed.subsec_nanos() as u64);
                },
                Err(err) => {
                    println!("acid: {}: failed: {}", arg, err);
                }
            }
        } else {
            println!("acid: {}: not found", arg);
            process::exit(1);
        }
    }

    if ! ran_test {
        for test in tests {
            println!("{}", test.0);
        }
    }
}
