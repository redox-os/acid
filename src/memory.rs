use std::{
    fs::{File, OpenOptions},
    hash::{DefaultHasher, Hasher},
    io::{Read, Write},
    os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd},
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Barrier,
    },
    thread,
    time::Instant,
};

use nix::sys::wait::WaitStatus;
use rand::{RngExt, SeedableRng};
use syscall::{Map, MapFlags, PAGE_SIZE};

pub fn clone_grant_using_fmap() {
    clone_grant_using_fmap_test_inner(false)
}

pub fn clone_grant_using_fmap_lazy() {
    clone_grant_using_fmap_test_inner(true)
}

pub fn test_shared_ref(shared_ref: &AtomicUsize) {
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
        assert_eq!(
            shared_ref.compare_exchange(0xDEADBEEF, 2, Ordering::SeqCst, Ordering::SeqCst),
            Ok(0xDEADBEEF)
        );
        let _ = syscall::write(write_fd2, &[0]).unwrap();
    }
}

fn clone_grant_using_fmap_test_inner(lazy: bool) {
    let lazy_flag = if lazy {
        MapFlags::MAP_LAZY
    } else {
        MapFlags::empty()
    };

    let mem = libredox::call::open(
        "shm:clone_grant_using_fmap_test",
        libredox::flag::O_CLOEXEC,
        0,
    )
    .unwrap();
    let base_ptr = unsafe {
        syscall::fmap(
            mem,
            &Map {
                address: 0,
                size: PAGE_SIZE,
                flags: MapFlags::PROT_READ
                    | MapFlags::PROT_WRITE
                    | MapFlags::MAP_SHARED
                    | lazy_flag,
                offset: 0,
            },
        )
        .unwrap()
    };
    let shared_ref: &'static AtomicUsize = unsafe { &*(base_ptr as *const AtomicUsize) };

    test_shared_ref(shared_ref);
}

pub fn file_mmap_test() {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open("acid_tmp_file")
        .unwrap();
    let fd = file.into_raw_fd() as usize;

    let buf = unsafe {
        let ptr = syscall::fmap(
            fd,
            &Map {
                address: 0,
                size: 16384 + 127,
                flags: MapFlags::PROT_READ | MapFlags::PROT_WRITE | MapFlags::MAP_SHARED,
                offset: 0,
            },
        )
        .unwrap();
        core::slice::from_raw_parts_mut(ptr as *mut u8, 16384 + 127)
    };
    let buf2 = unsafe {
        let ptr = syscall::fmap(
            fd,
            &Map {
                address: 0,
                size: 1337,
                flags: MapFlags::PROT_READ | MapFlags::PROT_WRITE | MapFlags::MAP_SHARED,
                offset: 3 * 4096,
            },
        )
        .unwrap();
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
                syscall::ADDRSPACE_OP_MMAP,
                parent_memory.as_raw_fd() as usize,
                buf2.as_ptr() as usize,
                0xDEADB000,
                4096,
                (MapFlags::PROT_READ | MapFlags::PROT_WRITE | MapFlags::MAP_FIXED_NOREPLACE).bits(),
            ];

            dbg!();
            child_memory
                .write(core::slice::from_raw_parts(
                    words.as_ptr().cast(),
                    words.len() * core::mem::size_of::<usize>(),
                ))
                .unwrap();
            dbg!();

            let _ = syscall::write(pipes1[1] as usize, &[1]).unwrap();
            dbg!();

            let words = [syscall::ADDRSPACE_OP_MUNMAP, 0xDEADB000, 4096];
            child_memory
                .write(core::slice::from_raw_parts(
                    words.as_ptr().cast(),
                    words.len() * core::mem::size_of::<usize>(),
                ))
                .unwrap();

            let _ = syscall::write(pipes2[1] as usize, &[1]).unwrap();
            dbg!();

            std::process::exit(0);
        } else {
            dbg!();
            let _ = syscall::read(pipes1[0] as usize, &mut [0]).unwrap();
            assert_eq!(
                syscall::funmap(buf2.as_ptr() as usize, 4096),
                Err(syscall::Error::new(syscall::EBUSY))
            );
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
}

pub fn mmap_delay() {
    // This needs to be a path to a large executable, cosmic-files is large and usually installed
    let path = "/usr/bin/cosmic-files";

    let file = OpenOptions::new().read(true).open(path).unwrap();

    let metadata = file.metadata().unwrap();
    println!(
        "File: {} bytes (~{:.2} MB)\n",
        metadata.len(),
        metadata.len() as f64 / 1048576.0
    );

    let instant = Instant::now();

    let ptr = unsafe {
        syscall::fmap(
            file.as_raw_fd() as usize,
            &Map {
                address: 0,
                size: metadata.len() as usize,
                flags: MapFlags::PROT_READ | MapFlags::MAP_PRIVATE,
                offset: 0,
            },
        )
        .unwrap()
    };

    let duration = instant.elapsed();
    println!("Time to map: {:?}", duration);

    let instant = Instant::now();

    let first_byte = unsafe { (ptr as *const u8).read_volatile() };

    let duration = instant.elapsed();
    println!("Time to first byte {:02X}: {:?}", first_byte, duration);

    unsafe {
        syscall::funmap(ptr, metadata.len() as usize).unwrap();
    }
}

pub fn anonymous_map_shared() {
    let base_ptr = unsafe {
        syscall::fmap(
            !0,
            &Map {
                address: 0,
                size: PAGE_SIZE,
                flags: MapFlags::PROT_READ | MapFlags::PROT_WRITE | MapFlags::MAP_SHARED,
                offset: 0,
            },
        )
        .unwrap()
    };
    let shared_ref: &'static AtomicUsize = unsafe { &*(base_ptr as *const AtomicUsize) };

    test_shared_ref(shared_ref);
}

pub fn pipe_test() {
    let read_fd =
        libredox::call::open("pipe:", libredox::flag::O_RDONLY, 0).expect("failed to open pipe:");
    let write_fd = libredox::call::dup(read_fd, b"write").expect("failed to obtain write pipe");

    let barrier = Barrier::new(2);

    let mut initial_buf = vec![0_u8; 131768];

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
            let bytes_written =
                syscall::write(write_fd, &vec![0_u8; 65537]).expect("failed to write to pipe");
            assert_eq!(bytes_written, 65536);

            barrier.wait();

            // Then try writing again.
            let bytes_written = syscall::write(write_fd, &[0_u8]).expect("failed to write to pipe");
            assert_eq!(bytes_written, 1);

            barrier.wait();

            let mut buf = vec![0_u8; 131768];

            for i in 0..131768 {
                buf.copy_from_slice(&initial_buf);
                for byte in &mut buf {
                    *byte = byte.wrapping_add(i as u8);
                }

                let mut bytes_written = 0;

                while bytes_written < i {
                    bytes_written += syscall::write(write_fd, &buf[bytes_written..i])
                        .expect("failed to write to pipe");
                }
            }
        });

        barrier.wait();

        let bytes_read =
            syscall::read(read_fd, &mut vec![0_u8; 65537]).expect("failed to read from pipe");
        assert_eq!(bytes_read, 65536);

        let bytes_read = syscall::read(read_fd, &mut [0_u8]).expect("failed to read from pipe");
        assert_eq!(bytes_read, 1);

        barrier.wait();

        let mut buf = vec![0_u8; 131768];

        for i in 0..131768 {
            let mut bytes_read = 0;

            while bytes_read < i {
                bytes_read += syscall::read(read_fd, &mut buf[bytes_read..i])
                    .expect("failed to read from pipe");
            }

            assert!(buf[..i]
                .iter()
                .copied()
                .enumerate()
                .all(|(idx, byte)| byte == initial_buf[idx].wrapping_add(i as u8)));
        }

        thread.join().unwrap();
    });
}

// TODO: use libc
/*fn page_fault_test() {
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

}*/

// TODO: replace physalloc/physfree
/*fn tlb_test() {
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

}*/

pub fn efault_test() {
    let ret = unsafe { syscall::syscall3(syscall::SYS_WRITE, 1, 0xdeadbeef, 0xfeedface) };
    assert_eq!(ret, Err(syscall::Error::new(syscall::EFAULT)));
}

pub(crate) fn pipe() -> [File; 2] {
    let mut fds = [0; 2];
    assert_ne!(unsafe { libc::pipe(fds.as_mut_ptr()) }, -1);
    fds.map(|f| unsafe { File::from_raw_fd(f) })
}

pub fn filetable_leak() {
    // Relies on the fact that readers of a pipe are always awoken when the writer is closed.
    let [mut reader, writer] = pipe();
    let first_child = unsafe { libc::fork() };
    assert_ne!(first_child, -1);

    if first_child == 0 {
        drop(reader);
        let _ft = File::open("thisproc:current/filetable").unwrap();
        std::process::exit(0);
    } else {
        drop(writer);
        assert_eq!(
            reader.read_exact(&mut [0]).unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    }
}

/// Physical pages are mapped on-demand on Redox. This benchmark checks the average overhead of
/// this, thus getting coverage of the interrupt entry point, frame allocator, and partly the
/// virtual memory subsystem in the kernel.
pub fn pgtbl_populate_bench(results: &mut crate::BenchResults) {
    // TODO: shouldn't hardcode length and should be page size-independent
    const LENGTH: usize = 1024 * 1024 * 1024; // 256k 4k-pages, 1 GiB
    const PAGE_SIZE: usize = 4096;
    const REPETITIONS: usize = 10;

    let mut ticks = 0;

    // TODO: mmap overhead may worsen the metrics for this test.
    // TODO: rdtsc or rdtscp?

    for _ in 0..REPETITIONS {
        ticks += unsafe {
            let base = libredox::call::mmap(libredox::call::MmapArgs {
                addr: core::ptr::null_mut(),
                length: LENGTH,
                prot: libredox::flag::PROT_WRITE | libredox::flag::PROT_READ,
                flags: libredox::flag::MAP_PRIVATE,
                fd: !0,
                offset: 0,
            })
            .unwrap()
            .cast::<u8>();

            let before = results.rdtsc();
            for i in 0..LENGTH / PAGE_SIZE {
                // will force the page to be mapped
                base.add(i * PAGE_SIZE).write_volatile(0x42);
            }
            let elapsed = results.rdtsc() - before;
            libredox::call::munmap(base.cast(), LENGTH).unwrap();
            elapsed
        };
    }
    results.add_metric(
        "pgtbl_populate_bench.ticks_per_page",
        (ticks as f64 / (LENGTH / PAGE_SIZE) as f64) / REPETITIONS as f64,
    );
}

/// Creates exponentially many child processes with a large amount of continuously modified CoW
/// memory.
// TODO: Create subtests with certain defaults. For example, a high fraction of reads and a very
// large buffer will test TLB miss overhead, whereas a high fraction of writes and smaller buffer
// will in addition to TLB misses, also test memory allocation, mapping, etc.
pub fn heavy_forking(results: &mut crate::BenchResults) {
    // 2^n processes will be created

    let param_exponent = std::env::var("ACID_FORK_EXPONENT")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(10);
    let param_bufsize = std::env::var("ACID_FORK_BUFSIZE")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(1024 * 1024);
    let param_read_prob = std::env::var("ACID_FORK_P_READ")
        .ok()
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.0);
    let param_write_prob = std::env::var("ACID_FORK_P_WRITE")
        .ok()
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(1.0);
    let param_iterations = std::env::var("ACID_FORK_ITERATIONS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(2000);
    let mut rng = match std::env::var("ACID_FORK_SEED")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
    {
        Some(seed) => rand::rngs::SmallRng::seed_from_u64(seed),
        None => rand::make_rng(),
    };
    let total_processes = 1_usize.checked_shl(param_exponent).unwrap();

    #[repr(C)]
    struct Stats {
        total_fork_ticks: AtomicU64,
        total_mem_ticks: AtomicU64,
        total_bytes_accessed: AtomicU64,
    }

    let stats_region = unsafe {
        &*libredox::call::mmap(libredox::call::MmapArgs {
            addr: core::ptr::null_mut(),
            length: syscall::PAGE_SIZE,
            prot: libredox::flag::PROT_READ | libredox::flag::PROT_WRITE,
            flags: libredox::flag::MAP_SHARED,
            fd: !0,
            offset: 0,
        })
        .unwrap()
        .cast::<Stats>()
    };

    let mut mem = vec![0_u8; param_bufsize];
    let mut children = Vec::with_capacity(param_exponent as usize);

    let mut ts = results.rdtsc();

    for _ in 0..param_exponent {
        let result = unsafe { nix::unistd::fork().expect("failed to fork") };

        let t = results.rdtsc();
        let fork_overhead = t - ts;
        ts = t;

        if result.is_child() {
            // ensure different fork branches do not have identical RNG outcomes
            let _ = rng.random_bool(0.5);
        }

        children.push(result);

        let mut bytes_accessed = 0_u64;

        for _ in 0..param_iterations {
            if rng.random_bool(param_read_prob) {
                bytes_accessed += 1;
                let offset = rng.random_range(0..mem.len());
                unsafe {
                    mem.as_ptr().add(offset).read_volatile();
                }
            }
            if rng.random_bool(param_write_prob) {
                bytes_accessed += 1;
                let offset = rng.random_range(0..mem.len());
                let byte = rng.random();
                unsafe {
                    mem.as_mut_ptr().add(offset).write_volatile(byte);
                }
            }
        }
        let t = results.rdtsc();
        let mem_overhead = t - ts;
        ts = t;

        // Every fork takes N ticks and creates a parent and a child. Of course, it would be wrong
        // to increment the total fork ticks by 2N.
        if !result.is_child() {
            stats_region
                .total_fork_ticks
                .fetch_add(fork_overhead, Ordering::Relaxed);
        }
        stats_region
            .total_mem_ticks
            .fetch_add(mem_overhead, Ordering::Relaxed);
        stats_region
            .total_bytes_accessed
            .fetch_add(bytes_accessed, Ordering::Relaxed);
    }

    for result in children.into_iter().rev() {
        match result {
            nix::unistd::ForkResult::Child => {
                std::process::exit(0);
            }
            nix::unistd::ForkResult::Parent { child } => {
                let status = nix::sys::wait::waitpid(child, None).expect("failed to await child");
                assert_eq!(status, WaitStatus::Exited(child, 0));
            }
        }
    }

    // Only the original parent process will have survived here.
    let total_fork_ticks = stats_region.total_fork_ticks.load(Ordering::Relaxed);
    let total_mem_ticks = stats_region.total_mem_ticks.load(Ordering::Relaxed);
    let total_bytes_accessed = stats_region.total_bytes_accessed.load(Ordering::Relaxed);

    eprintln!("total fork ticks {total_fork_ticks}; mem ticks {total_mem_ticks}; bytes accessed {total_bytes_accessed}");

    let ticks_per_fork = total_fork_ticks as f64 / total_processes as f64;
    let ticks_per_byte = total_mem_ticks as f64 / total_bytes_accessed as f64;

    results.add_metric("heavy_forking.ticks_per_fork", ticks_per_fork);
    results.add_metric("heavy_forking.ticks_per_byte", ticks_per_byte);
}
