//!Acid testing program
#![feature(array_chunks, core_intrinsics, thread_local)]

mod clone_grant_using_fmap;

fn e<T, E: ToString>(error: Result<T, E>) -> Result<T, String> {
    error.map_err(|e| e.to_string())
}

fn create_test() -> Result<(), String> {
    use std::fs;
    use std::io::{self, Read, Write};
    use std::path::PathBuf;

    let mut test_dir = PathBuf::new();
    test_dir.push("test_dir");

    let mut test_file = test_dir.clone();
    test_file.push("test_file");
    let test_file_err = fs::File::create(&test_file).err().map(|err| err.kind());
    if test_file_err != Some(io::ErrorKind::NotFound) {
        return Err(format!("Incorrect open error: {:?}, should be NotFound", test_file_err));
    }

    fs::create_dir(&test_dir).map_err(|err| format!("{}", err))?;

    let test_data = "Test data";
    {
        let mut file = fs::File::create(&test_file).map_err(|err| format!("{}", err))?;
        file.write(test_data.as_bytes()).map_err(|err| format!("{}", err))?;
    }

    {
        let mut file = fs::File::open(&test_file).map_err(|err| format!("{}", err))?;
        let mut buffer: Vec<u8> = Vec::new();
        file.read_to_end(&mut buffer).map_err(|err| format!("{}", err))?;
        assert_eq!(buffer.len(), test_data.len());
        for (&a, b) in buffer.iter().zip(test_data.bytes()) {
            if a != b {
                return Err(format!("{} did not contain the correct data", test_file.display()));
            }
        }
    }

    Ok(())
}

#[cfg(target_arch = "x86_64")]
const PAGE_SIZE: usize = 4096;

fn page_fault_test() -> Result<(), String> {
    use std::sync::atomic::{AtomicUsize, compiler_fence, Ordering};

    use syscall::flag::{MapFlags, SigActionFlags, SIGSEGV};
    use syscall::data::{Map, SigAction};

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
    syscall::sigaction(SIGSEGV, Some(&new_sigaction), None).map_err(|err| format!("{}", err))?;

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

fn switch_test() -> Result<(), String> {
    use std::thread;
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

fn tcp_fin_test() -> Result<(), String> {
    use std::io::Write;
    use std::net::TcpStream;

    let mut conn = TcpStream::connect("static.redox-os.org:80").map_err(|err| format!("{}", err))?;
    conn.write(b"TEST").map_err(|err| format!("{}", err))?;
    drop(conn);

    Ok(())
}

fn thread_test() -> Result<(), String> {
    use std::process::Command;
    use std::thread;
    use std::time::Instant;

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
static mut TDATA_TEST_NONZERO: usize = 0xFFFFFFFFFFFFFFFF;

fn tls_test() -> Result<(), String> {
    use std::thread;

    thread::spawn(|| {
        unsafe {
            assert_eq!(TBSS_TEST_ZERO, 0);
            TBSS_TEST_ZERO += 1;
            assert_eq!(TBSS_TEST_ZERO, 1);
            assert_eq!(TDATA_TEST_NONZERO, 0xFFFFFFFFFFFFFFFF);
            TDATA_TEST_NONZERO -= 1;
            assert_eq!(TDATA_TEST_NONZERO, 0xFFFFFFFFFFFFFFFE);
        }
    }).join().unwrap();

    unsafe {
        assert_eq!(TBSS_TEST_ZERO, 0);
        TBSS_TEST_ZERO += 1;
        assert_eq!(TBSS_TEST_ZERO, 1);
        assert_eq!(TDATA_TEST_NONZERO, 0xFFFFFFFFFFFFFFFF);
        TDATA_TEST_NONZERO -= 1;
        assert_eq!(TDATA_TEST_NONZERO, 0xFFFFFFFFFFFFFFFE);
    }

    Ok(())
}

use self::clone_grant_using_fmap::*;

fn main() {
    use std::collections::BTreeMap;
    use std::{env, process};
    use std::time::Instant;

    let mut tests: BTreeMap<&'static str, fn() -> Result<(), String>> = BTreeMap::new();
    tests.insert("create_test", create_test);
    tests.insert("page_fault", page_fault_test);
    tests.insert("switch", switch_test);
    tests.insert("tcp_fin", tcp_fin_test);
    tests.insert("thread", thread_test);
    tests.insert("tls", tls_test);
    tests.insert("clone_grant_using_fmap", clone_grant_using_fmap);
    tests.insert("check_clone_leak", check_clone_leak);

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
