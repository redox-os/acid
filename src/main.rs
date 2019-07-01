//!Acid testing program
#![feature(thread_local, asm)]

extern crate x86;

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

fn page_fault_test() -> Result<(), String> {
    use std::thread;

    thread::spawn(|| {
        println!("{:X}", unsafe { *(0xDEADC0DE as *const u8) });
    }).join().unwrap();

    Ok(())
}

fn ptrace() -> Result<(), String> {
    use std::{
        fs::File,
        io::prelude::*,
        os::{raw::c_int, unix::io::{AsRawFd, FromRawFd}}
    };

    let pid = unsafe { syscall::clone(0).map_err(|e| format!("clone failed: {}", e))? };
    if pid == 0 {
        unsafe {
            asm!("
                mov rax, 20 // GETPID
                syscall

                mov rdi, rax

                mov rax, 37 // SYS_KILL
                mov rsi, 19 // SIGSTOP
                syscall

                // Start of body
                mov rax, 1
                push rax
                mov rax, 2
                push rax
                mov rax, 3
                pop rax
                pop rax
                // End of body

                mov rax, 1 // SYS_EXIT
                mov rdi, 0
                syscall
                "
                : : : : "intel", "volatile"
            );
        }
    }

    // Wait until child is ready to be traced
    let mut status = 0;
    syscall::waitpid(pid, &mut status, syscall::WUNTRACED).map_err(|e| format!("waitpid failed: {}", e))?;

    // Stop & attach process + get handle to registers
    let mut proc_file = File::open(format!("proc:{}/trace", pid)).map_err(|e| format!("open failed: {}", e))?;
    let mut regs_file = unsafe {
        File::from_raw_fd(
            syscall::dup(proc_file.as_raw_fd() as usize, b"regs/int")
                .map_err(|e| format!("dup failed: {}", e))? as c_int
        )
    };

    // Schedule restart of process when resumed
    syscall::kill(pid, syscall::SIGCONT).map_err(|e| format!("kill failed: {}", e))?;

    let mut next = move |op| -> Result<syscall::IntRegisters, String> {
        proc_file.write(&[op]).map_err(|e| format!("ptrace operation failed: {}", e))?;

        let mut regs: syscall::IntRegisters = syscall::IntRegisters::default();
        regs_file.read(&mut regs).map_err(|e| format!("reading registers failed: {}", e))?;
        Ok(regs)
    };

    // Step out of syscall down to the next instruction
    let _ = next(syscall::PTRACE_SINGLESTEP)?;
    assert_eq!(next(syscall::PTRACE_SINGLESTEP)?.rax, 1);
    assert_eq!(next(syscall::PTRACE_SINGLESTEP)?.rax, 2);
    assert_eq!(next(syscall::PTRACE_SINGLESTEP)?.rax, 2);
    assert_eq!(next(syscall::PTRACE_SINGLESTEP)?.rax, 3);
    assert_eq!(next(syscall::PTRACE_SINGLESTEP)?.rax, 2);
    assert_eq!(next(syscall::PTRACE_SINGLESTEP)?.rax, 1);

    assert_eq!(next(syscall::PTRACE_SYSCALL)?.rax, syscall::SYS_EXIT);

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

fn main() {
    use std::collections::BTreeMap;
    use std::{env, process};
    use std::time::Instant;

    let mut tests: BTreeMap<&'static str, fn() -> Result<(), String>> = BTreeMap::new();
    tests.insert("create_test", create_test);
    tests.insert("page_fault", page_fault_test);
    tests.insert("ptrace", ptrace);
    tests.insert("switch", switch_test);
    tests.insert("tcp_fin", tcp_fin_test);
    tests.insert("thread", thread_test);
    tests.insert("tls", tls_test);

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
