use std::thread;
use std::time::{Duration, Instant};

use anyhow::Result;
use nix::sys::signal::{self, Signal};
use nix::sys::wait::{self, WaitPidFlag, WaitStatus};
use nix::unistd::{self, ForkResult, Pid};

pub fn fork_serial_bench<const EXEC: bool>() -> Result<()> {
    let now = Instant::now();

    for _ in 0..1 << 10 {
        let code = unsafe { libc::fork() };
        assert_ne!(code, -1);
        if code == 0 {
            if EXEC {
                unsafe {
                    let s = c"/usr/bin/true";
                    libc::execv(s.as_ptr(), [s.as_ptr(), core::ptr::null()].as_ptr());
                    unreachable!();
                }
            } else {
                std::process::exit(0);
            }
        }
        unsafe {
            libc::waitpid(code, &mut 0, 0);
        }
    }

    println!("TIME: {:?}", now.elapsed());
    Ok(())
}
pub fn fork_tree_bench<const EXEC: bool>() -> Result<()> {
    let mut is_parent = true;
    let now = Instant::now();

    let mut pids = [0; 10];

    for i in 0..10 {
        pids[i] = unsafe { libc::fork() };
        assert_ne!(pids[i], -1, "failed {}", unsafe {
            libc::__errno_location().read()
        });
        is_parent &= pids[i] != 0;
    }

    if !is_parent {
        if EXEC {
            unsafe {
                let s = c"/usr/bin/true";
                libc::execv(s.as_ptr(), [s.as_ptr(), core::ptr::null()].as_ptr());
                unreachable!();
            }
        } else {
            std::process::exit(0);
        }
    }
    println!("TIME: {:?}", now.elapsed());
    Ok(())
}

pub fn stop_orphan_pgrp() -> Result<()> {
    #[derive(Debug)]
    enum Case {
        Setsid,    // orphan due to different sid than parent
        SameGrp,   // orphan since parent chain preserves pgid
        Nonorphan, // nonorphan since parent has different pgid
    }
    unsafe fn inner(sig: Signal, case: Case) -> Result<()> {
        println!("Testing {sig:?} case {case:?}");

        if matches!(case, Case::SameGrp) {
            if unistd::getppid() != Pid::from_raw(1) {
                eprintln!("Have to skip {case:?} since parent is not init");
            }
            unistd::setpgid(Pid::from_raw(0), Pid::from_raw(1))?;
        }

        match unistd::fork().unwrap() {
            ForkResult::Parent { child } => {
                thread::sleep(Duration::from_millis(100));
                let status =
                    wait::waitpid(child, Some(WaitPidFlag::WNOHANG | WaitPidFlag::WUNTRACED))?;
                if matches!(case, Case::Setsid | Case::SameGrp) {
                    // Orphan pgrp, so stop signal must be discarded.
                    assert_eq!(status, WaitStatus::Exited(child, 42))
                } else {
                    // Non-orphan group, so the status must be Stopped.
                    assert_eq!(status, WaitStatus::Stopped(child, sig));
                    signal::kill(child, Signal::SIGKILL)?;
                }
            }
            ForkResult::Child => {
                match case {
                    Case::SameGrp => (),
                    Case::Nonorphan => {
                        unistd::setpgid(Pid::from_raw(0), Pid::from_raw(0))?;
                    }
                    Case::Setsid => {
                        unistd::setsid()?;

                        // TODO: getsid missing!
                        //assert_eq!(unistd::getsid(None)?, unistd::getpid());

                        assert_eq!(unistd::getpgid(None)?, unistd::getpid());
                    }
                }
                // Stop this process group using either SIGTTIN, SIGTTOU, or SIGTSTP
                signal::killpg(Pid::from_raw(0), sig)?;
                std::process::exit(42);
            }
        }
        Ok(())
    }
    unsafe {
        for sig in [Signal::SIGTTIN, Signal::SIGTTOU, Signal::SIGTSTP] {
            inner(sig, Case::Setsid)?;
            inner(sig, Case::Nonorphan)?;
            inner(sig, Case::SameGrp)?;
        }
    }
    Ok(())
}
