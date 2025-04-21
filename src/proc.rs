//! This file tries to enforce behavior interpreted from the POSIX 2024 standard:
//!
//! "IEEE/Open Group Standard for Information Technology--Portable Operating System Interface
//! (POSIX™) Base Specifications, Issue 8," in IEEE/Open Group Std 1003.1-2024 (Revision of IEEE
//! Std 1003.1-2017) , vol., no., pp.1-4107, 14 June 2024, doi: 10.1109/IEEESTD.2024.10555529.

use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::{AsRawFd, IntoRawFd};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::Result;
use nix::errno::Errno;
use nix::sys::signal::{self, SaFlags, SigHandler, SigSet, SigmaskHow, Signal};
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

pub fn reparenting() -> Result<()> {
    // Check that all children of a process are reparented to init, regardless of session or proc
    // group.

    match unsafe { unistd::fork()? } {
        ForkResult::Child => (),
        ForkResult::Parent {
            child: child_parent,
        } => {
            thread::sleep(Duration::from_millis(100));
            signal::kill(child_parent, Signal::SIGTERM)?;

            let res = wait::waitpid(None, Some(WaitPidFlag::WUNTRACED | WaitPidFlag::WCONTINUED))?;
            // TODO: check returned signal?
            assert!(matches!(res, WaitStatus::Exited(c, _) if c == child_parent));

            let res = wait::waitpid(None, Some(WaitPidFlag::WUNTRACED | WaitPidFlag::WCONTINUED));
            assert_eq!(res, Err(Errno::ECHILD), "children remain!");
        }
    }

    let ForkResult::Parent { .. } = (unsafe { unistd::fork()? }) else {
        // first child waits forever (a long time)
        unistd::setpgid(Pid::this(), Pid::this()).unwrap();
        thread::sleep(Duration::MAX);
        std::process::exit(42);
    };
    let ForkResult::Parent { .. } = (unsafe { unistd::fork()? }) else {
        unistd::setsid().unwrap();
        thread::sleep(Duration::MAX);
        std::process::exit(1337);
    };
    // TODO: Check that init killed them?

    Ok(())
}

// TODO: add to the nix and libc crates
extern "C" {
    fn getsid(pid: libc::pid_t) -> libc::pid_t;
}

pub fn setsid() -> Result<()> {
    // Create two processes in the same group.
    let orig_sid = Pid::from_raw(unsafe { getsid(0) });
    assert_ne!(orig_sid.as_raw(), -1);

    let parent = unistd::getpid();
    assert_eq!(unistd::setpgid(parent, parent), Ok(()));
    assert_eq!(unistd::getpgid(None)?, parent);
    assert_eq!(unistd::getpgid(Some(parent)), Ok(parent));

    let ForkResult::Parent { child } = (unsafe { unistd::fork()? }) else {
        thread::sleep(Duration::from_millis(100));
        let new_sid = unistd::setsid()?;
        assert_eq!(new_sid, unistd::getpid());
        assert_eq!(unistd::getpgid(None)?, new_sid);
        thread::sleep(Duration::MAX);
        std::process::exit(0);
    };

    // Process group leaders cannot become session leader unless the process group is only that
    // single process.
    assert_eq!(unistd::setsid(), Err(Errno::EPERM));
    thread::sleep(Duration::from_millis(200));

    // Still, already a process group leader
    assert_eq!(unistd::setsid(), Err(Errno::EPERM));

    assert_eq!(unsafe { getsid(parent.as_raw()) }, orig_sid.as_raw());
    assert_eq!(unsafe { getsid(child.as_raw()) }, child.as_raw());

    signal::kill(child, Signal::SIGTERM)?;

    assert_eq!(
        wait::waitpid(child, Some(WaitPidFlag::empty()))?,
        WaitStatus::Signaled(child, Signal::SIGTERM, false)
    );
    Ok(())
}

pub fn setpgid() -> Result<()> {
    #[derive(Debug)]
    enum Case {
        SessionLeader,
        DifferentSession,
        ModifyParent,
        NewPgidNotPid,
        HasRunExec,
        SetFromChild,
    }

    fn inner(case: Case) -> Result<()> {
        println!("Testing setpgid case {case:?}");
        if let ForkResult::Parent { child: wrapper } = unsafe { unistd::fork()? } {
            assert_eq!(
                wait::waitpid(wrapper, Some(WaitPidFlag::empty()))?,
                WaitStatus::Exited(wrapper, 0)
            );
            return Ok(());
        }

        let parent = unistd::getpid();

        match case {
            Case::SessionLeader => {
                unistd::setsid()?;
                // is a session leader (even though it would have been a no-op anyway)
                assert_eq!(unistd::setpgid(parent, parent), Err(Errno::EPERM));
                std::process::exit(0);
            }
            _ => (),
        }

        let ForkResult::Parent { child } = (unsafe { unistd::fork()? }) else {
            let child = unistd::getpid();
            match case {
                Case::DifferentSession => {
                    unistd::setsid()?;
                }
                Case::HasRunExec => {
                    unistd::execv(c"/usr/bin/sleep", &[c"/usr/bin/sleep", c"999999"])?;
                }
                Case::SessionLeader => unreachable!(),
                Case::ModifyParent => {
                    // can only modify children
                    assert_eq!(unistd::setpgid(parent, child), Err(Errno::ESRCH));
                    std::process::exit(0);
                }
                Case::NewPgidNotPid => (),
                Case::SetFromChild => {
                    unistd::setpgid(child, child)?;
                }
            }
            thread::sleep(Duration::MAX);
            std::process::exit(0);
        };
        thread::sleep(Duration::from_millis(100));
        match case {
            Case::HasRunExec => {
                assert_eq!(unistd::setpgid(child, child), Err(Errno::EACCES));
                signal::kill(child, Signal::SIGTERM)?;
                assert_eq!(
                    wait::waitpid(child, Some(WaitPidFlag::empty()))?,
                    WaitStatus::Signaled(child, Signal::SIGTERM, false)
                );
            }
            Case::SessionLeader => unreachable!(),
            Case::ModifyParent => {
                assert_eq!(
                    wait::waitpid(child, Some(WaitPidFlag::empty()))?,
                    WaitStatus::Exited(child, 0)
                );
            }
            Case::DifferentSession => {
                assert_eq!(unistd::setpgid(child, child), Err(Errno::EPERM));
                signal::kill(child, Signal::SIGTERM)?;
                assert_eq!(
                    wait::waitpid(child, Some(WaitPidFlag::empty()))?,
                    WaitStatus::Signaled(child, Signal::SIGTERM, false)
                );
            }
            Case::NewPgidNotPid => {
                // forbidden
                assert_eq!(unistd::setpgid(parent, child), Err(Errno::EPERM));

                // allowed
                assert_eq!(unistd::setpgid(child, child), Ok(()));
                assert_eq!(unistd::getpgid(Some(child))?, child);

                signal::kill(child, Signal::SIGTERM)?;
                assert_eq!(
                    wait::waitpid(child, Some(WaitPidFlag::empty()))?,
                    WaitStatus::Signaled(child, Signal::SIGTERM, false)
                );
            }
            Case::SetFromChild => {
                assert_eq!(unistd::getpgid(Some(child))?, child);
                signal::kill(child, Signal::SIGTERM)?;
                assert_eq!(
                    wait::waitpid(child, Some(WaitPidFlag::empty()))?,
                    WaitStatus::Signaled(child, Signal::SIGTERM, false)
                );
            }
        }
        std::process::exit(0);
    }
    let cases = [
        Case::SessionLeader,
        Case::DifferentSession,
        Case::ModifyParent,
        Case::NewPgidNotPid,
        Case::SetFromChild,
        Case::HasRunExec,
    ];
    for case in cases {
        inner(case)?;
    }
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
            unistd::setpgid(Pid::this(), Pid::from_raw(1))?;
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
                        unistd::setpgid(Pid::this(), Pid::this())?;
                    }
                    Case::Setsid => {
                        unistd::setsid()?;

                        // TODO: getsid missing!
                        //assert_eq!(unistd::getsid(None)?, unistd::getpid());

                        assert_eq!(unistd::getpgid(None)?, unistd::getpid());
                    }
                }
                // Stop this process group using either SIGTTIN, SIGTTOU, or SIGTSTP
                signal::killpg(Pid::this(), sig)?;
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
pub fn thread_reap() -> Result<()> {
    #[derive(Debug)]
    enum Case {
        Exit,
        PthreadExit,
    }
    fn parse_ps(path: &str) -> Result<Vec<Vec<String>>> {
        BufReader::new(File::open(path)?)
            .lines()
            .map(|l_res| {
                let l = l_res?;
                Ok(l.split(' ')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect::<Vec<String>>())
            })
            .collect::<Result<Vec<_>>>()
    }
    fn inner(case: Case) -> Result<()> {
        println!("Testing {case:?}");
        let [mut read_fd, write_fd] = crate::pipe();
        unsafe {
            assert_ne!(
                libc::fcntl(read_fd.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK),
                -1
            );
        }

        match unsafe { unistd::fork()? } {
            ForkResult::Child => thread::scope(|scope| {
                drop(read_fd);

                let threads = (0..16)
                    .map(|_| {
                        scope.spawn(|| {
                            thread::sleep(Duration::from_millis(200));
                            let _ = (&write_fd).write(&[1]).unwrap();
                            unsafe {
                                libc::pthread_exit(core::ptr::null_mut());
                            }
                        })
                    })
                    .collect::<Vec<_>>();
                thread::sleep(Duration::from_millis(100));

                // detach threads
                drop(threads);
                match case {
                    // other threads should be reaped
                    Case::Exit => std::process::exit(0),
                    // other threads will need to exit themselves
                    Case::PthreadExit => unsafe { libc::pthread_exit(core::ptr::null_mut()) },
                }
            }),
            ForkResult::Parent { child } => {
                assert_eq!(
                    wait::waitpid(child, Some(WaitPidFlag::empty())),
                    Ok(WaitStatus::Exited(child, 0))
                );
                match case {
                    Case::Exit => {
                        let error = read_fd.read(&mut [0]).expect_err("pipe was nonempty");
                        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
                    }
                    Case::PthreadExit => {
                        let mut buf = [0_u8; 16];
                        read_fd.read_exact(&mut buf).unwrap();
                        assert_eq!(buf, [1_u8; 16]);
                    }
                }
                drop(write_fd);
                for ref line in parse_ps("/scheme/sys/context")? {
                    let Some(line_f) = line.first() else {
                        continue;
                    };
                    let Ok(line_pid) = line_f.parse() else {
                        continue;
                    };
                    if child.as_raw() == line_pid {
                        panic!(
                            "thread remained for pid {}, (ps {:?})",
                            child.as_raw(),
                            line
                        );
                    }
                }
            }
        }

        Ok(())
    }

    inner(Case::Exit)?;
    inner(Case::PthreadExit)?;
    Ok(())
}
pub fn waitpid_setpgid_echild() -> Result<()> {
    #[derive(Debug)]
    enum Case {
        Setpgid,
        Setsid,
    }

    let parent = unistd::getpid();
    unistd::setpgid(parent, parent)?;

    for case in [Case::Setpgid, Case::Setsid] {
        println!("Testing waitpid-setpgid == ECHILD, case {case:?}");
        match unsafe { unistd::fork()? } {
            ForkResult::Child => {
                let child = unistd::getpid();
                thread::sleep(Duration::from_millis(100));
                match case {
                    Case::Setsid => assert_eq!(unistd::setsid()?, child),
                    Case::Setpgid => unistd::setpgid(child, child)?,
                }
                assert_eq!(unistd::getpgid(None)?, child);
                thread::sleep(Duration::MAX);
                std::process::exit(0);
            }
            ForkResult::Parent { child } => {
                let before = Instant::now();

                // group (-child) shall match child until setpgid, when there are no children left
                // matching pgid
                assert_eq!(
                    wait::waitpid(
                        Some(Pid::from_raw(-parent.as_raw())),
                        Some(WaitPidFlag::empty())
                    ),
                    Err(Errno::ECHILD)
                );

                // Check that it actually blocked
                let delta = before.elapsed();
                assert!(delta >= Duration::from_millis(100));

                signal::kill(child, Signal::SIGTERM)?;
                // None (-1) shall match child
                assert_eq!(
                    wait::waitpid(None, Some(WaitPidFlag::empty())),
                    Ok(WaitStatus::Signaled(child, Signal::SIGTERM, false))
                );
            }
        }
    }
    Ok(())
}
pub fn orphan_exit_sighup<const SEPARATE_SESSION: bool>() -> Result<()> {
    println!("Testing SIGHUP for newly-orphaned process groups");
    // Start a new session with a few subprocesses, and check that all of them get a SIGHUP if the
    // process group becomes an orphan process group. An orphaned process group is defined by POSIX
    // 2024 as
    //
    // > A process group in which the parent of every member is either itself a member of the group
    // > or is not a member of the group’s session (p. 67).
    //
    // with the behavior
    //
    // > If the exit of the process causes a process group to become orphaned, and if any member of
    // > the newly-orphaned process group is stopped, then a SIGHUP signal followed by a SIGCONT
    // > signal shall be sent to each process in the newly-orphaned process group (p. 569).
    //
    // A group is thus non-orphan iff there exists a process whose parent has the same sid but a
    // different pgid.
    //
    // So we want to construct a new group in the same session as before, making them group
    // nonorphan. We then kill the group leader, making it orphan since the children's pgids are
    // not the same as init's (1), and observe SIGHUP being sent to the reparented child processes.
    //
    //              GRANDPARENT (pgid=1)
    //                  PARENT (pgid!=1)
    //          CHILD0  CHILD1  CHILD2  ...CHILDn (pgid=1)
    //
    // We then make PARENT exit before CHILD0..n, reparenting all children to init. This removes
    // the link to outside the process group, and if any of CHILD0..CHILDn are stopped, they will
    // be SIGCONT'd and SIGHUP'd.

    if SEPARATE_SESSION {
        unistd::setsid()?;
    } else if unistd::getppid().as_raw() != 1 || unistd::getpgid(None)?.as_raw() != 1 {
        eprintln!("warning: this test only works when ppid and pgid is init!");
        std::process::exit(0);
    }

    // Mask SIGHUP
    let mut just_sighup = SigSet::empty();
    just_sighup.add(Signal::SIGHUP);
    signal::sigprocmask(SigmaskHow::SIG_BLOCK, Some(&just_sighup), None)?;

    let [mut read_fd, mut write_fd] = crate::pipe();

    const N: u8 = 4;

    if let ForkResult::Parent { child } = unsafe { unistd::fork()? } {
        // GRANDPARENT

        drop(write_fd);
        assert_eq!(
            wait::waitpid(child, Some(WaitPidFlag::empty())),
            Ok(WaitStatus::Exited(child, 0))
        );
        let mut buf = [0xFF_u8; N as usize];
        read_fd.read_exact(&mut buf)?;
        println!("BUF: {buf:?}");
        buf.sort();
        for i in 0..N {
            assert_eq!(buf[usize::from(i)], i);
        }
        return Ok(());
    }
    drop(read_fd);

    for i in 0..N {
        let ForkResult::Child = (unsafe { unistd::fork()? }) else {
            // PARENT
            continue;
        };
        // CHILDi

        // TODO: add to redox
        // just_sighup.wait().expect("failed to wait for SIGHUP");

        signal::kill(Pid::this(), Signal::SIGSTOP)?;

        let mut sig = 0 as libc::c_int;
        assert_eq!(
            unsafe { libc::sigwait(&just_sighup as *const _ as *const libc::sigset_t, &mut sig) },
            0
        );
        assert_eq!(sig, Signal::SIGHUP as libc::c_int);

        write_fd.write(&[i]).expect("failed to write to pipe");
        std::process::exit(0); // only init will notice
    }
    // PARENT
    unistd::setpgid(Pid::this(), Pid::this())?;
    thread::sleep(Duration::from_millis(100));
    std::process::exit(0);
}
pub fn wcontinued_sigcont_catching() -> Result<()> {
    let [mut read_fd, write_fd] = crate::pipe();

    let signals = [
        Signal::SIGSTOP,
        Signal::SIGTSTP,
        Signal::SIGTTIN,
        Signal::SIGTTOU,
    ];
    match unsafe { unistd::fork()? } {
        ForkResult::Child => {
            static WRITE_FD: AtomicUsize = AtomicUsize::new(0);
            WRITE_FD.store(write_fd.into_raw_fd() as usize, Ordering::SeqCst);

            // FIXME: this also fails, but not on Linux
            /*
            extern "C" fn handler(sig: libc::c_int) {
                let buf = [sig as u8];
                let fd = WRITE_FD.load(Ordering::SeqCst);
                if unsafe { libc::write(fd as libc::c_int, buf.as_ptr().cast(), buf.len()) } != 1 {
                    core::intrinsics::abort();
                }
            }
            unsafe {
                let handler = SigHandler::Handler(handler);
                let action = signal::SigAction::new(handler, SaFlags::empty(), SigSet::empty());
                signal::sigaction(Signal::SIGCONT, &action)?;
            }
            */

            drop(read_fd);
            for signal in signals {
                println!("Stopping due to {signal:?}");
                signal::raise(signal).unwrap();
                // allows signal handler to run
                thread::sleep(Duration::from_millis(500));
            }
            std::process::exit(0);
        }
        ForkResult::Parent { child } => {
            drop(write_fd);
            for signal in signals {
                println!("Signal {signal:?}");
                assert_eq!(
                    wait::waitpid(
                        child,
                        Some(WaitPidFlag::WUNTRACED | WaitPidFlag::WCONTINUED)
                    )?,
                    WaitStatus::Stopped(child, signal)
                );
                println!("--stopped");
                signal::kill(child, Signal::SIGCONT)?;
                assert_eq!(
                    wait::waitpid(
                        child,
                        Some(WaitPidFlag::WUNTRACED | WaitPidFlag::WCONTINUED)
                    )?,
                    WaitStatus::Continued(child)
                );
                println!("--contd");
                // FIXME: this also fails, but not on Linux
                /*
                let mut buf = [0xFF];
                assert_eq!(read_fd.read(&mut buf)?, 1);
                assert_eq!(buf[0], Signal::SIGCONT as u8);
                */
            }
        }
    }
    Ok(())
}
pub fn using_signal_hook() -> Result<()> {
    let flag = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGALRM, Arc::clone(&flag))?;

    struct ForceSendSync<T>(T);
    unsafe impl<T> Send for ForceSendSync<T> {}
    unsafe impl<T> Sync for ForceSendSync<T> {}

    let main_thread = ForceSendSync(unsafe { libc::pthread_self() });
    let thread = thread::spawn(move || unsafe {
        let main_thread = main_thread;
        thread::sleep(Duration::from_millis(100));
        assert_eq!(libc::pthread_kill(main_thread.0, libc::SIGALRM), 0);
    });
    thread::sleep(Duration::from_millis(200));
    assert!(flag.load(Ordering::SeqCst));
    thread.join().unwrap();
    Ok(())
}
pub fn waitpid_esrch() -> Result<()> {
    // Spawn a few children, then waitpid "any child" until ECHILD, followed by checks that further
    // waitpids return ESRCH.
    const N: usize = 4;

    let mut children = Vec::new();
    for _ in 0..N {
        if let ForkResult::Parent { child } = unsafe { unistd::fork()? } {
            // PARENT
            children.push(child);
            continue;
        }
        // CHILD: exit immediately
        std::process::exit(0);
    }
    children.sort();

    let mut awaited_children = Vec::new();

    loop {
        let res = wait::wait();
        if let Err(Errno::ECHILD) = res {
            break;
        };
        let Ok(WaitStatus::Exited(child, 0)) = res else {
            panic!("unexpected status: {res:?}");
        };
        awaited_children.push(child);
    }
    awaited_children.sort();
    assert_eq!(children, awaited_children);

    for child in awaited_children {
        assert_eq!(wait::waitpid(child, None), Err(Errno::ECHILD));
    }

    Ok(())
}

pub fn waitpid_status_discard() -> Result<()> {
    // POSIX 2024 states (p. 564):
    //
    // > If new status information is generated, and the process already had status information, the
    // > existing status information shall be discarded and replaced with the new status information.
    //
    // We can test this by creating a child process, stopping it+continuing it repeatedly, and
    // ensuring only the latest status information is available at any given time.

    match unsafe { unistd::fork()? } {
        ForkResult::Child => {
            thread::sleep(Duration::MAX);
            unreachable!();
        }
        ForkResult::Parent { child } => {
            signal::kill(child, Signal::SIGSTOP)?;

            // TODO: repeatedly?
            signal::kill(child, Signal::SIGCONT)?;
            signal::kill(child, Signal::SIGTERM)?;

            // Not guaranteed it has time to terminate otherwise.
            thread::sleep(Duration::from_millis(100));

            let flags = WaitPidFlag::WUNTRACED | WaitPidFlag::WCONTINUED;
            assert_eq!(
                wait::waitpid(child, Some(flags)),
                Ok(WaitStatus::Signaled(child, Signal::SIGTERM, false))
            );
            assert_eq!(wait::waitpid(child, Some(flags)), Err(Errno::ECHILD));
            assert_eq!(wait::wait(), Err(Errno::ECHILD));
            assert_eq!(signal::kill(child, Signal::SIGALRM), Err(Errno::ESRCH));
            assert_eq!(wait::waitpid(child, Some(flags)), Err(Errno::ECHILD));
        }
    }

    Ok(())
}
pub fn waitpid_transitive_queue() -> Result<()> {
    // Spawn a lot of children
    let mut children = Vec::new();

    for _ in 0..100 {
        if let ForkResult::Parent { child } = unsafe { unistd::fork()? } {
            children.push(child);
            continue;
        }
        // CHILDi
        thread::sleep(Duration::MAX);
        unreachable!();
    }
    // PARENT
    // make CHILDi where i divisble by 10, process group leaders
    for i in (0..100).filter(|i| *i % 10 == 0) {
        unistd::setpgid(children[i], children[i])?;
    }
    // make other CHILDi's belong to group leader CHILD_floor((100-i)/10)*10
    for i in (0..100).filter(|i| *i % 10 != 0) {
        let j = (100 - i) / 10 * 10;
        unistd::setpgid(children[i], children[j])?;
    }
    // exit all leaders and remove them from waitpid queue
    for i in (0..100).filter(|i| *i % 10 == 0) {
        signal::kill(children[i], Signal::SIGTERM)?;
        assert_eq!(
            wait::waitpid(
                Pid::from_raw(-children[i].as_raw()),
                Some(WaitPidFlag::empty())
            ),
            Ok(WaitStatus::Signaled(children[i], Signal::SIGTERM, false))
        );
    }
    // kill all remaining children
    for i in (0..100).filter(|i| *i % 10 != 0) {
        signal::kill(children[i], Signal::SIGTERM)?;
    }
    thread::sleep(Duration::from_millis(1000));

    // now, wait for process groups
    let res = wait::waitpid(
        Pid::from_raw(-children[30].as_raw()),
        Some(WaitPidFlag::WNOHANG),
    );
    // haven't waited for any non-leader child proc in that group
    assert_ne!(res, Err(Errno::ECHILD),);
    // all of the children should be dead by now
    assert_ne!(res, Ok(WaitStatus::StillAlive));

    Ok(())
}
