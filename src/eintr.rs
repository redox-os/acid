use std::thread;
use syscall::{Error, EINTR};

pub fn eintr() -> anyhow::Result<()> {
    let mut fds = [0; 2];
    unsafe {
        assert_ne!(libc::pipe(fds.as_mut_ptr()), -1);
    }
    let [reader1, writer1] = fds.map(|i| i as usize);

    let pid = syscall::getpid().unwrap();

    extern "C" fn h(_: usize) {
    }
    let _ = syscall::sigaction(syscall::SIGUSR1, Some(&syscall::SigAction {
        sa_handler: Some(h),
        ..Default::default()
    }), None);

    let handle = thread::spawn(move || {
        let _ = syscall::read(reader1, &mut [0]).unwrap();
        let _ = syscall::kill(pid, syscall::SIGUSR1).unwrap();
    });


    let listener = syscall::open("chan:acid", syscall::O_CREAT).unwrap();
    let _writer2 = syscall::open("chan:acid", 0).unwrap();
    let reader2 = syscall::dup(listener, b"listen").unwrap();

    let _ = syscall::write(writer1, &[0]);

    assert_eq!(syscall::read(reader2, &mut [0]).unwrap_err(), Error::new(EINTR));

    handle.join().unwrap();
    Ok(())
}
