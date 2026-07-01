use std::convert::Infallible;

use libc::c_int;
use libredox::call::close;
use redox_scheme::scheme::SchemeSync;
use syscall::{read, write, Error, Result, EINTR, EIO, O_CREAT, O_RDWR};

#[must_use = "Daemon::ready must be called"]
pub struct Daemon {
    write_pipe: usize,
}

pub struct DaemonGuard {
    pid: i32,
    #[allow(unused)]
    res: u8,
}

impl Daemon {
    #[must_use]
    pub fn new<F: FnOnce(Daemon) -> Infallible>(f: F) -> Result<DaemonGuard> {
        let mut pipes = [0 as c_int; 2];
        unsafe {
            assert_eq!(libc::pipe(pipes.as_mut_ptr()), 0);
        }

        let [read_pipe, write_pipe] = pipes.map(|p| p as usize);

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);

        if pid == 0 {
            let _ = close(read_pipe);

            f(Daemon { write_pipe });
            // TODO: Replace Infallible with the never type once it is stabilized.
            unreachable!();
        } else {
            let _ = close(write_pipe);

            let mut data = [0];
            let res = read(read_pipe, &mut data);
            let _ = close(read_pipe);

            if res? == 1 {
                //exit(data[0] as usize)?;
                //unreachable!();
                Ok(DaemonGuard { res: data[0], pid })
            } else {
                Err(Error::new(EIO))
            }
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

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        unsafe { libc::kill(self.pid, libc::SIGKILL) };
    }
}

pub fn scheme(name: &str, scheme_name: &str, mut _scheme: impl SchemeSync) -> Result<DaemonGuard> {
    let guard = Daemon::new(move |daemon: Daemon| -> std::convert::Infallible {
        let error_handler = |error: syscall::Error| -> ! {
            eprintln!("error in {} daemon: {}", name, error);
            std::process::exit(1)
        };

        let socket = libredox::call::open(
            format!(":{}", scheme_name),
            (O_CREAT | O_RDWR) as i32 | libredox::flag::O_CLOEXEC,
            0,
        )
        .unwrap_or_else(|error| error_handler(error.into()));

        daemon.ready().unwrap_or_else(|error| error_handler(error));

        let mut packet = [0; 4096];

        'outer: loop {
            'read: loop {
                match syscall::read(socket, &mut packet) {
                    Ok(0) => break 'outer,
                    Ok(_) => break 'read,
                    Err(Error { errno: EINTR }) => continue 'read,
                    Err(other) => error_handler(other),
                }
            }
            // scheme.handle(&mut packet);
            'write: loop {
                match syscall::write(socket, &packet) {
                    Ok(0) => break 'outer,
                    Ok(_) => break 'write,
                    Err(Error { errno: EINTR }) => continue 'write,
                    Err(other) => error_handler(other),
                }
            }
        }
        let _ = libredox::call::close(socket);

        std::process::exit(0);
    })?;

    Ok(guard)
}
