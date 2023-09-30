use std::convert::Infallible;

use libc::c_int;
use syscall::{
    Result,
    Error,
    close,
    EIO,
    pipe2,
    read,
    write,
    SchemeMut,
    Packet,
    O_CREAT,
    O_RDWR,
    O_CLOEXEC, EINTR,
};

#[must_use = "Daemon::ready must be called"]
pub struct Daemon {
    write_pipe: usize,
}

impl Daemon {
    pub fn new<F: FnOnce(Daemon) -> Infallible>(f: F) -> Result<u8> {
        let mut pipes = [0 as c_int; 2];
        unsafe {
            assert_eq!(libc::pipe(pipes.as_mut_ptr()), 0);
        }

        let [read_pipe, write_pipe] = pipes.map(|p| p as usize);

        let res = unsafe { libc::fork() };
        assert!(res >= 0);

        if res == 0 {
            let _ = close(read_pipe);

            f(Daemon {
                write_pipe,
            });
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
                Ok(data[0])
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

pub fn scheme(name: &str, scheme_name: &str, mut scheme: impl SchemeMut) -> Result<()> {
    Daemon::new(move |daemon: Daemon| -> std::convert::Infallible {
        let error_handler = |error| -> ! {
            eprintln!("error in {} daemon: {}", name, error);
            std::process::exit(1)
        };

        let socket = syscall::open(format!(":{}", scheme_name), O_CREAT | O_RDWR | O_CLOEXEC).unwrap_or_else(|error| error_handler(error));

        daemon.ready().unwrap_or_else(|error| error_handler(error));

        let mut packet = Packet::default();

        'outer: loop {
            'read: loop {
                match syscall::read(socket, &mut packet) {
                    Ok(0) => break 'outer,
                    Ok(_) => break 'read,
                    Err(Error { errno: EINTR }) => continue 'read,
                    Err(other) => error_handler(other),
                }
            }
            scheme.handle(&mut packet);
            'write: loop {
                match syscall::write(socket, &packet) {
                    Ok(0) => break 'outer,
                    Ok(_) => break 'write,
                    Err(Error { errno: EINTR }) => continue 'write,
                    Err(other) => error_handler(other),
                }
            }
        }
        let _ = syscall::close(socket);

        std::process::exit(0);
    })?;

    Ok(())
}
