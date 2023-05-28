use std::convert::Infallible;

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
    O_CLOEXEC,
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
        let e = |r| {
            match r {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("error in {} daemon: {}", name, e);
                    std::process::exit(1);
                }
            }
        };

        let socket = e(syscall::open(format!(":{}", scheme_name), O_CREAT | O_RDWR | O_CLOEXEC));

        daemon.ready();

        let mut packet = Packet::default();

        loop {
            if e(syscall::read(socket, &mut packet)) == 0 { break };
            scheme.handle(&mut packet);
            if e(syscall::write(socket, &packet)) == 0 { break }
        }
        let _ = syscall::close(socket);

        std::process::exit(0);
    })?;

    Ok(())
}
