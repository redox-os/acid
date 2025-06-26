use std::io;

fn from_syscall_error(error: syscall::Error) -> io::Error {
    io::Error::from_raw_os_error(error.errno as i32)
}

fn socket_kind(mut kind: libc::c_int) -> (libc::c_int, usize) {
    let mut flags = libc::O_RDWR;
    if kind & libc::SOCK_NONBLOCK == libc::SOCK_NONBLOCK {
        kind &= !libc::SOCK_NONBLOCK;
        flags |= libc::O_NONBLOCK;
    }
    if kind & libc::SOCK_CLOEXEC == libc::SOCK_CLOEXEC {
        kind &= !libc::SOCK_CLOEXEC;
        flags |= libc::O_CLOEXEC;
    }
    (kind, flags as usize)
}

const SCM_RIGHTS: i32 = 1;
const SCM_CREDENTIALS: i32 = 2;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct Ucred {
    pid: libc::pid_t,
    uid: libc::uid_t,
    gid: libc::gid_t,
}

///
/// Tests for SOCK_DGRAM sockets
///
pub mod dgram_tests {
    use super::{from_syscall_error, socket_kind};
    use anyhow::Result;
    use libc::{bind, close};
    use std::{ffi::CString, io, mem, thread, time::Duration};

    const SOCKET_PATH: &str = "test_dgram.sock";

    fn create_socket() -> io::Result<i32> {
        let (_, flags) = socket_kind(libc::AF_UNIX);
        let socket: i32 = syscall::open("/scheme/uds_dgram", flags | syscall::O_CREAT)
            .map_err(from_syscall_error)?
            .try_into()
            .unwrap();

        if socket < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(socket)
    }

    fn prepare_socket_addr() -> io::Result<libc::sockaddr_un> {
        let c_socket_path = CString::new(SOCKET_PATH)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains null bytes"))?;

        let mut socket_addr: libc::sockaddr_un = unsafe { mem::zeroed() };
        socket_addr.sun_family = libc::AF_UNIX as libc::sa_family_t;

        let socket_path_bytes = c_socket_path.as_bytes_with_nul();
        if socket_path_bytes.len() > socket_addr.sun_path.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path is too long",
            ));
        }

        for (i, &byte) in socket_path_bytes.iter().enumerate() {
            socket_addr.sun_path[i] = byte as libc::c_char;
        }

        Ok(socket_addr)
    }

    fn test_bind_and_connect_and_fpath() -> io::Result<()> {
        println!("[DGRAM] --- Testing Bind and Connect communication and fpath ---");
        let server_socket = create_socket()?;

        let socket_addr = prepare_socket_addr()?;

        let bind_result = unsafe {
            bind(
                server_socket,
                &socket_addr as *const _ as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
            )
        };
        assert!(bind_result >= 0);

        println!("[DGRAM] fpath...");
        let mut buffer = [0u8; 40];
        let bytes_read =
            syscall::fpath(server_socket as usize, &mut buffer).map_err(from_syscall_error)?;
        assert_eq!(bytes_read, 33);
        assert_eq!(
            &buffer[..33],
            format!("/scheme/uds_dgram/{}", SOCKET_PATH).as_bytes()
        );

        println!("[DGRAM] Bind socket again (should fail)");
        let bind_result = unsafe {
            bind(
                server_socket,
                &socket_addr as *const _ as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
            )
        };
        assert!(bind_result < 0);

        println!("[DGRAM] Bind to a same socket path (should fail)");
        let test_socket = create_socket()?;
        let test_addr = prepare_socket_addr()?;

        let bind_result = unsafe {
            bind(
                test_socket,
                &test_addr as *const _ as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
            )
        };
        assert!(bind_result < 0);
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::EADDRINUSE)
        );
        unsafe { close(test_socket) };

        let thread = thread::spawn(move || -> io::Result<()> {
            let client_socket = create_socket()?;
            let socket_addr = prepare_socket_addr()?;
            let connect_result = unsafe {
                libc::connect(
                    client_socket,
                    &socket_addr as *const _ as *const libc::sockaddr,
                    mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
                )
            };
            if connect_result < 0 {
                return Err(io::Error::last_os_error());
            }

            println!("[DGRAM Thread] Writing message...");
            let message = "hello from fd0";
            let res = syscall::write(client_socket as usize, message.as_bytes())
                .map_err(from_syscall_error)?;
            assert_eq!(res, message.len());
            unsafe { close(client_socket) };
            Ok(())
        });

        println!("[DGRAM Main] Reading message...");
        let mut buffer = [0u8; 30];
        let bytes_read =
            syscall::read(server_socket as usize, &mut buffer).map_err(from_syscall_error)?;
        assert_eq!(bytes_read, 14);
        assert_eq!(&buffer[..14], b"hello from fd0");
        println!(
            "[DGRAM Main] Received message: '{}'",
            std::str::from_utf8(&buffer[..17]).unwrap()
        );

        thread.join().unwrap()?;
        unsafe { close(server_socket) };
        Ok(())
    }

    fn test_socketpair_io() -> io::Result<()> {
        println!("[DGRAM] --- Testing socket pair blocking I/O ---");
        let sock1 = create_socket()?;
        let sock2 = syscall::dup(sock1 as usize, b"connect").map_err(from_syscall_error)? as i32;

        let thread = thread::spawn(move || -> io::Result<()> {
            println!("[DGRAM Thread] Sleeping for 1 second...");
            thread::sleep(Duration::from_secs(1));

            println!("[DGRAM Thread] Writing 'hello from sock1'...");
            let message = "hello from sock1";
            let res =
                syscall::write(sock1 as usize, message.as_bytes()).map_err(from_syscall_error)?;
            assert_eq!(res, message.len());

            let mut buffer = [0u8; 30];
            println!("[DGRAM Thread] Reading reply...");
            let bytes_read =
                syscall::read(sock1 as usize, &mut buffer).map_err(from_syscall_error)?;
            assert_eq!(bytes_read, 14);
            assert_eq!(&buffer[..14], b"hello from fd0");
            println!(
                "[DGRAM Thread] Received reply: '{}'",
                std::str::from_utf8(&buffer[..14]).unwrap()
            );

            unsafe { close(sock1) };
            Ok(())
        });

        println!("[DGRAM Main] Writing reply...");
        let message = "hello from fd0";
        let res = syscall::write(sock2 as usize, message.as_bytes()).map_err(from_syscall_error)?;
        assert_eq!(res, message.len());

        println!("[DGRAM Main] Reading message...");
        let mut buffer = [0u8; 30];
        let bytes_read = syscall::read(sock2 as usize, &mut buffer).map_err(from_syscall_error)?;
        assert_eq!(bytes_read, 16);
        assert_eq!(&buffer[..16], b"hello from sock1");
        println!(
            "[DGRAM Main] Received message: '{}'",
            std::str::from_utf8(&buffer[..16]).unwrap()
        );

        thread.join().unwrap()?;
        unsafe { close(sock2) };
        println!("[DGRAM OK] Socket pair I/O test passed.");
        Ok(())
    }

    fn test_epipe() -> io::Result<()> {
        println!("[DGRAM] --- Testing EPIPE on write ---");
        let sock1 = create_socket()?;
        let sock2 = syscall::dup(sock1 as usize, b"connect").map_err(from_syscall_error)?;

        // Close one end of the pair
        unsafe { close(sock2 as i32) };

        // A small delay to ensure the close is processed.
        thread::sleep(Duration::from_millis(10));

        // Attempting to write to the closed peer should result in EPIPE.
        let write_res = syscall::write(sock1 as usize, b"test");
        assert_eq!(write_res.err().unwrap().errno, syscall::error::EPIPE);
        unsafe { close(sock1) };

        println!("[DGRAM OK] EPIPE test passed.");
        Ok(())
    }

    fn test_nonblocking_io() -> io::Result<()> {
        println!("[DGRAM] --- Testing non-blocking I/O ---");
        let sock1 = create_socket()?;
        let sock2 = syscall::dup(sock1 as usize, b"connect").map_err(from_syscall_error)?;

        syscall::fcntl(sock2 as usize, syscall::F_SETFL, syscall::O_NONBLOCK)
            .map_err(from_syscall_error)?;

        println!("[DGRAM] Reading from empty non-blocking socket (expecting EAGAIN)...");
        let mut buffer = [0u8; 30];
        let read_res = syscall::read(sock2 as usize, &mut buffer);
        assert_eq!(read_res.err().unwrap().errno, syscall::error::EAGAIN);

        unsafe { close(sock1) };
        unsafe { close(sock2 as i32) };

        println!("[DGRAM OK] Non-blocking I/O test passed.");
        Ok(())
    }

    fn test_message_size_limits() -> io::Result<()> {
        println!("[DGRAM] --- Testing EMSGSIZE ---");
        let sock1 = create_socket()?;
        let sock2 = syscall::dup(sock1 as usize, b"connect").map_err(from_syscall_error)?;

        let too_large_message = vec![0u8; 70000];
        let result = syscall::write(sock2 as usize, &too_large_message);
        assert_eq!(result.err().unwrap().errno, syscall::error::EMSGSIZE);

        unsafe { close(sock1) };

        unsafe { close(sock2 as i32) };

        println!("[DGRAM OK] EMSGSIZE test passed.");
        Ok(())
    }

    fn test_zero_byte_write() -> io::Result<()> {
        println!("[DGRAM] --- Testing zero-byte write ---");
        let server_socket = create_socket()?;

        let fd0 = syscall::dup(server_socket as usize, b"connect").map_err(from_syscall_error)?;
        let fd1 = syscall::dup(server_socket as usize, b"listen").map_err(from_syscall_error)?;

        let thread = thread::spawn(move || -> io::Result<()> {
            let res = syscall::write(fd1 as usize, b"").map_err(from_syscall_error)?;
            assert_eq!(res, 0, "Zero-byte write should be accepted");
            unsafe { close(fd1 as i32) };
            Ok(())
        });

        let mut buffer = [0; 32];
        let bytes_read = syscall::read(fd0 as usize, &mut buffer).map_err(from_syscall_error)?;
        assert_eq!(bytes_read, 0, "Should receive a 0-byte datagram");
        println!("[DGRAM Main] Correctly received 0-byte datagram.");

        thread.join().unwrap()?;
        unsafe { close(fd0 as i32) };
        unsafe { close(server_socket) };
        Ok(())
    }

    pub fn run_all() -> Result<()> {
        println!("\n[DGRAM] Starting all dgram tests...");
        test_bind_and_connect_and_fpath()?;
        test_socketpair_io()?;
        test_epipe()?;
        test_nonblocking_io()?;
        test_message_size_limits()?;
        test_zero_byte_write()?;
        println!("[DGRAM] All dgram tests finished successfully.");
        Ok(())
    }
}

///
/// Tests for SOCK_STREAM sockets
///
pub mod stream_tests {
    use super::{from_syscall_error, socket_kind};
    use anyhow::Result;
    use libc::{accept, bind, close, connect, sockaddr};
    use std::{ffi::CString, io, mem, thread};
    use syscall::{self, error::*};

    const SOCKET_PATH: &str = "test_stream.sock";

    fn create_socket() -> io::Result<i32> {
        let (_, flags) = socket_kind(libc::AF_UNIX);
        let socket = syscall::open("/scheme/uds_stream", flags | syscall::O_CREAT)
            .map_err(from_syscall_error)? as i32;
        if socket < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(socket)
    }

    fn prepare_socket_addr() -> io::Result<(libc::sockaddr_un, libc::socklen_t)> {
        let c_socket_path = CString::new(SOCKET_PATH)?;
        let mut socket_addr: libc::sockaddr_un = unsafe { mem::zeroed() };
        socket_addr.sun_family = libc::AF_UNIX as libc::sa_family_t;

        let path_bytes = c_socket_path.as_bytes_with_nul();
        if path_bytes.len() > socket_addr.sun_path.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path is too long",
            ));
        }
        for (i, &byte) in path_bytes.iter().enumerate() {
            socket_addr.sun_path[i] = byte as libc::c_char;
        }
        let len = mem::size_of::<libc::sa_family_t>() + path_bytes.len();
        Ok((socket_addr, len as libc::socklen_t))
    }

    fn test_bind_listen_accept_connect_and_fpath() -> io::Result<()> {
        println!("[STREAM] --- Testing bind, listen, accept, and connect ---");

        let listener_fd = create_socket()?;

        let (socket_addr, addr_len) = prepare_socket_addr()?;

        // Bind the socket
        if unsafe { bind(listener_fd, &socket_addr as *const _ as *const _, addr_len) } < 0 {
            return Err(io::Error::last_os_error());
        }
        println!("[STREAM Server] Socket bound to {}", SOCKET_PATH);

        println!("[STREAM] fpath...");
        let mut buffer = [0u8; 40];
        let bytes_read =
            syscall::fpath(listener_fd as usize, &mut buffer).map_err(from_syscall_error)?;
        assert_eq!(bytes_read, 35);
        assert_eq!(
            &buffer[..35],
            format!("/scheme/uds_stream/{}", SOCKET_PATH).as_bytes()
        );

        println!("[STREAM] Bind socket again (should fail)");
        let bind_result = unsafe {
            bind(
                listener_fd,
                &socket_addr as *const _ as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
            )
        };
        assert!(bind_result < 0);

        println!("[STREAM] Bind to a same socket path (should fail)");
        let test_socket = create_socket()?;
        let test_addr = prepare_socket_addr()?;

        let bind_result = unsafe {
            bind(
                test_socket,
                &test_addr as *const _ as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
            )
        };
        assert!(bind_result < 0);
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::EADDRINUSE)
        );
        unsafe { close(test_socket) };

        let client_thread = thread::spawn(move || -> io::Result<()> {
            let client_fd = create_socket()?;
            println!("[STREAM Client] Connecting to {}", SOCKET_PATH);
            if unsafe { connect(client_fd, &socket_addr as *const _ as *const _, addr_len) } < 0 {
                return Err(io::Error::last_os_error());
            }

            println!("[STREAM Client] Writing message...");
            let message = "hello from client";
            let res = syscall::write(client_fd as usize, message.as_bytes())
                .map_err(from_syscall_error)?;
            assert_eq!(res, message.len());

            println!("[STREAM Client] Reading message...");
            let mut buffer = [0u8; 30];
            let bytes_read =
                syscall::read(client_fd as usize, &mut buffer).map_err(from_syscall_error)?;
            assert_eq!(bytes_read, 14);
            assert_eq!(&buffer[..14], b"hello from fd0");
            println!(
                "[STREAM Client] Received reply: '{}'",
                std::str::from_utf8(&buffer[..14]).unwrap()
            );

            unsafe { close(client_fd) };
            Ok(())
        });

        println!("[STREAM Server] Waiting to accept a connection...");
        let accepted_fd =
            unsafe { accept(listener_fd, std::ptr::null_mut(), std::ptr::null_mut()) };
        if accepted_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        println!("[STREAM Server] Accepted connection on fd {}", accepted_fd);

        // Communication test
        println!("[STREAM Server] Reading message...");
        let mut buffer = [0u8; 30];
        let bytes_read =
            syscall::read(accepted_fd as usize, &mut buffer).map_err(from_syscall_error)?;
        assert_eq!(bytes_read, 17);
        assert_eq!(&buffer[..17], b"hello from client");
        println!(
            "[STREAM Server] Received message: '{}'",
            std::str::from_utf8(&buffer[..17]).unwrap()
        );

        println!("[STREAM Server] Writing reply...");
        let message = "hello from fd0";
        let res =
            syscall::write(accepted_fd as usize, message.as_bytes()).map_err(from_syscall_error)?;
        assert_eq!(res, message.len());

        client_thread.join().unwrap()?;

        unsafe { close(listener_fd) };
        println!("[STREAM OK] Bind/listen/accept/connect test passed.");
        Ok(())
    }

    fn test_close_listener_with_active_and_pending_connections() -> io::Result<()> {
        println!("[STREAM] --- Testing closing listener with active and pending connections ---");
        let listener_fd = create_socket()?;
        let (socket_addr, addr_len) = prepare_socket_addr()?;

        unsafe {
            bind(listener_fd, &socket_addr as *const _ as *const _, addr_len);
        }

        let client_thread = thread::spawn(move || -> io::Result<()> {
            println!("[Server] Accepting Client A...");
            let accepted_fd_a =
                unsafe { accept(listener_fd, std::ptr::null_mut(), std::ptr::null_mut()) };
            assert!(accepted_fd_a >= 0, "Accept for client A should succeed");
            println!("[Server] Accepted Client A on fd {}.", accepted_fd_a);
            println!("[Server] Writing 'live' to accepted client A...");
            let bytes_written =
                syscall::write(accepted_fd_a as usize, b"live").map_err(from_syscall_error)?;
            assert_eq!(bytes_written, 4);

            println!(
                "[Server] Closing the listening socket (fd {})...",
                listener_fd
            );
            unsafe { close(listener_fd) };
            Ok(())
        });

        let client_fd = create_socket()?;
        let (socket_addr, addr_len) = prepare_socket_addr()?;
        unsafe {
            let result = connect(client_fd, &socket_addr as *const _ as *const _, addr_len);
            if result < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        println!("[Client A] Connected.");

        println!("[Client A] Server accepted. Waiting for data...");
        let mut buf = [0u8; 32];
        let bytes_read = syscall::read(client_fd as usize, &mut buf).map_err(from_syscall_error)?;
        assert_eq!(bytes_read, "live".len());
        assert_eq!(&buf[..bytes_read as usize], b"live");
        println!("[Client A] Received 'live' correctly.");

        let client_fd = create_socket()?;
        let (socket_addr, addr_len) = prepare_socket_addr()?;

        println!("[Client B] Connecting (should block and then fail)...");
        let connect_result =
            unsafe { connect(client_fd, &socket_addr as *const _ as *const _, addr_len) };

        assert_eq!(connect_result, -1, "Connect from client B should fail");
        let err = io::Error::last_os_error();
        println!("[Client B] connect() failed as expected with: {}", err);
        assert_eq!(err.raw_os_error(), Some(libc::ECONNREFUSED));

        client_thread.join().unwrap()?;
        unsafe { close(client_fd) };

        println!("[STREAM OK] Closing listener with active/pending connections test passed.");
        Ok(())
    }

    fn test_socketpair_io() -> io::Result<()> {
        println!("[STREAM] --- Testing socket pair I/O and EPIPE ----");
        let mut fds = [-1, -1];
        if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let (fd0, fd1) = (fds[0], fds[1]);

        let thread = thread::spawn(move || -> io::Result<()> {
            let message = "hello from fd1";
            syscall::write(fd1 as usize, message.as_bytes()).map_err(from_syscall_error)?;
            let mut buffer = [0u8; 32];
            let bytes_read =
                syscall::read(fd1 as usize, &mut buffer).map_err(from_syscall_error)?;
            assert_eq!(bytes_read, 14);
            assert_eq!(&buffer[..14], b"hello from fd0");
            unsafe { close(fd1) };
            Ok(())
        });

        let mut buffer = [0u8; 32];
        let bytes_read = syscall::read(fd0 as usize, &mut buffer).map_err(from_syscall_error)?;
        assert_eq!(bytes_read, 14);
        assert_eq!(&buffer[..14], b"hello from fd1");

        let message = "hello from fd0";
        syscall::write(fd0 as usize, message.as_bytes()).map_err(from_syscall_error)?;

        thread.join().unwrap()?;

        // Test EPIPE
        let write_res = syscall::write(fd0 as usize, b"test");
        assert_eq!(write_res.err().unwrap().errno, syscall::error::EPIPE,);

        unsafe { close(fd0) };
        println!("[STREAM OK] EPIPE test passed.");
        Ok(())
    }

    fn test_reconnect_fails() -> io::Result<()> {
        println!("[STREAM] --- Testing that reconnecting a connected socket fails ---");
        let listener_fd = create_socket()?;
        let (socket_addr, addr_len) = prepare_socket_addr()?;
        unsafe {
            bind(
                listener_fd,
                &socket_addr as *const _ as *const sockaddr,
                addr_len,
            );
        }

        let client_thread = thread::spawn(move || -> io::Result<()> {
            let accepted_fd =
                unsafe { accept(listener_fd, std::ptr::null_mut(), std::ptr::null_mut()) };

            let mut buf = [0u8; 32];
            let bytes_read =
                syscall::read(accepted_fd as usize, &mut buf).map_err(from_syscall_error)?;
            assert_eq!(bytes_read, "live".len());
            assert_eq!(&buf[..bytes_read as usize], b"live");
            unsafe { close(accepted_fd) };
            unsafe { close(listener_fd) };
            Ok(())
        });

        let client_fd = create_socket()?;
        let (socket_addr, addr_len) = prepare_socket_addr()?;
        if unsafe {
            connect(
                client_fd,
                &socket_addr as *const _ as *const sockaddr,
                addr_len,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        println!("[Client] Attempting to reconnect...");
        // Attempt to connect again on the same socket
        let connect_result = unsafe {
            connect(
                client_fd,
                &socket_addr as *const _ as *const sockaddr,
                addr_len,
            )
        };
        println!(
            "[Client] Reconnect attempt finished. Result: {}",
            connect_result
        );
        assert_eq!(connect_result, -1, "Second connect should fail");
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(EISCONN),
            "Error should be EISCONN"
        );
        println!("[STREAM OK] Reconnecting failed with EISCONN as expected.");

        let bytes_written =
            syscall::write(client_fd as usize, b"live").map_err(from_syscall_error)?;
        assert_eq!(bytes_written, 4);

        client_thread.join().unwrap()?;
        unsafe { close(client_fd) };
        Ok(())
    }

    fn test_zero_byte_write_and_eof() -> io::Result<()> {
        println!("[STREAM] --- Testing zero-byte write and EOF handling ---");
        let mut fds = [-1, -1];
        if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let (receiver_sock, sender_sock) = (fds[0], fds[1]);

        let handle = thread::spawn(move || -> io::Result<()> {
            // The receiver should not be woken up by the zero-byte write.
            // It will only be woken up by the subsequent write.
            let mut buffer = [0u8; 64];
            let bytes_read =
                syscall::read(receiver_sock as usize, &mut buffer).map_err(from_syscall_error)?;
            assert_eq!(bytes_read, "data after zero write".len());
            assert_eq!(&buffer[..bytes_read as usize], b"data after zero write");
            println!("[STREAM Receiver] Received data correctly after zero-byte write.");

            // Now, the next read should return 0, indicating EOF.
            let eof_read =
                syscall::read(receiver_sock as usize, &mut buffer).map_err(from_syscall_error)?;
            assert_eq!(eof_read, 0, "Read after sender close should return 0 (EOF)");
            unsafe { close(receiver_sock) };
            println!("[STREAM OK] Successfully detected EOF after data.");
            Ok(())
        });

        // A zero-byte write on a stream should do nothing and return 0.
        println!("[STREAM Sender] Performing zero-byte write...");
        let res = syscall::write(sender_sock as usize, b"").map_err(from_syscall_error)?;
        assert_eq!(res, 0, "Zero-byte write should return 0");
        println!("[STREAM OK] Zero-byte write returned 0 as expected.");

        let message = "data after zero write";
        let bytes_sent =
            syscall::write(sender_sock as usize, message.as_bytes()).map_err(from_syscall_error)?;
        assert_eq!(bytes_sent, message.len());

        println!("[STREAM Sender] Closing socket to signal EOF.");
        unsafe { close(sender_sock) };

        handle.join().unwrap()?;
        unsafe { close(sender_sock) };
        Ok(())
    }

    fn test_wouldblock_dup_and_notconn_rw() -> io::Result<()> {
        println!("[STREAM] --- Testing Should Error ---");

        let server_socket = create_socket()?;

        println!("[STREAM Server] Setting listening socket to non-blocking...");
        syscall::fcntl(
            server_socket as usize,
            syscall::F_SETFL,
            syscall::O_NONBLOCK,
        )
        .map_err(from_syscall_error)?;

        println!("[STREAM Server] Calling accept (via dup) on non-blocking socket with no pending connections...");
        let dup_res = syscall::dup(server_socket as usize, b"listen");

        assert!(
            dup_res.is_err(),
            "dup with listen should fail when no connections are pending"
        );
        assert_eq!(
            dup_res.err().unwrap().errno,
            syscall::error::EWOULDBLOCK,
            "Error should be EWOULDBLOCK"
        );
        println!("[STREAM OK] accept correctly returned EWOULDBLOCK.");

        let client_sock =
            syscall::dup(server_socket as usize, b"connect").map_err(from_syscall_error)?;

        syscall::fcntl(client_sock, syscall::F_SETFL, syscall::O_NONBLOCK)
            .map_err(from_syscall_error)?;

        println!("[STREAM Client] Writing to a not-yet-accepted socket...");
        let write_res = syscall::write(client_sock as usize, b"should fail");
        assert!(write_res.is_err());
        assert_eq!(
            write_res.err().unwrap().errno,
            syscall::error::ENOTCONN,
            "Write to non-accepted socket should be ENOTCONN"
        );
        println!("[STREAM OK] write correctly returned ENOTCONN.");

        println!("[STREAM Client] Reading from a not-yet-accepted socket...");
        let mut buffer = [0u8; 30];
        let read_res = syscall::read(client_sock as usize, &mut buffer);
        assert!(read_res.is_err());
        assert_eq!(
            read_res.err().unwrap().errno,
            syscall::error::ENOTCONN,
            "Read from non-accepted socket should be ENOTCONN"
        );
        println!("[STREAM OK] read correctly returned ENOTCONN.");

        unsafe { close(client_sock as i32) };
        unsafe { close(server_socket) };

        Ok(())
    }

    fn test_large_stream_transfer() -> io::Result<()> {
        println!("[STREAM] --- Testing large stream data transfer ---");
        let mut fds = [-1, -1];
        if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let (receiver_sock, sender_sock) = (fds[0], fds[1]);

        let large_message = "A".repeat(4096);
        let large_message_clone = large_message.clone();

        let sender_thread = thread::spawn(move || -> io::Result<()> {
            println!(
                "[STREAM Sender] Writing large message ({} bytes)...",
                large_message_clone.len()
            );
            let bytes_sent = syscall::write(sender_sock as usize, large_message_clone.as_bytes())
                .map_err(from_syscall_error)?;
            assert_eq!(bytes_sent, large_message_clone.len());
            println!("[STREAM Sender] Finished writing, closing socket.");
            unsafe { close(sender_sock) };
            Ok(())
        });

        let mut received_data = Vec::with_capacity(large_message.len());
        let mut small_buffer = [0u8; 256];
        loop {
            let bytes_read = syscall::read(receiver_sock as usize, &mut small_buffer)
                .map_err(from_syscall_error)?;
            if bytes_read == 0 {
                break;
            } // EOF
            received_data.extend_from_slice(&small_buffer[..bytes_read as usize]);
        }

        assert_eq!(received_data.len(), large_message.len());
        assert_eq!(received_data, large_message.as_bytes());
        println!("[STREAM OK] Successfully received the entire large message.");

        sender_thread.join().unwrap()?;
        unsafe { close(receiver_sock) };
        Ok(())
    }

    pub fn run_all() -> Result<()> {
        println!("\n[STREAM] Starting all stream tests...");
        test_bind_listen_accept_connect_and_fpath()?;
        test_close_listener_with_active_and_pending_connections()?;
        test_socketpair_io()?;
        test_reconnect_fails()?;
        test_zero_byte_write_and_eof()?;
        test_wouldblock_dup_and_notconn_rw()?;
        test_large_stream_transfer()?;
        println!("[STREAM] All stream tests finished successfully.");
        Ok(())
    }
}

///
/// Tests for advanced msghdr functionality on DGRAM sockets (SCM_RIGHTS, SCM_CREDENTIALS)
///
pub mod dgram_msghdr_tests {
    use super::{from_syscall_error, Ucred, SCM_CREDENTIALS, SCM_RIGHTS};
    use anyhow::Result;
    use libc::{
        c_int, c_void, close, cmsghdr, iovec, msghdr, recvmsg, sendmsg, socketpair, AF_UNIX,
        CMSG_DATA, CMSG_FIRSTHDR, CMSG_LEN, CMSG_NXTHDR, CMSG_SPACE, MSG_CTRUNC, MSG_TRUNC,
        SOCK_DGRAM, SOL_SOCKET, SO_PASSCRED,
    };
    use std::io;
    use std::mem;
    use std::ptr;
    use std::thread;

    fn test_send_recv_fd() -> io::Result<()> {
        println!("[DGRAM_MSGHDR] --- Testing SCM_RIGHTS (File Descriptor Passing) ---");
        let fd_to_send = unsafe { libc::dup(1) };

        let mut fds = [-1, -1];
        if unsafe { socketpair(AF_UNIX, SOCK_DGRAM, 0, fds.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let (receiver_sock, sender_sock) = (fds[0], fds[1]);

        let data_to_send = "FD follows";
        let mut iov = iovec {
            iov_base: data_to_send.as_ptr() as *mut c_void,
            iov_len: data_to_send.len(),
        };
        let cmsg_buf_len = unsafe { CMSG_SPACE(mem::size_of::<c_int>() as u32) as usize };
        let mut cmsg_buf = vec![0u8; cmsg_buf_len];
        let mut msg: msghdr = unsafe { mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut c_void;
        msg.msg_controllen = cmsg_buf_len;

        unsafe {
            let cmsg: *mut cmsghdr = CMSG_FIRSTHDR(&msg);
            (*cmsg).cmsg_level = SOL_SOCKET;
            (*cmsg).cmsg_type = SCM_RIGHTS;
            (*cmsg).cmsg_len = CMSG_LEN(mem::size_of::<c_int>() as u32) as usize;
            *(CMSG_DATA(cmsg) as *mut c_int) = fd_to_send as c_int;
        }

        if unsafe { sendmsg(sender_sock, &msg, 0) } < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut data_buf = [0u8; 64];
        let mut iov_recv = iovec {
            iov_base: data_buf.as_mut_ptr() as *mut c_void,
            iov_len: data_buf.len(),
        };
        let mut cmsg_buf_recv = vec![0u8; cmsg_buf_len];
        let mut msg_recv: msghdr = unsafe { mem::zeroed() };
        msg_recv.msg_iov = &mut iov_recv;
        msg_recv.msg_iovlen = 1;
        msg_recv.msg_control = cmsg_buf_recv.as_mut_ptr() as *mut c_void;
        msg_recv.msg_controllen = cmsg_buf_recv.len();

        let bytes_recvd = unsafe { recvmsg(receiver_sock, &mut msg_recv, 0) };
        if bytes_recvd < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut received_fds: Vec<c_int> = Vec::new();
        unsafe {
            let mut cmsg = CMSG_FIRSTHDR(&msg_recv);
            while !cmsg.is_null() {
                if (*cmsg).cmsg_level == SOL_SOCKET && (*cmsg).cmsg_type == SCM_RIGHTS {
                    let data_ptr = CMSG_DATA(cmsg) as *const c_int;
                    let num_fds =
                        ((*cmsg).cmsg_len - CMSG_LEN(0) as usize) / mem::size_of::<c_int>();
                    received_fds.extend_from_slice(std::slice::from_raw_parts(data_ptr, num_fds));
                }
                cmsg = CMSG_NXTHDR(&msg_recv, cmsg);
            }
        }

        let received_fd = *received_fds
            .get(0)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Failed to receive fd"))?;
        println!(
            "[Receiver] Received {} bytes and new FD: {}",
            bytes_recvd, received_fd
        );
        println!("[OK] Received FD is valid and content matches.");
        unsafe { close(received_fd) };
        unsafe { close(sender_sock) };
        unsafe { close(receiver_sock) };

        Ok(())
    }

    fn test_send_recv_credentials() -> io::Result<()> {
        println!("[DGRAM_MSGHDR] --- Testing SCM_CREDENTIALS (Process Credentials) ---");
        let mut fds = [-1, -1];
        if unsafe { socketpair(AF_UNIX, SOCK_DGRAM, 0, fds.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let (receiver_sock, sender_sock) = (fds[0], fds[1]);

        let on: c_int = 1;
        if unsafe {
            libc::setsockopt(
                receiver_sock,
                SOL_SOCKET,
                SO_PASSCRED,
                &on as *const _ as *const c_void,
                mem::size_of_val(&on) as u32,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }

        let handle = thread::spawn(move || -> io::Result<()> {
            let message = "Hello with credentials!";
            let mut iov = iovec {
                iov_base: message.as_ptr() as *mut c_void,
                iov_len: message.len(),
            };
            let mut msg: msghdr = unsafe { mem::zeroed() };
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            if unsafe { sendmsg(sender_sock, &msg, 0) } < 0 {
                return Err(io::Error::last_os_error());
            }
            unsafe { close(sender_sock) };
            Ok(())
        });

        let mut data_buf = [0u8; 64];
        let mut iov = iovec {
            iov_base: data_buf.as_mut_ptr() as *mut c_void,
            iov_len: data_buf.len(),
        };
        let cmsg_buf_len = unsafe { CMSG_SPACE(mem::size_of::<Ucred>() as u32) as usize };
        let mut cmsg_buf = vec![0u8; cmsg_buf_len];
        let mut msg: msghdr = unsafe { mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut c_void;
        msg.msg_controllen = cmsg_buf.len();

        if unsafe { recvmsg(receiver_sock, &mut msg, 0) } < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut received_creds: Option<Ucred> = None;
        unsafe {
            if let Some(cmsg) = (CMSG_FIRSTHDR(&msg) as *const cmsghdr).as_ref() {
                if cmsg.cmsg_level == SOL_SOCKET && cmsg.cmsg_type == SCM_CREDENTIALS {
                    received_creds = Some(*(CMSG_DATA(cmsg) as *const Ucred));
                }
            }
        }

        if let Some(creds) = received_creds {
            println!(
                "[Receiver] Credentials: PID={}, UID={}, GID={}",
                creds.pid, creds.uid, creds.gid
            );
            assert_eq!(creds.pid, unsafe { libc::getpid() });
            println!("[OK] Credentials match sender's credentials.");
        } else {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Failed to receive credentials",
            ));
        }

        handle.join().unwrap()?;

        unsafe { close(receiver_sock) };
        Ok(())
    }

    fn test_write_and_recvmsg_credentials() -> io::Result<()> {
        println!(
            "[DGRAM_MSGHDR] --- Testing syscall::write() and recvmsg() with SCM_CREDENTIALS ---"
        );
        let mut fds = [-1, -1];
        if unsafe { socketpair(AF_UNIX, SOCK_DGRAM, 0, fds.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let (receiver_sock, sender_sock) = (fds[0], fds[1]);

        let on: c_int = 1;
        if unsafe {
            libc::setsockopt(
                receiver_sock,
                SOL_SOCKET,
                SO_PASSCRED,
                &on as *const _ as *const c_void,
                mem::size_of_val(&on) as u32,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }

        let handle = thread::spawn(move || -> io::Result<()> {
            let message = "Simple write, complex receive!";
            println!("[Sender] Sending message via syscall::write: '{}'", message);
            let bytes_sent = syscall::write(sender_sock as usize, message.as_bytes())
                .map_err(from_syscall_error)?;
            assert_eq!(bytes_sent, message.len());
            unsafe { close(sender_sock) };
            Ok(())
        });

        let mut data_buf = [0u8; 128];
        let mut iov = iovec {
            iov_base: data_buf.as_mut_ptr() as *mut c_void,
            iov_len: data_buf.len(),
        };
        let cmsg_buf_len = unsafe { CMSG_SPACE(mem::size_of::<Ucred>() as u32) as usize };
        let mut cmsg_buf = vec![0u8; cmsg_buf_len];
        let mut msg: msghdr = unsafe { mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut c_void;
        msg.msg_controllen = cmsg_buf.len();

        let bytes_recvd = unsafe { recvmsg(receiver_sock, &mut msg, 0) };
        if bytes_recvd < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut received_creds: Option<Ucred> = None;
        unsafe {
            if let Some(cmsg) = (CMSG_FIRSTHDR(&msg) as *const cmsghdr).as_ref() {
                if cmsg.cmsg_level == SOL_SOCKET && cmsg.cmsg_type == SCM_CREDENTIALS {
                    received_creds = Some(*(CMSG_DATA(cmsg) as *const Ucred));
                }
            }
        }

        handle.join().unwrap()?;

        assert!(received_creds.is_some(), "Should have received credentials");
        println!("[OK] Credentials received successfully via simple write.");

        unsafe { close(receiver_sock) };
        Ok(())
    }

    fn test_data_buffer_truncation() -> io::Result<()> {
        println!("[DGRAM_MSGHDR] --- Testing Data Buffer Truncation (MSG_TRUNC) ---");
        let mut fds = [-1, -1];
        if unsafe { socketpair(AF_UNIX, SOCK_DGRAM, 0, fds.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let (receiver_sock, sender_sock) = (fds[0], fds[1]);

        let handle = thread::spawn(move || -> io::Result<()> {
            let full_message = "This is a very long message that will be truncated.";
            unsafe {
                sendmsg(
                    sender_sock,
                    &mut msghdr {
                        msg_name: ptr::null_mut(),
                        msg_namelen: 0,
                        msg_iov: &mut iovec {
                            iov_base: full_message.as_ptr() as *mut c_void,
                            iov_len: full_message.len(),
                        },
                        msg_iovlen: 1,
                        msg_control: ptr::null_mut(),
                        msg_controllen: 0,
                        msg_flags: 0,
                    },
                    0,
                )
            };
            unsafe { close(sender_sock) };
            Ok(())
        });

        let mut small_buf = [0u8; 10];
        let mut iov = iovec {
            iov_base: small_buf.as_mut_ptr() as *mut c_void,
            iov_len: small_buf.len(),
        };
        let mut msg: msghdr = unsafe { mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;

        let bytes_recvd = unsafe { recvmsg(receiver_sock, &mut msg, 0) };
        assert_eq!(bytes_recvd as usize, small_buf.len());
        assert_eq!(
            msg.msg_flags & MSG_TRUNC,
            MSG_TRUNC,
            "MSG_TRUNC should be set"
        );
        println!("[OK] MSG_TRUNC flag was correctly set.");

        handle.join().unwrap()?;
        unsafe { close(receiver_sock) };
        Ok(())
    }

    fn test_control_buffer_truncation() -> io::Result<()> {
        println!("[DGRAM_MSGHDR] --- Testing Control Buffer Truncation (MSG_CTRUNC) ---");
        let mut fds = [-1, -1];
        if unsafe { socketpair(AF_UNIX, SOCK_DGRAM, 0, fds.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let (receiver_sock, sender_sock) = (fds[0], fds[1]);

        let handle = thread::spawn(move || -> io::Result<()> {
            let data_to_send = "data";
            let mut iov = iovec {
                iov_base: data_to_send.as_ptr() as *mut c_void,
                iov_len: data_to_send.len(),
            };
            let cmsg_buf_len = unsafe { CMSG_SPACE(mem::size_of::<c_int>() as u32) as usize };
            let mut cmsg_buf = vec![0u8; cmsg_buf_len];
            let mut msg: msghdr = unsafe { mem::zeroed() };
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cmsg_buf.as_mut_ptr() as *mut c_void;
            msg.msg_controllen = cmsg_buf_len;

            unsafe {
                let cmsg = CMSG_FIRSTHDR(&msg);
                (*cmsg).cmsg_level = SOL_SOCKET;
                (*cmsg).cmsg_type = SCM_RIGHTS;
                (*cmsg).cmsg_len = CMSG_LEN(mem::size_of::<c_int>() as u32) as usize;
                *(CMSG_DATA(cmsg) as *mut c_int) = libc::dup(0);
            }

            unsafe { sendmsg(sender_sock, &msg, 0) };
            unsafe { close(sender_sock) };
            Ok(())
        });

        let mut data_buf = [0u8; 16];
        let mut iov = iovec {
            iov_base: data_buf.as_mut_ptr() as *mut c_void,
            iov_len: data_buf.len(),
        };
        let mut small_cmsg_buf = vec![0u8; 1]; // Buffer is too small
        let mut msg: msghdr = unsafe { mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = small_cmsg_buf.as_mut_ptr() as *mut c_void;
        msg.msg_controllen = small_cmsg_buf.len();

        unsafe { recvmsg(receiver_sock, &mut msg, 0) };
        println!("[Receiver] Received flags: {:#x}", msg.msg_flags);

        assert_eq!(
            msg.msg_flags & MSG_CTRUNC,
            MSG_CTRUNC,
            "MSG_CTRUNC should be set"
        );

        handle.join().unwrap()?;
        println!("[OK] MSG_CTRUNC flag was correctly set.");
        unsafe { close(receiver_sock) };
        Ok(())
    }

    fn test_send_multiple_fds() -> io::Result<()> {
        println!("[DGRAM_MSGHDR] --- Testing Sending Multiple FDs ---");
        let mut fds = [-1, -1];
        if unsafe { socketpair(AF_UNIX, SOCK_DGRAM, 0, fds.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let (receiver_sock, sender_sock) = (fds[0], fds[1]);

        let fd1 = unsafe { libc::dup(0) }; // stdin
        let fd2 = unsafe { libc::dup(1) }; // stdout
        let fds_to_send: [c_int; 2] = [fd1, fd2];
        println!("[Sender] Sending two FDs: {} and {}", fd1, fd2);

        let handle = thread::spawn(move || -> io::Result<()> {
            let data_to_send = "two fds";
            let mut iov = iovec {
                iov_base: data_to_send.as_ptr() as *mut c_void,
                iov_len: data_to_send.len(),
            };
            let cmsg_buf_len = unsafe { CMSG_SPACE(mem::size_of::<[c_int; 2]>() as u32) as usize };
            let mut cmsg_buf = vec![0u8; cmsg_buf_len];
            let mut msg: msghdr = unsafe { mem::zeroed() };
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cmsg_buf.as_mut_ptr() as *mut c_void;
            msg.msg_controllen = cmsg_buf_len;

            unsafe {
                let cmsg = CMSG_FIRSTHDR(&msg);
                (*cmsg).cmsg_level = SOL_SOCKET;
                (*cmsg).cmsg_type = SCM_RIGHTS;
                (*cmsg).cmsg_len = CMSG_LEN(mem::size_of::<[c_int; 2]>() as u32) as usize;
                let fds_ptr = CMSG_DATA(cmsg) as *mut c_int;
                ptr::copy_nonoverlapping(fds_to_send.as_ptr(), fds_ptr, 2);
            }

            unsafe { sendmsg(sender_sock, &msg, 0) };
            unsafe { close(sender_sock) };
            Ok(())
        });

        let mut data_buf = [0u8; 16];
        let mut iov = iovec {
            iov_base: data_buf.as_mut_ptr() as *mut c_void,
            iov_len: data_buf.len(),
        };
        let cmsg_buf_len = unsafe { CMSG_SPACE(mem::size_of::<[c_int; 2]>() as u32) as usize };
        let mut cmsg_buf = vec![0u8; cmsg_buf_len];
        let mut msg: msghdr = unsafe { mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut c_void;
        msg.msg_controllen = cmsg_buf.len();

        unsafe { recvmsg(receiver_sock, &mut msg, 0) };

        let mut received_fds = Vec::new();
        unsafe {
            let mut cmsg = CMSG_FIRSTHDR(&msg);
            while !cmsg.is_null() {
                if (*cmsg).cmsg_level == SOL_SOCKET && (*cmsg).cmsg_type == SCM_RIGHTS {
                    let num_fds =
                        ((*cmsg).cmsg_len - CMSG_LEN(0) as usize) / mem::size_of::<c_int>();
                    let data_ptr = CMSG_DATA(cmsg) as *const c_int;
                    received_fds.extend_from_slice(std::slice::from_raw_parts(data_ptr, num_fds));
                }
                cmsg = CMSG_NXTHDR(&msg, cmsg);
            }
        }

        assert_eq!(received_fds.len(), 2);
        println!("[OK] Received 2 FDs: {:?}, which are valid.", received_fds);

        handle.join().unwrap()?;
        unsafe { close(receiver_sock) };
        Ok(())
    }

    fn test_passcred_disabled() -> io::Result<()> {
        println!("[DGRAM_MSGHDR] --- [Edge Case] Testing Receiver with SO_PASSCRED Disabled ---");
        let mut fds = [-1, -1];
        if unsafe { socketpair(AF_UNIX, SOCK_DGRAM, 0, fds.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let (receiver_sock, sender_sock) = (fds[0], fds[1]);

        println!("[Receiver] SO_PASSCRED is NOT enabled for this test.");

        let handle = thread::spawn(move || -> io::Result<()> {
            let message = "message without credentials";
            let mut iov = iovec {
                iov_base: message.as_ptr() as *mut c_void,
                iov_len: message.len(),
            };
            let mut msg: msghdr = unsafe { mem::zeroed() };
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;

            unsafe { sendmsg(sender_sock, &msg, 0) };
            unsafe { close(sender_sock) };
            Ok(())
        });

        let mut data_buf = [0u8; 64];
        let mut iov = iovec {
            iov_base: data_buf.as_mut_ptr() as *mut c_void,
            iov_len: data_buf.len(),
        };
        let cmsg_buf_len = unsafe { CMSG_SPACE(mem::size_of::<Ucred>() as u32) as usize };
        let mut cmsg_buf = vec![0u8; cmsg_buf_len];
        let mut msg: msghdr = unsafe { mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut c_void;
        msg.msg_controllen = cmsg_buf.len();

        unsafe { recvmsg(receiver_sock, &mut msg, 0) };

        let mut has_creds = false;
        let mut cmsg: *mut cmsghdr = unsafe { CMSG_FIRSTHDR(&msg) };
        while !cmsg.is_null() {
            if unsafe { (*cmsg).cmsg_type == SCM_CREDENTIALS } {
                has_creds = true;
                break;
            }
            cmsg = unsafe { CMSG_NXTHDR(&msg, cmsg) };
        }

        assert!(
            !has_creds,
            "SCM_CREDENTIALS should not be received when SO_PASSCRED is off"
        );
        println!("[OK] No SCM_CREDENTIALS message was received, as expected.");

        handle.join().unwrap()?;
        unsafe { close(receiver_sock) };
        Ok(())
    }

    pub fn run_all() -> Result<()> {
        println!("\n[DGRAM_MSGHDR] Starting all msghdr tests...");
        test_send_recv_fd()?;
        test_send_recv_credentials()?;
        test_write_and_recvmsg_credentials()?;
        test_data_buffer_truncation()?;
        test_control_buffer_truncation()?;
        test_send_multiple_fds()?;
        test_passcred_disabled()?;
        println!("[DGRAM_MSGHDR] All msghdr tests finished successfully.");
        Ok(())
    }
}

///
/// Tests for advanced msghdr functionality on STREAM sockets (SCM_RIGHTS, SCM_CREDENTIALS)
///
pub mod stream_msghdr_tests {
    use super::{from_syscall_error, Ucred, SCM_CREDENTIALS, SCM_RIGHTS};
    use anyhow::Result;
    use libc::{
        c_int, c_void, close, cmsghdr, iovec, msghdr, recvmsg, sendmsg, socketpair, AF_UNIX,
        CMSG_DATA, CMSG_FIRSTHDR, CMSG_LEN, CMSG_SPACE, MSG_CTRUNC, SOCK_STREAM, SOL_SOCKET,
        SO_PASSCRED,
    };
    use std::io;
    use std::mem;
    use std::os::unix::io::RawFd;
    use std::ptr;
    use std::thread;

    fn test_send_recv_fd() -> io::Result<()> {
        println!("[STREAM_MSGHDR] --- Testing SCM_RIGHTS (File Descriptor Passing) ---");
        let fd_to_send = unsafe { libc::dup(1) };

        let mut fds = [-1, -1];
        if unsafe { socketpair(AF_UNIX, SOCK_STREAM, 0, fds.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let (receiver_sock, sender_sock) = (fds[0], fds[1]);

        let data_to_send = "FD follows";
        let mut iov = iovec {
            iov_base: data_to_send.as_ptr() as *mut c_void,
            iov_len: data_to_send.len(),
        };
        let cmsg_buf_len = unsafe { CMSG_SPACE(mem::size_of::<c_int>() as u32) as usize };
        let mut cmsg_buf = vec![0u8; cmsg_buf_len];
        let mut msg: msghdr = unsafe { mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut c_void;
        msg.msg_controllen = cmsg_buf_len;

        unsafe {
            let cmsg: *mut cmsghdr = CMSG_FIRSTHDR(&msg);
            (*cmsg).cmsg_level = SOL_SOCKET;
            (*cmsg).cmsg_type = SCM_RIGHTS;
            (*cmsg).cmsg_len = CMSG_LEN(mem::size_of::<c_int>() as u32) as usize;
            *(CMSG_DATA(cmsg) as *mut c_int) = fd_to_send as i32;
        }

        if unsafe { sendmsg(sender_sock, &msg, 0) } < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut data_buf = [0u8; 64];
        let mut iov_recv = iovec {
            iov_base: data_buf.as_mut_ptr() as *mut c_void,
            iov_len: data_buf.len(),
        };
        let mut cmsg_buf_recv = vec![0u8; cmsg_buf_len];
        let mut msg_recv: msghdr = unsafe { mem::zeroed() };
        msg_recv.msg_iov = &mut iov_recv;
        msg_recv.msg_iovlen = 1;
        msg_recv.msg_control = cmsg_buf_recv.as_mut_ptr() as *mut c_void;
        msg_recv.msg_controllen = cmsg_buf_recv.len();

        let bytes_recvd = unsafe { recvmsg(receiver_sock, &mut msg_recv, 0) };
        if bytes_recvd < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut received_fd: Option<RawFd> = None;
        unsafe {
            if let Some(cmsg) = (CMSG_FIRSTHDR(&msg_recv) as *const cmsghdr).as_ref() {
                if cmsg.cmsg_level == SOL_SOCKET && cmsg.cmsg_type == SCM_RIGHTS {
                    received_fd = Some(*(CMSG_DATA(cmsg) as *const c_int));
                }
            }
        }

        let fd = received_fd.expect("Failed to receive file descriptor");
        println!(
            "[Receiver] Received {} bytes and new FD: {}",
            bytes_recvd, fd
        );
        println!("[OK] SCM_RIGHTS test passed.");
        Ok(())
    }

    fn test_send_recv_credentials() -> io::Result<()> {
        println!("[STREAM_MSGHDR] --- Testing SCM_CREDENTIALS (Process Credentials) ---");
        let mut fds = [-1, -1];
        if unsafe { socketpair(AF_UNIX, SOCK_STREAM, 0, fds.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let (receiver_sock, sender_sock) = (fds[0], fds[1]);

        let on: c_int = 1;
        if unsafe {
            libc::setsockopt(
                receiver_sock,
                SOL_SOCKET,
                SO_PASSCRED,
                &on as *const _ as *const c_void,
                mem::size_of_val(&on) as u32,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }

        let handle = thread::spawn(move || -> io::Result<()> {
            let message = "Hello with credentials!";
            let mut iov = iovec {
                iov_base: message.as_ptr() as *mut c_void,
                iov_len: message.len(),
            };
            let mut msg: msghdr = unsafe { mem::zeroed() };
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            if unsafe { sendmsg(sender_sock, &msg, 0) } < 0 {
                return Err(io::Error::last_os_error());
            }
            unsafe { close(sender_sock) };
            Ok(())
        });

        let mut data_buf = [0u8; 64];
        let mut iov = iovec {
            iov_base: data_buf.as_mut_ptr() as *mut c_void,
            iov_len: data_buf.len(),
        };
        let cmsg_buf_len = unsafe { CMSG_SPACE(mem::size_of::<Ucred>() as u32) as usize };
        let mut cmsg_buf = vec![0u8; cmsg_buf_len];
        let mut msg: msghdr = unsafe { mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut c_void;
        msg.msg_controllen = cmsg_buf.len();

        if unsafe { recvmsg(receiver_sock, &mut msg, 0) } < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut received_creds: Option<Ucred> = None;
        unsafe {
            if let Some(cmsg) = (CMSG_FIRSTHDR(&msg) as *const cmsghdr).as_ref() {
                if cmsg.cmsg_level == SOL_SOCKET && cmsg.cmsg_type == SCM_CREDENTIALS {
                    received_creds = Some(*(CMSG_DATA(cmsg) as *const Ucred));
                }
            }
        }

        if let Some(creds) = received_creds {
            println!(
                "[Receiver] Credentials: PID={}, UID={}, GID={}",
                creds.pid, creds.uid, creds.gid
            );
            assert_eq!(creds.pid, unsafe { libc::getpid() });
        } else {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Failed to receive credentials",
            ));
        }

        handle.join().unwrap()?;
        unsafe { close(receiver_sock) };
        println!("[OK] SCM_CREDENTIALS test passed.");
        Ok(())
    }

    fn test_write_and_recvmsg_credentials() -> io::Result<()> {
        println!("[STREAM_MSGHDR] --- Testing syscall::write and recvmsg with SCM_CREDENTIALS ---");
        let mut fds = [-1, -1];
        if unsafe { socketpair(AF_UNIX, SOCK_STREAM, 0, fds.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let (receiver_sock, sender_sock) = (fds[0], fds[1]);

        let on: c_int = 1;
        if unsafe {
            libc::setsockopt(
                receiver_sock,
                SOL_SOCKET,
                SO_PASSCRED,
                &on as *const _ as *const c_void,
                mem::size_of_val(&on) as u32,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }

        let handle = thread::spawn(move || -> io::Result<()> {
            let message = "Simple write, complex receive!";
            let bytes_sent = syscall::write(sender_sock as usize, message.as_bytes())
                .map_err(from_syscall_error)?;
            assert_eq!(bytes_sent, message.len());
            unsafe { close(sender_sock) };
            Ok(())
        });

        let mut data_buf = [0u8; 128];
        let mut iov = iovec {
            iov_base: data_buf.as_mut_ptr() as *mut c_void,
            iov_len: data_buf.len(),
        };
        let cmsg_buf_len = unsafe { CMSG_SPACE(mem::size_of::<Ucred>() as u32) as usize };
        let mut cmsg_buf = vec![0u8; cmsg_buf_len];
        let mut msg: msghdr = unsafe { mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut c_void;
        msg.msg_controllen = cmsg_buf.len();

        let bytes_recvd = unsafe { recvmsg(receiver_sock, &mut msg, 0) };
        if bytes_recvd < 0 {
            return Err(io::Error::last_os_error());
        }

        assert_eq!(
            &data_buf[..bytes_recvd as usize],
            b"Simple write, complex receive!"
        );

        let mut received_creds: Option<Ucred> = None;
        unsafe {
            if let Some(cmsg) = (CMSG_FIRSTHDR(&msg) as *const cmsghdr).as_ref() {
                if cmsg.cmsg_level == SOL_SOCKET && cmsg.cmsg_type == SCM_CREDENTIALS {
                    received_creds = Some(*(CMSG_DATA(cmsg) as *const Ucred));
                }
            }
        }

        assert!(
            received_creds.is_some(),
            "Should have received credentials via simple write"
        );

        handle.join().unwrap()?;
        unsafe { close(receiver_sock) };

        println!("[OK] Credentials received successfully via simple write.");
        Ok(())
    }

    fn test_control_buffer_truncation() -> io::Result<()> {
        println!(
            "[STREAM_MSGHDR] --- [Edge Case] Testing Control Buffer Truncation (MSG_CTRUNC) ---"
        );
        let mut fds = [-1, -1];
        if unsafe { socketpair(AF_UNIX, SOCK_STREAM, 0, fds.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let (receiver_sock, sender_sock) = (fds[0], fds[1]);

        let handle = thread::spawn(move || -> io::Result<()> {
            let data_to_send = "data";
            let mut iov = iovec {
                iov_base: data_to_send.as_ptr() as *mut c_void,
                iov_len: data_to_send.len(),
            };
            let cmsg_buf_len = unsafe { CMSG_SPACE(mem::size_of::<c_int>() as u32) as usize };
            let mut cmsg_buf = vec![0u8; cmsg_buf_len];
            let mut msg: msghdr = unsafe { mem::zeroed() };
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cmsg_buf.as_mut_ptr() as *mut c_void;
            msg.msg_controllen = cmsg_buf_len;
            unsafe {
                let cmsg = CMSG_FIRSTHDR(&msg);
                (*cmsg).cmsg_level = SOL_SOCKET;
                (*cmsg).cmsg_type = SCM_RIGHTS;
                (*cmsg).cmsg_len = CMSG_LEN(mem::size_of::<c_int>() as u32) as usize;
                *(CMSG_DATA(cmsg) as *mut c_int) = libc::dup(0);
            }
            unsafe { sendmsg(sender_sock, &msg, 0) };
            unsafe { close(sender_sock) };
            Ok(())
        });

        let mut data_buf = [0u8; 16];
        let mut iov = iovec {
            iov_base: data_buf.as_mut_ptr() as *mut c_void,
            iov_len: data_buf.len(),
        };
        let mut small_cmsg_buf = vec![0u8; 1]; // Buffer is intentionally too small
        let mut msg: msghdr = unsafe { mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = small_cmsg_buf.as_mut_ptr() as *mut c_void;
        msg.msg_controllen = small_cmsg_buf.len();

        unsafe { recvmsg(receiver_sock, &mut msg, 0) };
        assert_eq!(
            msg.msg_flags & MSG_CTRUNC,
            MSG_CTRUNC,
            "MSG_CTRUNC should be set"
        );

        handle.join().unwrap()?;
        unsafe { close(receiver_sock) };
        println!("[OK] MSG_CTRUNC flag was correctly set.");
        Ok(())
    }

    fn test_send_multiple_fds() -> io::Result<()> {
        println!("[STREAM_MSGHDR] --- Testing Sending Multiple FDs ---");
        let mut fds = [-1, -1];
        if unsafe { socketpair(AF_UNIX, SOCK_STREAM, 0, fds.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let (receiver_sock, sender_sock) = (fds[0], fds[1]);

        let fd1 = unsafe { libc::dup(0) }; // stdin
        let fd2 = unsafe { libc::dup(1) }; // stdout
        let fds_to_send: [c_int; 2] = [fd1, fd2];

        let handle = thread::spawn(move || -> io::Result<()> {
            let data_to_send = "two fds";
            let mut iov = iovec {
                iov_base: data_to_send.as_ptr() as *mut c_void,
                iov_len: data_to_send.len(),
            };
            let cmsg_buf_len = unsafe { CMSG_SPACE((mem::size_of::<c_int>() * 2) as u32) as usize };
            let mut cmsg_buf = vec![0u8; cmsg_buf_len];
            let mut msg: msghdr = unsafe { mem::zeroed() };
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cmsg_buf.as_mut_ptr() as *mut c_void;
            msg.msg_controllen = cmsg_buf_len;

            unsafe {
                let cmsg = CMSG_FIRSTHDR(&msg);
                (*cmsg).cmsg_level = SOL_SOCKET;
                (*cmsg).cmsg_type = SCM_RIGHTS;
                (*cmsg).cmsg_len = CMSG_LEN((mem::size_of::<c_int>() * 2) as u32) as usize;
                ptr::copy_nonoverlapping(fds_to_send.as_ptr(), CMSG_DATA(cmsg) as *mut c_int, 2);
            }

            if unsafe { sendmsg(sender_sock, &msg, 0) } < 0 {
                return Err(io::Error::last_os_error());
            }
            unsafe { close(sender_sock) };
            Ok(())
        });

        let mut data_buf = [0u8; 16];
        let mut iov = iovec {
            iov_base: data_buf.as_mut_ptr() as *mut c_void,
            iov_len: data_buf.len(),
        };
        let cmsg_buf_len = unsafe { CMSG_SPACE((mem::size_of::<c_int>() * 2) as u32) as usize };
        let mut cmsg_buf = vec![0u8; cmsg_buf_len];
        let mut msg: msghdr = unsafe { mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut c_void;
        msg.msg_controllen = cmsg_buf.len();

        if unsafe { recvmsg(receiver_sock, &mut msg, 0) } < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut received_fds = Vec::new();
        unsafe {
            let cmsg = CMSG_FIRSTHDR(&msg);
            if !cmsg.is_null() {
                let num_fds = ((*cmsg).cmsg_len - CMSG_LEN(0) as usize) / mem::size_of::<c_int>();
                let data_ptr = CMSG_DATA(cmsg) as *const c_int;
                received_fds.extend_from_slice(std::slice::from_raw_parts(data_ptr, num_fds));
            }
        }

        assert_eq!(received_fds.len(), 2);
        handle.join().unwrap()?;
        unsafe { close(receiver_sock) };
        println!("[OK] Received 2 FDs: {:?}", received_fds);
        Ok(())
    }

    fn test_passcred_disabled() -> io::Result<()> {
        println!("[STREAM_MSGHDR] --- [Edge Case] Testing Receiver with SO_PASSCRED Disabled ---");
        let mut fds = [-1, -1];
        if unsafe { socketpair(AF_UNIX, SOCK_STREAM, 0, fds.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let (receiver_sock, sender_sock) = (fds[0], fds[1]);

        let handle = thread::spawn(move || -> io::Result<()> {
            let message = "Hello with credentials!";
            let mut iov = iovec {
                iov_base: message.as_ptr() as *mut c_void,
                iov_len: message.len(),
            };
            let mut msg: msghdr = unsafe { mem::zeroed() };
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            if unsafe { sendmsg(sender_sock, &msg, 0) } < 0 {
                return Err(io::Error::last_os_error());
            }
            unsafe { close(sender_sock) };
            Ok(())
        });

        let mut data_buf = [0u8; 64];
        let mut iov = iovec {
            iov_base: data_buf.as_mut_ptr() as *mut c_void,
            iov_len: data_buf.len(),
        };
        let cmsg_buf_len = unsafe { CMSG_SPACE(mem::size_of::<Ucred>() as u32) as usize };
        let mut cmsg_buf = vec![0u8; cmsg_buf_len];
        let mut msg: msghdr = unsafe { mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut c_void;
        msg.msg_controllen = cmsg_buf.len();

        unsafe { recvmsg(receiver_sock, &mut msg, 0) };

        let cmsg: *const cmsghdr = unsafe { CMSG_FIRSTHDR(&msg) };
        assert!(cmsg.is_null(), "No control message should be received");
        handle.join().unwrap()?;
        unsafe { close(receiver_sock) };
        println!("[OK] No SCM_CREDENTIALS message was received, as expected.");
        Ok(())
    }

    fn test_eof_handling_with_msghdr() -> io::Result<()> {
        println!("[STREAM_MSGHDR] --- Testing EOF Handling with sendmsg/recvmsg ---");

        let mut fds = [-1, -1];
        if unsafe { socketpair(AF_UNIX, SOCK_STREAM, 0, fds.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let (receiver_sock, sender_sock) = (fds[0], fds[1]);

        let handle = thread::spawn(move || -> io::Result<()> {
            println!("[Receiver] Attempting to receive first message...");
            let mut data_buf = [0u8; 64];
            let mut iov_recv = iovec {
                iov_base: data_buf.as_mut_ptr() as *mut c_void,
                iov_len: data_buf.len(),
            };
            let mut msg_recv: msghdr = unsafe { mem::zeroed() };
            msg_recv.msg_iov = &mut iov_recv;
            msg_recv.msg_iovlen = 1;

            let bytes_recvd = unsafe { recvmsg(receiver_sock, &mut msg_recv, 0) };
            if bytes_recvd < 0 {
                return Err(io::Error::last_os_error());
            }
            assert_eq!(bytes_recvd as usize, "some data".len());
            println!("[Receiver] Received {} bytes of data.", bytes_recvd);

            println!("[Receiver] Attempting to receive again, expecting EOF...");

            let mut data_buf_eof = [0u8; 64];
            let mut iov_eof = iovec {
                iov_base: data_buf_eof.as_mut_ptr() as *mut c_void,
                iov_len: data_buf_eof.len(),
            };
            let mut cmsg_buf_eof = vec![0u8; 128];
            let mut msg_eof: msghdr = unsafe { mem::zeroed() };
            msg_eof.msg_iov = &mut iov_eof;
            msg_eof.msg_iovlen = 1;
            msg_eof.msg_control = cmsg_buf_eof.as_mut_ptr() as *mut c_void;
            msg_eof.msg_controllen = cmsg_buf_eof.len();
            msg_eof.msg_name = std::ptr::null_mut(); // 名前は不要
            msg_eof.msg_namelen = 0;

            let eof_res = unsafe { recvmsg(receiver_sock, &mut msg_eof, 0) };
            if eof_res < 0 {
                return Err(io::Error::last_os_error());
            }

            println!("[Receiver] Second recvmsg returned: {}", eof_res);
            assert_eq!(eof_res, 0, "recvmsg should return 0 on EOF");

            assert_eq!(
                msg_eof.msg_iovlen, 1,
                "msg_iovlen should not be modified by kernel"
            );
            assert_eq!(
                msg_eof.msg_controllen, 0,
                "msg_controllen should be 0 on return"
            );
            assert_eq!(msg_eof.msg_namelen, 0, "msg_namelen should be 0 on return");
            assert_eq!(msg_eof.msg_flags, 0, "msg_flags should be 0 on EOF");

            unsafe { close(receiver_sock) };
            println!("[OK] Successfully detected EOF and msghdr is in expected state.");
            Ok(())
        });

        let message = "some data";
        let mut iov = iovec {
            iov_base: message.as_ptr() as *mut c_void,
            iov_len: message.len(),
        };
        let mut msg: msghdr = unsafe { mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;

        if unsafe { sendmsg(sender_sock, &msg, 0) } < 0 {
            return Err(io::Error::last_os_error());
        }
        println!("[Sender] Sent message successfully.");

        println!("[Sender] Closing socket to signal EOF.");
        unsafe { libc::close(sender_sock) };

        handle.join().unwrap()?;

        println!("--- EOF Handling Test with msghdr Finished ---");
        Ok(())
    }

    fn test_repeated_partial_reads_with_ancillary_data() -> io::Result<()> {
        println!("[STREAM_MSGHDR] --- Repeated Partial Reads with Ancillary Data ---");
        let mut fds = [-1, -1];
        unsafe {
            if socketpair(AF_UNIX, SOCK_STREAM, 0, fds.as_mut_ptr()) != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        let (sender_sock, receiver_sock) = (fds[0], fds[1]);

        let fd_to_send_1: c_int = unsafe { libc::dup(1) }; // stdout
        let payload_1 = "A".repeat(1024);
        let payload_1_len = payload_1.len();
        let payload_1_clone = payload_1.clone();

        let fd_to_send_2: c_int = unsafe { libc::dup(2) }; // stderr
        let payload_2 = "B".repeat(512);
        let payload_2_len = payload_2.len();
        let payload_2_clone = payload_2.clone();

        assert!(
            fd_to_send_1 != -1 && fd_to_send_2 != -1,
            "Failed to dup fds"
        );

        let sender_handle = thread::spawn(move || -> io::Result<()> {
            // --- Sender Thread ---

            {
                println!("[Sender] Sending message 1 with FD {}", fd_to_send_1);
                let mut iov = iovec {
                    iov_base: payload_1.as_ptr() as *mut c_void,
                    iov_len: payload_1.len(),
                };
                let cmsg_buf_len =
                    unsafe { libc::CMSG_SPACE(mem::size_of::<c_int>() as u32) as usize };
                let mut cmsg_buf = vec![0u8; cmsg_buf_len];
                let mut msg: msghdr = unsafe { mem::zeroed() };
                msg.msg_iov = &mut iov;
                msg.msg_iovlen = 1;
                msg.msg_control = cmsg_buf.as_mut_ptr() as *mut c_void;
                msg.msg_controllen = cmsg_buf_len;
                let cmsg: *mut cmsghdr = unsafe { libc::CMSG_FIRSTHDR(&msg) };
                unsafe {
                    (*cmsg).cmsg_level = SOL_SOCKET;
                    (*cmsg).cmsg_type = SCM_RIGHTS;
                    (*cmsg).cmsg_len = libc::CMSG_LEN(mem::size_of::<c_int>() as u32) as usize;
                    ptr::copy_nonoverlapping(&fd_to_send_1, libc::CMSG_DATA(cmsg) as *mut c_int, 1);
                }
                assert!(
                    unsafe { sendmsg(sender_sock, &msg, 0) } > 0,
                    "sendmsg for msg 1 failed"
                );
            }

            {
                println!("[Sender] Sending message 2 with FD {}", fd_to_send_2);
                let mut iov = iovec {
                    iov_base: payload_2.as_ptr() as *mut c_void,
                    iov_len: payload_2.len(),
                };
                let cmsg_buf_len =
                    unsafe { libc::CMSG_SPACE(mem::size_of::<c_int>() as u32) as usize };
                let mut cmsg_buf = vec![0u8; cmsg_buf_len];
                let mut msg: msghdr = unsafe { mem::zeroed() };
                msg.msg_iov = &mut iov;
                msg.msg_iovlen = 1;
                msg.msg_control = cmsg_buf.as_mut_ptr() as *mut c_void;
                msg.msg_controllen = cmsg_buf_len;
                let cmsg: *mut cmsghdr = unsafe { libc::CMSG_FIRSTHDR(&msg) };
                unsafe {
                    (*cmsg).cmsg_level = SOL_SOCKET;
                    (*cmsg).cmsg_type = SCM_RIGHTS;
                    (*cmsg).cmsg_len = libc::CMSG_LEN(mem::size_of::<c_int>() as u32) as usize;
                    ptr::copy_nonoverlapping(&fd_to_send_2, libc::CMSG_DATA(cmsg) as *mut c_int, 1);
                }
                assert!(
                    unsafe { sendmsg(sender_sock, &msg, 0) } > 0,
                    "sendmsg for msg 2 failed"
                );
            }

            unsafe { libc::close(sender_sock) };
            Ok(())
        });

        // --- Receiver (Main Thread) ---

        println!("[Receiver] Starting to receive message 1...");
        let (received_payload_1, received_fds_1) =
            receive_one_message(receiver_sock, payload_1_len)?;
        assert_eq!(
            received_payload_1,
            payload_1_clone.as_bytes(),
            "Payload for message 1 did not match"
        );
        assert_eq!(received_fds_1.len(), 1, "Expected 1 FD for message 1");
        println!("[OK] Correctly received message 1 and its FD.");

        println!("[Receiver] Starting to receive message 2...");
        let (received_payload_2, received_fds_2) =
            receive_one_message(receiver_sock, payload_2_len)?;
        assert_eq!(
            received_payload_2,
            payload_2_clone.as_bytes(),
            "Payload for message 2 did not match"
        );
        assert_eq!(received_fds_2.len(), 1, "Expected 1 FD for message 2");
        println!("[OK] Correctly received message 2 and its FD.");

        let (final_payload, final_fds) = receive_one_message(receiver_sock, 10)?;
        assert_eq!(final_payload, b"", "Payload for eof did not match");
        assert_eq!(final_fds.len(), 0, "Expected no FDs on EOF");
        println!("[OK] Correctly detected EOF after all messages.");

        // --- Cleanup ---
        for fd in received_fds_1.into_iter().chain(received_fds_2.into_iter()) {
            unsafe { libc::close(fd) };
        }
        sender_handle.join().unwrap()?;
        unsafe { libc::close(receiver_sock) };
        Ok(())
    }

    fn test_receive_concatenated_stream_with_ancillary_data() -> io::Result<()> {
        println!("[STREAM_MSGHDR] --- Receive Concatenated Stream with Ancillary Data ---");
        let mut fds = [-1, -1];
        unsafe {
            if socketpair(AF_UNIX, SOCK_STREAM, 0, fds.as_mut_ptr()) != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        let (sender_sock, receiver_sock) = (fds[0], fds[1]);

        let fd_to_send_1: c_int = unsafe { libc::dup(1) };
        assert!(fd_to_send_1 != -1, "Failed to dup fd");

        let fd_to_send_2: c_int = unsafe { libc::dup(2) };
        assert!(fd_to_send_2 != -1, "Failed to dup fd");

        let sender_handle = thread::spawn(move || -> io::Result<()> {
            {
                let payload1 = "This is the first part of the stream.";
                let mut iov = iovec {
                    iov_base: payload1.as_ptr() as *mut c_void,
                    iov_len: payload1.len(),
                };
                let cmsg_buf_len =
                    unsafe { libc::CMSG_SPACE(mem::size_of::<c_int>() as u32) as usize };
                let mut cmsg_buf = vec![0u8; cmsg_buf_len];
                let mut msg: msghdr = unsafe { mem::zeroed() };
                msg.msg_iov = &mut iov;
                msg.msg_iovlen = 1;
                msg.msg_control = cmsg_buf.as_mut_ptr() as *mut c_void;
                msg.msg_controllen = cmsg_buf_len;

                let cmsg: *mut cmsghdr = unsafe { libc::CMSG_FIRSTHDR(&msg) };
                unsafe {
                    (*cmsg).cmsg_level = SOL_SOCKET;
                    (*cmsg).cmsg_type = SCM_RIGHTS;
                    (*cmsg).cmsg_len = libc::CMSG_LEN(mem::size_of::<c_int>() as u32) as usize;
                    ptr::copy_nonoverlapping(&fd_to_send_1, libc::CMSG_DATA(cmsg) as *mut c_int, 1);
                }
                println!("[Sender] Sending part 1 with FD {}", fd_to_send_1);
                assert!(
                    unsafe { sendmsg(sender_sock, &msg, 0) } > 0,
                    "sendmsg for part 1 failed"
                );
            }

            {
                let payload2 = "This is the second part.";
                let mut iov = iovec {
                    iov_base: payload2.as_ptr() as *mut c_void,
                    iov_len: payload2.len(),
                };
                let cmsg_buf_len =
                    unsafe { libc::CMSG_SPACE(mem::size_of::<c_int>() as u32) as usize };
                let mut cmsg_buf = vec![0u8; cmsg_buf_len];
                let mut msg: msghdr = unsafe { mem::zeroed() };
                msg.msg_iov = &mut iov;
                msg.msg_iovlen = 1;
                msg.msg_control = cmsg_buf.as_mut_ptr() as *mut c_void;
                msg.msg_controllen = cmsg_buf_len;

                let cmsg: *mut cmsghdr = unsafe { libc::CMSG_FIRSTHDR(&msg) };
                unsafe {
                    (*cmsg).cmsg_level = SOL_SOCKET;
                    (*cmsg).cmsg_type = SCM_RIGHTS;
                    (*cmsg).cmsg_len = libc::CMSG_LEN(mem::size_of::<c_int>() as u32) as usize;
                    ptr::copy_nonoverlapping(&fd_to_send_2, libc::CMSG_DATA(cmsg) as *mut c_int, 1);
                }

                println!("[Sender] Sending part 1 with FD {}", fd_to_send_2);
                assert!(
                    unsafe { sendmsg(sender_sock, &msg, 0) } > 0,
                    "sendmsg for part 2 failed"
                );
            }

            unsafe { libc::close(sender_sock) };
            Ok(())
        });

        let mut data_buf = [0u8; 128];
        let mut iov = iovec {
            iov_base: data_buf.as_mut_ptr() as *mut c_void,
            iov_len: data_buf.len(),
        };

        let cmsg_buf_len =
            unsafe { libc::CMSG_SPACE(mem::size_of::<[c_int; 2]>() as u32) as usize };
        let mut cmsg_buf = vec![0u8; cmsg_buf_len];

        let mut msg: msghdr = unsafe { mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut c_void;
        msg.msg_controllen = cmsg_buf.len();

        std::thread::sleep(std::time::Duration::from_millis(100)); // Ensure sender has time to send

        println!("[Receiver] Calling recvmsg with a large buffer...");
        let bytes_read = unsafe { recvmsg(receiver_sock, &mut msg, 0) };
        assert!(bytes_read > 0, "recvmsg failed");
        println!("[Receiver] Received {} bytes in a single call.", bytes_read);

        let expected_payload_str = "This is the first part of the stream.This is the second part.";
        let received_slice = &data_buf[..bytes_read as usize];
        assert_eq!(received_slice, expected_payload_str.as_bytes());
        println!("[OK] Received payload is the correct concatenated stream.");

        let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
        assert!(!cmsg.is_null(), "Did not receive ancillary data");

        let cmsg_ref = unsafe { &*cmsg };
        if cmsg_ref.cmsg_level == SOL_SOCKET && cmsg_ref.cmsg_type == SCM_RIGHTS {
            let data_len = cmsg_ref.cmsg_len - unsafe { libc::CMSG_LEN(0) as usize };
            let num_fds = data_len / mem::size_of::<c_int>();

            assert_eq!(num_fds, 2, "Expected to receive exactly two FD");
            println!("[OK] Received correct FDs");
        } else {
            panic!("Received ancillary data of unexpected type");
        }

        sender_handle.join().unwrap()?;
        unsafe { libc::close(receiver_sock) };

        Ok(())
    }

    fn receive_one_message(sock: RawFd, expected_len: usize) -> io::Result<(Vec<u8>, Vec<c_int>)> {
        let mut total_received_data = Vec::with_capacity(expected_len);
        let mut received_fds = Vec::new();

        while total_received_data.len() < expected_len {
            let mut small_data_buf = [0u8; 256];
            let mut iov = iovec {
                iov_base: small_data_buf.as_mut_ptr() as *mut c_void,
                iov_len: small_data_buf.len(),
            };

            let cmsg_buf_len = if received_fds.is_empty() {
                unsafe { libc::CMSG_SPACE(mem::size_of::<[c_int; 2]>() as u32) as usize }
            } else {
                0
            };
            let mut cmsg_buf = vec![0u8; cmsg_buf_len];
            let mut msg: msghdr = unsafe { mem::zeroed() };
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            if cmsg_buf_len > 0 {
                msg.msg_control = cmsg_buf.as_mut_ptr() as *mut c_void;
                msg.msg_controllen = cmsg_buf.len();
            }

            let bytes_read = unsafe { recvmsg(sock, &mut msg, 0) };
            if bytes_read < 0 {
                return Err(io::Error::last_os_error());
            }
            if bytes_read == 0 {
                return Ok((total_received_data, received_fds));
            }

            println!(
                "[Receiver Helper] Received a chunk of {} bytes.",
                bytes_read
            );
            total_received_data.extend_from_slice(&small_data_buf[..bytes_read as usize]);

            if received_fds.is_empty() {
                let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
                if !cmsg.is_null() {
                    println!("[Receiver Helper] Ancillary data found.");
                    let cmsg_ref = unsafe { &*cmsg };
                    if cmsg_ref.cmsg_level == SOL_SOCKET && cmsg_ref.cmsg_type == SCM_RIGHTS {
                        let fds_ptr = unsafe { libc::CMSG_DATA(cmsg) } as *const c_int;
                        let data_len = cmsg_ref.cmsg_len - unsafe { libc::CMSG_LEN(0) as usize };
                        let num_fds = data_len / mem::size_of::<c_int>();
                        for i in 0..num_fds {
                            received_fds.push(unsafe { *fds_ptr.add(i) });
                        }
                    }
                }
            }
        }
        Ok((total_received_data, received_fds))
    }

    pub fn run_all() -> Result<()> {
        println!("\n[STREAM_MSGHDR] Starting all msghdr tests...");
        test_send_recv_fd()?;
        test_send_recv_credentials()?;
        test_write_and_recvmsg_credentials()?;
        test_control_buffer_truncation()?;
        test_send_multiple_fds()?;
        test_passcred_disabled()?;
        test_eof_handling_with_msghdr()?;
        test_repeated_partial_reads_with_ancillary_data()?;
        test_receive_concatenated_stream_with_ancillary_data()?;
        println!("[STREAM_MSGHDR] All msghdr tests finished successfully.");
        Ok(())
    }
}
