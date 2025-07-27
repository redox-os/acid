use std::{io, mem};
use syscall::Error as SyscallError;
use syscall::UPPER_FDTBL_TAG;
use syscall::{self, CallFlags};

fn from_syscall_error(error: SyscallError) -> io::Error {
    io::Error::from_raw_os_error(error.errno as i32)
}

const RESOURCE_NAME: &str = "/scheme/uds_stream";
fn prepare_fd_to_send(name: &str) -> io::Result<usize> {
    let fd = syscall::open(RESOURCE_NAME, syscall::O_RDWR | syscall::O_CREAT)
        .map_err(from_syscall_error)?;

    let mut name_str = name.to_string();

    let payload = unsafe { name_str.as_bytes_mut() };
    redox_rt::sys::sys_call(
        fd,
        payload,
        CallFlags::empty(),
        &[redox_rt::protocol::SocketCall::Bind as u64],
    )
    .map_err(from_syscall_error)?;

    Ok(fd)
}
fn verify_fpath(fd: usize, expected_name: &str) -> io::Result<()> {
    let mut buffer = [0u8; 128];
    let bytes_read = syscall::fpath(fd, &mut buffer).map_err(from_syscall_error)?;
    let path_str = std::str::from_utf8(&buffer[..bytes_read]).unwrap();
    let expected_path = format!("{}/{}", RESOURCE_NAME, expected_name);
    println!("      fpath({}) -> '{}'", fd, path_str);
    assert_eq!(path_str, expected_path);
    Ok(())
}

fn create_socket_pair() -> io::Result<(usize, usize)> {
    let mut fds = [-1, -1];
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((fds[0] as usize, fds[1] as usize))
}

fn send_fds(sender_sock: usize, fds_to_send: &[usize]) -> Result<(), SyscallError> {
    let mut payload: Vec<u8> = Vec::new();
    fds_to_send.iter().for_each(|fd| {
        payload.extend_from_slice(&fd.to_ne_bytes());
    });
    redox_rt::sys::sys_call(
        sender_sock,
        &mut payload,
        CallFlags::WRITE | CallFlags::FD,
        &[],
    )?;
    Ok(())
}

fn send_fds_with_clone(sender_sock: usize, fds_to_send: &[usize]) -> Result<(), SyscallError> {
    let mut payload: Vec<u8> = Vec::new();
    fds_to_send.iter().for_each(|fd| {
        payload.extend_from_slice(&fd.to_ne_bytes());
    });
    redox_rt::sys::sys_call(
        sender_sock,
        &mut payload,
        CallFlags::WRITE | CallFlags::FD | CallFlags::FD_CLONE,
        &[],
    )?;
    Ok(())
}

fn receive_fds(
    receiver_sock: usize,
    dst_fds: &mut [usize],
    flags: CallFlags,
) -> Result<(), SyscallError> {
    let dst_fds_bytes: &mut [u8] = unsafe {
        core::slice::from_raw_parts_mut(
            dst_fds.as_mut_ptr() as *mut u8,
            dst_fds.len() * mem::size_of::<usize>(),
        )
    };
    redox_rt::sys::sys_call(
        receiver_sock,
        dst_fds_bytes,
        CallFlags::READ | CallFlags::FD | flags,
        &[],
    )?;
    Ok(())
}

pub fn run_all() -> anyhow::Result<()> {
    println!("\n--- FdTbl Indirect Tests ---");

    println!("[TEST] Automatic allocation to POSIX table and sends with clone and should failed with EBADF");
    let (receiver, sender) = create_socket_pair()?;
    let fd1 = prepare_fd_to_send("test_posix_auto1")?;
    let fd2 = prepare_fd_to_send("test_posix_auto2")?;
    println!("Sending FDs with clone and automatic allocation to POSIX table");
    send_fds_with_clone(sender, &[fd1, fd2]).map_err(from_syscall_error)?;
    println!("Sending FDs with move)");
    send_fds(sender, &[fd1, fd2]).map_err(from_syscall_error)?;
    println!("Sending moved FDs (should fail with EBADF)");
    let result = send_fds(sender, &[fd1, fd2]);
    assert!(result.is_err(), "Expected an error but got Ok");
    if let Err(e) = result {
        println!("   -> Received expected error: {:?}", e);
        assert_eq!(e.errno, syscall::EBADF as i32);
    }

    let mut new_fds_posix = [0_usize; 2];
    receive_fds(receiver, &mut new_fds_posix, CallFlags::empty())?;
    println!("   -> Received FDs: {:?}", new_fds_posix);
    verify_fpath(new_fds_posix[0], "test_posix_auto1")?;
    verify_fpath(new_fds_posix[1], "test_posix_auto2")?;

    let mut new_fds_posix = [0_usize; 2];
    receive_fds(receiver, &mut new_fds_posix, CallFlags::empty())?;
    println!("   -> Received FDs: {:?}", new_fds_posix);
    verify_fpath(new_fds_posix[0], "test_posix_auto1")?;
    verify_fpath(new_fds_posix[1], "test_posix_auto2")?;

    println!("[TEST] Automatic allocation to upper table");
    let fd3 = prepare_fd_to_send("test_upper_auto1")?;
    let fd4 = prepare_fd_to_send("test_upper_auto2")?;
    send_fds(sender, &[fd3, fd4]).map_err(from_syscall_error)?;

    let mut new_fds_upper = [usize::MAX; 2];
    println!("Receiving FDs with automatic allocation to upper table");
    receive_fds(receiver, &mut new_fds_upper, CallFlags::FD_UPPER)?;
    println!("   -> Received FDs: {:?}", new_fds_upper);
    assert_eq!(new_fds_upper[0] & UPPER_FDTBL_TAG, UPPER_FDTBL_TAG);
    assert_eq!(new_fds_upper[1] & UPPER_FDTBL_TAG, UPPER_FDTBL_TAG);
    verify_fpath(new_fds_upper[0], "test_upper_auto1")?;
    verify_fpath(new_fds_upper[1], "test_upper_auto2")?;

    println!("[TEST] Manual allocation to upper table");
    let fd5 = prepare_fd_to_send("test_upper_manual1")?;
    let fd6 = prepare_fd_to_send("test_upper_manual2")?;
    send_fds(sender, &[fd5, fd6]).map_err(from_syscall_error)?;

    let mut manual_fds = [10 | UPPER_FDTBL_TAG, 20 | UPPER_FDTBL_TAG];
    println!("Receiving FDs with manual allocation to upper table");
    receive_fds(receiver, &mut manual_fds, CallFlags::FD_UPPER)?;
    println!("   -> Received FDs into slots: {:?}", manual_fds);
    verify_fpath(manual_fds[0], "test_upper_manual1")?;
    verify_fpath(manual_fds[1], "test_upper_manual2")?;

    println!("[TEST] Manual allocation to upper table with invalid slots range (should fail with EMFILE)");
    let fd5 = prepare_fd_to_send("test_upper_manual1")?;
    let fd6 = prepare_fd_to_send("test_upper_manual2")?;
    send_fds(sender, &[fd5, fd6]).map_err(from_syscall_error)?;

    let mut manual_fds = [100 | UPPER_FDTBL_TAG, (65_536 + 1) | UPPER_FDTBL_TAG];
    println!("Receiving FDs with manual allocation to upper table with invalid slots range");
    let result = receive_fds(receiver, &mut manual_fds, CallFlags::FD_UPPER);
    assert!(result.is_err(), "Expected an error but got Ok");
    if let Err(e) = result {
        println!("   -> Received expected error: {:?}", e);
        assert_eq!(e.errno, syscall::EMFILE as i32);
    }

    println!("[TEST] Manual upper allocation to an occupied slot (should fail with EEXIST)");
    let (receiver, sender) = create_socket_pair()?;

    let obstacle_fd = prepare_fd_to_send("obstacle")?;
    syscall::dup2(obstacle_fd, 150 | UPPER_FDTBL_TAG, &[])?;

    let failing_fd1 = prepare_fd_to_send("should_fail1")?;
    let failing_fd2 = prepare_fd_to_send("should_fail2")?;
    send_fds(sender, &[failing_fd1, failing_fd2]).map_err(from_syscall_error)?;

    let mut failing_slot = [50 | UPPER_FDTBL_TAG, 150 | UPPER_FDTBL_TAG];
    println!("Receiving FDs with manual allocation to upper table with an occupied slot");
    let result = receive_fds(receiver, &mut failing_slot, CallFlags::FD_UPPER);

    assert!(result.is_err(), "Expected an error but got Ok");
    if let Err(e) = result {
        println!("   -> Received expected error: {:?}", e);
        assert_eq!(e.errno, syscall::EEXIST as i32);
    }

    syscall::close(receiver)?;
    syscall::close(sender)?;

    println!("\n--- FdTbl Indirect Tests Passed Successfully ---");
    Ok(())
}
