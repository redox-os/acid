use std::{io, mem};
use syscall::Error as SyscallError;
use syscall::UPPER_FDTBL_TAG;
use syscall::{self, CallFlags};

fn from_syscall_error(error: SyscallError) -> io::Error {
    io::Error::from_raw_os_error(error.errno as i32)
}

fn prepare_fd_to_send(name: &str) -> io::Result<usize> {
    let fd = syscall::open(
        format!("chan:{}", name).as_str(),
        syscall::O_RDWR | syscall::O_CREAT | syscall::O_CLOEXEC,
    )
    .map_err(from_syscall_error)?;

    Ok(fd)
}

fn verify_fpath(fd: usize, expected_name: &str) -> io::Result<()> {
    let mut buffer = [0u8; 128];
    let bytes_read = syscall::fpath(fd, &mut buffer).map_err(from_syscall_error)?;
    let path_str =
        std::str::from_utf8(&buffer[..bytes_read]).expect("fpath returned invalid UTF-8");
    let expected_path = format!("chan:{}", expected_name);
    println!("      fpath({}) -> '{}'", fd, path_str);
    assert_eq!(path_str, expected_path, "Path verification failed");
    Ok(())
}

fn create_socket_pair() -> io::Result<(usize, usize)> {
    let mut fds = [-1, -1];
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((fds[0] as usize, fds[1] as usize))
}

fn send_fds(sender_sock: usize, fds_to_send: &[usize]) -> Result<usize, SyscallError> {
    let mut payload: Vec<u8> = Vec::with_capacity(fds_to_send.len() * mem::size_of::<usize>());
    for &fd in fds_to_send {
        payload.extend_from_slice(&fd.to_ne_bytes());
    }
    libredox::call::call_wo(sender_sock, &payload, CallFlags::FD, &[])
}

fn send_fds_with_clone(sender_sock: usize, fds_to_send: &[usize]) -> Result<usize, SyscallError> {
    let mut payload: Vec<u8> = Vec::with_capacity(fds_to_send.len() * mem::size_of::<usize>());
    for &fd in fds_to_send {
        payload.extend_from_slice(&fd.to_ne_bytes());
    }
    libredox::call::call_wo(
        sender_sock,
        &payload,
        CallFlags::FD | CallFlags::FD_CLONE,
        &[],
    )
}

fn receive_fds(
    receiver_sock: usize,
    dst_fds: &mut [usize],
    flags: CallFlags,
) -> Result<usize, SyscallError> {
    let dst_fds_bytes: &mut [u8] = unsafe {
        core::slice::from_raw_parts_mut(
            dst_fds.as_mut_ptr() as *mut u8,
            dst_fds.len() * mem::size_of::<usize>(),
        )
    };
    libredox::call::call_ro(receiver_sock, dst_fds_bytes, CallFlags::FD | flags, &[])
}

fn test_send_moved_fd_fails_with_ebadf() -> anyhow::Result<()> {
    println!("\n[TEST] Sending a moved FD fails with EBADF");
    let (receiver, sender) = create_socket_pair()?;
    let fd = prepare_fd_to_send("move_and_fail")?;

    println!("  -> Sending FD {} with move semantics", fd);
    send_fds(sender, &[fd])?;

    println!("  -> Resending moved FD {} (should fail with EBADF)", fd);
    let result = send_fds(sender, &[fd]);

    assert!(result.is_err(), "Expected an error but got Ok");
    if let Err(e) = result {
        println!("    -> Received expected error: {:?}", e);
        assert_eq!(e.errno, syscall::EBADF);
    }

    let mut received_fd = [0];
    receive_fds(receiver, &mut received_fd, CallFlags::empty())?;
    syscall::close(received_fd[0])?;
    syscall::close(receiver)?;
    syscall::close(sender)?;

    Ok(())
}

fn test_send_cloned_fd_remains_valid() -> anyhow::Result<()> {
    println!("\n[TEST] Sending a cloned FD remains valid on the sender side");
    let (receiver, sender) = create_socket_pair()?;
    let fd = prepare_fd_to_send("clone_and_verify")?;

    println!("  -> Sending FD {} with clone semantics", fd);
    send_fds_with_clone(sender, &[fd])?;

    println!("  -> Verifying original FD {} is still valid", fd);
    verify_fpath(fd, "clone_and_verify")?;

    let mut received_fd = [0];
    receive_fds(receiver, &mut received_fd, CallFlags::empty())?;
    syscall::close(received_fd[0])?;
    syscall::close(fd)?;
    syscall::close(receiver)?;
    syscall::close(sender)?;

    Ok(())
}

fn test_auto_alloc_to_posix_table() -> anyhow::Result<()> {
    println!("\n[TEST] Automatic allocation to POSIX table");
    let (receiver, sender) = create_socket_pair()?;
    let fd1 = prepare_fd_to_send("posix_auto1")?;
    let fd2 = prepare_fd_to_send("posix_auto2")?;

    send_fds(sender, &[fd1, fd2])?;

    let mut new_fds = [0; 2];
    receive_fds(receiver, &mut new_fds, CallFlags::empty())?;
    println!("  -> Received FDs: {:?}", new_fds);

    verify_fpath(new_fds[0], "posix_auto1")?;
    verify_fpath(new_fds[1], "posix_auto2")?;

    syscall::close(new_fds[0])?;
    syscall::close(new_fds[1])?;
    syscall::close(receiver)?;
    syscall::close(sender)?;

    Ok(())
}

fn test_auto_alloc_to_upper_table() -> anyhow::Result<()> {
    println!("\n[TEST] Automatic allocation to upper table");
    let (receiver, sender) = create_socket_pair()?;
    let fd1 = prepare_fd_to_send("upper_auto1")?;
    let fd2 = prepare_fd_to_send("upper_auto2")?;

    send_fds(sender, &[fd1, fd2])?;

    let mut new_fds = [usize::MAX; 2];
    receive_fds(receiver, &mut new_fds, CallFlags::FD_UPPER)?;
    println!("  -> Received FDs: {:?}", new_fds);

    assert_eq!(new_fds[0] & UPPER_FDTBL_TAG, UPPER_FDTBL_TAG);
    assert_eq!(new_fds[1] & UPPER_FDTBL_TAG, UPPER_FDTBL_TAG);
    verify_fpath(new_fds[0], "upper_auto1")?;
    verify_fpath(new_fds[1], "upper_auto2")?;

    syscall::close(new_fds[0])?;
    syscall::close(new_fds[1])?;
    syscall::close(receiver)?;
    syscall::close(sender)?;

    Ok(())
}

fn test_manual_alloc_to_upper_table() -> anyhow::Result<()> {
    println!("\n[TEST] Manual allocation to upper table");
    let (receiver, sender) = create_socket_pair()?;
    let fd1 = prepare_fd_to_send("upper_manual1")?;
    let fd2 = prepare_fd_to_send("upper_manual2")?;

    send_fds(sender, &[fd1, fd2])?;

    let mut manual_fds = [10 | UPPER_FDTBL_TAG, 20 | UPPER_FDTBL_TAG];
    receive_fds(receiver, &mut manual_fds, CallFlags::FD_UPPER)?;
    println!("  -> Received FDs into slots: {:?}", manual_fds);

    verify_fpath(manual_fds[0], "upper_manual1")?;
    verify_fpath(manual_fds[1], "upper_manual2")?;

    syscall::close(manual_fds[0])?;
    syscall::close(manual_fds[1])?;
    syscall::close(receiver)?;
    syscall::close(sender)?;

    Ok(())
}

fn test_manual_alloc_invalid_slot_fails_with_emfile() -> anyhow::Result<()> {
    println!("\n[TEST] Manual allocation to an invalid upper slot fails with EMFILE");
    let (receiver, sender) = create_socket_pair()?;
    let fd = prepare_fd_to_send("should_fail_emfile")?;
    send_fds(sender, &[fd])?;

    let mut invalid_slot = [(1 << 16) | UPPER_FDTBL_TAG];
    let result = receive_fds(receiver, &mut invalid_slot, CallFlags::FD_UPPER);

    assert!(result.is_err(), "Expected an error but got Ok");
    if let Err(e) = result {
        println!("  -> Received expected error: {:?}", e);
        assert_eq!(e.errno, syscall::EMFILE);
    }

    syscall::close(receiver)?;
    syscall::close(sender)?;

    Ok(())
}

fn test_manual_alloc_to_occupied_slot_fails_with_eexist() -> anyhow::Result<()> {
    println!("\n[TEST] Manual allocation to an occupied upper slot fails with EEXIST");
    let (receiver, sender) = create_socket_pair()?;

    let obstacle_fd = prepare_fd_to_send("obstacle")?;
    let target_slot = 150 | UPPER_FDTBL_TAG;
    println!("  -> Placing an obstacle FD at slot {}", target_slot);
    syscall::dup2(obstacle_fd, target_slot, &[])?;

    let failing_fd = prepare_fd_to_send("should_fail_eexist")?;
    send_fds(sender, &[failing_fd])?;

    let mut failing_slot = [target_slot];
    let result = receive_fds(receiver, &mut failing_slot, CallFlags::FD_UPPER);

    assert!(result.is_err(), "Expected an error but got Ok");
    if let Err(e) = result {
        println!("  -> Received expected error: {:?}", e);
        assert_eq!(e.errno, syscall::EEXIST);
    }

    syscall::close(receiver)?;
    syscall::close(sender)?;

    Ok(())
}

fn test_receive_buffer_too_small() -> anyhow::Result<()> {
    println!("\n[TEST] Behavior when receive buffer is smaller than sent FDs");
    let (receiver, sender) = create_socket_pair()?;
    let fd1 = prepare_fd_to_send("buf_small1")?;
    let fd2 = prepare_fd_to_send("buf_small2")?;
    let fd3 = prepare_fd_to_send("buf_small3")?;

    println!("  -> Sending 3 FDs");
    send_fds(sender, &[fd1, fd2, fd3])?;

    let mut small_buffer = [0; 2];
    println!("  -> Receiving with a buffer of size 2 (should fail with EMSGSIZE)");
    let result = receive_fds(receiver, &mut small_buffer, CallFlags::empty());

    assert!(
        result.is_err(),
        "Expected an error for insufficient buffer but got Ok"
    );
    if let Err(e) = result {
        println!("    -> Received expected error: {:?}", e);
        assert_eq!(e.errno, syscall::EINVAL);
    }
    syscall::close(receiver)?;
    syscall::close(sender)?;

    Ok(())
}

fn test_receive_buffer_too_large() -> anyhow::Result<()> {
    println!("\n[TEST] Behavior when receive buffer is larger than sent FDs");
    let (receiver, sender) = create_socket_pair()?;
    let fd1 = prepare_fd_to_send("buf_large1")?;
    let fd2 = prepare_fd_to_send("buf_large2")?;

    println!("  -> Sending 2 FDs");
    send_fds(sender, &[fd1, fd2])?;

    let mut large_buffer = [usize::MAX; 5];
    println!("  -> Receiving with a buffer of size 5");

    let result = receive_fds(receiver, &mut large_buffer, CallFlags::empty());
    assert!(
        result.is_err(),
        "Expected an error for larger buffer but got Ok"
    );
    if let Err(e) = result {
        println!("    -> Received expected error: {:?}", e);
        assert_eq!(e.errno, syscall::EINVAL);
    }

    syscall::close(receiver)?;
    syscall::close(sender)?;

    Ok(())
}

fn test_send_zero_fds() -> anyhow::Result<()> {
    println!("\n[TEST] Sending and receiving zero FDs");
    let (receiver, sender) = create_socket_pair()?;

    println!("  -> Sending an empty FD list");
    let bytes_sent = send_fds(sender, &[])?;
    assert_eq!(bytes_sent, 0, "Expected 0 bytes to be sent");

    let mut buffer = [0; 1];
    println!("  -> Receiving with a non-blocking flag to check for empty message");
    let result = receive_fds(receiver, &mut buffer, CallFlags::empty());

    assert!(result.is_err(), "Expected an error for no data but got Ok");
    if let Err(e) = result {
        println!("  -> Received expected error: {:?}", e);
        assert_eq!(e.errno, syscall::EAGAIN);
    }

    syscall::close(receiver)?;
    syscall::close(sender)?;
    Ok(())
}

pub fn run_all() -> anyhow::Result<()> {
    println!("\n--- FdTbl Indirect Tests ---");

    test_send_moved_fd_fails_with_ebadf()?;
    test_send_cloned_fd_remains_valid()?;
    test_auto_alloc_to_posix_table()?;
    test_auto_alloc_to_upper_table()?;
    test_manual_alloc_to_upper_table()?;
    test_manual_alloc_invalid_slot_fails_with_emfile()?;
    test_manual_alloc_to_occupied_slot_fails_with_eexist()?;
    test_receive_buffer_too_small()?;
    test_receive_buffer_too_large()?;
    test_send_zero_fds()?;

    println!("\n--- FdTbl Indirect Tests Passed Successfully ---");
    Ok(())
}
