use std::env::scheme_path;
use std::{io, mem};
use syscall::UPPER_FDTBL_TAG;
use syscall::{self, CallFlags};

fn from_syscall_error(error: syscall::Error) -> io::Error {
    io::Error::from_raw_os_error(error.errno as i32)
}

fn create_dummy_fd(name: &str) -> io::Result<usize> {
    let path = format!("/scheme/chan/{}", name);
    syscall::open(path, syscall::O_CREAT | syscall::O_RDWR).map_err(from_syscall_error)
}

fn verify_fpath(fd: usize, expected_path_prefix: &str, expected_name: &str) -> io::Result<()> {
    let mut buffer = [0u8; 128];
    let bytes_read = syscall::fpath(fd, &mut buffer).map_err(from_syscall_error)?;
    let path_str = std::str::from_utf8(&buffer[..bytes_read]).unwrap();
    let expected_path = format!("{}/{}", expected_path_prefix, expected_name);
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

fn send_fds(sender_sock: usize, fds_to_send: &[usize]) -> io::Result<()> {
    let mut payload: Vec<u8> = Vec::new();
    fds_to_send.iter().for_each(|fd| {
        payload.extend_from_slice(&fd.to_ne_bytes());
    });
    redox_rt::sys::sys_call(
        sender_sock,
        &mut payload,
        CallFlags::WRITE | CallFlags::FD,
        &[],
    )
    .map_err(|e| from_syscall_error(e.into()))?;
    Ok(())
}

fn receive_fds(receiver_sock: usize, dst_fds: &mut [usize], flags: CallFlags) -> io::Result<()> {
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
    )
    .map_err(|e| from_syscall_error(e.into()))?;
    Ok(())
}

pub fn run_all() -> io::Result<()> {
    let scheme_path = "/scheme/chan";
    println!("\n--- FdTbl Indirect Tests ---");

    println!("[TEST] Automatic allocation to POSIX table");
    let (receiver, sender) = create_socket_pair()?;
    let fd1 = create_dummy_fd("test_posix_auto1")?;
    let fd2 = create_dummy_fd("test_posix_auto2")?;
    send_fds(sender, &[fd1, fd2])?;
    syscall::close(fd1).unwrap();
    syscall::close(fd2).unwrap();

    let mut new_fds_posix = [0_usize; 2];
    receive_fds(receiver, &mut new_fds_posix, CallFlags::empty())?;
    println!("   -> Received FDs: {:?}", new_fds_posix);
    assert!(new_fds_posix[0] < 10 && new_fds_posix[1] < 10);
    verify_fpath(new_fds_posix[0], scheme_path, "test_posix_auto1")?;
    verify_fpath(new_fds_posix[1], scheme_path, "test_posix_auto2")?;

    println!("[TEST] Automatic allocation to upper table");
    let fd3 = create_dummy_fd("test_upper_auto1")?;
    let fd4 = create_dummy_fd("test_upper_auto2")?;
    send_fds(sender, &[fd3, fd4])?;
    syscall::close(fd3).unwrap();
    syscall::close(fd4).unwrap();

    let mut new_fds_upper = [0_usize; 2];
    receive_fds(receiver, &mut new_fds_upper, CallFlags::FD_UPPER)?;
    println!("   -> Received FDs: {:?}", new_fds_upper);
    assert_eq!(new_fds_upper[0] & UPPER_FDTBL_TAG, UPPER_FDTBL_TAG);
    assert_eq!(new_fds_upper[1] & UPPER_FDTBL_TAG, UPPER_FDTBL_TAG);
    verify_fpath(new_fds_upper[0], scheme_path, "test_upper_auto1")?;
    verify_fpath(new_fds_upper[1], scheme_path, "test_upper_auto2")?;

    println!("[TEST] Manual allocation to upper table");
    let fd5 = create_dummy_fd("test_upper_manual1")?;
    let fd6 = create_dummy_fd("test_upper_manual2")?;
    send_fds(sender, &[fd5, fd6])?;
    syscall::close(fd5).unwrap();
    syscall::close(fd6).unwrap();

    let mut manual_fds = [100 | UPPER_FDTBL_TAG, 200 | UPPER_FDTBL_TAG];
    receive_fds(
        receiver,
        &mut manual_fds,
        CallFlags::FD_UPPER | CallFlags::MANUAL_FD,
    )?;
    println!("   -> Received FDs into slots: {:?}", manual_fds);
    verify_fpath(manual_fds[0], scheme_path, "test_upper_manual1")?;
    verify_fpath(manual_fds[1], scheme_path, "test_upper_manual2")?;

    syscall::close(receiver).unwrap();
    syscall::close(sender).unwrap();

    println!("[TEST] Manual allocation to upper table with invalid slots range (should fail with EMFILE)");
    let fd5 = create_dummy_fd("test_upper_manual1")?;
    let fd6 = create_dummy_fd("test_upper_manual2")?;
    send_fds(sender, &[fd5, fd6])?;
    syscall::close(fd5).unwrap();
    syscall::close(fd6).unwrap();

    let mut manual_fds = [100 | UPPER_FDTBL_TAG, (65_536 + 1) | UPPER_FDTBL_TAG];
    let result = receive_fds(
        receiver,
        &mut manual_fds,
        CallFlags::FD_UPPER | CallFlags::MANUAL_FD,
    );
    assert!(result.is_err(), "Expected an error but got Ok");
    if let Err(e) = result {
        println!("   -> Received expected error: {:?}", e);
        assert_eq!(e.errno, Some(syscall::EMFILE as i32));
    }

    syscall::close(receiver).unwrap();
    syscall::close(sender).unwrap();

    println!("[TEST] Manual upper allocation to an occupied slot (should fail with EEXIST)");
    let (receiver, sender) = create_socket_pair()?;

    let obstacle_fd = create_dummy_fd("obstacle")?;
    send_fds(sender, &[obstacle_fd])?;
    syscall::close(obstacle_fd)?;

    let mut target_slot = [150 | UPPER_FDTBL_TAG];
    receive_fds(
        receiver,
        &mut target_slot,
        CallFlags::FD_UPPER | CallFlags::MANUAL_FD,
    )?;
    println!("   -> Occupied slot {} successfully.", target_slot[0]);

    let failing_fd = create_dummy_fd("should_fail")?;
    send_fds(sender, &[failing_fd])?;
    syscall::close(failing_fd)?;

    let mut failing_slot = [150 | UPPER_FDTBL_TAG];
    let result = receive_fds(
        receiver,
        &mut failing_slot,
        CallFlags::FD_UPPER | CallFlags::MANUAL_FD,
    );

    assert!(result.is_err(), "Expected an error but got Ok");
    if let Err(e) = result {
        println!("   -> Received expected error: {:?}", e);
        assert_eq!(e.errno, Some(syscall::EEXIST as i32));
    }

    syscall::close(target_slot[0])?;
    syscall::close(receiver)?;
    syscall::close(sender)?;

    println!("\n--- FdTbl Indirect Tests Passed Successfully ---");
    Ok(())
}
