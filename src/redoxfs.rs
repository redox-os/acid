use libredox::flag::O_CREAT;
use std::thread;
use syscall::{Error, EINTR};

// TODO
pub fn eintr() {
    let mut fds = [0; 2];
    unsafe {
        assert_ne!(libc::pipe(fds.as_mut_ptr()), -1);
    }
    let [reader1, writer1] = fds.map(|i| i as usize);

    let pid = syscall::getpid().unwrap();

    extern "C" fn h(_: usize) {}
    let _ = syscall::sigaction(
        syscall::SIGUSR1,
        Some(&syscall::SigAction {
            sa_handler: Some(h),
            ..Default::default()
        }),
        None,
    );

    let handle = thread::spawn(move || {
        let _ = syscall::read(reader1, &mut [0]).unwrap();
        let _ = syscall::kill(pid, syscall::SIGUSR1).unwrap();
    });

    let listener = libredox::call::open("chan:acid", O_CREAT).unwrap();
    let _writer2 = libredox::call::open("chan:acid", 0).unwrap();
    let reader2 = libredox::call::dup(listener, b"listen").unwrap();

    let _ = syscall::write(writer1, &[0]);

    assert_eq!(
        syscall::read(reader2, &mut [0]).unwrap_err(),
        Error::new(EINTR)
    );

    handle.join().unwrap();
}

// TODO: FIX openat_test
/*
fn openat_test() -> Result<()> {
    fn test_access_modes(raw_fd: c_int, folder_path: &str) -> Result<()> {
        // Test O_RDONLY - read-only access
        let test_file = format!("{}/readonly_test", folder_path);
        std::fs::write(&test_file, b"readonly content")?;

        let file_fd = libredox::call::openat(raw_fd as _, "readonly_test", O_RDONLY)?;
        let mut file: File = unsafe { File::from_raw_fd(file_fd as RawFd) };
        let mut buffer = [0u8; 16];
        let read = file.read(&mut buffer)?;
        assert_eq!(read, 16);
        assert_eq!(&buffer[..16], b"readonly content");

        // Try to write to read-only file
        let write_result = file.write(b"test");
        assert!(write_result.is_err());

        let _ = libredox::call::close(file_fd);
        std::fs::remove_file(&test_file)?;

        // Test O_WRONLY - write-only access
        let test_file = format!("{}/writeonly_test", folder_path);
        std::fs::write(&test_file, b"original content")?;

        let file_fd = libredox::call::openat(raw_fd as _, "writeonly_test", syscall::O_WRONLY)?;
        let mut file: File = unsafe { File::from_raw_fd(file_fd as RawFd) };

        // Try to read from write-only file
        let mut buffer = [0u8; 20];
        let read_result = file.read(&mut buffer);
        assert!(read_result.is_err());

        let write_result = file.write(b"new content");
        assert!(write_result.is_ok());

        let _ = libredox::call::close(file_fd);
        std::fs::remove_file(&test_file)?;

        Ok(())
    }

    fn test_creation_flags(raw_fd: c_int, folder_path: &str) -> Result<()> {
        // Test O_CREAT - create new file
        let file_fd = libredox::call::openat(raw_fd as _, "new_file", O_CREAT | O_RDWR)?;
        let mut file: File = unsafe { File::from_raw_fd(file_fd as RawFd) };
        file.write(b"new file content")?;
        let _ = libredox::call::close(file_fd);

        // Verify file was created
        let content = std::fs::read(format!("{}/new_file", folder_path))?;
        assert_eq!(content, b"new file content");

        // Test O_EXCL - exclusive creation
        let excl_result =
            libredox::call::openat(raw_fd as _, "new_file", O_CREAT | syscall::O_EXCL | O_RDWR);
        assert!(excl_result.is_err());

        // Test O_TRUNC - truncate existing file
        let file_fd = libredox::call::openat(raw_fd as _, "new_file", syscall::O_TRUNC | O_RDWR)?;
        let mut file: File = unsafe { File::from_raw_fd(file_fd as RawFd) };
        file.write(b"truncated content")?;
        let _ = libredox::call::close(file_fd);

        // Verify file was truncated
        let content = std::fs::read(format!("{}/new_file", folder_path))?;
        assert_eq!(content, b"truncated content");

        // Test O_APPEND - append mode
        let file_fd = libredox::call::openat(raw_fd as _, "new_file", syscall::O_APPEND | O_RDWR)?;
        let mut file: File = unsafe { File::from_raw_fd(file_fd as RawFd) };
        file.write(b" appended")?;
        let _ = libredox::call::close(file_fd);

        // Verify content was appended
        let content = std::fs::read(format!("{}/new_file", folder_path))?;
        assert_eq!(content, b"truncated content appended");

        std::fs::remove_file(format!("{}/new_file", folder_path))?;

        Ok(())
    }

    fn test_error_conditions(raw_fd: c_int, folder_path: &str) -> Result<()> {
        // Test ENOTDIR - try to openat with a file descriptor that's not a directory
        let test_file = format!("{}/notdir_test", folder_path);
        std::fs::write(&test_file, b"test content")?;

        let file_fd = libredox::call::open(&test_file, O_RDONLY)?;
        let notdir_result = libredox::call::openat(file_fd, "some_file", O_RDONLY)
            .expect_err("Expected an error for not directory");
        assert_eq!(
            notdir_result.errno,
            syscall::ENOTDIR,
            "Expected ENOTDIR, got: {notdir_result}"
        );

        let _ = libredox::call::close(file_fd);
        std::fs::remove_file(&test_file)?;

        // TODO: Test should emit ENAMETOOLONG, but gives EINVAL
        let long_name = "a".repeat(1000);
        let toolong_result = libredox::call::openat(raw_fd as _, &long_name, O_CREAT | O_RDWR);
        assert!(toolong_result.is_err());

        Ok(())
    }

    fn create_file_test(
        raw_fd: c_int,
        folder_path: &str,
        file_path: &str,
        content: &[u8],
    ) -> Result<()> {
        let full_path = {
            // Write content to a temporary file
            let full_path = format!("{}/{}", folder_path, file_path);
            std::fs::write(&full_path, content)?;
            full_path
        };

        let file_fd = libredox::call::openat(raw_fd as _, file_path, O_RDWR)?;
        let mut file: File = unsafe { File::from_raw_fd(file_fd as RawFd) };
        let mut buffer: [u8; 24] = [0; 24];
        // Read the content back
        let read = file.read(&mut buffer)?;
        assert_eq!(read, content.len());
        assert_eq!(&buffer[..content.len()], content);

        // Clean up
        let _ = libredox::call::close(file_fd);
        std::fs::remove_file(&full_path)?;

        Ok(())
    }

    // Test: rename directory after opening dir fd
    fn test_rename_dir(path: &str) -> Result<()> {
        let orig_dir = format!("{}/rename_test_dir", path);
        let new_dir = format!("{}/renamed_dir", path);

        std::fs::create_dir(&orig_dir)?;
        let dir_fd = libredox::call::open(&orig_dir, O_DIRECTORY | O_RDONLY)?;
        std::fs::rename(&orig_dir, &new_dir)?;

        let fd = libredox::call::openat(dir_fd, "file_after_rename", O_CREAT | O_RDWR)?;
        let mut file: File = unsafe { File::from_raw_fd(fd as RawFd) };
        file.write_all(b"hello after rename")?;
        let _ = libredox::call::close(fd);
        let content = std::fs::read(format!("{}/file_after_rename", new_dir))?;
        assert_eq!(content, b"hello after rename");
        std::fs::remove_file(format!("{}/file_after_rename", new_dir))?;

        let _ = libredox::call::close(dir_fd);
        std::fs::remove_dir(&new_dir)?;
        Ok(())
    }

    let path = "/scheme/file/openat_test";
    // Create the directory if it doesn't exist
    let raw_fd = libredox::call::open(&path, O_CREAT | O_DIRECTORY)? as _;
    if raw_fd < 0 {
        bail!("Failed to open directory");
    }

    test_access_modes(raw_fd, &path)?;
    test_creation_flags(raw_fd, &path)?;
    test_error_conditions(raw_fd, &path)?;

    create_file_test(raw_fd, &path, "tmp1", b"Temporary File Content 1")?;
    create_file_test(raw_fd, &path, "tmp2", b"Temporary File Content 2")?;
    create_file_test(raw_fd, &path, "tmp3", b"Temporary File Content 3")?;

    test_rename_dir(&path)?;

    // Error case - invalid directory fd
    let error = create_file_test(999999, &path, "tmp", b"")
        .expect_err("Expected an error for invalid directory fd");
    assert!(
        matches!(error.downcast_ref::<syscall::Error>(), Some(e) if e.errno == syscall::EBADF),
        "Expected EBADF, got: {error}"
    );

    // Error case - non-existent file
    let non_existent = libredox::call::openat(raw_fd as _, "non_existent", O_RDWR)
        .expect_err("Expected an error for non-existent file");
    assert_eq!(
        non_existent.errno,
        syscall::ENOENT,
        "Expected ENOENT, got: {non_existent}"
    );

    // Cleanup
    let _ = libredox::call::close(raw_fd as _);
    std::fs::remove_dir_all(&path)?;

    Ok(())
}
*/
