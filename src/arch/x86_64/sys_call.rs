use std::{os::unix::thread::JoinHandleExt, time::Duration};

// Crate named sys_call to avoid confusion with redox_syscall

pub fn invalid_syscall<const P2ITER: u32>() {
    let before = unsafe { x86::time::rdtscp() };

    // TODO: Support deeper syscalls, like reading O_NONBLOCK from an empty pipe.
    unsafe {
        core::arch::asm!("
            mov edx, 1337 // invalid syscall
            mov edi, 1 << {P2ITER} // iteration count

            .p2align 6

            2:
            .rept 15
            mov eax, edx
            syscall
            .endr
            dec edi
            jnz 2b
        ", out("edx") _, out("edi") _, out("ecx") _, out("r11") _, out("eax") _, P2ITER = const P2ITER);
    }
    let total_ticks = unsafe { x86::time::rdtscp() } - before;
    let total_iters = 15 << P2ITER;
    let ticks_per_iter = (total_ticks as f64) / (total_iters as f64);
    println!("Ticks per iteration: {ticks_per_iter}");
}

// TODO: Update with openat?
pub fn direction_flag_syscall() {
    let path = *b"sys:context";

    let result: usize;

    unsafe {
        // TODO
        core::arch::asm!("
            std
            syscall
            cld
        ", inout("rax") syscall::SYS_OPENAT => result, in("rdi") path.as_ptr(), in("rsi") path.len(), in("rdx") syscall::O_RDONLY, out("rcx") _, out("r11") _);
    }

    let file = syscall::Error::demux(result).unwrap();

    let mut buf = [0_u8; 4096];

    let result: usize;

    unsafe {
        core::arch::asm!("
            std
            syscall
            cld
        ", inout("rax") syscall::SYS_READ => result, in("rdi") file, in("rsi") buf.as_mut_ptr(), in("rdx") buf.len(), out("rcx") _, out("r11") _);
    }

    syscall::Error::demux(result).unwrap();
}

pub fn direction_flag_interrupt() {
    let thread = std::thread::spawn(|| unsafe {
        core::arch::asm!(
            "
                std
            2:
                pause
                jmp 2b
            ",
            options(noreturn)
        );
    });

    // TODO: A way to remove sleep so this test can be benched
    std::thread::sleep(Duration::from_secs(1));

    let pthread: libc::pthread_t = thread.into_pthread_t();

    unsafe {
        assert_eq!(libc::pthread_detach(pthread), 0);
        assert_eq!(libc::pthread_kill(pthread, libc::SIGKILL), 0);
    }
}

#[cfg(test)]
mod tests {
    extern crate test;
    use super::*;
    use test::Bencher;

    #[test]
    fn test_invalid_syscall() {
        invalid_syscall::<10>()
    }

    // throwing SIGKILL
    // #[test]
    // fn test_direction_flag_syscall() {
    //     direction_flag_syscall()
    // }

    // #[test]
    // fn test_direction_flag_interrupt() {
    //     direction_flag_interrupt()
    // }

    #[bench]
    fn bench_invalid_syscall(b: &mut Bencher) {
        b.iter(|| invalid_syscall::<10>())
    }
}
