#[cfg(target_arch = "x86_64")]
pub fn bench() -> anyhow::Result<()> {
    // TODO: Support deeper syscalls, like reading O_NONBLOCK from an empty pipe.
    unsafe {
        let before = x86::time::rdtscp();
        core::arch::asm!("
            mov edx, 1337 // invalid syscall
            mov edi, 1 << 24 // iteration count

            .p2align 6

            2:
            .rept 15
            mov eax, edx
            syscall
            .endr
            dec edi
            jnz 2b
        ", out("edx") _, out("edi") _, out("ecx") _, out("r11") _, out("eax") _);
        let after = x86::time::rdtscp();

        let time: f64 = (after - before) as f64 / (15 << 24) as f64;

        println!("TIME_PER_SYSCALL: {time}");
    }
    Ok(())
}
#[cfg(not(target_arch = "x86_64"))]
pub fn bench() -> anyhow::Result<()> { Ok(()) }
