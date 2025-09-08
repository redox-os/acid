use std::fs::File;
use std::io::BufWriter;

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
pub fn bench() -> anyhow::Result<()> {
    Ok(())
}

#[cfg(target_arch = "x86_64")]
pub fn scheme_call_bench() -> anyhow::Result<()> {
    // getppid is not currently cached, but TODO this is perhaps not relibc-future-proof for
    // benchmarking

    const N: usize = 1024 * 1024;

    let _distorters = (0..16)
        .map(|_| {
            std::thread::spawn(|| loop {
                std::thread::yield_now();
            })
        })
        .collect::<Vec<_>>();

    let mut times = vec![0_u64; N];

    let mut old = unsafe { x86::time::rdtsc() };

    for i in 0..N {
        assert_ne!(unsafe { libc::getppid() }, -1);
        let new = unsafe { x86::time::rdtsc() };
        times[i] = new - old;
        old = new;
    }

    let mut data = BufWriter::new(File::create("times.txt")?);

    for time in times {
        use std::io::Write;

        writeln!(data, "{time}")?;
    }

    Ok(())
}

#[cfg(not(target_arch = "x86_64"))]
pub fn scheme_call_bench() -> anyhow::Result<()> {
    Ok(())
}