//!Acid testing program
#![allow(internal_features)]
#![feature(core_intrinsics, thread_local, test)]

use std::collections::{BTreeMap, HashMap};
use std::io::Write;
use std::time::Instant;
use std::{env, process};

#[cfg(any(test, target_os = "redox"))]
mod daemon;
#[cfg(any(test, target_os = "redox"))]
mod scheme_call;

mod arch;
mod fdtbl;
mod memory;
mod proc;
mod thread;
mod uds;

pub struct BenchResults {
    metrics: BTreeMap<String, f64>,
    start: std::time::Instant,
}
impl BenchResults {
    pub fn add_metric(&mut self, name: impl Into<String>, metric: f64) {
        self.metrics.insert(name.into(), metric);
    }
    /// Read timestamp counter, non-serializing
    pub fn rdtsc(&mut self) -> u64 {
        // TODO: better fallback
        #[cfg(not(target_arch = "x86_64"))]
        return self.start.elapsed().as_nanos() as u64;
        #[cfg(target_arch = "x86_64")]
        return unsafe { x86::time::rdtsc() };
    }
    /// Read timestamp counter, serializing
    pub fn rdtscp(&mut self) -> u64 {
        // TODO: better fallback
        #[cfg(not(target_arch = "x86_64"))]
        return self.start.elapsed().as_nanos() as u64;
        #[cfg(target_arch = "x86_64")]
        return unsafe { x86::time::rdtscp() };
    }
}

fn main() {
    // TODO: consider unifying these
    let mut tests: HashMap<&'static str, fn()> = HashMap::new();
    let mut benches: HashMap<&'static str, fn(&mut BenchResults)> = HashMap::new();

    #[cfg(target_arch = "x86_64")]
    tests.insert("avx2", arch::avx2);
    tests.insert("channel", thread::channel);
    // tests.insert("page_fault", page_fault_test); // TODO
    tests.insert("sleep_granularity", thread::sleep_granularity);
    tests.insert("context_switch", thread::context_switch);
    tests.insert("thread_spawn", thread::thread_spawn);
    tests.insert("tls", thread::tls);
    #[cfg(any(test, target_os = "redox"))]
    tests.insert("cross_scheme_link", scheme_call::cross_scheme_link);
    tests.insert("efault", memory::efault_test);
    #[cfg(target_arch = "x86_64")]
    // tests.insert("direction_flag_sc", arch::direction_flag_syscall);
    #[cfg(target_arch = "x86_64")]
    tests.insert("direction_flag_int", arch::direction_flag_interrupt);
    tests.insert("pipe", memory::pipe_test);
    #[cfg(any(test, target_os = "redox"))]
    {
        tests.insert(
            "scheme_data_leak_proc",
            scheme_call::scheme_data_leak_test_proc,
        );
        tests.insert(
            "scheme_data_leak_thread",
            scheme_call::scheme_data_leak_test_thread,
        );
    }
    #[cfg(any(test, target_os = "redox"))]
    tests.insert("libc_call", scheme_call::libc_call);
    tests.insert("clone_grant_using_fmap", memory::clone_grant_using_fmap);
    tests.insert(
        "clone_grant_using_fmap_lazy",
        memory::clone_grant_using_fmap_lazy,
    );
    // TODO: FIX openat_test
    // tests.insert("openat", openat_test);
    tests.insert("anonymous_map_shared", memory::anonymous_map_shared);
    //tests.insert("tlb", tlb_test); // TODO
    tests.insert("file_mmap", memory::file_mmap_test);
    tests.insert("mmap_delay", memory::mmap_delay);
    #[cfg(target_arch = "x86_64")]
    tests.insert("redoxfs_range_bookkeeping", arch::redoxfs_range_bookkeeping);
    //tests.insert("eintr", eintr::eintr); // TODO
    tests.insert("filetable_leak", memory::filetable_leak);
    #[cfg(any(test, target_os = "redox"))]
    tests.insert("scheme_call", scheme_call::scheme_call);
    #[cfg(any(test, target_os = "redox"))]
    tests.insert("scheme_relpathat", scheme_call::scheme_relpathat);

    // TODO: convert these 4 to benchmarks and make CI-compatible
    tests.insert("fork_tree_bench", proc::fork_tree_bench::<false>);
    tests.insert("fork_serial_bench", proc::fork_serial_bench::<false>);
    tests.insert("fork_exec_serial_bench", proc::fork_serial_bench::<true>);
    tests.insert("fork_exec_tree_bench", proc::fork_tree_bench::<true>);

    tests.insert("stop_orphan_pgrp", proc::stop_orphan_pgrp);
    tests.insert("setpgid", proc::setpgid);
    tests.insert("setsid", proc::setsid);
    tests.insert("reparenting", proc::reparenting);
    tests.insert("waitpid_setpgid_echild", proc::waitpid_setpgid_echild);
    tests.insert("thread_reap", proc::thread_reap);
    tests.insert("orphan_exit_sighup", proc::orphan_exit_sighup::<false>);
    tests.insert(
        "orphan_exit_sighup_session",
        proc::orphan_exit_sighup::<true>,
    );
    tests.insert(
        "wcontinued_sigcont_catching",
        proc::wcontinued_sigcont_catching,
    );
    tests.insert("using_signal_hook", proc::using_signal_hook);
    tests.insert("waitpid_esrch", proc::waitpid_esrch);
    tests.insert("waitpid_status_discard", proc::waitpid_status_discard);
    tests.insert("waitpid_transitive_queue", proc::waitpid_transitive_queue);
    tests.insert("pgrp_lifetime", proc::pgrp_lifetime);
    tests.insert("waitpid_eintr", proc::waitpid_eintr);
    tests.insert("raise_correct_sig_group", proc::raise_correct_sig_group);
    tests.insert("sigkill_fail_code", proc::sigkill_fail_code);

    // TODO: unpack these UDS tests
    tests.insert("uds_dgram", uds::dgram_tests::run_all);
    tests.insert("uds_stream", uds::stream_tests::run_all);
    tests.insert("uds_dgram_msghdr", uds::dgram_msghdr_tests::run_all);
    tests.insert("uds_stream_msghdr", uds::stream_msghdr_tests::run_all);
    tests.insert("fdtbl", fdtbl::run_all);

    #[cfg(target_arch = "x86_64")]
    {
        benches.insert("invalid_syscall", arch::invalid_syscall::<20>);
        benches.insert("getppid_bench", proc::getppid_bench);
        benches.insert("pgtbl_populate_bench", memory::pgtbl_populate_bench);
    }

    // TODO: allow specifying the number of times to repeat a benchmark, in order to get mean/stdev
    // statistics
    let mut bench_results = BenchResults {
        metrics: Default::default(),
        start: Instant::now(),
    };

    let mut ran_test = false;
    let mut ran_bench = false;

    for arg in env::args().skip(1) {
        let name = arg.as_str();
        if let Some(test) = tests.get(name) {
            ran_test = true;

            let time = Instant::now();
            test();
            let elapsed = time.elapsed();
            println!("acid: took {}ms", elapsed.as_millis());
        } else if let Some(bench) = benches.get(name) {
            ran_bench = true;

            let time = Instant::now();
            bench(&mut bench_results);
            let elapsed = time.elapsed();
            bench_results.add_metric(
                format!("{name}.total_time_ms"),
                elapsed.as_secs_f64() * 1000.0,
            );
            println!("acid: took {}ms", elapsed.as_millis());
        } else {
            println!("acid: {}: not found", arg);
            process::exit(1);
        }
    }
    if ran_bench {
        let mut stderr;
        let mut file;
        let output: &mut dyn std::io::Write;

        // TODO: might just use stderr if we verify nothing else here uses it
        if let Ok(path) = std::env::var("ACID_BENCH_OUTPUT") {
            file = std::fs::File::create(path).unwrap();
            output = &mut file;
        } else {
            stderr = std::io::stderr();
            output = &mut stderr;
        }
        let mut output = std::io::BufWriter::new(output);

        for (metric, value) in bench_results.metrics.iter() {
            writeln!(output, "{metric}={value}").unwrap();
        }
    }

    if !ran_test && !ran_bench {
        for test_or_bench in tests.keys().chain(benches.keys()) {
            println!("{}", test_or_bench);
        }
    }
}
