use std::fs::File;
use std::io::prelude::*;

use libredox::Fd;
use nix::unistd::ForkResult;
use redox_scheme::scheme::Op;
use redox_scheme::{RequestKind, Response, SignalBehavior};
use syscall::{CallFlags, EOPNOTSUPP};

use crate::BenchResults;

/// Similar to `getppid_bench`, except trying to be even more lightweight (such avoiding event queues).
pub fn ipc_latency_bench<const USE_SIMULTANEOUS: bool>(results: &mut BenchResults) {
    let scheme = redox_scheme::Socket::create().unwrap();
    let fd = {
        let offset = 0;
        let number = 0;
        let flags = 0;
        let internal_flags = 0;
        Fd::new(
            scheme
                .create_this_scheme_fd(offset, number, flags, internal_flags)
                .unwrap(),
        )
    };

    let n = std::env::var("ACID_IPC_ITERATIONS")
        .ok()
        .and_then(|i| i.parse::<u64>().ok())
        .unwrap_or(1 << 20);

    match unsafe { nix::unistd::fork().unwrap() } {
        ForkResult::Child => {
            let before = results.rdtscp();
            for _ in 0..n {
                assert_eq!(fd.call_wo(&[], CallFlags::empty(), &[0]).unwrap(), 0);
            }
            let after = results.rdtscp();

            let ticks_per_ipc = (after - before) as f64 / n as f64;
            fd.call_wo(&f64::to_ne_bytes(ticks_per_ipc), CallFlags::empty(), &[0])
                .unwrap();
            std::process::exit(0);
        }
        ForkResult::Parent { child } => {
            let mut res_to_write = None;

            loop {
                let req = match (res_to_write.take(), USE_SIMULTANEOUS) {
                    (Some(response), true) => match scheme
                        .write_response_and_await_next_request(SignalBehavior::Restart, response)
                        .unwrap()
                    {
                        (true, Some(req)) => req,
                        (false, _) | (true, None) => break,
                    },
                    (Some(response), false) => {
                        if !scheme
                            .write_response(response, SignalBehavior::Restart)
                            .unwrap()
                        {
                            break;
                        };
                        let Some(req) = scheme.next_request(SignalBehavior::Restart).unwrap()
                        else {
                            break;
                        };
                        req
                    }
                    (None, _) => {
                        let Some(req) = scheme.next_request(SignalBehavior::Restart).unwrap()
                        else {
                            break;
                        };
                        req
                    }
                };
                let RequestKind::Call(req) = req.kind() else {
                    continue;
                };
                let (response, payload) = match req.op() {
                    Ok(Op::Call(mut c)) => {
                        let payload = <[u8; size_of::<f64>()]>::try_from(c.payload())
                            .ok()
                            .map(f64::from_ne_bytes);
                        (Response::ok(0, c), payload)
                    }
                    Ok(op) => (Response::err(EOPNOTSUPP, op), None),
                    Err(req) => (Response::err(EOPNOTSUPP, req), None),
                };
                if let Some(ticks_per_ipc) = payload {
                    results.add_metric("ipc_latency.ticks_per_ipc", ticks_per_ipc);
                    let _ = scheme
                        .write_response(response, SignalBehavior::Restart)
                        .unwrap();
                    nix::sys::wait::waitpid(child, None).unwrap();
                    break;
                } else {
                    res_to_write = Some(response);
                }
            }
        }
    }
}

/// Same as `dd if=/dev/urandom of=/dev/zero bs=$ACID_IPC_BLOCK_SIZE count=$ACID_IPC_NUM_BLOCKS`,
/// except more suitable for benchmarking.
pub fn simple_file_io_bench(results: &mut BenchResults) {
    let count = std::env::var("ACID_IPC_NUM_BLOCKS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(128 * 1024);
    let bs = std::env::var("ACID_IPC_BLOCK_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4096);

    let mut input = File::open("/dev/urandom").unwrap();
    let mut output = File::open("/dev/zero").unwrap();

    // TODO: allow specifying alignment?
    let mut buf = vec![0; bs];

    let t1 = results.rdtsc();
    for _ in 0..count {
        input.read_exact(&mut buf).unwrap();
        output.write_all(&buf).unwrap();
    }
    let t2 = results.rdtsc();
    // TODO: track ticks spent in read vs in write?
    results.add_metric(
        "simple_file_io_bench.ticks_per_iter",
        (t2 - t1) as f64 / count as f64,
    );
}
