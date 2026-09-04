use libredox::Fd;
use nix::unistd::ForkResult;
use redox_scheme::scheme::Op;
use redox_scheme::{RequestKind, Response, SignalBehavior};
use syscall::{CallFlags, EOPNOTSUPP};

use crate::BenchResults;

/// Similar to `getppid_bench`, except trying to be even more lightweight (such avoiding event queues).
pub fn ipc_latency_bench(results: &mut BenchResults) {
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

    let n = 1 << 20;

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
        ForkResult::Parent { child } => loop {
            let Some(req) = scheme.next_request(SignalBehavior::Restart).unwrap() else {
                break;
            };
            let RequestKind::Call(req) = req.kind() else {
                continue;
            };
            let mut c = match req.op() {
                Ok(Op::Call(c)) => c,
                Ok(op) => {
                    if !scheme
                        .write_response(Response::err(EOPNOTSUPP, op), SignalBehavior::Restart)
                        .unwrap()
                    {
                        break;
                    };
                    continue;
                }
                Err(req) => {
                    if !scheme
                        .write_response(Response::err(EOPNOTSUPP, req), SignalBehavior::Restart)
                        .unwrap()
                    {
                        break;
                    };
                    continue;
                }
            };
            let payload = <[u8; size_of::<f64>()]>::try_from(c.payload())
                .ok()
                .map(f64::from_ne_bytes);
            if !scheme
                .write_response(Response::ok(0, c), SignalBehavior::Restart)
                .unwrap()
            {
                break;
            }
            if let Some(ticks_per_ipc) = payload {
                results.add_metric("ipc_latency.ticks_per_ipc", ticks_per_ipc);
                nix::sys::wait::waitpid(child, None).unwrap();
                break;
            }
        },
    }
}
