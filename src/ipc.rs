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
