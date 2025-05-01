use redox_scheme::scheme::SchemeSync;
use redox_scheme::{CallerCtx, OpenResult, RequestKind, SignalBehavior, Socket};
use syscall::schemev2::NewFdFlags;
use syscall::{CallFlags, Result};

use crate::daemon::Daemon;

struct TestScheme {}
impl SchemeSync for TestScheme {
    fn open(&mut self, _path: &str, _flags: usize, _ctx: &CallerCtx) -> Result<OpenResult> {
        println!("CALLED SYS_OPEN");
        Ok(OpenResult::ThisScheme {
            number: 0,
            flags: NewFdFlags::empty(),
        })
    }
    fn call(&mut self, id: usize, payload: &mut [u8], metadata: &[u64]) -> Result<usize> {
        println!("CALLED SYS_CALL, ID {id} payload {payload:?} metadata {metadata:?}");
        payload[0] += metadata[0] as u8;
        Ok(1337)
    }
}

pub fn scheme_call() -> anyhow::Result<()> {
    Daemon::new(move |ready| {
        let sock = Socket::create("test-scheme").unwrap();
        let mut scheme = TestScheme {};
        ready.ready().unwrap();

        loop {
            let Some(req) = sock.next_request(SignalBehavior::Restart).unwrap() else {
                break;
            };
            let RequestKind::Call(req) = req.kind() else {
                continue;
            };
            let res = req.handle_sync(&mut scheme);
            let _ = sock.write_response(res, SignalBehavior::Restart).unwrap();
        }
        std::process::exit(0);
    })
    .unwrap();

    let fd = syscall::open("/scheme/test-scheme/file", 0).unwrap();

    let mut data_buf: [u8; 1] = [3];
    let metadata_buf: [u64; 1] = [7];

    let code = unsafe {
        syscall::syscall5(
            syscall::SYS_CALL,
            fd,
            data_buf.as_mut_ptr() as usize,
            data_buf.len(),
            metadata_buf.len(),
            metadata_buf.as_ptr() as usize,
        )
        .unwrap()
    };
    assert_eq!(code, 1337);
    assert_eq!(data_buf[0], 10);

    Ok(())
}
