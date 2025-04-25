use std::cell::RefCell;
use std::time::Duration;

use redox_scheme::scheme::SchemeSync;
use redox_scheme::wrappers::ReadinessBased;
use redox_scheme::{CallerCtx, OpenResult, Socket};
use syscall::error::*;
use syscall::flag::{MapFlags, O_CLOEXEC};

use crate::daemon::Daemon;

struct Scheme(Case);

impl SchemeSync for Scheme {
    fn open(&mut self, _: &str, _: usize, _ctx: &CallerCtx) -> Result<OpenResult> {
        Ok(OpenResult::ThisScheme {
            number: 0,
            flags: Default::default(),
        })
    }
    fn read(
        &mut self,
        _: usize,
        buf: &mut [u8],
        _off: u64,
        _fl: u32,
        _ctx: &CallerCtx,
    ) -> Result<usize> {
        if matches!(self.0, Case::Process) {
            verify_head_tail(buf, 0, 0, 0xD7, 0, 0, Some(0xBA), Some(0xAD));
        } else {
            // TODO: Verify what can be verified
        }
        buf.fill(0xF1);

        Ok(buf.len())
    }
    fn write(
        &mut self,
        _: usize,
        buf: &[u8],
        _off: u64,
        _fl: u32,
        _ctx: &CallerCtx,
    ) -> Result<usize> {
        if matches!(self.0, Case::Process) {
            verify_head_tail(buf, 0, 0xDA, 0xDA, 0xDA, 0, None, None);
        } else {
            // TODO: Verify what can be verified
        }

        Ok(buf.len())
    }
}
fn verify_head_tail(
    buf: &[u8],
    before: u8,
    head_valid: u8,
    middle: u8,
    tail_valid: u8,
    after: u8,
    write_to_head: Option<u8>,
    write_to_tail: Option<u8>,
) {
    let head = unsafe {
        core::slice::from_raw_parts_mut(
            ((buf.as_ptr() as usize) / 4096 * 4096) as *mut u8,
            (buf.as_ptr() as usize) % 4096,
        )
    };
    let tail = unsafe {
        let end = buf.as_ptr().add(buf.len());
        core::slice::from_raw_parts_mut(end as *mut u8, (4096 - (end as usize % 4096)) % 4096)
    };
    let (head_valid_slice, aligned_slice) = buf.split_at((4096 - head.len()) % 4096);
    let (middle_slice, tail_valid_slice) =
        aligned_slice.split_at(aligned_slice.len() / 4096 * 4096);

    assert_eq!(aligned_slice.as_ptr() as usize % 4096, 0);
    assert_eq!(middle_slice.len() % 4096, 0);
    assert_eq!(head_valid_slice.len() + head.len(), 4096);
    assert_eq!(tail_valid_slice.len() + tail.len(), 4096);
    assert_eq!(
        buf.len(),
        middle_slice.len() + head_valid_slice.len() + tail_valid_slice.len()
    );

    assert_eq!(head, &*vec![before; head.len()]);
    assert_eq!(head_valid_slice, &*vec![head_valid; head_valid_slice.len()]);
    assert_eq!(middle_slice, &*vec![middle; middle_slice.len()]);
    assert_eq!(tail_valid_slice, &*vec![tail_valid; tail_valid_slice.len()]);
    assert_eq!(tail, &*vec![after; tail.len()]);

    if let Some(write) = write_to_head {
        head.fill(write);
    }
    if let Some(write) = write_to_tail {
        tail.fill(write);
    }
}

const SPLIT: usize = 3057;
const LEN: usize = 1256 + 8192;
pub fn scheme_data_leak_test_proc() -> anyhow::Result<()> {
    inner(Case::Process)
}

pub fn scheme_data_leak_test_thread() -> anyhow::Result<()> {
    inner(Case::Thread)
}
#[derive(Clone, Copy, Debug)]
enum Case {
    Process,
    Thread,
}
fn inner(case: Case) -> anyhow::Result<()> {
    let _guard;
    let scheme = move |daemon: Option<Daemon>| {
        let sock = Socket::create("schemeleak").unwrap();
        if let Some(d) = daemon {
            d.ready().unwrap();
        }
        let mut b = ReadinessBased::new(&sock, 16);
        let scheme = RefCell::new(Scheme(case));
        loop {
            b.read_requests().unwrap();
            b.process_requests(|| scheme.borrow_mut());
            b.write_responses().unwrap();
        }
    };
    match case {
        Case::Process => {
            crate::daemon::Daemon::new(move |daemon| scheme(Some(daemon))).unwrap();
        }
        Case::Thread => {
            _guard = std::thread::spawn(move || {
                scheme(None);
            });
            // TODO: better sync
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    let buf = unsafe {
        let addr = syscall::fmap(
            !0,
            &syscall::Map {
                offset: 0,
                size: 16384,
                address: 0,
                flags: MapFlags::PROT_WRITE | MapFlags::PROT_READ,
            },
        )
        .unwrap();

        core::slice::from_raw_parts_mut(addr as *mut u8, 16384)
    };
    let fd = syscall::open("schemeleak:", O_CLOEXEC).unwrap();

    buf[..SPLIT].fill(0xBE);
    buf[SPLIT..][..LEN].fill(0xDA);
    buf[SPLIT + LEN..].fill(0xAF);

    let _ = syscall::write(fd, &buf[SPLIT..][..LEN]).unwrap();

    buf[..SPLIT].fill(0xBF);
    buf[SPLIT..4096].fill(0xDE);
    buf[4096..12288].fill(0xD7);
    buf[12288..4096 + LEN].fill(0xAF);
    buf[4096 + LEN..].fill(0xAD);

    let _ = syscall::read(fd, &mut buf[SPLIT..][..LEN]).unwrap();

    assert_eq!(&buf[..SPLIT], vec![0xBF; SPLIT]); // untouched by the kernel
    assert_eq!(&buf[SPLIT..][..LEN], vec![0xF1; LEN]); // copied from scheme
    assert_eq!(&buf[4096 + LEN..], vec![0xAD; buf.len() - 4096 - LEN]); // untouched by the kernel

    std::fs::remove_file(":schemeleak").unwrap();

    Ok(())
}
