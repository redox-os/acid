use syscall::{scheme::SchemeMut, flag::{MapFlags, O_CLOEXEC}};
use syscall::error::*;

struct Scheme;

impl SchemeMut for Scheme {
    fn open(&mut self, _: &str, _: usize, _: u32, _: u32) -> Result<usize> {
        Ok(0)
    }
    fn read(&mut self, _: usize, buf: &mut [u8]) -> Result<usize> {
        verify_head_tail(buf, 0, 0, 0xD7, 0, 0);

        Ok(buf.len())
    }
    fn write(&mut self, _: usize, buf: &[u8]) -> Result<usize> {
        verify_head_tail(buf, 0, 0xDA, 0xDA, 0xDA, 0);

        Ok(buf.len())
    }
}
fn verify_head_tail(buf: &[u8], before: u8, head_valid: u8, middle: u8, tail_valid: u8, after: u8) {
    let head = unsafe { core::slice::from_raw_parts(((buf.as_ptr() as usize) / 4096 * 4096) as *const u8, (buf.as_ptr() as usize) % 4096) };
    let tail = unsafe {
        let end = buf.as_ptr().add(buf.len());
        core::slice::from_raw_parts(end, (4096 - (end as usize % 4096)) % 4096)
    };
    let (head_valid_slice, aligned_slice) = buf.split_at((4096 - head.len()) % 4096);
    let (middle_slice, tail_valid_slice) = aligned_slice.split_at(aligned_slice.len() / 4096 * 4096);

    assert_eq!(aligned_slice.as_ptr() as usize % 4096, 0);
    assert_eq!(middle_slice.len() % 4096, 0);
    assert_eq!(head_valid_slice.len() + head.len(), 4096);
    assert_eq!(tail_valid_slice.len() + tail.len(), 4096);
    assert_eq!(buf.len(), middle_slice.len() + head_valid_slice.len() + tail_valid_slice.len());

    assert_eq!(head, &*vec! [before; head.len()]);
    assert_eq!(head_valid_slice, &*vec! [head_valid; head_valid_slice.len()]);
    assert_eq!(middle_slice, &*vec! [middle; middle_slice.len()]);
    assert_eq!(tail_valid_slice, &*vec! [tail_valid; tail_valid_slice.len()]);
    assert_eq!(tail, &*vec! [after; tail.len()]);
}

const SPLIT: usize = 3057;
const LEN: usize = 1256 + 8192;

pub fn scheme_data_leak_test() -> Result<(), String> {
    crate::daemon::scheme("scheme_leak_test", "schemeleak", Scheme).unwrap();

    let buf = unsafe {
        let addr = syscall::fmap(!0, &syscall::Map {
            offset: 0,
            size: 16384,
            address: 0,
            flags: MapFlags::PROT_WRITE | MapFlags::PROT_READ,
        }).unwrap();

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

    std::fs::remove_file(":schemeleak").unwrap();

    Ok(())
}
