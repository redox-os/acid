#[cfg(target_arch = "x86_64")]
mod x86_64;

#[cfg(target_arch = "x86_64")]
pub use x86_64::*;

#[cfg(not(target_arch = "x86_64"))]
pub struct PerfCtrState;

#[cfg(not(target_arch = "x86_64"))]
impl PerfCtrState {
    pub fn new() -> Option<Self> {
        // TODO: print warning?
        None
    }
}
