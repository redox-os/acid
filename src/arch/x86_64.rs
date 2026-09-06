mod avx;
mod redoxfs;
mod sys_call;

use std::cell::Cell;

use anyhow::{anyhow, bail, Context, Result};

pub use avx::*;
pub use redoxfs::*;
pub use sys_call::*;
use syscall::CallFlags;
use x86::cpuid::CpuId;

#[derive(Debug)]
pub struct Idx<'perf> {
    idx: u8,
    ctrs: &'perf PerfCtrState,
}
#[derive(Clone, Copy, Debug)]
struct Ctr {
    event: u16,    // 11:0
    unit_mask: u8, // 7:0
    name: &'static str,
}

#[derive(Debug)]
pub struct PerfCtrState {
    cpuid: CpuId,
    counters: [Cell<Option<Ctr>>; 4],
    family: u8,
    model: u8,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum CountWhere {
    DontCount = 0b00,
    InUserspace = 0b01,
    InKernel = 0b10,
    Everywhere = 0b11,
}

// TODO: saner macro allowing structs to be initialized naturally and declared with e.g. Verilog
// notation (which AMD itself appears to be using in its docs).
bitfield::bitfield! {
    struct PerfEvtSel(u64);
    event_select_lo, set_event_select_lo: 7, 0;
    unit_mask, set_unit_mask: 15, 8;
    usr, set_usr: 16;
    os, set_os: 17;
    edge, set_edge: 18;
    int, set_int: 20;
    en, set_en: 22;
    inv, set_inv: 23;
    cnt_mask, set_cnt_mask: 31, 24;
    event_select_hi, set_event_select_hi: 35, 32;
    // ignoring host/guest only
}
bitfield::bitfield! {
    struct AmdExt0001Edx(u32);
    impl Debug;
    stepping_id, set_stepping_id: 3, 0;
    extended_model, set_extended_model: 19, 16;
    model, set_model: 7, 4;
    extended_family, set_extended_family: 27, 20;
    family, set_family: 11, 8;
}

bitflags::bitflags! {
    /// Number of times there's an L1 DTLB miss, filterable by page sizes and whether it was still
    /// a hit in the L2 TLB.
    ///
    /// Checked to exist for both (some) 17h and 19h, although the meaning of "coalesced" may
    /// differ.
    #[derive(Clone, Copy, Debug)]
    pub struct CoreLsL1DTlbMiss: u8 {
        const TLB_RELOAD_1G_L2_MISS = 1 << 7;
        const TLB_RELOAD_2M_L2_MISS = 1 << 6;
        const TLB_RELOAD_COALESCED_PAGE_MISS = 1 << 5;
        const TLB_RELOAD_4K_L2_MISS = 1 << 4;

        const TLB_RELOAD_1G_L2_HIT = 1 << 3;
        const TLB_RELOAD_2M_L2_HIT = 1 << 2;
        const TLB_RELOAD_COALESCED_PAGE_HIT = 1 << 1;
        const TLB_RELOAD_4K_L2_HIT = 1 << 0;
    }
    /// Number of misaligned loads, filterable by those that cross cache lines and those that cross
    /// pages.
    ///
    /// Checked to exist on 19h.
    #[derive(Clone, Copy, Debug)]
    pub struct CoreLsMisalLoads: u8 {
        const MA4K = 1 << 1;
        const MA64 = 1 << 0;
    }
}

// TODO: I could be wrong, but it looks like if a perf ctr in mentioned in an AMD Processor
// Programming Reference pdf, and all bits are marked "Reserved" , then the counter is still
// supported by the processor, merely that it cannot distinguish between sub-events of that
// counter.
#[derive(Clone, Copy, Debug)]
pub enum PerfCtrEvent {
    /// Core::X86::Pmc::Core::LsMisalLoads
    CoreLsMisalLoads(CoreLsMisalLoads),
    CoreLsL1DtlbMiss(CoreLsL1DTlbMiss),
    CoreLsNotHaltedCyc,
}
impl PerfCtrEvent {
    pub fn name(&self) -> &'static str {
        match self {
            Self::CoreLsL1DtlbMiss(_) => "Core::X86::Pmc::Core::LsL1DTlbMiss",
            Self::CoreLsMisalLoads(_) => "Core::X86::Pmc::Core::LsMisalLoads",
            Self::CoreLsNotHaltedCyc => "Core::X86::Pmc::Core::LsNotHaltedCyc",
        }
    }
}

impl PerfCtrState {
    pub fn new() -> Option<Self> {
        let cpuid = CpuId::new();

        if cpuid
            .get_vendor_info()
            .is_none_or(|v| v.as_str() != "AuthenticAMD")
        {
            eprintln!("Perf counters are only supported for AMD CPUs");
            return None;
        }

        let processor_specific = AmdExt0001Edx(x86::cpuid::cpuid!(0x0000_0001).eax);
        let model = (processor_specific.model() | (processor_specific.extended_model() << 4)) as u8;
        let family = (processor_specific.family() + processor_specific.extended_family()) as u8;
        let stepping = processor_specific.stepping_id();
        println!("AuthenticAMD, family {family:x}h, model {model:x}h rev {stepping:x}h");

        Some(Self {
            cpuid,
            counters: [const { Cell::new(None) }; 4],
            family,
            model,
        })
    }
    fn amd64_evtseln_msr(idx: u8) -> u32 {
        assert!(idx < 4);
        // TODO: Intel
        0xc001_0000 | u32::from(idx)
    }
    fn lookup_ctr(&self, event: PerfCtrEvent) -> Result<(u16, u8)> {
        // TODO: this list is heavily model-dependent and if complete would be potentially very
        // long.
        match (event, self.family, self.model) {
            (PerfCtrEvent::CoreLsMisalLoads(bits), 0x17, _) => {
                if !bits.is_empty() {
                    bail!("17h does not support individual misaligned-loads fields");
                }
                Ok((0x047, 0))
            }
            (PerfCtrEvent::CoreLsMisalLoads(bits), 0x19, _) => Ok((0x047, bits.bits())),
            (PerfCtrEvent::CoreLsL1DtlbMiss(bits), 0x17 | 0x19, _) => Ok((0x045, bits.bits())),
            (PerfCtrEvent::CoreLsNotHaltedCyc, 0x17 | 0x19, _) => Ok((0x076, 0)),

            _ => Err(anyhow!(
                "Failed to lookup perf counter {} for model {:x}h family {:x}h",
                event.name(),
                self.model,
                self.family
            )),
        }
    }
    pub fn add_perf_ctr(&self, event: PerfCtrEvent, count_where: CountWhere) -> Result<Idx<'_>> {
        let name = event.name();

        let (event, unit_mask) = self.lookup_ctr(event)?;
        assert!(event < 4096);
        let ctr = Ctr {
            name,
            event,
            unit_mask,
        };
        let free = self
            .counters
            .iter()
            .position(|c| c.get().is_none())
            .context("have used up all available perf counters")?;

        {
            let mut value = PerfEvtSel(0);
            let count_where_value = count_where as u8;
            value.set_event_select_hi(u64::from(event >> 8));
            value.set_event_select_lo(u64::from(event & 0xff));
            value.set_usr(count_where_value & 1 != 0);
            value.set_os((count_where_value >> 1) != 0);
            value.set_unit_mask(unit_mask.into());
            value.set_en(true);

            self.x86_wrmsr(Self::amd64_evtseln_msr(free as u8), value.0);
            //assert_eq!(self.x86_rdmsr(0xc001_0000), value.0);
        }
        self.counters[free].set(Some(ctr));

        Ok(Idx {
            idx: free as u8,
            ctrs: self,
        })
    }
    fn _x86_rdmsr(&self, reg: u32) -> u64 {
        let mut buf = [0_u8; 8];
        let fd = libredox::Fd::open("/scheme/kernel.acpi/msr", libredox::flag::O_CLOEXEC, 0)
            .expect("failed to open MSR handle");
        //let verb = AcpiVerb::Msr; // TODO: nix stops compiling after cargo update, don't hardcode
        let verb = 3;
        fd.call_ro(&mut buf, CallFlags::empty(), &[verb as u64, reg.into()])
            .expect("failed to read MSR");
        u64::from_ne_bytes(buf)
    }
    fn x86_wrmsr(&self, reg: u32, value: u64) {
        let fd = libredox::Fd::open("/scheme/kernel.acpi/msr", libredox::flag::O_CLOEXEC, 0)
            .expect("failed to open MSR handle");
        //let verb = AcpiVerb::Msr; // TODO: nix stops compiling after cargo update, don't hardcode
        let verb = 3;
        fd.call_wo(
            &u64::to_ne_bytes(value),
            CallFlags::empty(),
            &[verb as u64, reg.into()],
        )
        .expect("failed to write MSR");
    }
    fn x86_rdpmc(&self, index: u8) -> u64 {
        assert!(index < 4);
        let lo: u32;
        let hi: u32;

        unsafe {
            // TODO: add a relibc wrapper for rdpmc that handles #GP to make it panic-safe?
            // SAFETY: This doesn't affect memory, but can fail with #GP if CR4.PCE is clear
            // (currently, when the kernel is not compiled with profiling) or when there is no perf
            // counter with `index`. That isn't memory-unsafe though and can be compared to a
            // predictable safe panic!.
            core::arch::asm!(
                "rdpmc",
                out("eax") lo,
                out("edx") hi,
                in("ecx") u32::from(index),
            )
        }

        u64::from(lo) | (u64::from(hi) << 32)
    }
}
impl<'perf> Idx<'perf> {
    pub fn rdpmc(&mut self) -> u64 {
        self.ctrs.x86_rdpmc(self.idx)
    }
}
impl<'perf> Drop for Idx<'perf> {
    fn drop(&mut self) {
        // 0 will clear the enable bit
        self.ctrs
            .x86_wrmsr(PerfCtrState::amd64_evtseln_msr(self.idx), 0);
        self.ctrs.counters[usize::from(self.idx)].set(None);
    }
}

pub fn perf_ctr_meta_test(results: &mut crate::BenchResults) {
    let perf_ctrs = results.perf_ctrs.unwrap();

    let mut perf_ctr = perf_ctrs
        .add_perf_ctr(
            PerfCtrEvent::CoreLsMisalLoads(CoreLsMisalLoads::all()),
            CountWhere::InUserspace,
        )
        .unwrap();
    let mut not_halted_cyc = perf_ctrs
        .add_perf_ctr(PerfCtrEvent::CoreLsNotHaltedCyc, CountWhere::InUserspace)
        .unwrap();

    // TODO: Currently the test is meant to run manually. Maybe expand it to check with all
    // combinations of event bits and read misalignments?

    let buf = [0_u8; 8192];
    // page-crossing (and cacheline-crossing)
    let page_misaligned = buf.as_ptr().map_addr(|a| a | 0xfff).cast::<u64>();
    // both cache and page-aligned
    let page_aligned = page_misaligned.map_addr(|a| a + 1).cast::<u64>();
    // just cacheline-crossing
    let cache_misaligned = page_aligned.map_addr(|a| a + 63).cast::<u64>();

    eprintln!("Page-aligned:     {page_aligned:p}");
    eprintln!("Cache-misaligned: {cache_misaligned:p}");
    eprintln!("Page-misaligned:  {page_misaligned:p}");

    // misaligned loads
    let c1 = perf_ctr.rdpmc();
    let d1 = not_halted_cyc.rdpmc();
    let t1 = results.rdtsc();

    let n = 100000000_u32;

    for _ in 0..n {
        //let _ = unsafe { page_misaligned.read_volatile() };
        let _ = unsafe { cache_misaligned.read_volatile() };
        //let _ = unsafe { page_aligned.read_volatile() };
    }

    let c2 = perf_ctr.rdpmc();
    let d2 = not_halted_cyc.rdpmc();
    let t2 = results.rdtsc();
    drop(perf_ctr);
    drop(not_halted_cyc);

    let ctr = c2 - c1;
    let dtr = d2 - d1;
    let ttr = t2 - t1;
    eprintln!("MISAL. COUNTERS: {c2} - {c1} = {ctr}");
    eprintln!("CYC.   COUNTERS: {d2} - {d1} = {dtr}");
    eprintln!("TSC    COUNTERS: {t2} - {t1} = {ttr}");
    eprintln!(
        "{:.3} page-unaligned loads per iteration",
        ctr as f64 / f64::from(n)
    );
}
