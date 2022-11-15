//! Implementation of [`PageTableEntry`] and [`PageTable`].

use super::{frame_alloc, FrameTracker, PhysPageNum, StepByOne, VirtAddr, VirtPageNum};
use _core::ops::Index;
use alloc::vec;
use alloc::vec::Vec;
use bitflags::*;

bitflags! {
    /// page table entry flags
    pub struct PTEFlags: u8 {
        const V = 1 << 0;
        const R = 1 << 1;
        const W = 1 << 2;
        const X = 1 << 3;
        const U = 1 << 4;
        const G = 1 << 5;
        const A = 1 << 6;
        const D = 1 << 7;
    }
}

#[derive(Copy, Clone)]
#[repr(C)]
/// page table entry structure
pub struct PageTableEntry {
    pub bits: usize,
}

impl core::fmt::Debug for PageTableEntry {
    fn fmt(&self, f: &mut _core::fmt::Formatter<'_>) -> _core::fmt::Result {
        f.debug_struct("PageTableEntry")
            .field("ppn", &self.ppn())
            .field("flags", &self.flags())
            .finish()
    }
}

impl PageTableEntry {
    pub fn new(ppn: PhysPageNum, flags: PTEFlags) -> Self {
        PageTableEntry {
            bits: ppn.0 << 10 | flags.bits as usize,
        }
    }
    pub fn empty() -> Self {
        PageTableEntry { bits: 0 }
    }
    pub fn ppn(&self) -> PhysPageNum {
        (self.bits >> 10 & ((1usize << 44) - 1)).into()
    }
    pub fn flags(&self) -> PTEFlags {
        PTEFlags::from_bits(self.bits as u8).unwrap()
    }
    pub fn is_valid(&self) -> bool {
        (self.flags() & PTEFlags::V) != PTEFlags::empty()
    }
    pub fn readable(&self) -> bool {
        (self.flags() & PTEFlags::R) != PTEFlags::empty()
    }
    pub fn writable(&self) -> bool {
        (self.flags() & PTEFlags::W) != PTEFlags::empty()
    }
    pub fn executable(&self) -> bool {
        (self.flags() & PTEFlags::X) != PTEFlags::empty()
    }
}

/// page table structure
pub struct PageTable {
    root_ppn: PhysPageNum,
    frames: Vec<FrameTracker>,
}

/// Assume that it won't oom when creating/mapping.
impl PageTable {
    pub fn new() -> Self {
        let frame = frame_alloc().unwrap();
        PageTable {
            root_ppn: frame.ppn,
            frames: vec![frame],
        }
    }
    /// Temporarily used to get arguments from user space.
    pub fn from_token(satp: usize) -> Self {
        Self {
            root_ppn: PhysPageNum::from(satp & ((1usize << 44) - 1)),
            frames: Vec::new(),
        }
    }
    fn find_pte_create(&mut self, vpn: VirtPageNum) -> Option<&mut PageTableEntry> {
        let mut idxs = vpn.indexes();
        let mut ppn = self.root_ppn;
        let mut result: Option<&mut PageTableEntry> = None;
        // debug!("Finding entry {vpn:?} => {idxs:?}");
        for (i, idx) in idxs.iter_mut().enumerate() {
            let pte = &mut ppn.get_pte_array()[*idx];
            if i == 2 {
                result = Some(pte);
                break;
            }
            if !pte.is_valid() {
                self.dbg_0x10000();
                let frame = frame_alloc().unwrap();
                *pte = PageTableEntry::new(frame.ppn, PTEFlags::V);
                debug!("Initializing {vpn:?}:{i}=>{idx} -> {pte:?}");
                self.dbg_0x10000();
                self.frames.push(frame);
            }
            ppn = pte.ppn();
        }
        result
    }
    fn find_pte(&self, vpn: VirtPageNum) -> Option<&PageTableEntry> {
        let idxs = vpn.indexes();
        let mut ppn = self.root_ppn;
        let mut result: Option<&PageTableEntry> = None;
        for (i, idx) in idxs.iter().enumerate() {
            let pte = &ppn.get_pte_array()[*idx];
            if i == 2 {
                result = Some(pte);
                break;
            }
            if !pte.is_valid() {
                return None;
            }
            ppn = pte.ppn();
        }
        result
    }

    pub fn dbg_0x10000(&self) {
        let vpn = 0x10000.into();
        let pte = self.find_pte(vpn);
        warn!("PTE-find: {pte:?}");
        if let Some(pte) = pte {
            warn!("PTE PTR: {:x}", pte as *const PageTableEntry as usize)
        }
        // let pte = self.find_pte_create(vpn).unwrap();
        // warn!("PTE-find_create: {pte:?}");
    }

    pub fn mmap(&mut self, vpn: VirtPageNum, flags: PTEFlags) -> bool {
        trace!("MMAP {vpn:?} BEGIN");
        let pte = self.find_pte(vpn);
        trace!("PTE-before:find: {pte:?}");
        self.dbg_0x10000();
        let pte = self.find_pte_create(vpn).unwrap();
        trace!("PTE-before: {pte:?}");
        trace!("PTE PTR: {:X}", pte as *mut PageTableEntry as usize);
        assert!(!pte.is_valid(), "vpn {:?} is mapped before mapping", vpn);
        let Some(tracker) = frame_alloc() else { return false; };
        let ppn = tracker.ppn;
        *pte = PageTableEntry::new(ppn, flags | PTEFlags::V);
        trace!("PTE-after: {pte:?}");
        self.dbg_0x10000();
        let pte = self.find_pte(vpn);
        trace!("PTE-find: {pte:?}");
        let pte = self.find_pte_create(vpn).unwrap();
        trace!("PTE-aaaaafter: {pte:?}");
        self.frames.push(tracker);
        trace!("MMAP {vpn:?} SUCCESS");
        true
    }

    pub fn munmap(&mut self, vpn: VirtPageNum) -> bool {
        let Some(pte) = self.find_pte_create(vpn) else { return false; };
        let ppn = pte.ppn();

        if !pte.is_valid() {
            return false;
        }
        *pte = PageTableEntry::empty();
        let id = self
            .frames
            .iter()
            .position(|fr| fr.ppn == ppn)
            .unwrap();
        self.frames.remove(id);
        true
    }

    #[allow(unused)]
    pub fn map(&mut self, vpn: VirtPageNum, ppn: PhysPageNum, flags: PTEFlags) {
        let pte = self.find_pte_create(vpn).unwrap();
        assert!(!pte.is_valid(), "vpn {:?} is mapped before mapping", vpn);
        *pte = PageTableEntry::new(ppn, flags | PTEFlags::V);
        // debug!("MAP {vpn:?} => {ppn:?}, flags: {flags:?}")
    }
    #[allow(unused)]
    pub fn unmap(&mut self, vpn: VirtPageNum) {
        let pte = self.find_pte_create(vpn).unwrap();
        assert!(pte.is_valid(), "vpn {:?} is invalid before unmapping", vpn);
        *pte = PageTableEntry::empty();
        debug!("UNMAP {vpn:?} => {pte:?}")
    }
    pub fn translate(&self, vpn: VirtPageNum) -> Option<PageTableEntry> {
        self.find_pte(vpn).copied()
    }
    pub fn token(&self) -> usize {
        8usize << 60 | self.root_ppn.0
    }
}

/// translate a pointer to a mutable u8 Vec through page table
pub fn translated_byte_buffer(token: usize, ptr: *const u8, len: usize) -> Vec<&'static mut [u8]> {
    let page_table = PageTable::from_token(token);
    let mut start = ptr as usize;
    let end = start + len;
    let mut v = Vec::new();
    while start < end {
        let start_va = VirtAddr::from(start);
        let mut vpn = start_va.floor();
        let ppn = page_table.translate(vpn).unwrap().ppn();
        vpn.step();
        let mut end_va: VirtAddr = vpn.into();
        end_va = end_va.min(VirtAddr::from(end));
        if end_va.page_offset() == 0 {
            v.push(&mut ppn.get_bytes_array()[start_va.page_offset()..]);
        } else {
            v.push(&mut ppn.get_bytes_array()[start_va.page_offset()..end_va.page_offset()]);
        }
        start = end_va.into();
    }
    v
}
