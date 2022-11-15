//! Process management syscalls

use core::mem;

use crate::config::MAX_SYSCALL_NUM;
use crate::mm::{frame_alloc, PTEFlags, PageTable, VPNRange, VirtAddr, PageTableEntry};
use crate::task::{
    current_syscall_times, current_user_start_time, current_user_token, exit_current_and_run_next,
    suspend_current_and_run_next, TaskStatus,
};
use crate::timer::{get_time_ms, get_time_us};

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

#[derive(Clone, Copy)]
pub struct TaskInfo {
    pub status: TaskStatus,
    pub syscall_times: [u32; MAX_SYSCALL_NUM],
    pub time: usize,
}

bitflags! {
    struct MmapPort : usize {
        const R = 0b001;
        const W = 0b010;
        const X = 0b100;
    }
}

pub fn sys_exit(exit_code: i32) -> ! {
    info!("[kernel] Application exited with code {}", exit_code);
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    suspend_current_and_run_next();
    0
}

// YOUR JOB: 引入虚地址后重写 sys_get_time
pub fn sys_get_time(ts: *mut TimeVal, _tz: usize) -> isize {
    let us = get_time_us();
    let token = current_user_token();
    let page_table = PageTable::from_token(token);
    let v_addr: VirtAddr = (ts as usize).into();
    let vpn = v_addr.floor();
    let ppn = page_table.translate(vpn).unwrap().ppn();
    let offset = v_addr.page_offset();
    *ppn.get_mut_offset(offset) = TimeVal {
        sec: us / 1_000_000,
        usec: us % 1_000_000,
    };
    0
}

// CLUE: 从 ch4 开始不再对调度算法进行测试~
pub fn sys_set_priority(_prio: isize) -> isize {
    -1
}


pub fn sys_dbg() -> isize {
    warn!("sizeof PTE: {}", mem::size_of::<PageTableEntry>());
    let token = current_user_token();
    let mut page_table = PageTable::from_token(token);
    page_table.dbg_0x10000();
    0
}

// YOUR JOB: 扩展内核以实现 sys_mmap 和 sys_munmap
pub fn sys_mmap(start: usize, len: usize, port: usize) -> isize {
    let Some(flags) = MmapPort::from_bits(port) else { return -1;};
    let s_addr = VirtAddr::from(start);
    let offset = s_addr.page_offset();
    if port & 0b111 == 0 || offset != 0 {
        // 1. Meaningless combination
        // 2. start not aligned by page size

        debug!("MMAP got invalid argument!, port = {port}, s_addr = {s_addr:?}, offset = {offset}");
        return -1;
    }
    let e_vpn = VirtAddr::from(start + len).ceil();
    if len == 0 {
        // No allocation at all.
        // TODO: check
        return 0;
    }
    let token = current_user_token();
    let mut page_table = PageTable::from_token(token);
    let flags = PTEFlags::U | PTEFlags::from_bits((flags.bits as u8) << 1).unwrap();
    trace!("PTEFlags: {flags:?}");
    for vpn in VPNRange::new(s_addr.into(), e_vpn) {
        
        if !page_table.mmap(vpn, flags) {
            // Roll back partial alloc
            debug!("MMAP failed!");
            // page_table.unmap(vpn);
            return -1;
        }
        page_table.dbg_0x10000();
    }
    0
}

pub fn sys_munmap(start: usize, len: usize) -> isize {
    let s_addr = VirtAddr::from(start);
    if s_addr.page_offset() != 0 {
        // start not aligned by page size
        return -1;
    }
    if len == 0 {
        // no need to unmap
        return 0;
    }
    let e_vpn = VirtAddr::from(start + len).ceil();
    let token = current_user_token();
    let mut page_table = PageTable::from_token(token);
    for vpn in VPNRange::new(s_addr.into(), e_vpn) {
        if !page_table.munmap(vpn) {
            return -1;
        }
    }
    0
}

// YOUR JOB: 引入虚地址后重写 sys_task_info
pub fn sys_task_info(ti: *mut TaskInfo) -> isize {
    let token = current_user_token();
    let page_table = PageTable::from_token(token);
    let v_addr: VirtAddr = (ti as usize).into();
    let vpn = v_addr.floor();
    let ppn = page_table.translate(vpn).unwrap().ppn();
    let offset = v_addr.page_offset();
    *ppn.get_mut_offset(offset) = TaskInfo {
        status: TaskStatus::Running,
        syscall_times: current_syscall_times(),
        time: get_time_ms() - current_user_start_time(),
    };
    0
}
