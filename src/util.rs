use alloc::{alloc::alloc, boxed::Box};
use core::{alloc::Layout, mem::MaybeUninit, time::Duration};

pub fn sleep(duration: Duration) {
    // untie the sleep function from the system table
    // so that it can be used in the opal lib
    let bt = unsafe { uefi_services::system_table().as_ref() }.boot_services();
    // duration.as_nanos() works with u128 which is unsupported lol
    let nanos = duration.as_secs() * 1_000_000_000 + duration.subsec_nanos() as u64;
    bt.stall((nanos / 1000) as usize);
}

pub unsafe fn alloc_uninit_aligned(len: usize, align: usize) -> Box<[MaybeUninit<u8>]> {
    let ptr = alloc(Layout::from_size_align(len, align).unwrap()) as _;
    Box::from_raw(core::slice::from_raw_parts_mut(ptr, len))
}
