use alloc::vec::Vec;
use core::mem::MaybeUninit;

use uefi::Status;

use crate::{
    nvme_passthru::{self, Command, CommandPacket, NvmExpressPassthru, QueueType, SendTarget},
    secure_device::SecureProtocol,
};

pub struct NvmeDevice {
    passthru: *mut NvmExpressPassthru,
    align: usize,
    serial_num: Vec<u8>,
}

impl NvmeDevice {
    pub fn new(passthru: *mut NvmExpressPassthru) -> uefi::Result<NvmeDevice> {
        let serial_num = recv_serial_num(passthru)?.log();
        let align = unsafe { &mut *passthru }.mode().io_align as _;
        Ok(Self {
            passthru,
            align,
            serial_num,
        }
        .into())
    }
}

fn recv_serial_num(passthru: *mut NvmExpressPassthru) -> uefi::Result<Vec<u8>> {
    let passthru = unsafe { &mut *passthru };
    let mut data =
        unsafe { crate::util::alloc_uninit_aligned(4096, passthru.mode().io_align as usize) };
    let command = Command::new(0x06).cdw_10(1);
    let mut packet = CommandPacket::new(
        nvme_passthru::NVME_GENERIC_TIMEOUT,
        Some(&mut data),
        None,
        QueueType::ADMIN,
        &command,
    );

    unsafe { passthru.send(SendTarget::Controller, &mut packet) }?.log();

    let serial_num = unsafe { MaybeUninit::slice_assume_init_ref(&data[4..24]) };
    Ok(serial_num.to_vec().into())
}

#[repr(u8)]
enum Direction {
    Send = 0x81,
    Recv = 0x82,
}

unsafe fn secure_protocol(
    passthru: *mut NvmExpressPassthru,
    direction: Direction,
    protocol: u8,
    com_id: u16,
    buffer: &mut [MaybeUninit<u8>],
) -> uefi::Result {
    let command = Command::new(direction as u8)
        .cdw_10((protocol as u32) << 24 | (com_id as u32) << 8)
        .cdw_11(buffer.len() as u32);

    let mut packet = CommandPacket::new(
        nvme_passthru::NVME_GENERIC_TIMEOUT,
        Some(buffer),
        None,
        QueueType::ADMIN,
        &command,
    );
    (&mut *passthru)
        .send(SendTarget::Controller, &mut packet)?
        .log();

    Status::SUCCESS.into()
}

impl SecureProtocol for NvmeDevice {
    unsafe fn secure_send(&mut self, protocol: u8, com_id: u16, data: &mut [u8]) -> uefi::Result {
        secure_protocol(
            self.passthru,
            Direction::Send,
            protocol,
            com_id,
            core::slice::from_raw_parts_mut(data.as_mut_ptr() as _, data.len()),
        )
    }

    unsafe fn secure_recv(
        &mut self,
        protocol: u8,
        com_id: u16,
        buffer: &mut [MaybeUninit<u8>],
    ) -> uefi::Result {
        secure_protocol(self.passthru, Direction::Recv, protocol, com_id, buffer)
    }

    fn align(&self) -> usize {
        self.align
    }

    fn serial_num(&self) -> &[u8] {
        &self.serial_num
    }
}
