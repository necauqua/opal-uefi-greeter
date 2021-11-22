use alloc::vec::Vec;
use core::mem::MaybeUninit;

use bitflags::bitflags;
use core::{
    fmt::{Debug, Display, Formatter},
    ptr::null_mut,
    slice,
};
use uefi::{
    data_types::unsafe_guid,
    newtype_enum,
    proto::{device_path::DevicePath, Protocol},
    Event, Status,
};

#[unsafe_guid("52c78312-8edc-4233-98f2-1a1aa5e388a5")]
#[derive(Protocol)]
#[repr(C)]
pub struct NvmExpressPassthru {
    mode: *const Mode,
    pass_thru: unsafe extern "efiapi" fn(
        this: &NvmExpressPassthru,
        namespace_id: u32,
        packet: &mut CommandPacket,
        event: Event,
    ) -> Status,
    get_next_namespace:
        unsafe extern "efiapi" fn(this: &NvmExpressPassthru, namespace_id: &mut u32) -> Status,
    build_device_path: unsafe extern "efiapi" fn(
        this: &NvmExpressPassthru,
        namespace_id: u32,
        device_path: &mut *mut DevicePath,
    ) -> Status,
    get_namespace: unsafe extern "efiapi" fn(
        this: &NvmExpressPassthru,
        device_path: &DevicePath,
        namespace_id: &mut u32,
    ) -> Status,
}

impl NvmExpressPassthru {
    pub fn mode(&self) -> &Mode {
        unsafe { &*self.mode }
    }

    pub unsafe fn send<'a, 'b: 'a>(
        &'a mut self,
        target: SendTarget,
        packet: &mut CommandPacket<'b>,
    ) -> uefi::Result<NvmeCompletion> {
        self.send_async(target, packet, core::mem::zeroed())
    }

    pub unsafe fn send_async<'a, 'b: 'a>(
        &'a mut self,
        target: SendTarget,
        mut packet: &mut CommandPacket<'b>,
        event: Event,
    ) -> uefi::Result<NvmeCompletion> {
        let id = match target {
            SendTarget::Controller => 0,
            SendTarget::Namespace(id) => id.to_u32(),
            SendTarget::AllNamespaces => 0xFFFFFFFF,
        };
        let mut completion = Default::default();
        packet.completion = Some(&mut completion);
        (self.pass_thru)(self, id, packet, event).into_with_val(|| completion)
    }

    // shorthand assuming there is always at least one namespace on the NVMe controller
    pub fn first_namespace(&self) -> uefi::Result<NamespaceId> {
        let mut namespace_id = 0xFFFFFFFF;
        unsafe { (self.get_next_namespace)(self, &mut namespace_id) }
            .into_with_val(|| NamespaceId(namespace_id))
    }

    pub fn list_namespaces(&self) -> uefi::Result<Vec<NamespaceId>> {
        let mut namespace_id = 0xFFFFFFFF;
        let mut result = Vec::new();
        loop {
            let status = unsafe { (self.get_next_namespace)(self, &mut namespace_id) };
            if status.is_success() {
                result.push(NamespaceId(namespace_id));
            } else if status == Status::NOT_FOUND {
                break Status::SUCCESS.into_with_val(|| result);
            } else {
                break Err(status.into());
            }
        }
    }

    pub fn build_device_path(&self, namespace_id: NamespaceId) -> uefi::Result<&mut DevicePath> {
        let mut device_path = null_mut();
        unsafe { (self.build_device_path)(self, namespace_id.to_u32(), &mut device_path) }
            .into_with_val(|| unsafe { device_path.as_mut() }.unwrap())
    }

    pub fn get_namespace(&self, device_path: &DevicePath) -> uefi::Result<NamespaceId> {
        let mut namespace_id = 0;
        unsafe { (self.get_namespace)(self, device_path, &mut namespace_id) }
            .into_with_val(|| unsafe { NamespaceId::new(namespace_id) })
    }
}

#[derive(Debug)]
pub enum SendTarget {
    Controller,
    Namespace(NamespaceId),
    AllNamespaces,
}

newtype_enum! {
    #[must_use]
    pub enum QueueType: u8 => {
        ADMIN = 0,
        IO    = 1,
    }
}

bitflags! {
    #[repr(transparent)]
    pub struct Attributes: u32 {
        const PHYSICAL    = 0x01;
        const LOGICAL     = 0x02;
        const NONBLOCKIO  = 0x04;
        const CMD_SET_NVM = 0x08;
    }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct Version {
    data: [u8; 4],
}

impl Version {
    pub fn major(&self) -> u16 {
        (self.data[0] as u16) << 8 | self.data[1] as u16
    }
    pub fn minor(&self) -> u8 {
        self.data[2]
    }
    pub fn tertiary(&self) -> u8 {
        self.data[3]
    }
}

impl Debug for Version {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        f.debug_struct("Version")
            .field("major", &self.major())
            .field("minor", &self.major())
            .field("tertiary", &self.tertiary())
            .finish()
    }
}

impl Display for Version {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        write!(f, "{}.{}.{}", self.major(), self.minor(), self.tertiary())
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct Mode {
    pub attributes: Attributes,
    pub io_align: u32,
    pub version: Version,
}

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Copy, Clone)]
#[repr(transparent)]
pub struct NamespaceId(u32);

impl NamespaceId {
    /// # Safety
    /// This contructor allows to construct arbitrary unchecked NamespaceIds.
    ///
    /// This is to ensure that only safe way to get them is to actually query the device,
    /// as well as because all-zero and all-one bit patterns are not allowed to be NamespaceIds.
    pub const unsafe fn new(id: u32) -> NamespaceId {
        NamespaceId(id)
    }

    pub const fn to_u32(self) -> u32 {
        self.0
    }
}

pub const NVME_GENERIC_TIMEOUT: u64 = 5_000_000;

bitflags! {
    #[repr(transparent)]
    struct CdwValidityFlags: u8 {
        const CDW_2  = 0x01;
        const CDW_3  = 0x02;
        const CDW_10 = 0x04;
        const CDW_11 = 0x08;
        const CDW_12 = 0x10;
        const CDW_13 = 0x20;
        const CDW_14 = 0x40;
        const CDW_15 = 0x80;
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
struct Cdw0 {
    opcode: u8, // UINT32 Opcode:8;
    fused: u8,  // UINT32 FusedOperation:2;
    _res1: u8,  //
    _res2: u8,  // UINT32 Reserved:22;
}

#[repr(C)]
#[derive(Debug)]
pub struct Command {
    cdw_0: Cdw0,
    flags: CdwValidityFlags,
    pub nsid: u32,
    pub cdw_2: u32,
    pub cdw_3: u32,
    pub cdw_10: u32,
    pub cdw_11: u32,
    pub cdw_12: u32,
    pub cdw_13: u32,
    pub cdw_14: u32,
    pub cdw_15: u32,
}

macro_rules! cdws {
    ($($name:ident: $flag:ident;)*) => {
        $(
            pub const fn $name(mut self, $name: u32) -> Self {
                self.$name = $name;
                self.flags.bits |= CdwValidityFlags::$flag.bits;
                self
            }
        )*
    };
}

impl Command {
    pub const fn new(opcode: u8) -> Command {
        Command {
            cdw_0: Cdw0 {
                opcode,
                fused: 0,
                _res1: 0,
                _res2: 0,
            },
            flags: CdwValidityFlags::empty(),
            nsid: 0,
            cdw_2: 0,
            cdw_3: 0,
            cdw_10: 0,
            cdw_11: 0,
            cdw_12: 0,
            cdw_13: 0,
            cdw_14: 0,
            cdw_15: 0,
        }
    }

    pub const fn fused_first(mut self) -> Self {
        self.cdw_0.fused |= 0b10000000;
        self
    }

    pub const fn fused_second(mut self) -> Self {
        self.cdw_0.fused |= 0b01000000;
        self
    }

    pub const fn ns(mut self, namespace: NamespaceId) -> Self {
        self.nsid = namespace.to_u32();
        self
    }

    cdws! {
        cdw_2: CDW_2;
        cdw_3: CDW_3;
        cdw_10: CDW_10;
        cdw_11: CDW_11;
        cdw_12: CDW_12;
        cdw_13: CDW_13;
        cdw_14: CDW_14;
        cdw_15: CDW_15;
    }
}

#[repr(C)]
#[derive(Debug, Default, Clone)]
pub struct NvmeCompletion {
    pub dw_0: u32,
    pub dw_1: u32,
    pub dw_2: u32,
    pub dw_3: u32,
}

#[repr(C)]
pub struct CommandPacket<'a> {
    pub timeout: u64,
    transfer_buffer: *mut MaybeUninit<u8>,
    transfer_length: u32,
    metadata_buffer: *mut MaybeUninit<u8>,
    metadata_length: u32,
    pub queue_type: QueueType,
    pub cmd: &'a Command,
    pub completion: Option<*mut NvmeCompletion>,
}

impl Debug for CommandPacket<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CommandPacket")
            .field("timeout", &self.timeout)
            .field("transfer_buffer", unsafe {
                &slice::from_raw_parts_mut(self.transfer_buffer, self.transfer_length as usize)
            })
            .field("metadata_buffer", unsafe {
                &slice::from_raw_parts_mut(self.metadata_buffer, self.metadata_length as usize)
            })
            .field("queue_type", &self.queue_type)
            .field("cmd", &self.cmd)
            // .field("completion", &self.completion)
            .finish()
    }
}

impl<'a> CommandPacket<'a> {
    pub fn new(
        timeout: u64,
        transfer_buffer: Option<&mut [MaybeUninit<u8>]>,
        metadata_buffer: Option<&mut [MaybeUninit<u8>]>,
        queue_type: QueueType,
        cmd: &'a Command,
    ) -> Self {
        let (transfer_buffer, transfer_length) = transfer_buffer
            .map(|it| (it.as_mut_ptr(), it.len() as u32))
            .unwrap_or((null_mut(), 0));
        let (metadata_buffer, metadata_length) = metadata_buffer
            .map(|it| (it.as_mut_ptr(), it.len() as u32))
            .unwrap_or((null_mut(), 0));
        Self {
            timeout,
            transfer_buffer,
            transfer_length,
            metadata_buffer,
            metadata_length,
            queue_type,
            cmd,
            completion: None,
        }
    }
}
