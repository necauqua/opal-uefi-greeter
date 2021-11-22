use core::{mem::MaybeUninit, ptr::null};
use uefi::{prelude::BootServices, proto::device_path::DevicePath, table::Header, Handle, Status};

#[repr(C)]
struct BootServicesHack {
    header: Header,
    _ignored: [usize; 22],
    load_image: unsafe extern "efiapi" fn(
        boot_policy: u8,
        parent_image_handle: Handle,
        device_path: *const DevicePath,
        source_buffer: *const u8,
        source_size: usize,
        *mut MaybeUninit<Handle>,
    ) -> Status,
    _ignored2: [usize; 7],
    connect_controller: unsafe extern "efiapi" fn(
        controller: Handle,
        driver_image: Handle,
        remaining_device_path: *const DevicePath,
        recursive: bool,
    ) -> Status,
    disconnect_controller: unsafe extern "efiapi" fn(
        controller: Handle,
        driver_image: Handle,
        child: Handle,
    ) -> Status,
}

pub trait BootServicesExt: Sized {
    fn connect_controller(
        &self,
        controller: Handle,
        driver_image: Option<Handle>,
        remaining_device_path: Option<&DevicePath>,
        recursive: bool,
    ) -> uefi::Result {
        let hack = self as *const _ as *const BootServicesHack;
        unsafe {
            ((*hack).connect_controller)(
                controller,
                driver_image.unwrap_or_else(|| MaybeUninit::zeroed().assume_init()),
                remaining_device_path.map(|dp| dp as _).unwrap_or(null()),
                recursive,
            )
        }
        .into_with_err(|_| ())
    }

    fn disconnect_controller(
        &self,
        controller: Handle,
        driver_image: Option<Handle>,
        child: Option<Handle>,
    ) -> uefi::Result {
        let hack = self as *const _ as *const BootServicesHack;
        unsafe {
            ((*hack).disconnect_controller)(
                controller,
                driver_image.unwrap_or_else(|| MaybeUninit::zeroed().assume_init()),
                child.unwrap_or_else(|| MaybeUninit::zeroed().assume_init()),
            )
        }
        .into_with_err(|_| ())
    }

    fn load_image(
        &self,
        boot_policy: bool,
        parent_image_handle: Handle,
        device_path: Option<&DevicePath>,
        source_buffer: Option<&[u8]>,
    ) -> uefi::Result<Handle> {
        let hack = self as *const _ as *const BootServicesHack;
        unsafe {
            let mut image_handle = MaybeUninit::uninit();
            let device_path = device_path.map(|b| b as _).unwrap_or(null());
            ((*hack).load_image)(
                boot_policy as u8,
                parent_image_handle,
                device_path,
                source_buffer.map(|b| b.as_ptr()).unwrap_or(null()),
                source_buffer.map(|b| b.len()).unwrap_or_default(),
                &mut image_handle,
            )
            .into_with_val(|| image_handle.assume_init())
        }
    }
}

impl BootServicesExt for BootServices {}
