use alloc::string::String;
use uefi::{
    proto::{device_path::DevicePath, Protocol},
    unsafe_guid, CStr16, Char16,
};

type ToTextFn = unsafe extern "efiapi" fn(
    device_node: &DevicePath,
    display_only: bool,
    allow_shortcuts: bool,
) -> *const Char16;

#[unsafe_guid("8b843e20-8132-4852-90cc-551a4e4a7f1c")]
#[derive(Protocol)]
struct DevicePathToText {
    convert_device_node_to_text: ToTextFn,
    convert_device_path_to_text: ToTextFn,
}

pub fn device_path_to_text(
    device_path: &DevicePath,
    display_only: bool,
    allow_shortcuts: bool,
) -> uefi::Result<String> {
    let p = unsafe { uefi_services::system_table().as_ref() }
        .boot_services()
        .locate_protocol::<DevicePathToText>()?
        .log();

    do_to_text(
        unsafe { &mut *p.get() }.convert_device_path_to_text,
        device_path,
        display_only,
        allow_shortcuts,
    )
}

pub fn device_node_to_text(
    device_path: &DevicePath,
    display_only: bool,
    allow_shortcuts: bool,
) -> uefi::Result<String> {
    let p = unsafe { uefi_services::system_table().as_ref() }
        .boot_services()
        .locate_protocol::<DevicePathToText>()?
        .log();

    do_to_text(
        unsafe { &mut *p.get() }.convert_device_node_to_text,
        device_path,
        display_only,
        allow_shortcuts,
    )
}

fn do_to_text(
    ptr: ToTextFn,
    device_node: &DevicePath,
    display_only: bool,
    allow_shortcuts: bool,
) -> uefi::Result<String> {
    let res_ptr = unsafe { (ptr)(device_node, display_only, allow_shortcuts) };
    if res_ptr.is_null() {
        return Err(uefi::Status::NOT_FOUND.into());
    }
    let res = unsafe { CStr16::from_ptr(res_ptr) }.as_string();
    unsafe { uefi_services::system_table().as_ref() }
        .boot_services()
        .free_pool(res_ptr as _)?
        .status()
        .into_with_val(|| res)
}
