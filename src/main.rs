#![no_std]
#![no_main]
#![feature(abi_efiapi)]
#![feature(negative_impls)]
#![feature(const_fn_trait_bound)]
#![feature(new_uninit)]
#![feature(maybe_uninit_slice)]
#![feature(bool_to_option)]
#![allow(clippy::missing_safety_doc)]

#[macro_use]
extern crate alloc;
// make sure to link this
extern crate rlibc;

use alloc::{string::String, vec::Vec};
use core::{convert::TryFrom, fmt::Write, time::Duration};

use uefi::{
    prelude::*,
    proto::{
        console::text::{Key, ScanCode},
        device_path::DevicePath,
        loaded_image::LoadedImage,
        media::{
            block::BlockIO,
            file::{File, FileAttribute, FileInfo, FileMode, FileType},
            fs::SimpleFileSystem,
            partition::{GptPartitionType, PartitionInfo},
        },
    },
    table::{boot::MemoryType, runtime::ResetType},
    CStr16, CString16,
};

use crate::{
    boot_services_ext::BootServicesExt,
    config::Config,
    error::{Error, OpalError, Result, ResultFixupExt},
    nvme_device::NvmeDevice,
    nvme_passthru::*,
    opal::{session::OpalSession, uid, LockingState, StatusCode},
    secure_device::SecureDevice,
    util::sleep,
};

pub mod boot_services_ext;
pub mod config;
pub mod dp_to_text;
pub mod error;
pub mod nvme_device;
pub mod nvme_passthru;
pub mod opal;
pub mod secure_device;
pub mod util;

#[entry]
fn main(image_handle: Handle, mut st: SystemTable<Boot>) -> Status {
    if uefi_services::init(&mut st).log_warning().is_err() {
        log::error!("Failed to initialize UEFI services");
        log::error!("Shutting down in 10s..");
        sleep(Duration::from_secs(10));
    }
    if let Err(err) = run(image_handle, &mut st) {
        log::error!("Error: {:?}", err);
        log::error!("Shutting down in 10s..");
        sleep(Duration::from_secs(10));
    }
    st.runtime_services()
        .reset(ResetType::Shutdown, Status::SUCCESS, None)
}

fn run(image_handle: Handle, st: &mut SystemTable<Boot>) -> Result {
    config_stdout(st).fix(info!())?;

    let config = load_config(image_handle, st)?;

    let devices = find_secure_devices(st).fix(info!())?;

    for mut device in devices {
        if device.recv_locked().fix(info!())? {
            // session mutably borrows the device
            {
                let mut prompt = config.prompt.as_deref().unwrap_or("password: ");
                let mut session = loop {
                    let password = read_password(st, prompt)?;

                    let mut hash = vec![0; 32];

                    // as in sedutil-cli, maybe will change
                    pbkdf2::pbkdf2::<hmac::Hmac<sha1::Sha1>>(
                        password.as_bytes(),
                        device.proto().serial_num(),
                        75000,
                        &mut hash,
                    );

                    if let Some(s) =
                        pretty_session(st, &mut device, &*hash, config.sed_locked_msg.as_deref())?
                    {
                        break s;
                    }

                    if config.clear_on_retry {
                        st.stdout().clear().fix(info!())?;
                    }

                    prompt = config
                        .retry_prompt
                        .as_deref()
                        .unwrap_or("bad password, retry: ");
                };

                session.set_mbr_done(true)?;
                session.set_locking_range(0, LockingState::ReadWrite)?;
            }

            // reconnect the controller to see
            // the real partition pop up after unlocking
            device.reconnect_controller(st).fix(info!())?;
        }
    }

    let handle = find_boot_partition(st)?;

    let dp = st
        .boot_services()
        .handle_protocol::<DevicePath>(handle)
        .fix(info!())?;
    let dp = unsafe { &mut *dp.get() };

    let image = config.image;
    let buf = read_file(st, handle, &image)
        .fix(info!())?
        .ok_or(Error::ImageNotFound(image))?;

    if buf.get(0..2) != Some(&[0x4d, 0x5a]) {
        return Err(Error::ImageNotPeCoff);
    }

    let loaded_image_handle = st
        .boot_services()
        .load_image(false, image_handle, Some(dp), Some(&buf))
        .fix(info!())?;
    let loaded_image = st
        .boot_services()
        .handle_protocol::<LoadedImage>(loaded_image_handle)
        .fix(info!())?;
    let loaded_image = unsafe { &mut *loaded_image.get() };

    let args = CString16::try_from(&*config.args).or(Err(Error::ConfigArgsBadUtf16))?;
    unsafe { loaded_image.set_load_options(args.as_ptr(), args.num_bytes() as _) };

    st.boot_services()
        .start_image(loaded_image_handle)
        .fix(info!())?;

    Ok(())
}

fn config_stdout(st: &mut SystemTable<Boot>) -> uefi::Result {
    st.stdout().reset(false)?.log();

    if let Some(mode) = st.stdout().modes().max_by_key(|m| {
        let m = m.log();
        m.rows() * m.columns()
    }) {
        st.stdout().set_mode(mode.split().1)?.log();
    };
    Ok(().into())
}

fn load_config(image_handle: Handle, st: &mut SystemTable<Boot>) -> Result<Config> {
    let loaded_image = st
        .boot_services()
        .handle_protocol::<LoadedImage>(image_handle)
        .fix(info!())?;
    let device_path = st
        .boot_services()
        .handle_protocol::<DevicePath>(unsafe { &*loaded_image.get() }.device())
        .fix(info!())?;
    let device_handle = st
        .boot_services()
        .locate_device_path::<SimpleFileSystem>(unsafe { &mut *device_path.get() })
        .fix(info!())?;
    let buf = read_file(st, device_handle, "config")
        .fix(info!())?
        .ok_or(Error::ConfigMissing)?;
    let config = Config::parse(&buf)?;
    log::set_max_level(config.log_level);
    log::debug!("loaded config = {:#?}", config);
    Ok(config)
}

fn write_char(st: &mut SystemTable<Boot>, ch: u16) -> Result {
    let str = &[ch, 0];
    st.stdout()
        .output_string(unsafe { CStr16::from_u16_with_nul_unchecked(str) })
        .fix(info!())
}

fn read_password(st: &mut SystemTable<Boot>, prompt: &str) -> Result<String> {
    st.stdout().write_str(prompt).unwrap();

    let mut wait_for_key = [unsafe { st.stdin().wait_for_key_event().unsafe_clone() }];

    let mut data = String::with_capacity(32);
    loop {
        st.boot_services()
            .wait_for_event(&mut wait_for_key)
            .fix(info!())?;

        match st.stdin().read_key().fix(info!())? {
            Some(Key::Printable(k)) if [0xD, 0xA].contains(&u16::from(k)) => {
                write_char(st, 0x0D)?;
                write_char(st, 0x0A)?;
                break Ok(data);
            }
            Some(Key::Printable(k)) if u16::from(k) == 0x8 => {
                if data.pop().is_some() {
                    write_char(st, 0x08)?;
                }
            }
            Some(Key::Printable(k)) => {
                write_char(st, '*' as u16)?;
                data.push(k.into());
            }
            Some(Key::Special(ScanCode::ESCAPE)) => {
                st.runtime_services()
                    .reset(ResetType::Shutdown, Status::SUCCESS, None)
            }
            _ => {}
        }
    }
}

fn pretty_session<'d>(
    st: &mut SystemTable<Boot>,
    device: &'d mut SecureDevice,
    challenge: &[u8],
    sed_locked_msg: Option<&str>,
) -> Result<Option<OpalSession<'d>>> {
    match OpalSession::start(
        device,
        uid::OPAL_LOCKINGSP,
        uid::OPAL_ADMIN1,
        Some(challenge),
    ) {
        Ok(session) => Ok(Some(session)),
        Err(Error::Opal(OpalError::Status(StatusCode::NOT_AUTHORIZED))) => Ok(None),
        Err(Error::Opal(OpalError::Status(StatusCode::AUTHORITY_LOCKED_OUT))) => {
            st.stdout()
                .write_str(
                    sed_locked_msg
                        .unwrap_or("Too many bad tries, SED locked out, resetting in 10s.."),
                )
                .unwrap();
            sleep(Duration::from_secs(10));
            st.runtime_services()
                .reset(ResetType::Cold, Status::WARN_RESET_REQUIRED, None);
        }
        e => e.map(Some),
    }
}

fn find_secure_devices(st: &mut SystemTable<Boot>) -> uefi::Result<Vec<SecureDevice>> {
    let mut result = Vec::new();

    for handle in st.boot_services().find_handles::<BlockIO>()?.log() {
        let blockio = st.boot_services().handle_protocol::<BlockIO>(handle)?.log();

        if unsafe { &mut *blockio.get() }
            .media()
            .is_logical_partition()
        {
            continue;
        }

        let device_path = st
            .boot_services()
            .handle_protocol::<DevicePath>(handle)?
            .log();
        let device_path = unsafe { &mut *device_path.get() };

        if let Ok(nvme) = st
            .boot_services()
            .locate_device_path::<NvmExpressPassthru>(device_path)
            .log_warning()
        {
            let nvme = st
                .boot_services()
                .handle_protocol::<NvmExpressPassthru>(nvme)?
                .log();

            result.push(SecureDevice::new(handle, NvmeDevice::new(nvme.get())?.log())?.log())
        }

        // todo something like that:
        //
        // if let Ok(ata) = st
        //     .boot_services()
        //     .locate_device_path::<AtaExpressPassthru>(device_path)
        //     .log_warning()
        // {
        //     let ata = st
        //         .boot_services()
        //         .handle_protocol::<AtaExpressPassthru>(ata)?
        //         .log();
        //
        //     result.push(SecureDevice::new(handle, AtaDevice::new(ata.get())?.log())?.log())
        // }
        //
        // ..etc
    }
    Ok(result.into())
}

fn find_boot_partition(st: &mut SystemTable<Boot>) -> Result<Handle> {
    let mut res = None;
    for handle in st
        .boot_services()
        .find_handles::<PartitionInfo>()
        .fix(info!())?
    {
        let pi = st
            .boot_services()
            .handle_protocol::<PartitionInfo>(handle)
            .fix(info!())?;
        let pi = unsafe { &mut *pi.get() };

        match pi.gpt_partition_entry() {
            Some(gpt) if { gpt.partition_type_guid } == GptPartitionType::EFI_SYSTEM_PARTITION => {
                if res.replace(handle).is_some() {
                    return Err(Error::MultipleBootPartitions);
                }
            }
            _ => {}
        }
    }
    res.ok_or(Error::NoBootPartitions)
}

fn read_file(
    st: &mut SystemTable<Boot>,
    device: Handle,
    file: &str,
) -> uefi::Result<Option<Vec<u8>>> {
    let sfs = st
        .boot_services()
        .handle_protocol::<SimpleFileSystem>(device)?
        .log();
    let sfs = unsafe { &mut *sfs.get() };

    let file_handle = sfs
        .open_volume()?
        .log()
        .open(file, FileMode::Read, FileAttribute::empty())?
        .log();

    if let FileType::Regular(mut f) = file_handle.into_type()?.log() {
        let info = f.get_boxed_info::<FileInfo>()?.log();
        let size = info.file_size() as usize;
        let ptr = st
            .boot_services()
            .allocate_pool(MemoryType::LOADER_DATA, size)?
            .log();
        let mut buf = unsafe { Vec::from_raw_parts(ptr, size, size) };

        let read = f
            .read(&mut buf)
            .map_err(|_| uefi::Status::BUFFER_TOO_SMALL)?
            .log();
        buf.truncate(read);
        Ok(Some(buf).into())
    } else {
        Ok(None.into())
    }
}
