use alloc::string::String;
use core::{fmt::Write, mem::size_of_val, time::Duration};

use crate::{
    error::{Error, OpalError, Result},
    opal::{
        command::{OpalCommand, OpalCommandBuilder, OpalResponse},
        method, tiny_atom, token, uid, LockingState, OpalHeader, SimpleToken, StatusCode, BS8,
    },
    secure_device::SecureDevice,
    token_list, token_name, tokens,
    util::sleep,
};

pub struct OpalSession<'d> {
    device: &'d mut SecureDevice,
    tsn: u32,
    hsn: u32,
    protocol: u8,
}

impl<'d> OpalSession<'d> {
    pub fn start(
        device: &'d mut SecureDevice,
        sp_uid: BS8,
        sign_authority: BS8,
        challenge: Option<&[u8]>,
    ) -> Result<Self> {
        let mut s = Self {
            device,
            tsn: 0,
            hsn: 0,
            protocol: 0x01,
        };

        let challenge_tokens = match challenge {
            Some(challenge) if !s.device.is_eprise() => {
                tokens![
                    token_name!(tiny_atom::UINT_00, challenge),
                    token_name!(tiny_atom::UINT_03, sign_authority),
                ]
            }
            _ => tokens![],
        };

        let command = OpalCommandBuilder::new(uid::OPAL_SMUID, method::STARTSESSION)
            .payload(token_list![
                105, // our HSN, same as in sedutil, although looks like it can be arbitrary
                sp_uid,
                tiny_atom::UINT_01,
                challenge_tokens,
                if s.device.is_eprise() {
                    token_name!(b"SessionTimeout", 60000)
                } else {
                    tokens![]
                }
            ])
            .build();

        let response = unsafe { s.send_raw_command(command) }?;

        s.hsn = response.get_uint(4) as _;
        s.tsn = response.get_uint(5) as _;

        match &challenge {
            Some(_challenge) if s.device.is_eprise() => {
                unimplemented!();
                // LOG(D1) << "Entering DtaSession::authenticate ";
                // 	vector<uint8_t> hash;
                // 	DtaCommand *cmd = new DtaCommand();
                // 	if (NULL == cmd) {
                // 		LOG(E) << "Unable to create session object ";
                // 		return DTAERROR_OBJECT_CREATE_FAILED;
                // 	}
                // 	DtaResponse response;
                // 	cmd->reset(OPAL_UID::OPAL_THISSP_UID, OPAL_METHOD::EAUTHENTICATE);
                // 	cmd->addToken(OPAL_TOKEN::STARTLIST); // [  (Open Bracket)
                // 	cmd->addToken(Authority);
                //     if (Challenge && *Challenge)
                //     {
                // 		cmd->addToken(OPAL_TOKEN::STARTNAME);
                // 		if (d->isEprise())
                // 			cmd->addToken("Challenge");
                // 		else
                // 			cmd->addToken(OPAL_TINY_ATOM::UINT_00);
                // 		if (hashPwd) {
                // 			hash.clear();
                // 			DtaHashPwd(hash, Challenge, d);
                // 			cmd->addToken(hash);
                // 		}
                // 		else
                // 			cmd->addToken(Challenge);
                // 		cmd->addToken(OPAL_TOKEN::ENDNAME);
                //     }
                // 	cmd->addToken(OPAL_TOKEN::ENDLIST); // ]  (Close Bracket)
                // 	cmd->complete();
                // 	if ((lastRC = sendCommand(cmd, response)) != 0) {
                // 		LOG(E) << "Session Authenticate failed";
                // 		delete cmd;
                // 		return lastRC;
                // 	}
                // 	if (0 == response.getUint8(1)) {
                // 		LOG(E) << "Session Authenticate failed (response = false)";
                // 		delete cmd;
                // 		return DTAERROR_AUTH_FAILED;
                // 	}
            }
            _ => {}
        }

        Ok(s)
    }

    pub fn protocol(mut self, protocol: u8) -> Self {
        self.protocol = protocol;
        self
    }

    pub unsafe fn send_raw_command(&mut self, mut command: OpalCommand) -> Result<OpalResponse> {
        command.set_session(self.device.com_id(), self.tsn, self.hsn);

        let eod = command.eod;

        let mut header = command.header;

        let offset = size_of_val(&header);
        let mut buffer = crate::util::alloc_uninit_aligned(
            command.payload.len() + offset,
            self.device.proto().align(),
        );

        header.cp.length = header.cp.length.to_be();
        header.pkt.length = header.pkt.length.to_be();
        header.subpkt.length = header.subpkt.length.to_be();

        core::ptr::write(buffer.as_mut_ptr() as _, header);

        for (i, &b) in command.payload.iter().enumerate() {
            buffer[offset + i].write(b);
        }

        let mut buffer = buffer.assume_init();

        dump("sending", &buffer);

        let com_id = self.device.com_id();
        self.device
            .proto()
            .secure_send(self.protocol, com_id, buffer.as_mut())
            .map_err(|e| e.status())?
            .log();

        let mut buffer = crate::util::alloc_uninit_aligned(2048, self.device.proto().align());

        let mut header: OpalHeader;
        loop {
            sleep(Duration::from_millis(25));

            self.device
                .proto()
                .secure_recv(self.protocol, com_id, &mut buffer)
                .map_err(|e| e.status())?
                .log();

            header = core::ptr::read(buffer.as_ptr() as _);

            // zeroes are zeroes in any endianess
            if header.cp.outstanding_data == 0 || header.cp.min_transfer != 0 {
                break;
            }
        }
        header.cp.length = u32::from_be(header.cp.length);
        header.pkt.length = u32::from_be(header.pkt.length);
        header.subpkt.length = u32::from_be(header.subpkt.length);

        let buffer = buffer.assume_init();

        dump(
            "received",
            &buffer[..header.cp.length as usize + size_of_val(&header.cp)],
        );

        let response = OpalResponse::parse(header, buffer.as_ref());

        let len = response.len();
        if eod
            && len >= 6
            && response.is(len - 6, token::ENDOFDATA)
            && response.is(len - 5, token::STARTLIST)
            && response.is(len - 1, token::ENDLIST)
        {
            let code = StatusCode(response.get_uint(len - 4) as _);
            if code != StatusCode::SUCCESS {
                Err(code.into())
            } else {
                Ok(response)
            }
        } else {
            Err(OpalError::NoMethodStatus.into())
        }
    }

    #[allow(clippy::missing_safety_doc)]
    pub unsafe fn set_locking_sp_value(
        &mut self,
        table: BS8,
        name: SimpleToken,
        value: SimpleToken,
    ) -> Result {
        self.send_raw_command(
            OpalCommandBuilder::new(table, method::SET)
                .payload(token_list![token_name!(
                    token::VALUES,
                    token_list![token_name!(name, value)]
                )])
                .build(),
        )?;
        Ok(())
    }

    pub fn set_mbr_done(&mut self, done: bool) -> Result {
        unsafe { self.set_locking_sp_value(uid::OPAL_MBRCONTROL, token::MBRDONE, done.into()) }
    }

    pub fn set_locking_range(&mut self, locking_range: u8, locking_state: LockingState) -> Result {
        let mut archive_user = false;
        let mut read_lock = token::OPAL_FALSE;
        let mut write_lock = token::OPAL_FALSE;

        match locking_state {
            LockingState::ReadWrite => {}
            LockingState::ArchiveUnlocked | LockingState::ArchiveLocked => {
                archive_user = true;
            }
            LockingState::ReadOnly => {
                write_lock = token::OPAL_TRUE;
            }
            LockingState::Locked => {
                read_lock = token::OPAL_TRUE;
                write_lock = token::OPAL_TRUE;
            }
        }

        let locking_range = if locking_range != 0 {
            let mut bytes = uid::OPAL_LOCKINGRANGE_GLOBAL.bytes;
            bytes[5] = 0x03;
            bytes[7] = locking_range;
            BS8::new(bytes, "LOCKING_RANGE_N")
        } else {
            uid::OPAL_LOCKINGRANGE_GLOBAL
        };

        let command = OpalCommandBuilder::new(locking_range, method::SET)
            .payload(token_list![token_name!(
                token::VALUES,
                token_list![
                    token_name!(token::READLOCKED, read_lock),
                    if archive_user {
                        tokens![]
                    } else {
                        token_name!(token::WRITELOCKED, write_lock)
                    }
                ]
            )])
            .build();

        unsafe { self.send_raw_command(command) }?;
        Ok(())
    }
}

impl<'d> Drop for OpalSession<'d> {
    fn drop(&mut self) {
        let command = OpalCommandBuilder::empty()
            .payload(tokens![token::ENDOFSESSION])
            .build_no_end_of_data();
        match unsafe { self.send_raw_command(command) } {
            Err(Error::Opal(OpalError::NoMethodStatus)) => {} // that's expected
            Err(e) => log::error!("failed to send close session message: {:?}", e),
            _ => log::warn!("somehow got successful method status after CloseSession"),
        }
    }
}

fn dump(title: &str, buffer: impl AsRef<[u8]>) {
    let mut dump = String::new();
    for (i, b) in buffer.as_ref().iter().enumerate() {
        if i % 4 == 0 {
            dump.push(if i % 16 == 0 { '\n' } else { ' ' });
        }
        write!(&mut dump, "{:02X}", b).unwrap();
    }
    log::trace!("{}:{}", title, dump);
}
