use crate::{
    opal::{
        tiny_atom, token, OpalHeader, PacketHeader, SimpleToken, SubpacketHeader, Token,
        TokenStream, BS8,
    },
    token_list, tokens,
};
use alloc::{borrow::ToOwned, vec::Vec};
use core::mem::{size_of, size_of_val};

pub struct OpalCommandBuilder {
    payload: Vec<u8>,
}

impl OpalCommandBuilder {
    pub fn empty() -> Self {
        Self {
            payload: Vec::new(),
        }
    }

    pub fn new(invoking_uid: BS8, method: BS8) -> Self {
        Self {
            payload: tokens![token::CALL, invoking_uid, method].0.unwrap(),
        }
    }

    pub fn payload(mut self, payload: TokenStream) -> OpalCommandBuilder {
        if let Some(p) = payload.0 {
            self.payload.extend(p);
        }
        self
    }

    fn build_eod(mut self, eod: bool) -> OpalCommand {
        let mut header = OpalHeader::default();

        if eod {
            tokens![
                token::ENDOFDATA,
                token_list![tiny_atom::UINT_00, tiny_atom::UINT_00, tiny_atom::UINT_00],
            ]
            .write(&mut self.payload);
        }
        header.subpkt.length = self.payload.len() as u32;
        while self.payload.len() % 4 != 0 {
            self.payload.push(0);
        }
        header.pkt.length = (self.payload.len() + size_of::<SubpacketHeader>()) as u32;
        header.cp.length =
            (self.payload.len() + size_of::<SubpacketHeader>() + size_of::<PacketHeader>()) as u32;

        OpalCommand {
            header,
            payload: self.payload,
            eod,
        }
    }

    pub fn build(self) -> OpalCommand {
        self.build_eod(true)
    }

    pub fn build_no_end_of_data(self) -> OpalCommand {
        self.build_eod(false)
    }
}

pub struct OpalCommand {
    pub header: OpalHeader,
    pub payload: Vec<u8>,
    pub eod: bool,
}

impl OpalCommand {
    pub fn set_session(&mut self, com_id: u16, tsn: u32, hsn: u32) {
        self.header.cp.extended_com_id = [
            ((com_id & 0xff00) >> 8) as u8,
            (com_id & 0x00ff) as u8,
            0,
            0,
        ];
        self.header.pkt.tsn = tsn.to_be();
        self.header.pkt.hsn = hsn.to_be();
    }
}

pub struct OpalResponse {
    pub header: OpalHeader,
    pub tokens: Vec<Vec<u8>>,
}

impl OpalResponse {
    pub fn parse(header: OpalHeader, bytes: &[u8]) -> Self {
        let mut tokens = Vec::new();
        let offset = size_of_val(&header);

        let mut pos = offset;

        let len = header.subpkt.length as usize + offset;

        while pos < len {
            let token_len = if bytes[pos] & 0x80 == 0 {
                // tiny atom
                1
            } else if bytes[pos] & 0x40 == 0 {
                // short atom
                (bytes[pos] as usize & 0x0F) + 1
            } else if bytes[pos] & 0x20 == 0 {
                // medium atom
                (((bytes[pos] as usize & 0x07) << 8) | bytes[pos + 1] as usize) + 2
            } else if bytes[pos] & 0x10 == 0 {
                // long atom
                (((bytes[pos + 1] as usize) << 16)
                    | ((bytes[pos + 2] as usize) << 8)
                    | bytes[pos + 3] as usize)
                    + 4
            } else {
                // token
                1
            };
            // skip empty atoms
            if token_len != 1 || bytes[pos] != 0xFF {
                tokens.push(bytes[pos..pos + token_len as usize].to_owned());
            }
            pos += token_len as usize;
        }

        log::trace!("parsed tokens: {:X?}", tokens);

        Self { header, tokens }
    }

    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }

    pub fn is(&self, index: usize, token: SimpleToken) -> bool {
        self.tokens.get(index).map(Vec::as_slice) == Some(&[token.token])
    }

    pub fn get_uint(&self, index: usize) -> u64 {
        let token = &self.tokens[index];

        if token[0] & 0x80 == 0 {
            // tiny atom
            if token[0] & 0x40 == 0 {
                (token[0] & 0x3f) as u64
            } else {
                panic!("unsigned int requested for signed tiny atom")
            }
        } else if token[0] & 0x40 == 0 {
            // short atom
            if token[0] & 0x10 == 0 {
                let mut whatever = 0;
                if token.len() > 9 {
                    panic!("u64 with more than 8 bytes");
                }
                let mut i = token.len();
                for b in 0..token.len() {
                    i -= 1;
                    whatever |= (token[i] as u64) << (8 * b);
                }
                whatever
            } else {
                panic!("unsigned int requested for signed short atom")
            }
        } else if (token[0] & 0x20) == 0 {
            // medium atom
            panic!("unsigned int requested for medium atom is unsupported");
        } else if (token[0] & 0x10) == 0 {
            // long atom
            panic!("unsigned int requested for long atom is unsupported");
        } else {
            // token
            panic!("unsigned int requested for token is unsupported");
        }
    }
}
