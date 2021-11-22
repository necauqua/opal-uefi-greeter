use alloc::vec::Vec;
use uefi::newtype_enum;

pub mod command;
pub mod session;

#[repr(C)]
#[derive(Debug, Default)]
pub struct ComPacketHeader {
    _reserved: u32,
    pub extended_com_id: [u8; 4],
    pub outstanding_data: u32,
    pub min_transfer: u32,
    pub length: u32,
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct PacketHeader {
    pub tsn: u32,
    pub hsn: u32,
    pub seq_number: u32,
    _reserved: u16,
    pub ack_type: u16,
    pub acknowledgement: u32,
    pub length: u32,
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct SubpacketHeader {
    _reserved: [u8; 6],
    pub kind: u16,
    pub length: u32,
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct OpalHeader {
    pub cp: ComPacketHeader,
    pub pkt: PacketHeader,
    pub subpkt: SubpacketHeader,
}

#[derive(Copy, Clone)]
pub struct SimpleToken {
    pub token: u8,
    #[cfg(debug_assertions)]
    name: &'static str,
}

impl SimpleToken {
    pub fn new(token: u8, _debug_name: &'static str) -> Self {
        Self {
            token,
            #[cfg(debug_assertions)]
            name: _debug_name,
        }
    }
}

impl core::fmt::Debug for SimpleToken {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        #[cfg(debug_assertions)]
        {
            f.write_str(self.name)
        }
        #[cfg(not(debug_assertions))]
        {
            write!(f, "SimpleToken({:02X})", self.token)
        }
    }
}

#[derive(Copy, Clone)]
pub struct BS8 {
    pub bytes: [u8; 8],
    #[cfg(debug_assertions)]
    name: &'static str,
}

impl BS8 {
    pub fn new(bytes: [u8; 8], _debug_name: &'static str) -> Self {
        Self {
            bytes,
            #[cfg(debug_assertions)]
            name: _debug_name,
        }
    }
}

impl core::fmt::Debug for BS8 {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        #[cfg(debug_assertions)]
        {
            f.write_str(self.name)
        }
        #[cfg(not(debug_assertions))]
        {
            write!(f, "BS8({:02X?})", self.bytes)
        }
    }
}

macro_rules! simple_tokens {
    ($($name:ident = $value:literal;)*) => {
        $(
            pub const $name: crate::opal::SimpleToken = crate::opal::SimpleToken {
                token: $value,
                #[cfg(debug_assertions)]
                name: stringify!($name),
            };
        )*
    };
}

macro_rules! bytestrings {
    ($($name:ident = $value:literal;)*) => {
        $(
            pub const $name: crate::opal::BS8 = crate::opal::BS8 {
                bytes: {
                    let u: u64 = $value;
                    u.to_be_bytes()
                },
                #[cfg(debug_assertions)]
                name: stringify!($name),
            };
        )*
    };
}

pub mod method {
    bytestrings! {
        PROPERTIES = 0xFF01;
        STARTSESSION = 0xFF02;
        REVERT = 0x600000202;
        ACTIVATE = 0x600000203;
        EGET = 0x600000006;
        ESET = 0x600000007;
        NEXT = 0x600000008;
        EAUTHENTICATE = 0x60000000C;
        GETACL = 0x60000000D;
        GENKEY = 0x600000010;
        REVERTSP = 0x600000011;
        GET = 0x600000016;
        SET = 0x600000017;
        AUTHENTICATE = 0x60000001C;
        RANDOM = 0x600000601;
        ERASE = 0x600000803;
    }
}

pub mod uid {
    bytestrings! {
        // users
        OPAL_SMUID = 0xFF;
        OPAL_THISSP = 0x1;
        OPAL_ADMINSP = 0x20500000001;
        OPAL_LOCKINGSP = 0x20500000002;
        ENTERPRISE_LOCKINGSP = 0x20500010001;
        OPAL_ANYBODY = 0x900000001;
        OPAL_SID = 0x900000006;
        OPAL_ADMIN1 = 0x900010001;
        OPAL_USER1 = 0x900030001;
        OPAL_USER2 = 0x900030002;
        OPAL_PSID = 0x90001FF01;
        ENTERPRISE_BANDMASTER0 = 0x900008001;
        ENTERPRISE_ERASEMASTER = 0x900008401;
        // tables
        OPAL_LOCKINGRANGE_GLOBAL = 0x80200000001;
        OPAL_LOCKINGRANGE_ACE_RDLOCKED = 0x80003E001;
        OPAL_LOCKINGRANGE_ACE_WRLOCKED = 0x80003E801;
        OPAL_LOCKINGRANGE_GLOBAL_ACE_RDLOCKED = 0x80003E000;
        OPAL_LOCKINGRANGE_GLOBAL_ACE_WRLOCKED = 0x80003E800;
        OPAL_MBRCONTROL_SET_DONE_TO_DOR = 0x80003F801;
        OPAL_MBRCONTROL = 0x80300000001;
        OPAL_MBR = 0x80400000000;
        OPAL_AUTHORITY_TABLE = 0x900000000;
        OPAL_C_PIN_TABLE = 0xB00000000;
        OPAL_LOCKING_INFO_TABLE = 0x80100000001;
        ENTERPRISE_LOCKING_INFO_TABLE = 0x80100000000;
        // C_PIN_TABLE object ID's
        OPAL_C_PIN_MSID = 0xB00008402;
        OPAL_C_PIN_SID = 0xB00000001;
        OPAL_C_PIN_ADMIN1 = 0xB00010001;
        // half UID's (only first 4 bytes used)
        OPAL_HALF_UID_AUTHORITY_OBJ_REF = 0xC05FFFFFFFF;
        OPAL_HALF_UID_BOOLEAN_ACE = 0x40EFFFFFFFF;
        // omitted optional parameter
        OPAL_UID_HEXFF = 0xFFFFFFFFFFFFFFFF;
    }
}

impl From<bool> for SimpleToken {
    fn from(b: bool) -> Self {
        if b {
            token::OPAL_TRUE
        } else {
            token::OPAL_FALSE
        }
    }
}

pub mod token {
    simple_tokens! {
        OPAL_TRUE = 0x01;
        OPAL_FALSE = 0x00;
        OPAL_BOOLEAN_EXPR = 0x03;

        // cellblocks
        TABLE = 0x00;
        STARTROW = 0x01;
        ENDROW = 0x02;
        STARTCOLUMN = 0x03;
        ENDCOLUMN = 0x04;
        VALUES = 0x01;

        // authority table
        PIN = 0x03;

        // locking tokens
        RANGESTART = 0x03;
        RANGELENGTH = 0x04;
        READLOCKENABLED = 0x05;
        WRITELOCKENABLED = 0x06;
        READLOCKED = 0x07;
        WRITELOCKED = 0x08;
        ACTIVEKEY = 0x0A;

        //locking info table
        MAXRANGES = 0x04;

        // mbr control
        MBRENABLE = 0x01;
        MBRDONE = 0x02;

        // properties
        HOSTPROPERTIES = 0x00;

        // response tokenis() returned values
        DTA_TOKENID_BYTESTRING = 0xE0;
        DTA_TOKENID_SINT = 0xE1;
        DTA_TOKENID_UINT = 0xE2;
        DTA_TOKENID_TOKEN = 0xE3;

        // atoms
        STARTLIST = 0xF0;
        ENDLIST = 0xF1;
        STARTNAME = 0xF2;
        ENDNAME = 0xF3;
        CALL = 0xF8;
        ENDOFDATA = 0xF9;
        ENDOFSESSION = 0xFA;
        STARTTRANSACTON = 0xFB;
        ENDTRANSACTON = 0xFC;
        EMPTYATOM = 0xFF;
        WHERE = 0x00;
    }
}

pub mod tiny_atom {
    simple_tokens! {
        UINT_00 = 0x00;
        UINT_01 = 0x01;
        UINT_02 = 0x02;
        UINT_03 = 0x03;
        UINT_04 = 0x04;
        UINT_05 = 0x05;
        UINT_06 = 0x06;
        UINT_07 = 0x07;
        UINT_08 = 0x08;
        UINT_09 = 0x09;
        UINT_10 = 0x0A;
        UINT_11 = 0x0B;
        UINT_12 = 0x0C;
        UINT_13 = 0x0D;
        UINT_14 = 0x0E;
        UINT_15 = 0x0F;
    }
}

pub mod short_atom {
    simple_tokens! {
        UINT_3 = 0x83;
        BYTESTRING4 = 0xA4;
        BYTESTRING8 = 0xA8;
    }
}

#[repr(u8)]
#[derive(Debug, Copy, Clone)]
pub enum LockingState {
    ReadWrite = 0x01,
    ReadOnly = 0x02,
    Locked = 0x03,
    ArchiveLocked = 0x04,
    ArchiveUnlocked = 0x05,
}

impl Token for LockingState {
    fn write(&self, buffer: &mut Vec<u8>) {
        buffer.push(*self as u8);
    }
}

newtype_enum! {
    #[must_use]
    pub enum StatusCode: u8 => {
        SUCCESS = 0x00,
        NOT_AUTHORIZED = 0x01,
        // OBSOLETE = 0x02,
        SP_BUSY = 0x03,
        SP_FAILED = 0x04,
        SP_DISABLED = 0x05,
        SP_FROZEN = 0x06,
        NO_SESSIONS_AVAILABLE = 0x07,
        UNIQUENESS_CONFLICT = 0x08,
        INSUFFICIENT_SPACE = 0x09,
        INSUFFICIENT_ROWS = 0x0A,
        INVALID_FUNCTION = 0x0B, // defined in early specs, still used in some firmware
        INVALID_PARAMETER = 0x0C,
        INVALID_REFERENCE = 0x0D,
        // OBSOLETE = 0x0E,
        TPER_MALFUNCTION = 0x0F,
        TRANSACTION_FAILURE = 0x10,
        RESPONSE_OVERFLOW = 0x11,
        AUTHORITY_LOCKED_OUT = 0x12,
        FAIL = 0x3F,
    }
}

pub trait Token: core::fmt::Debug {
    fn write(&self, buffer: &mut Vec<u8>);

    fn to_token_stream(&self) -> TokenStream {
        let mut res = Vec::new();
        self.write(&mut res);
        TokenStream(Some(res))
    }
}

#[derive(Debug)]
pub struct TokenStream(Option<Vec<u8>>);

impl TokenStream {
    pub fn empty() -> Self {
        Self(None)
    }
}

impl Token for SimpleToken {
    #[inline]
    fn write(&self, buffer: &mut Vec<u8>) {
        buffer.push(self.token)
    }
}

impl Token for BS8 {
    #[inline]
    fn write(&self, buffer: &mut Vec<u8>) {
        short_atom::BYTESTRING8.write(buffer);
        buffer.extend(self.bytes);
    }
}

impl Token for TokenStream {
    #[inline]
    fn write(&self, buffer: &mut Vec<u8>) {
        if let Some(x) = self.0.as_deref() {
            buffer.extend(x)
        }
    }
}

impl Token for u64 {
    fn write(&self, buffer: &mut Vec<u8>) {
        if *self < 64 {
            buffer.push(*self as u8 & 0b00111111);
            return;
        }
        let mut startat = 0;
        if *self < 0x100 {
            buffer.push(0x81);
        } else if *self < 0x10000 {
            buffer.push(0x82);
            startat = 1;
        } else if *self < 0x100000000 {
            buffer.push(0x84);
            startat = 3;
        } else {
            buffer.push(0x88);
            startat = 7;
        }
        while startat > -1 {
            buffer.push(((*self >> (startat * 8)) & 0xFF) as u8);
            startat -= 1;
        }
    }
}

impl Token for &[u8] {
    fn write(&self, buffer: &mut Vec<u8>) {
        if self.is_empty() {
            // null token
            buffer.push(0xA1);
            buffer.push(0x00);
        } else if self.len() < 16 {
            // tiny atom len
            buffer.push((self.len() | 0xA0) as u8);
        } else if self.len() < 2048 {
            // medium atom len
            buffer.push(0xD0 | ((self.len() >> 8) & 0x07) as u8);
            buffer.push((self.len() & 0xff) as u8);
        } else {
            panic!(
                "Bytestring too large ({} > 2048) to use in OpalPacket",
                self.len()
            );
        }
        buffer.extend(*self);
    }
}

impl<const N: usize> Token for &[u8; N] {
    #[inline]
    fn write(&self, buffer: &mut Vec<u8>) {
        self.as_slice().write(buffer)
    }
}

#[derive(Debug)]
pub struct TokenName<K: Token, V: Token>(pub K, pub V);

impl<K: Token, V: Token> Token for TokenName<K, V> {
    fn write(&self, buffer: &mut Vec<u8>) {
        token::STARTNAME.write(buffer);
        self.0.write(buffer);
        self.1.write(buffer);
        token::ENDNAME.write(buffer);
    }
}

#[derive(Debug)]
pub struct TokensNil;

#[derive(Debug)]
pub struct TokensCons<T: Token, R>(T, R);

pub trait TokensPush<T> {
    type Next;
    fn push(self, token: T) -> Self::Next;
}

impl<T: Token> TokensPush<T> for TokensNil {
    type Next = TokensCons<T, TokensNil>;

    fn push(self, token: T) -> Self::Next {
        TokensCons(token, self)
    }
}

impl<N: Token, T: Token, R> TokensPush<N> for TokensCons<T, R> {
    type Next = TokensCons<N, TokensCons<T, R>>;

    fn push(self, token: N) -> Self::Next {
        TokensCons(token, self)
    }
}

#[macro_export]
macro_rules! token_list {
    ($($t:expr),* $(,)?) => {{
        #[allow(unused_imports)]
        use crate::opal::{Token, TokensPush};
        crate::opal::TokensNil $(.push($t))* .to_token_stream()
    }};
}

#[macro_export]
macro_rules! token_name {
    ($k:expr, $v:expr $(,)?) => {{
        #[allow(unused_imports)]
        use crate::opal::Token;
        crate::opal::TokenName($k, $v).to_token_stream()
    }};
}

#[macro_export]
macro_rules! tokens {
    () => { crate::opal::TokenStream::empty() };
    ($t:expr $(,)?) => { crate::opal::Token::to_token_stream(&$t) };
    ($($t:expr),* $(,)?) => {{
        #[allow(unused_imports)]
        use crate::opal::{TokenList, TokensPush};
        crate::opal::TokensNil $(.push($t))* .to_bare_token_stream()
    }};
}

pub trait TokenList: core::fmt::Debug {
    fn write_bare(&self, buffer: &mut Vec<u8>);

    fn to_bare_token_stream(&self) -> TokenStream {
        let mut res = Vec::new();
        self.write_bare(&mut res);
        TokenStream(Some(res))
    }
}

impl TokenList for TokensNil {
    fn write_bare(&self, _buffer: &mut Vec<u8>) {}
}

impl<T: Token, R: TokenList> TokenList for TokensCons<T, R> {
    #[inline]
    fn write_bare(&self, buffer: &mut Vec<u8>) {
        self.1.write_bare(buffer);
        self.0.write(buffer);
    }
}

impl Token for TokensNil {
    #[inline]
    fn write(&self, buffer: &mut Vec<u8>) {
        token::STARTLIST.write(buffer);
        token::ENDLIST.write(buffer);
    }
}

impl<T: Token, R: TokenList> Token for TokensCons<T, R> {
    #[inline]
    fn write(&self, buffer: &mut Vec<u8>) {
        token::STARTLIST.write(buffer);
        self.1.write_bare(buffer);
        self.0.write(buffer);
        token::ENDLIST.write(buffer);
    }
}
