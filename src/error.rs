use crate::opal::StatusCode;
use alloc::string::String;
use uefi::{ResultExt, Status};

pub type Result<T = ()> = core::result::Result<T, Error>;

#[derive(Debug, Copy, Clone)]
pub enum OpalError {
    Status(StatusCode),
    NoMethodStatus,
}

const UNKNOWN: &str = "";

#[derive(Debug, Clone)]
pub enum Error {
    Uefi(uefi::Status, &'static str),
    Opal(OpalError),
    ConfigMissing,
    ConfigNonUtf8,
    ConfigArgsBadUtf16,
    ConfigVerbMissing(&'static str),
    NoBootPartitions,
    MultipleBootPartitions,
    ImageNotFound(String),
    ImageNotPeCoff,
}

impl From<Status> for Error {
    fn from(status: Status) -> Self {
        Self::Uefi(status, UNKNOWN)
    }
}

impl From<OpalError> for Error {
    fn from(error: OpalError) -> Self {
        Self::Opal(error)
    }
}

impl From<StatusCode> for Error {
    fn from(status: StatusCode) -> Self {
        OpalError::Status(status).into()
    }
}

pub trait ResultFixupExt<T>: Sized {
    fn fix(self, name: &'static str) -> Result<T>;
}

#[macro_export]
macro_rules! info {
    () => {
        concat!(file!(), ":", line!())
    };
}

impl<T, D: core::fmt::Debug> ResultFixupExt<T> for uefi::Result<T, D> {
    fn fix(self, info: &'static str) -> Result<T> {
        self.log_warning()
            .map_err(|e| Error::Uefi(e.status(), info))
    }
}
