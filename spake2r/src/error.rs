//! Error types.

use core::fmt;

/// [`Result`][`core::result::Result`] type with `spake2r`'s [`Error`] type.
pub type Result<T> = core::result::Result<T, Error>;

/// SPake2r errors.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// Bad side
    BadSide,

    /// Corrupt message
    CorruptMessage,

    /// Wrong length
    WrongLength,
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadSide => fmt.write_str("bad side"),
            Self::CorruptMessage => fmt.write_str("corrupt message"),
            Self::WrongLength => fmt.write_str("invalid length"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
