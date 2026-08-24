use std::fmt;

#[derive(Debug)]
pub enum Error {
    Db(rusqlite::Error),
    Io(std::io::Error),
    KeyDerivationFailed,
    InvalidPassword,
    InvalidShareToken,
    ShareExpired,
    ShareRevoked,
    ShareExhausted,
    IntegrityCheckFailed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Db(e) => write!(f, "database error: {e}"),
            Error::Io(e) => write!(f, "I/O error: {e}"),
            Error::KeyDerivationFailed => write!(f, "key derivation failed"),
            Error::InvalidPassword => write!(f, "incorrect password"),
            Error::InvalidShareToken => write!(f, "invalid share token"),
            Error::ShareExpired => write!(f, "share link has expired"),
            Error::ShareRevoked => write!(f, "share link has been revoked"),
            Error::ShareExhausted => write!(f, "share link has reached its use limit"),
            Error::IntegrityCheckFailed => write!(f, "decrypted content failed integrity check"),
        }
    }
}

impl std::error::Error for Error {}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Error::Db(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
