use core::fmt;

/// Errors that can occur during the protocol
#[non_exhaustive]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// Error while performing a password hash
    PasswordHashing(password_hash::Error),
    /// PasswordHasher produced an empty hash.
    HashEmpty,
    /// PasswordHasher produced a hash of an invalid size (size was not 32 or 64 bytes)
    HashSizeInvalid,
    /// Failure during Explicit Mutual Authentication
    MutualAuthFail,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::PasswordHashing(error) => write!(f, "Error while hashing password: {}", error),
            Error::HashEmpty => write!(f, "password hash empty"),
            Error::HashSizeInvalid => write!(f, "password hash invalid, should be 32 or 64 bytes"),
            Error::MutualAuthFail => write!(
                f,
                "explicit mutual authentication failed, authenticators didn't match"
            ),
        }
    }
}

/// Result type
pub type Result<T> = core::result::Result<T, Error>;
