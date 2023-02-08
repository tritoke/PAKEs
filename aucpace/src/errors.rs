use core::fmt;

/// Errors that can occur during the protocol
#[non_exhaustive]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// Wrapper around `password_hash`'s error type, for propagating errors should they occur
    PasswordHashing(password_hash::Error),
    /// PasswordHasher produced an empty hash.
    HashEmpty,
    /// PasswordHasher produced a hash of an invalid size (size was not 32 or 64 bytes)
    HashSizeInvalid,
    /// Failure during Explicit Mutual Authentication
    MutualAuthFail,
    /// The username:password string would overflow the buffer size allocated for hashing the password
    /// Note: this error can only occur when using the *_alloc APIs
    UsernameOrPasswordTooLong,
    /// The SSID provided is too short to be secure, SSIDs must be at least 16 bytes long
    /// Note: this error can only occur if the SSID establishment phase is bypassed
    InsecureSsid,
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
            Error::UsernameOrPasswordTooLong => write!(f, "Username or password too long"),
            Error::InsecureSsid => write!(
                f,
                "Provided SSID is insecure - SSIDs must be at least 16 bytes long"
            ),
        }
    }
}

/// Result type
pub type Result<T> = core::result::Result<T, Error>;
