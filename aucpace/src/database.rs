use password_hash::ParamsString;

/// trait for AuCPace to use to abstract over the storage and retrieval of verifiers
pub trait Database {
    /// The type of password verifier stored in the database
    type PasswordVerifier;

    /// perform LookupW, returning the password verifier W if it exists
    fn lookup_verifier(&self, username: &[u8]) -> Option<Self::PasswordVerifier>;

    /// store a username, salt, verifier and hash parameters to the database
    /// Verification is performed by the server and credentials will only be stored once verified.
    fn store_verifier(&mut self, username: &[u8], salt: &[u8], uad: Option<&[u8]>, verifier: Self::PasswordVerifier, params: ParamsString);
}