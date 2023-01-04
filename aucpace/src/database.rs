use password_hash::{ParamsString, SaltString};

/// trait for AuCPace to use to abstract over the storage and retrieval of verifiers
pub trait Database {
    /// The type of password verifier stored in the database
    type PasswordVerifier;

    /// perform LookupW, returning the password verifier W if it exists
    ///
    /// # Return:
    /// `(password verifier, salt, sigma)`
    /// where `password verifier` is the verifier stored for the given user
    /// `salt` is the salt used when hashing the password
    /// `sigma` is the parameters used by the the PBKDF when hashing the user's password
    fn lookup_verifier(
        &self,
        username: &[u8],
    ) -> Option<(Self::PasswordVerifier, SaltString, ParamsString)>;

    /// store a username, salt, verifier and hash parameters to the database
    /// Verification is performed by the server and credentials will only be stored once verified.
    /// This function should all for overwriting users credentials if they exist.
    /// This is required for password changes and will only be performed when appropriate by the
    ///
    /// # Arguments:
    /// - `username`: The name of the user who is storing a verifier
    /// - `salt`: The salt used when creating the verifier
    /// - `uad`: Optional - User Attached Data - "represents application data associated with
    ///          this specific user account, e.g. specifying the granted authorization level
    ///          on the server."
    /// - `verifier`: The password verifier for the given user
    /// - `params`: The parameters used when hashing the password into the verifier -
    ///             It is called sigma in the protocol defionition
    fn store_verifier(
        &mut self,
        username: &[u8],
        salt: SaltString,
        uad: Option<&[u8]>,
        verifier: Self::PasswordVerifier,
        params: ParamsString,
    );
}