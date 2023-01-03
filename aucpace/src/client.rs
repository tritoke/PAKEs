use crate::utils::{
    compute_authenticator_messages, compute_first_session_key, compute_session_key, generate_nonce,
};
use crate::{
    errors::{Error, Result},
    utils::{compute_ssid, generate_keypair},
};
use curve25519_dalek::{
    digest::consts::U64,
    digest::{Digest, Output},
    ristretto::RistrettoPoint,
    scalar::Scalar,
};
use password_hash::{PasswordHash, PasswordHasher, Salt};
use rand_core::{CryptoRng, RngCore};
use std::marker::PhantomData;
use subtle::ConstantTimeEq;

/// Implementation of the client side of the AuCPace protocol
pub struct AuCPaceClient<D, CSPRNG, const K1: usize>
where
    D: Digest<OutputSize = U64> + Default,
    CSPRNG: RngCore + CryptoRng,
{
    rng: CSPRNG,
    d: PhantomData<D>,
}

impl<D, CSPRNG, const K1: usize> AuCPaceClient<D, CSPRNG, K1>
where
    D: Digest<OutputSize = U64> + Default,
    CSPRNG: RngCore + CryptoRng,
{
    /// Create new server
    pub fn new(rng: CSPRNG) -> Self {
        Self {
            rng,
            d: Default::default(),
        }
    }

    /// Generate a nonce for ssid establishment
    ///
    /// # Return:
    /// `nonce` - a fresh ephemeral nonce for establishing an sub-session ID with the client
    pub fn generate_client_nonce(&mut self) -> [u8; K1] {
        generate_nonce(&mut self.rng)
    }

    /// Computes the SSID from the server and client nonces
    ///
    /// # Arguments:
    /// - `s` - the server nonce
    /// - `t` - the client nonce
    ///
    /// # Return
    /// `hash`: the output of hashing the concatenation of these nonces
    ///         - `H0(s || t)`
    pub fn compute_ssid(&self, s: [u8; K1], t: [u8; K1]) -> Output<D> {
        compute_ssid::<D, K1>(s, t)
    }

    /// Compute the password related string
    ///
    /// # Arguments:
    /// - `x_pub`: public X used to verify the user's password
    /// - `username`: username of authenticating user
    /// - `password`: password of authenticating user
    /// - `salt`: salt used in hashing the user's password during registration
    /// - `params`: parameters of the password hashing algorithm used
    /// - `hasher`: password hasher to use
    ///
    /// # Return:
    /// - `Ok(PRS)` - the computation suceeded, PRS is the password related string
    /// - `Err(Error::PasswordHashing(_))` - the hasher returned an error while hashing
    /// - `Err(Error::HashEmpty)` - the hasher returned an empty hash
    /// - `Err(Error::HashSizeInvalid)` - the hasher returned a hash of the wrong size
    ///                                   - only hashes of 32 bytes or 64 bytes are permitted.
    pub fn compute_prs<H>(
        &self,
        x_pub: RistrettoPoint,
        username: impl AsRef<[u8]>,
        password: impl AsRef<[u8]>,
        salt: Salt<'_>,
        params: H::Params,
        hasher: H,
    ) -> Result<[u8; 32]>
    where
        H: PasswordHasher,
    {
        let cofactor = Scalar::one();
        let pw_hash = hash_password(username, password, salt, params, hasher)?;
        let hash = pw_hash.hash.ok_or(Error::HashEmpty)?;
        let hash_bytes = hash.as_bytes();

        // support both 32 and 64 byte hashes
        let w = match hash_bytes.len() {
            32 => {
                let arr = hash_bytes
                    .try_into()
                    .expect("slice length invariant broken");
                Scalar::from_bytes_mod_order(arr)
            }
            64 => {
                let arr = hash_bytes
                    .try_into()
                    .expect("slice length invariant broken");
                Scalar::from_bytes_mod_order_wide(arr)
            }
            _ => return Err(Error::HashSizeInvalid),
        };

        Ok((x_pub * (w * cofactor)).compress().to_bytes())
    }

    /// Generate the diffie-hellman key pair for the CPace substep of the protocol
    /// Arguments:
    /// - ssid: sub-session identifier
    /// - prs: password related string
    /// - ci: channel identifier
    ///
    /// Returns:
    /// `(private key, public key)`
    /// `private key` is used to generate the shared key
    /// `public key` is sent to the server to allow them to compute the shared key
    pub fn generate_keypair(
        &mut self,
        ssid: Output<D>,
        prs: [u8; 32],
        ci: impl AsRef<[u8]>,
    ) -> (Scalar, RistrettoPoint) {
        generate_keypair::<D, CSPRNG>(&mut self.rng, ssid, prs, ci)
    }

    /// Compute the first session key sk1 from the SSID, our private key and their public key
    ///
    /// # Arguments:
    /// - `ssid`: sub-session identifier
    /// - `prs`: password related string
    /// - `ci`: channel identifier
    ///
    /// # Return:
    /// `sk1` - the first session key
    pub fn compute_first_session_key(
        &self,
        ssid: Output<D>,
        priv_key: Scalar,
        pub_key: RistrettoPoint,
    ) -> Output<D> {
        compute_first_session_key::<D>(ssid, priv_key, pub_key)
    }

    /// Compute the authenticator messages Ta and Tb
    ///
    /// # Arguments:
    /// - `ssid`: sub-session identifier
    /// - `prss`: sub-session identifier
    ///
    /// # Return:
    /// `(Ta, Tb)`
    /// where Tb is the authenticator message to be sent to the server
    /// and Ta is the value used to verify the authenticator message from the server
    pub fn compute_authenticator_messages(
        &self,
        ssid: Output<D>,
        first_session_key: Output<D>,
    ) -> (Output<D>, Output<D>) {
        compute_authenticator_messages::<D>(ssid, first_session_key)
    }

    /// Checks whether the server authenticator is valid in **constant time**
    ///
    /// # Arguments:
    /// - `tb`: the server authenticator we computed
    /// - `server_tb`: the server authenticator sent by the server
    pub fn is_server_authenticator_valid(&self, tb: Output<D>, server_tb: &[u8; 64]) -> bool {
        tb.as_ref().ct_eq(server_tb).into()
    }

    /// Compute the shared session key
    ///
    /// # Arguments:
    /// - `ssid`: the sub-session ID
    /// - `sk1`: the first session key
    ///
    /// # Return:
    /// `sk` - the final session key
    pub fn compute_session_key(&self, ssid: Output<D>, sk1: Output<D>) -> Output<D> {
        compute_session_key::<D>(ssid, sk1)
    }
}

/// Hash a username and password with the given password hasher
fn hash_password<'a, H>(
    username: impl AsRef<[u8]>,
    password: impl AsRef<[u8]>,
    salt: impl Into<Salt<'a>>,
    params: H::Params,
    hasher: H,
) -> Result<PasswordHash<'a>>
where
    H: PasswordHasher,
{
    // this is a stop-gap solution so I can use the function before
    // I work out how to do this without allocating...

    // hash "{username}:{password}"
    let mut v = username.as_ref().to_vec();
    v.push(b':');
    v.extend_from_slice(password.as_ref());

    hasher
        .hash_password_customized(v.as_slice(), None, None, params, salt)
        .map_err(Error::PasswordHashing)
}
