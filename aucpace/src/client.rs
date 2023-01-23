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

    /// Create a new client in the SSID agreement phase
    ///
    /// # Return
    /// `next_step`: the client in the SSID establishment stage
    ///
    pub fn begin(&mut self) -> (AuCPaceClientSsidEstablish<D, K1>, ClientMessage<'_, D, K1>) {
        let next_step = AuCPaceClientSsidEstablish::new(&mut self.rng);
        let message = ClientMessage::ClientNonce(next_step.nonce);

        (next_step, message)
    }
}

/// Client in the SSID agreement phase
pub struct AuCPaceClientSsidEstablish<D, const K1: usize>
where
    D: Digest<OutputSize = U64> + Default,
{
    nonce: [u8; K1],
    d: PhantomData<D>,
}

impl<D, const K1: usize> AuCPaceClientSsidEstablish<D, K1>
where
    D: Digest<OutputSize = U64> + Default,
{
    fn new<CSPRNG>(rng: &mut CSPRNG) -> Self
    where
        CSPRNG: RngCore + CryptoRng,
    {
        Self {
            nonce: generate_nonce(rng),
            d: Default::default(),
        }
    }

    /// Consume the server's nonce - `s` and progress to the Augmentation Layer
    ///
    /// # Arguments:
    /// - `s` - the server nonce
    ///
    /// # Return
    /// `next_step`: the client in the pre-augmentation stage
    ///
    pub fn agree_ssid(self, server_nonce: [u8; K1]) -> AuCPaceClientPreAug<D, K1> {
        let ssid = compute_ssid::<D, K1>(server_nonce, self.nonce);
        AuCPaceClientPreAug::new(ssid)
    }
}

pub struct AuCPaceClientPreAug<D, const K1: usize>
where
    D: Digest<OutputSize = U64> + Default,
{
    ssid: Output<D>,
}

impl<D, const K1: usize> AuCPaceClientPreAug<D, K1>
where
    D: Digest<OutputSize = U64> + Default,
{
    fn new(ssid: Output<D>) -> Self {
        Self { ssid }
    }

    /// Consume the client's username and begin the augmentation layer
    pub fn start_augmentation(
        self,
        username: &[u8],
    ) -> (AuCPaceClientAugLayer<'_, D, K1>, ClientMessage<'_, D, K1>) {
        let next_step = AuCPaceClientAugLayer::new(self.ssid, username);
        let message = ClientMessage::Username(username);

        (next_step, message)
    }
}

pub struct AuCPaceClientAugLayer<'a, D, const K1: usize>
where
    D: Digest<OutputSize = U64> + Default,
{
    ssid: Output<D>,
    username: &'a [u8],
}

impl<'a, D, const K1: usize> AuCPaceClientAugLayer<'a, D, K1>
where
    D: Digest<OutputSize = U64> + Default,
{
    fn new(ssid: Output<D>, username: &'a [u8]) -> Self {
        Self { ssid, username }
    }

    pub fn generate_cpace<'salt, H>(
        self,
        x_pub: RistrettoPoint,
        password: impl AsRef<[u8]>,
        salt: impl Into<Salt<'salt>>,
        params: H::Params,
        hasher: H,
    ) -> Result<AuCPaceClientCPaceSubstep<D, K1>>
    where
        H: PasswordHasher,
    {
        let cofactor = Scalar::one();
        let pw_hash = hash_password(self.username, password, salt, params, hasher)?;
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

        let prs = (x_pub * (w * cofactor)).compress().to_bytes();

        Ok(AuCPaceClientCPaceSubstep::new(self.ssid, prs))
    }
}

pub struct AuCPaceClientCPaceSubstep<D, const K1: usize>
where
    D: Digest<OutputSize = U64> + Default,
{
    ssid: Output<D>,
    prs: [u8; 32],
}

impl<D, const K1: usize> AuCPaceClientCPaceSubstep<D, K1>
where
    D: Digest<OutputSize = U64> + Default,
{
    fn new(ssid: Output<D>, prs: [u8; 32]) -> Self {
        Self { ssid, prs }
    }

    /// Generate a public key
    /// moving the protocol onto the second half of the CPace substep - Receive Server Pubkey
    pub fn generate_public_key<CI, CSPRNG>(
        self,
        channel_identifier: CI,
        rng: &mut CSPRNG,
    ) -> (
        AuCPaceClientRecvServerKey<D, K1>,
        ClientMessage<'static, D, K1>,
    )
    where
        CI: AsRef<[u8]>,
        CSPRNG: RngCore + CryptoRng,
    {
        let (priv_key, pub_key) =
            generate_keypair::<D, CSPRNG, CI>(rng, self.ssid, self.prs, channel_identifier);

        let next_step = AuCPaceClientRecvServerKey::new(self.ssid, priv_key);
        let message = ClientMessage::PublicKey(pub_key);

        (next_step, message)
    }
}

pub struct AuCPaceClientRecvServerKey<D, const K1: usize>
where
    D: Digest<OutputSize = U64> + Default,
{
    ssid: Output<D>,
    priv_key: Scalar,
}

impl<D, const K1: usize> AuCPaceClientRecvServerKey<D, K1>
where
    D: Digest<OutputSize = U64> + Default,
{
    fn new(ssid: Output<D>, priv_key: Scalar) -> Self {
        Self { ssid, priv_key }
    }

    pub fn receive_server_pubkey(
        self,
        server_pubkey: RistrettoPoint,
    ) -> (
        AuCPaceClientExpMutAuth<D, K1>,
        ClientMessage<'static, D, K1>,
    ) {
        // TODO: verify the server pubkey here - how??
        let sk1 = compute_first_session_key::<D>(self.ssid, self.priv_key, server_pubkey);
        let (ta, tb) = compute_authenticator_messages::<D>(self.ssid, sk1.clone());
        let next_step = AuCPaceClientExpMutAuth::new(self.ssid, sk1, ta);
        let message = ClientMessage::ClientAuthenticator(tb);
        (next_step, message)
    }
}

/// Server in the Explicit Mutual Authenticaton phase
pub struct AuCPaceClientExpMutAuth<D, const K1: usize>
where
    D: Digest<OutputSize = U64> + Default,
{
    ssid: Output<D>,
    sk1: Output<D>,
    server_authenticator: Output<D>,
}

impl<D, const K1: usize> AuCPaceClientExpMutAuth<D, K1>
where
    D: Digest<OutputSize = U64> + Default,
{
    fn new(ssid: Output<D>, sk1: Output<D>, server_authenticator: Output<D>) -> Self {
        Self {
            ssid,
            sk1,
            server_authenticator,
        }
    }

    pub fn receive_server_authenticator(self, server_authenticator: [u8; 64]) -> Result<Output<D>> {
        if self
            .server_authenticator
            .as_ref()
            .ct_eq(&server_authenticator)
            .into()
        {
            Ok(compute_session_key::<D>(self.ssid, self.sk1))
        } else {
            Err(Error::MutualAuthFail)
        }
    }

    /// Allow the user to exit the protocol early in the case of implicit authentication
    /// Note: this should only be used in special circumstances and the
    ///       explicit mutual authentication stage should be used in all other cases
    pub fn implicit_auth(self) -> Output<D> {
        compute_session_key::<D>(self.ssid, self.sk1)
    }
}

//     /// Generate a nonce for ssid establishment
//     ///
//     /// # Return:
//     /// `nonce` - a fresh ephemeral nonce for establishing an sub-session ID with the client
//     pub fn generate_client_nonce(&mut self) -> [u8; K1] {
//         generate_nonce(&mut self.rng)
//     }
//
//     /// Computes the SSID from the server and client nonces
//     ///
//     /// # Arguments:
//     /// - `s` - the server nonce
//     /// - `t` - the client nonce
//     ///
//     /// # Return
//     /// `hash`: the output of hashing the concatenation of these nonces
//     ///         - `H0(s || t)`
//     pub fn compute_ssid(&self, s: [u8; K1], t: [u8; K1]) -> Output<D> {
//         compute_ssid::<D, K1>(s, t)
//     }
//
//     /// Compute the password related string
//     ///
//     /// # Arguments:
//     /// - `x_pub`: public X used to verify the user's password
//     /// - `username`: username of authenticating user
//     /// - `password`: password of authenticating user
//     /// - `salt`: salt used in hashing the user's password during registration
//     /// - `params`: parameters of the password hashing algorithm used
//     /// - `hasher`: password hasher to use
//     ///
//     /// # Return:
//     /// - `Ok(PRS)` - the computation suceeded, PRS is the password related string
//     /// - `Err(Error::PasswordHashing(_))` - the hasher returned an error while hashing
//     /// - `Err(Error::HashEmpty)` - the hasher returned an empty hash
//     /// - `Err(Error::HashSizeInvalid)` - the hasher returned a hash of the wrong size
//     ///                                   - only hashes of 32 bytes or 64 bytes are permitted.
//     pub fn compute_prs<H>(
//         &self,
//         x_pub: RistrettoPoint,
//         username: impl AsRef<[u8]>,
//         password: impl AsRef<[u8]>,
//         salt: Salt<'_>,
//         params: H::Params,
//         hasher: H,
//     ) -> Result<[u8; 32]>
//     where
//         H: PasswordHasher,
//     {
//         let cofactor = Scalar::one();
//         let pw_hash = hash_password(username, password, salt, params, hasher)?;
//         let hash = pw_hash.hash.ok_or(Error::HashEmpty)?;
//         let hash_bytes = hash.as_bytes();
//
//         // support both 32 and 64 byte hashes
//         let w = match hash_bytes.len() {
//             32 => {
//                 let arr = hash_bytes
//                     .try_into()
//                     .expect("slice length invariant broken");
//                 Scalar::from_bytes_mod_order(arr)
//             }
//             64 => {
//                 let arr = hash_bytes
//                     .try_into()
//                     .expect("slice length invariant broken");
//                 Scalar::from_bytes_mod_order_wide(arr)
//             }
//             _ => return Err(Error::HashSizeInvalid),
//         };
//
//         Ok((x_pub * (w * cofactor)).compress().to_bytes())
//     }
//
//     /// Generate the diffie-hellman key pair for the CPace substep of the protocol
//     /// Arguments:
//     /// - ssid: sub-session identifier
//     /// - prs: password related string
//     /// - ci: channel identifier
//     ///
//     /// Returns:
//     /// `(private key, public key)`
//     /// `private key` is used to generate the shared key
//     /// `public key` is sent to the server to allow them to compute the shared key
//     pub fn generate_keypair(
//         &mut self,
//         ssid: Output<D>,
//         prs: [u8; 32],
//         ci: impl AsRef<[u8]>,
//     ) -> (Scalar, RistrettoPoint) {
//         generate_keypair::<D, CSPRNG>(&mut self.rng, ssid, prs, ci)
//     }
//
//     /// Compute the first session key sk1 from the SSID, our private key and their public key
//     ///
//     /// # Arguments:
//     /// - `ssid`: sub-session identifier
//     /// - `prs`: password related string
//     /// - `ci`: channel identifier
//     ///
//     /// # Return:
//     /// `sk1` - the first session key
//     pub fn compute_first_session_key(
//         &self,
//         ssid: Output<D>,
//         priv_key: Scalar,
//         pub_key: RistrettoPoint,
//     ) -> Output<D> {
//         compute_first_session_key::<D>(ssid, priv_key, pub_key)
//     }
//
//     /// Compute the authenticator messages Ta and Tb
//     ///
//     /// # Arguments:
//     /// - `ssid`: sub-session identifier
//     /// - `prss`: sub-session identifier
//     ///
//     /// # Return:
//     /// `(Ta, Tb)`
//     /// where Tb is the authenticator message to be sent to the server
//     /// and Ta is the value used to verify the authenticator message from the server
//     pub fn compute_authenticator_messages(
//         &self,
//         ssid: Output<D>,
//         first_session_key: Output<D>,
//     ) -> (Output<D>, Output<D>) {
//         compute_authenticator_messages::<D>(ssid, first_session_key)
//     }
//
//     /// Checks whether the server authenticator is valid in **constant time**
//     ///
//     /// # Arguments:
//     /// - `tb`: the server authenticator we computed
//     /// - `server_tb`: the server authenticator sent by the server
//     pub fn is_server_authenticator_valid(&self, tb: Output<D>, server_tb: &[u8; 64]) -> bool {
//         tb.as_ref().ct_eq(server_tb).into()
//     }
//
//     /// Compute the shared session key
//     ///
//     /// # Arguments:
//     /// - `ssid`: the sub-session ID
//     /// - `sk1`: the first session key
//     ///
//     /// # Return:
//     /// `sk` - the final session key
//     pub fn compute_session_key(&self, ssid: Output<D>, sk1: Output<D>) -> Output<D> {
//         compute_session_key::<D>(ssid, sk1)
//     }

pub enum ClientMessage<'a, D, const K1: usize>
where
    D: Digest<OutputSize = U64> + Default,
{
    /// SSID establishment message - the client's nonce: `t`
    ClientNonce([u8; K1]),

    /// Username - the client's username
    Username(&'a [u8]),

    /// PublicKey - the client's public key: `Ya`
    PublicKey(RistrettoPoint),

    /// Explicit Mutual Authentication - the client's authenticator: `Tb`
    ClientAuthenticator(Output<D>),
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
