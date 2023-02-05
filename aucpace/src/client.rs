use crate::utils::{
    compute_authenticator_messages, compute_first_session_key, compute_session_key, generate_nonce,
    scalar_from_hash,
};
use crate::{
    errors::{Error, Result},
    utils::{compute_ssid, generate_keypair},
};

#[cfg(feature = "serde")]
use crate::utils::{serde_paramsstring, serde_saltstring};

use core::marker::PhantomData;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::{
    digest::consts::U64,
    digest::{Digest, Output},
    ristretto::RistrettoPoint,
    scalar::Scalar,
};
use password_hash::{ParamsString, PasswordHash, PasswordHasher, Salt, SaltString};
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;

#[cfg(feature = "alloc")]
extern crate alloc;

/// Implementation of the client side of the AuCPace protocol
pub struct AuCPaceClient<D, CSPRNG, const K1: usize, const BUFSIZ: usize>
where
    D: Digest<OutputSize = U64> + Default,
    CSPRNG: RngCore + CryptoRng,
{
    rng: CSPRNG,
    d: PhantomData<D>,
}

impl<D, CSPRNG, const K1: usize, const BUFSIZ: usize> AuCPaceClient<D, CSPRNG, K1, BUFSIZ>
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
    /// # Return:
    /// (`next_step`, `message`)
    /// - `next_step`: the client in the SSID establishment stage
    /// - `messsage`: the message to send to the server
    ///
    pub fn begin(
        &mut self,
    ) -> (
        AuCPaceClientSsidEstablish<D, K1, BUFSIZ>,
        ClientMessage<'_, K1>,
    ) {
        let next_step = AuCPaceClientSsidEstablish::new(&mut self.rng);
        let message = ClientMessage::ClientNonce(next_step.nonce);

        (next_step, message)
    }

    /// Register a username/password
    ///
    /// # Return:
    /// (`next_step`, `message`)
    /// - `next_step`: the client in the SSID establishment stage
    /// - `messsage`: the message to send to the server
    ///
    pub fn register<'a, P, H>(
        &mut self,
        username: &'a [u8],
        password: P,
        params: H::Params,
        hasher: H,
    ) -> Result<ClientMessage<'a, K1>>
    where
        P: AsRef<[u8]>,
        H: PasswordHasher,
    {
        // adapted from SaltString::generate, which we cannot use due to curve25519 versions of rand_core
        let mut salt = [0u8; Salt::RECOMMENDED_LENGTH];
        self.rng.fill_bytes(&mut salt);
        let salt_string = SaltString::b64_encode(&salt).expect("Salt length invariant broken.");

        // compute the verifier W
        let pw_hash = hash_password::<&[u8], P, &SaltString, H, BUFSIZ>(
            username,
            password,
            &salt_string,
            params.clone(),
            hasher,
        )?;
        let cofactor = Scalar::one();
        let w = scalar_from_hash(pw_hash)?;
        let verifier = RISTRETTO_BASEPOINT_POINT * (w * cofactor);

        // attempt to convert the parameters to a ParamsString
        let params_string = params.try_into().map_err(Error::PasswordHashing)?;

        Ok(ClientMessage::Registration {
            username,
            salt: salt_string,
            params: params_string,
            verifier,
        })
    }
}

/// Client in the SSID agreement phase
pub struct AuCPaceClientSsidEstablish<D, const K1: usize, const BUFSIZ: usize>
where
    D: Digest<OutputSize = U64> + Default,
{
    nonce: [u8; K1],
    d: PhantomData<D>,
}

impl<D, const K1: usize, const BUFSIZ: usize> AuCPaceClientSsidEstablish<D, K1, BUFSIZ>
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

    /// Consume the server's nonce - `s` and progress to the augmentation layer
    ///
    /// # arguments:
    /// - `server_nonce` - the nonce received from the server
    ///
    /// # return:
    /// `next_step`: the client in the pre-augmentation stage
    ///
    pub fn agree_ssid(self, server_nonce: [u8; K1]) -> AuCPaceClientPreAug<D, K1, BUFSIZ> {
        let ssid = compute_ssid::<D, K1>(server_nonce, self.nonce);
        AuCPaceClientPreAug::new(ssid)
    }
}

/// Client in the pre-augmentation phase
pub struct AuCPaceClientPreAug<D, const K1: usize, const BUFSIZ: usize>
where
    D: Digest<OutputSize = U64> + Default,
{
    ssid: Output<D>,
}

impl<D, const K1: usize, const BUFSIZ: usize> AuCPaceClientPreAug<D, K1, BUFSIZ>
where
    D: Digest<OutputSize = U64> + Default,
{
    fn new(ssid: Output<D>) -> Self {
        Self { ssid }
    }

    /// Consume the client's username and begin the augmentation layer
    ///
    /// # Arguments:
    /// - `username` - a reference to the client's username
    ///
    /// # Return:
    /// (`next_step`, `message`)
    /// - `next_step`: the client in the augmentation layer
    /// - `message`: the message to send to the server
    ///
    pub fn start_augmentation(
        self,
        username: &[u8],
    ) -> (
        AuCPaceClientAugLayer<'_, D, K1, BUFSIZ>,
        ClientMessage<'_, K1>,
    ) {
        let next_step = AuCPaceClientAugLayer::new(self.ssid, username);
        let message = ClientMessage::Username(username);

        (next_step, message)
    }
}

/// Client in the augmentation layer
pub struct AuCPaceClientAugLayer<'a, D, const K1: usize, const BUFSIZ: usize>
where
    D: Digest<OutputSize = U64> + Default,
{
    ssid: Output<D>,
    username: &'a [u8],
}

impl<'a, D, const K1: usize, const BUFSIZ: usize> AuCPaceClientAugLayer<'a, D, K1, BUFSIZ>
where
    D: Digest<OutputSize = U64> + Default,
{
    fn new(ssid: Output<D>, username: &'a [u8]) -> Self {
        Self { ssid, username }
    }

    /// Process the augmentation layer information from the server, hashes the user's password
    /// together with their username, then computes `w` and `PRS`.
    ///
    /// # Arguments:
    /// - `x_pub` - `x` from the protocol definition, used in generating the password related string (prs)
    /// - `password` - the user's password
    /// - `salt` - the salt value sent by the server
    /// - `params` - the parameters used by the hasher
    /// - `hasher` - the hasher to use when computing `w`
    ///
    /// # Return:
    /// either
    /// - ok(`next_step`): the client in the cpace substep
    /// - err(error::passwordhashing(hasher_error) | error::hashempty | error::hashsizeinvalid):
    ///     one of the three error variants that can result from the password hashing process
    ///
    pub fn generate_cpace<'salt, P, S, H>(
        self,
        x_pub: RistrettoPoint,
        password: P,
        salt: S,
        params: H::Params,
        hasher: H,
    ) -> Result<AuCPaceClientCPaceSubstep<D, K1>>
    where
        P: AsRef<[u8]>,
        S: Into<Salt<'a>>,
        H: PasswordHasher,
    {
        let cofactor = Scalar::one();
        let pw_hash =
            hash_password::<&[u8], P, S, H, BUFSIZ>(self.username, password, salt, params, hasher)?;
        let w = scalar_from_hash(pw_hash)?;

        let prs = (x_pub * (w * cofactor)).compress().to_bytes();

        Ok(AuCPaceClientCPaceSubstep::new(self.ssid, prs))
    }
}

/// Client in the CPace substep
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
    ///
    /// # Arguments:
    /// - `channel_identifier` - `CI` from the protocol definition, in the context of TCP/IP this
    ///     is usually some combination of the server and client's IP address and TCP port numbers.
    ///     It's purpose is to prevent relay attacks.
    /// - `rng` - the CSPRNG used when generating the public/private keypair
    ///
    /// # Return:
    /// (`next_step`, `message`)
    /// - `next_step`: the client waiting for the server's public key
    /// - `message`: the message to send to the server
    ///
    pub fn generate_public_key<CI, CSPRNG>(
        self,
        channel_identifier: CI,
        rng: &mut CSPRNG,
    ) -> (
        AuCPaceClientRecvServerKey<D, K1>,
        ClientMessage<'static, K1>,
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

/// Client waiting to receive the server's public key
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

    /// Receive the server's public key
    /// This completes the CPace substep and moves the client on to explicit mutual authentication.
    ///
    /// # Arguments:
    /// - `server_pubkey` - the server's public key
    ///
    /// # Return:
    /// (`next_step`, `message`)
    /// - `next_step`: the client in the Explicit Mutual Authentication phase
    /// - `message`: the message to send to the server
    ///
    pub fn receive_server_pubkey(
        self,
        server_pubkey: RistrettoPoint,
    ) -> (AuCPaceClientExpMutAuth<D, K1>, ClientMessage<'static, K1>) {
        // TODO: verify the server pubkey here - how??
        let sk1 = compute_first_session_key::<D>(self.ssid, self.priv_key, server_pubkey);
        let (ta, tb) = compute_authenticator_messages::<D>(self.ssid, sk1);
        let next_step = AuCPaceClientExpMutAuth::new(self.ssid, sk1, ta);
        let message = ClientMessage::ClientAuthenticator(
            tb.as_slice()
                .try_into()
                .expect("array length invariant broken"),
        );
        (next_step, message)
    }

    /// Allow the user to exit the protocol early in the case of implicit authentication
    /// Note: this should only be used in special circumstances and the
    ///       explicit mutual authentication stage should be used in all other cases
    ///
    /// # Arguments:
    /// - `server_pubkey` - the server's public key
    ///
    /// # Return:
    /// `sk`: the session key reached by the AuCPace protocol
    ///
    pub fn implicit_auth(self, server_pubkey: RistrettoPoint) -> Output<D> {
        let sk1 = compute_first_session_key::<D>(self.ssid, self.priv_key, server_pubkey);
        compute_session_key::<D>(self.ssid, sk1)
    }
}

/// Client in the Explicit Mutual Authenticaton phase
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

    /// Receive the server's authenticator.
    /// This completes the protocol and returns the derived key.
    ///
    /// # Arguments:
    /// - `server_authenticator` - the server's authenticator
    ///
    /// # Return:
    /// either:
    /// - Ok(`sk`): the session key reached by the AuCPace protocol
    /// - Err(Error::MutualAuthFail): an error if the authenticator we computed doesn't match
    ///     the server's authenticator, compared in constant time.
    ///
    pub fn receive_server_authenticator(self, server_authenticator: [u8; 64]) -> Result<Output<D>> {
        if self
            .server_authenticator
            .ct_eq(&server_authenticator)
            .into()
        {
            Ok(compute_session_key::<D>(self.ssid, self.sk1))
        } else {
            Err(Error::MutualAuthFail)
        }
    }
}

/// Hash a username and password with the given password hasher
#[cfg(not(feature = "alloc"))]
fn hash_password<'a, U, P, S, H, const BUFSIZ: usize>(
    username: U,
    password: P,
    salt: S,
    params: H::Params,
    hasher: H,
) -> Result<PasswordHash<'a>>
where
    H: PasswordHasher,
    U: AsRef<[u8]>,
    P: AsRef<[u8]>,
    S: Into<Salt<'a>>,
{
    // this could maybe be a generic but it would change the signature of functions that use it
    // based on a feature flag so maybe not worth it?
    // const BUFSIZ: usize = 100;

    let user = username.as_ref();
    let pass = password.as_ref();
    let u = user.len();
    let p = pass.len();

    if u + p + 1 > BUFSIZ {
        return Err(Error::UsernameOrPasswordTooLong);
    }

    let mut buf = [0u8; BUFSIZ];
    buf[0..u].copy_from_slice(user);
    buf[u] = b':';
    buf[u + 1..u + p + 1].copy_from_slice(pass);

    hasher
        .hash_password_customized(&buf[0..u + p + 1], None, None, params, salt)
        .map_err(Error::PasswordHashing)
}

/// Hash a username and password with the given password hasher
#[cfg(feature = "alloc")]
fn hash_password<'a, U, P, S, H, const _BUFSIZ: usize>(
    username: U,
    password: P,
    salt: S,
    params: H::Params,
    hasher: H,
) -> Result<PasswordHash<'a>>
where
    H: PasswordHasher,
    U: AsRef<[u8]>,
    P: AsRef<[u8]>,
    S: Into<Salt<'a>>,
{
    let user = username.as_ref();
    let pass = password.as_ref();

    // hash "{username}:{password}"
    let mut v = alloc::vec::Vec::with_capacity(user.len() + pass.len() + 1);
    v.extend_from_slice(user);
    v.push(b':');
    v.extend_from_slice(pass);

    hasher
        .hash_password_customized(v.as_slice(), None, None, params, salt)
        .map_err(Error::PasswordHashing)
}

/// An enum representing the different messages the client can send to the server
#[cfg_attr(
    feature = "serde",
    derive(our_serde::Serialize, our_serde::Deserialize)
)]
#[cfg_attr(feature = "serde", serde(crate = "our_serde"))]
#[derive(Debug)]
pub enum ClientMessage<'a, const K1: usize> {
    /// SSID establishment message - the client's nonce: `t`
    ClientNonce(#[cfg_attr(feature = "serde", serde(with = "serde_arrays"))] [u8; K1]),

    /// Username - the client's username
    Username(&'a [u8]),

    /// PublicKey - the client's public key: `Ya`
    PublicKey(RistrettoPoint),

    /// Explicit Mutual Authentication - the client's authenticator: `Tb`
    ClientAuthenticator(#[cfg_attr(feature = "serde", serde(with = "serde_arrays"))] [u8; 64]),

    /// Registration - the username, verifier, salt and parameters needed for registering a user
    /// NOTE: if the UAD field is desired this should be handled separately and sent at the same time
    Registration {
        /// The username of whoever is registering
        username: &'a [u8],

        /// The salt used when computing the verifier
        #[cfg_attr(feature = "serde", serde(with = "serde_saltstring"))]
        salt: SaltString,

        /// The password hasher's parameters used when computing the verifier
        #[cfg_attr(feature = "serde", serde(with = "serde_paramsstring"))]
        params: ParamsString,

        /// The verifier computer from the user's password
        verifier: RistrettoPoint,
    },
}
