use crate::database::Database;
use crate::utils::{
    compute_authenticator_messages, compute_first_session_key, compute_session_key, compute_ssid,
    generate_keypair, generate_nonce,
};
use crate::{Error, Result};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    digest::consts::U64,
    digest::{Digest, Output},
    ristretto::RistrettoPoint,
    scalar::Scalar,
};
use password_hash::{ParamsString, SaltString};
use rand_core::{CryptoRng, RngCore};
use std::marker::PhantomData;
use subtle::ConstantTimeEq;

/// A non-copy wrapper around u64
#[derive(Clone)]
struct ServerSecret(u64);

impl ServerSecret {
    fn new<CSPRNG: RngCore + CryptoRng>(rng: &mut CSPRNG) -> Self {
        Self(rng.next_u64())
    }
}

/// Implementation of the server side of the AuCPace protocol
pub struct AuCPaceServer<D, CSPRNG, const K1: usize>
where
    D: Digest + Default,
    CSPRNG: CryptoRng + RngCore,
{
    /// The CSPRNG used to generate random values where needed
    rng: CSPRNG,

    /// the secret used to obscure when a password lookup failed
    secret: ServerSecret,

    d: PhantomData<D>,
}

impl<D, CSPRNG, const K1: usize> AuCPaceServer<D, CSPRNG, K1>
where
    D: Digest<OutputSize = U64> + Default,
    CSPRNG: RngCore + CryptoRng,
{
    /// Create a new server
    pub fn new(mut rng: CSPRNG) -> Self {
        let secret = ServerSecret::new(&mut rng);
        Self {
            rng,
            secret,
            d: Default::default(),
        }
    }

    /// Create a new server in the SSID agreement phase
    ///
    /// # Return:
    /// (`next_step`, `message`)
    /// - `next_step`: the server in the SSID establishment stage
    /// - `messsage`: the message to send to the server
    ///
    pub fn begin(&mut self) -> (AuCPaceServerSsidEstablish<D, K1>, ServerMessage<D, K1>) {
        let next_step = AuCPaceServerSsidEstablish::new(self.secret.clone(), &mut self.rng);
        let message = ServerMessage::SsidEstablish(next_step.nonce);
        (next_step, message)
    }
}

/// Server in the SSID agreement phase
pub struct AuCPaceServerSsidEstablish<D, const K1: usize>
where
    D: Digest<OutputSize = U64> + Default,
{
    secret: ServerSecret,
    nonce: [u8; K1],
    _d: PhantomData<D>,
}

impl<D, const K1: usize> AuCPaceServerSsidEstablish<D, K1>
where
    D: Digest<OutputSize = U64> + Default,
{
    fn new<CSPRNG>(secret: ServerSecret, rng: &mut CSPRNG) -> Self
    where
        CSPRNG: RngCore + CryptoRng,
    {
        Self {
            secret,
            nonce: generate_nonce(rng),
            _d: Default::default(),
        }
    }

    /// Consume the client's nonce - `t` and progress to the augmentation layer
    ///
    /// # arguments:
    /// - `client_nonce` - the nonce received from the server
    ///
    /// # return:
    /// `next_step`: the server in the augmentation layer
    ///
    pub fn agree_ssid(self, client_nonce: [u8; K1]) -> AuCPaceServerAugLayer<D, K1> {
        let ssid = compute_ssid::<D, K1>(self.nonce, client_nonce);
        AuCPaceServerAugLayer::new(self.secret, ssid)
    }
}

/// Server in the Augmentation layer phase
pub struct AuCPaceServerAugLayer<D, const K1: usize>
where
    D: Digest<OutputSize = U64> + Default,
{
    secret: ServerSecret,
    ssid: Output<D>,
}

impl<D, const K1: usize> AuCPaceServerAugLayer<D, K1>
where
    D: Digest<OutputSize = U64> + Default,
{
    fn new(secret: ServerSecret, ssid: Output<D>) -> Self {
        Self { secret, ssid }
    }

    /// Accept the user's username and generate the ClientInfo for the response.
    /// Moves the protocol into the CPace substep phase
    ///
    /// # Arguments:
    /// - `username`: the client's username
    /// - `database`: the password verifier database to retrieve the client's information from
    ///
    /// # Return:
    /// (`next_step`, `message`)
    /// - `next_step`: the server in the CPace substep stage
    /// - `messsage`: the message to send to the client
    ///
    pub fn generate_client_info<CSPRNG>(
        self,
        username: impl AsRef<[u8]>,
        database: &mut impl Database<PasswordVerifier = RistrettoPoint>,
        mut rng: CSPRNG,
    ) -> (
        AuCPaceServerCPaceSubstep<D, CSPRNG, K1>,
        ServerMessage<D, K1>,
    )
    where
        CSPRNG: RngCore + CryptoRng,
    {
        // for ristretto255 the cofactor is 1, for normal curve25519 it is 8
        // this will need to be provided by a group trait in the future
        let cofactor = Scalar::one();
        let x = Scalar::random(&mut rng) * cofactor;
        let x_pub = RISTRETTO_BASEPOINT_POINT * x;

        // generate the password related string (PRS) and the client info
        let prs;
        let message;
        if let Some((w, salt, sigma)) = database.lookup_verifier(username.as_ref()) {
            prs = (w * x).compress().to_bytes();
            message = ServerMessage::AugmentationLayer {
                // this will have to be provided by the trait in future
                group: "ristretto255",
                x_pub,
                salt,
                pbkdf_params: sigma,
            };
        } else {
            // generate a random PRS
            // TODO: would it be better to generate this via RistrettoPoint::random
            prs = {
                let mut tmp = [0u8; 32];
                rng.fill_bytes(&mut tmp);
                tmp
            };

            // generate the salt from the hash of the server secret and the user's name
            let mut hasher: D = Default::default();
            hasher.update(self.secret.0.to_le_bytes());
            hasher.update(username);
            let hash = hasher.finalize();
            let hash_bytes: &[u8] = hash.as_ref();

            // It is okay to expect here because SaltString has a buffer of 64 bytes by requirement
            // from the PHC spec. 48 bytes of data when encoded as base64 transform to 64 bytes.
            // This gives us the most entropy possible from the hash in the SaltString.
            let salt = SaltString::b64_encode(&hash_bytes[..48])
                .expect("SaltString maximum length invariant broken");

            message = ServerMessage::AugmentationLayer {
                group: "ristretto255",
                x_pub,
                salt,
                pbkdf_params: Default::default(),
            };
        };

        let next_step = AuCPaceServerCPaceSubstep::new(self.ssid, prs, rng);

        (next_step, message)
    }
}

/// Server in the CPace substep phase
pub struct AuCPaceServerCPaceSubstep<D, CSPRNG, const K1: usize>
where
    D: Digest<OutputSize = U64> + Default,
    CSPRNG: RngCore + CryptoRng,
{
    ssid: Output<D>,
    prs: [u8; 32],
    rng: CSPRNG,
}

impl<D, CSPRNG, const K1: usize> AuCPaceServerCPaceSubstep<D, CSPRNG, K1>
where
    D: Digest<OutputSize = U64> + Default,
    CSPRNG: RngCore + CryptoRng,
{
    fn new(ssid: Output<D>, prs: [u8; 32], rng: CSPRNG) -> Self {
        Self { ssid, prs, rng }
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
    /// - `next_step`: the server waiting for the client's public key
    /// - `message`: the message to send to the client
    ///
    pub fn generate_public_key<CI: AsRef<[u8]>>(
        mut self,
        channel_identifier: CI,
    ) -> (AuCPaceServerRecvClientKey<D, K1>, ServerMessage<D, K1>) {
        let (priv_key, pub_key) = generate_keypair::<D, CSPRNG, CI>(
            &mut self.rng,
            self.ssid,
            self.prs,
            channel_identifier,
        );

        let next_step = AuCPaceServerRecvClientKey::new(self.ssid, priv_key);
        let message = ServerMessage::CPaceSubstep(pub_key);

        (next_step, message)
    }
}

/// Server in the CPace substep phase
pub struct AuCPaceServerRecvClientKey<D, const K1: usize>
where
    D: Digest<OutputSize = U64> + Default,
{
    ssid: Output<D>,
    priv_key: Scalar,
}

impl<D, const K1: usize> AuCPaceServerRecvClientKey<D, K1>
where
    D: Digest<OutputSize = U64> + Default,
{
    fn new(ssid: Output<D>, priv_key: Scalar) -> Self {
        Self { ssid, priv_key }
    }

    /// Receive the client's public key
    /// This completes the CPace substep and moves the client on to explicit mutual authentication.
    ///
    /// # Arguments:
    /// - `client_pubkey` - the client's public key
    ///
    /// # Return:
    /// `next_step`: the server in the Explicit Mutual Authentication phase
    ///
    pub fn receive_client_pubkey(
        self,
        client_pubkey: RistrettoPoint,
    ) -> AuCPaceServerExpMutAuth<D, K1> {
        // TODO: verify the client pubkey here - how??
        let sk1 = compute_first_session_key::<D>(self.ssid, self.priv_key, client_pubkey);
        AuCPaceServerExpMutAuth::new(self.ssid, sk1)
    }

    /// Allow exiting the protocol early in the case of implicit authentication
    /// Note: this should only be used in special circumstances and the
    ///       explicit mutual authentication stage should be used in all other cases
    ///
    /// # Arguments:
    /// - `client_pubkey` - the client's public key
    ///
    /// # Return:
    /// `sk`: the session key reached by the AuCPace protocol
    ///
    pub fn implicit_auth(self, client_pubkey: RistrettoPoint) -> Output<D> {
        let sk1 = compute_first_session_key::<D>(self.ssid, self.priv_key, client_pubkey);
        compute_session_key::<D>(self.ssid, sk1)
    }
}

/// Server in the Explicity Mutual Authenticaton phase
pub struct AuCPaceServerExpMutAuth<D, const K1: usize>
where
    D: Digest<OutputSize = U64> + Default,
{
    ssid: Output<D>,
    sk1: Output<D>,
}

impl<D, const K1: usize> AuCPaceServerExpMutAuth<D, K1>
where
    D: Digest<OutputSize = U64> + Default,
{
    fn new(ssid: Output<D>, sk1: Output<D>) -> Self {
        Self { ssid, sk1 }
    }

    /// Receive the server's authenticator.
    /// This completes the protocol and returns the derived key.
    ///
    /// # Arguments:
    /// - `server_authenticator` - the server's authenticator
    ///
    /// # Return:
    /// either:
    /// - Ok((`sk`, `message`)):
    ///     - `sk` - the session key reached by the AuCPace protocol
    ///     - `message` - the message to send to the client
    /// - Err(Error::MutualAuthFail): an error if the authenticator we computed doesn't match
    ///     the client's authenticator, compared in constant time.
    ///
    pub fn receive_client_authenticator(
        self,
        client_authenticator: [u8; 64],
    ) -> Result<(Output<D>, ServerMessage<D, K1>)> {
        let (ta, tb) = compute_authenticator_messages::<D>(self.ssid, self.sk1);
        if tb.as_ref().ct_eq(&client_authenticator).into() {
            let sk = compute_session_key::<D>(self.ssid, self.sk1);
            let message = ServerMessage::ExplicitMutualAuthentication(ta);
            Ok((sk, message))
        } else {
            Err(Error::MutualAuthFail)
        }
    }
}

/// An enum representing the different messages the server can send to the client
pub enum ServerMessage<D, const K1: usize>
where
    D: Digest<OutputSize = U64> + Default,
{
    /// SSID establishment message - the server's nonce: `s`
    SsidEstablish([u8; K1]),

    /// Information required for the AuCPace Augmentation layer sub-step
    AugmentationLayer {
        /// J from the protocol definition
        group: &'static str,
        /// X from the protocol definition
        x_pub: RistrettoPoint,
        /// the salt used with the PBKDF
        salt: SaltString,
        /// the parameters for the PBKDF used - sigma from the protocol definition
        pbkdf_params: ParamsString,
    },

    /// CPace substep message - the server's public key: `Ya`
    CPaceSubstep(RistrettoPoint),

    /// Explicit Mutual Authentication - the server's authenticator: `Ta`
    ExplicitMutualAuthentication(Output<D>),
}
