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

    /// Begin the protocol
    pub fn begin(
        &mut self,
    ) -> (
        AuCPaceServerSsidEstablish<D, CSPRNG, K1>,
        ServerMessage<D, K1>,
    ) {
        let next_step = AuCPaceServerSsidEstablish::new(self.secret.clone(), &mut self.rng);
        let message = ServerMessage::SsidEstablish(next_step.nonce);
        (next_step, message)
    }
}

/// Server in the SSID agreement phase
pub struct AuCPaceServerSsidEstablish<D, CSPRNG, const K1: usize>
where
    D: Digest<OutputSize = U64> + Default,
    CSPRNG: RngCore + CryptoRng,
{
    secret: ServerSecret,
    nonce: [u8; K1],
    _d: PhantomData<D>,
    _csprng: PhantomData<CSPRNG>,
}

impl<D, CSPRNG, const K1: usize> AuCPaceServerSsidEstablish<D, CSPRNG, K1>
where
    D: Digest<OutputSize = U64> + Default,
    CSPRNG: RngCore + CryptoRng,
{
    fn new(secret: ServerSecret, rng: &mut CSPRNG) -> Self {
        Self {
            secret,
            nonce: generate_nonce(rng),
            _d: Default::default(),
            _csprng: Default::default(),
        }
    }

    /// Consume the client's nonce - `t` and progress to the Augmentation Layer
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
    /// moving the protocol onto the second half of the CPace substep - Receive Client Pubkey
    pub fn generate_public_key(
        mut self,
        channel_identifier: impl AsRef<[u8]>,
    ) -> (AuCPaceServerRecvClientKey<D, K1>, ServerMessage<D, K1>) {
        let (priv_key, pub_key) =
            generate_keypair::<D, CSPRNG>(&mut self.rng, self.ssid, self.prs, channel_identifier);

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

    /// Generate a public key
    /// moving the protocol onto the second half of the CPace substep - Receive Client Pubkey
    pub fn receive_client_pubkey(
        self,
        client_pubkey: RistrettoPoint,
    ) -> AuCPaceServerExpMutAuth<D, K1> {
        // TODO: verify the client pubkey here - how??
        let sk1 = compute_first_session_key::<D>(self.ssid, self.priv_key, client_pubkey);
        AuCPaceServerExpMutAuth::new(self.ssid, sk1)
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

//     /// Generate a nonce for ssid establishment
//     ///
//     /// # Return:
//     /// `nonce` - a fresh ephemeral nonce for establishing an sub-session ID with the client
//     pub fn generate_server_nonce(&mut self) -> [u8; K1] {
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
//     /// Provides an implementation for the AuCPace Augmentation layer
//     ///
//     /// Arguments:
//     /// - `database`: the object which acts as storage for the password verifiers
//     /// - `username`: the username of the connecting client
//     ///
//     /// Return:
//     /// `(PRS, client info)`
//     ///
//     /// where PRS is the Password Related String from the protocol definition
//     /// and client info is all of the information the client needs for the next step of the protocol
//     pub fn generate_client_info(
//         &mut self,
//         database: &mut impl Database<PasswordVerifier = RistrettoPoint>,
//         username: impl AsRef<[u8]>,
//     ) -> ([u8; 32], ClientInfo) {
//         // for ristretto255 the cofactor is 1, for normal curve25519 it is 8
//         // this will need to be provided by a group trait in the future
//         let cofactor = Scalar::one();
//         let x = Scalar::random(&mut self.rng) * cofactor;
//         let x_pub = RISTRETTO_BASEPOINT_POINT * x;
//
//         if let Some((w, salt, sigma)) = database.lookup_verifier(username.as_ref()) {
//             let prs = (w * x).compress().to_bytes();
//             let client_info = ClientInfo {
//                 // this will have to be provided by the trait in future
//                 group: "ristretto255",
//                 x_pub,
//                 salt,
//                 pbkdf_params: sigma,
//             };
//             (prs, client_info)
//         } else {
//             // generate a random PRS
//             // TODO: would it be better to generate this via RistrettoPoint::random
//             let mut prs = [0u8; 32];
//             self.rng.fill_bytes(&mut prs);
//
//             // generate the salt from the hash of the server secret and the user's name
//             let mut hasher: D = Default::default();
//             hasher.update(self.secret.to_le_bytes());
//             hasher.update(username);
//             let hash = hasher.finalize();
//             let hash_bytes: &[u8] = hash.as_ref();
//
//             // It is okay to expect here because SaltString has a buffer of 64 bytes by requirement
//             // from the PHC spec. 48 bytes of data when encoded as base64 transform to 64 bytes.
//             // This gives us the most entropy possible from the hash in the SaltString.
//             let salt = SaltString::b64_encode(&hash_bytes[..48])
//                 .expect("SaltString maximum length invariant broken");
//
//             let client_info = ClientInfo {
//                 group: "ristretto255",
//                 x_pub,
//                 salt,
//                 pbkdf_params: Default::default(),
//             };
//
//             (prs, client_info)
//         }
//     }
//
//     /// Generate the diffie-hellman key pair for the CPace substep of the protocol
//     ///
//     /// Arguments:
//     /// - `ssid`: sub-session identifier
//     /// - `prs`: password related string
//     /// - `ci`: channel identifier
//     ///
//     /// Returns:
//     /// `(private key, public key)`
//     ///
//     /// `private key` is used to generate the shared key
//     /// `public key` is sent to the client to allow them to compute the shared key
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
//     /// where Ta is the authenticator message to be sent to the client
//     /// and Tb is the value used to verify the authenticator message from the client
//     pub fn compute_authenticator_messages(
//         &self,
//         ssid: Output<D>,
//         first_session_key: Output<D>,
//     ) -> (Output<D>, Output<D>) {
//         compute_authenticator_messages::<D>(ssid, first_session_key)
//     }
//
//     /// Checks whether the client authenticator is valid in **constant time**
//     ///
//     /// # Arguments:
//     /// - `ta`: the client authenticator we computed
//     /// - `client_ta`: the client authenticator sent by the client
//     pub fn is_client_authenticator_valid(&self, ta: Output<D>, client_ta: &[u8; 64]) -> bool {
//         ta.as_ref().ct_eq(client_ta).into()
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
// }
