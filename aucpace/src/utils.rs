use curve25519_dalek::{
    digest::consts::U64,
    digest::{Digest, Output},
    ristretto::RistrettoPoint,
    scalar::Scalar,
};
use rand_core::{CryptoRng, RngCore};

#[allow(non_snake_case)]
#[inline(always)]
fn H<D: Digest + Default, const N: u32>() -> D {
    let mut hasher: D = Default::default();
    hasher.update(N.to_le_bytes());
    hasher
}

macro_rules! create_h_impl {
    ($name:ident, $n:literal) => {
        #[allow(non_snake_case)]
        pub(crate) fn $name<D: Digest + Default>() -> D {
            H::<D, $n>()
        }
    };
}

// implement H0..H5 hash functions
create_h_impl!(H0, 0);
create_h_impl!(H1, 1);
create_h_impl!(H2, 2);
create_h_impl!(H3, 3);
create_h_impl!(H4, 4);
create_h_impl!(H5, 5);

/// Generate a fixed length nonce using a CSPRNG
#[inline(always)]
pub(crate) fn generate_nonce<CSPRNG, const N: usize>(rng: &mut CSPRNG) -> [u8; N]
where
    CSPRNG: RngCore + CryptoRng,
{
    let mut nonce = [0; N];
    rng.fill_bytes(&mut nonce);
    nonce
}

/// Computes the SSID from two server and client nonces - s and t
#[inline(always)]
pub(crate) fn compute_ssid<D: Digest + Default, const K1: usize>(
    s: [u8; K1],
    t: [u8; K1],
) -> Output<D> {
    let mut hasher: D = H0();
    hasher.update(s);
    hasher.update(t);
    hasher.finalize()
}

/// Generate a Diffie-Hellman keypair for the CPace substep of the protocol
#[inline(always)]
pub(crate) fn generate_keypair<D, CSPRNG, CI>(
    rng: &mut CSPRNG,
    ssid: Output<D>,
    prs: [u8; 32],
    ci: CI,
) -> (Scalar, RistrettoPoint)
where
    D: Digest<OutputSize = U64> + Default,
    CSPRNG: RngCore + CryptoRng,
    CI: AsRef<[u8]>,
{
    let mut hasher: D = H1();
    hasher.update(ssid);
    hasher.update(prs);
    hasher.update(ci);

    let generator = RistrettoPoint::from_hash(hasher);
    let priv_key = Scalar::random(rng);
    let cofactor = Scalar::one();
    let pub_key = generator * (priv_key * cofactor);

    (priv_key, pub_key)
}

/// Compute the first session key sk1 from our private key and the other participant's public key
#[inline(always)]
pub(crate) fn compute_first_session_key<D>(
    ssid: Output<D>,
    priv_key: Scalar,
    pub_key: RistrettoPoint,
) -> Output<D>
where
    D: Digest<OutputSize = U64> + Default,
{
    let shared_point = pub_key * priv_key;

    let mut hasher: D = H2();
    hasher.update(ssid);
    hasher.update(shared_point.compress().to_bytes());

    hasher.finalize()
}

/// Compute the two authenticator messages Ta and Tb
#[inline(always)]
pub(crate) fn compute_authenticator_messages<D>(
    ssid: Output<D>,
    sk1: Output<D>,
) -> (Output<D>, Output<D>)
where
    D: Digest<OutputSize = U64> + Default,
{
    let mut ta_hasher: D = H3();
    ta_hasher.update(ssid);
    ta_hasher.update(sk1);

    let mut tb_hasher: D = H4();
    tb_hasher.update(ssid);
    tb_hasher.update(sk1);

    (ta_hasher.finalize(), tb_hasher.finalize())
}

/// Compute the session key - sk
#[inline(always)]
pub(crate) fn compute_session_key<D>(ssid: Output<D>, sk1: Output<D>) -> Output<D>
where
    D: Digest<OutputSize = U64> + Default,
{
    let mut hasher: D = H5();
    hasher.update(ssid);
    hasher.update(sk1);
    hasher.finalize()
}

// serde_with helper modules for serialising

#[cfg(feature = "serde")]
pub(crate) mod serde_saltstring {
    use core::fmt;
    use our_serde::de::{Error, Visitor};
    use our_serde::{Deserializer, Serializer};
    use password_hash::SaltString;

    pub fn serialize<S>(data: &SaltString, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(data.as_str())
    }

    struct SaltStringVisitor {}

    impl<'de> Visitor<'de> for SaltStringVisitor {
        type Value = SaltString;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "a valid ASCII salt string")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: Error,
        {
            SaltString::new(v).map_err(Error::custom)
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<SaltString, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(SaltStringVisitor {})
    }
}

#[cfg(any(feature = "serde"))]
pub(crate) mod serde_paramsstring {
    use core::fmt;
    use our_serde::de::{Error, Visitor};
    use our_serde::{Deserializer, Serializer};
    use password_hash::ParamsString;

    pub fn serialize<S>(data: &ParamsString, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(data.as_str())
    }

    struct ParamsStringVisitor {}

    impl<'de> Visitor<'de> for ParamsStringVisitor {
        type Value = ParamsString;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "a valid PHC parameter string")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: Error,
        {
            v.parse().map_err(Error::custom)
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<ParamsString, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(ParamsStringVisitor {})
    }
}
