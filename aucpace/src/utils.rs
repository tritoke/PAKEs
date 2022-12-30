use digest::{Digest, Output};
use rand_core::{CryptoRng, RngCore};

/// implement H0..H5 hash functions
#[allow(non_snake_case)]
#[inline(always)]
fn H<D: Digest, const N: u32>() -> D {
    D::new_with_prefix(N.to_le_bytes())
}

macro_rules! create_h_impl {
    ($name:ident, $n:literal) => {
        #[allow(non_snake_case)]
        pub(crate) fn $name<D: Digest>() -> D {
            H::<D, $n>()
        }
    };
}

create_h_impl!(H0, 0);
create_h_impl!(H1, 1);
create_h_impl!(H2, 2);
create_h_impl!(H3, 3);
create_h_impl!(H4, 4);
create_h_impl!(H5, 5);

/// Computes the SSID from two server and client nonces - s and t
pub fn compute_ssid<D: Digest, const K1: usize>(s: [u8; K1], t: [u8; K1]) -> Output<D> {
    let mut hasher: D = H0();
    hasher.update(s);
    hasher.update(t);
    hasher.finalize()
}
