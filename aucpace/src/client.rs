use std::marker::PhantomData;
use rand_core::{CryptoRng, RngCore};
use digest::{Digest, Output};
use crate::database::Database;

struct Client<D: Digest, const K1: usize> {
    d: PhantomData<D>,
}

impl<D: Digest, const K1: usize> Client<D, K1> {
    /// Create new server
    pub fn new() -> Self {
        Self {
            d: Default::default()
        }
    }

    /// Generate a nonce for ssid establishment
    pub fn generate_s(rng: &mut impl CryptoRng + RngCore) -> [u8; K1] {
        let mut s = [0u8; K1];
        rng.fill_bytes(&mut s);
        s
    }
}
