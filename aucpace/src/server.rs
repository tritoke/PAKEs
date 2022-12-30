use std::marker::PhantomData;
use curve25519_dalek::scalar::Scalar;

use digest::{Digest, Output};
use rand_core::RngCore;
use crate::database::Database;
use crate::utils::H0;

pub struct Server<D: Digest, const K1: usize> {
    d: PhantomData<D>
}

/// Information required for the AuCPace Augmentation layer sub-step
pub struct ClientInfo {
    /// J from the protocol definition
    group: &'static str,
}

impl<D: Digest, const K1: usize> Server<D, K1> {
    /// Create new server
    pub fn new() -> Self {
        Self {
            d: Default::default()
        }
    }

    /// Generate a nonce for ssid establishment
    pub fn generate_s(rng: &mut impl RngCore) -> [u8; K1] {
        let mut s = [0u8; K1];
        rng.fill_bytes(&mut s);
        s
    }

    /// Generate the information for the Augmentation sub-step to send to the client
    pub fn generate_client_info(database: &mut impl Database, username: impl AsRef<[u8]>) {
        if let Some(w) = database.lookup_verifier(username.as_ref()) {
            todo!("do something")
        } else {
            todo!("handle failure nicely")
        }
    }
}