// will refactor to be no_std, while developing I will keep std to make things easier for myself.
// #![no_std]

#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]

//! # Usage
//! Add `aucpace` to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! aucpace = "0.1"
//! ```
//!
//! Next read documentation for [`client`](client/index.html) and
//! [`server`](server/index.html) modules.
//!
//! # Protocol description
//! Here we briefly describe the AuCPace Protocol. For additional information
//! refer to AuCPace literature. All arithmetic is done on the (hyper-) elliptic curve `C`
//! in group `J`, with co-factor `c_J` and Diffie-Hellman base point `B` in `J`.
//! It's STRONGLY recommended to use AuCPace parameters provided by this crate
//! in the TODO: insert default instantiation here
//!
//! |       Server                    |   Data transfer   |      Client                     |
//! |---------------------------------|-------------------|---------------------------------|
//! |                                 | Agree on ssid     |                                 |
//! |`s = ${0,1}^k1`                  | <- `t`,    `s` -> | `t = {0,1}^k1`                  |
//! |`ssid = H0(s || t)`              |                   | `ssid = H0(s || t)`             |
//! |                                 |Augmentation layer |                                 |
//! |`x = ${1..m_J}`                  |                   |                                 |
//! |`X = B^(x * c_J)`                | <- `username`     |                                 |
//! |`W,salt = lookupW(user)`         | J,X,salt,sigma -> |                                 |
//! |                                 |                   |`w = PBKDF_sigma(pw, user, salt)`|
//! |if lookup failed `PRS = {0,1}^k2`|                   |abort if X invalid               |
//! |else `PRS = W^(x * c_J)`         |                   |`PRS = X^(w * c_J)`              |
//! |                                 |CPace substep      |                                 |
//! |`g' = H1(ssid||PRS||CI)`         |                   |`g' = H1(ssid||PRS||CI)`         |
//! |`G = Map2Point(g')`              |                   |`G = Map2Point(g')`              |
//! |`ya = ${1..m_J}`                 |                   | `yb = ${1..m_J}`                |
//! |`Ya = G^(ya * cj)`               | <-Yb         Ya-> | `Yb = G^(yb * cj)`              |
//! |`K = Yb^(ya * cj)`               |                   | `K = Ya^(yb * cj)`              |
//! |abort if `Yb` invalid            |                   |abort if Ya invalid              |
//! |`sk1 = H2(ssid || K)`            |                   |`sk1 = H2(ssid || K)`            |
//! |                                 |Explicit Mutual Authentication|                      |
//! |`Ta = H3(ssid || sk1)`           |              Ta-> |`Ta = H3(ssid || sk1)`           |
//! |`Tb = H4(ssid || sk1)`           | <- Tb             |`Tb = H4(ssid || sk1)`           |
//! |verify `Tb`                      |                   |verify `Ta`                      |
//! |`sk = H5(ssid || sk1)`           |                   |`sk = H5(ssid || sk1)`           |
//!
//! Variables and notations have the following meaning:
//!
//! - `k1` — length of nonce to use in SSID agreement step
//! - `k2` — length of nonce to use in SSID agreement step
//! - `s`, `t` — nonces used in SSID agreement
//! - `H` — one-way hash function
//! - `H0..H5` — `H` where the index is prepended to the input as a little-endian four-byte word
//! - `${a,b}^N` — pick randomly from `a` and `b`, `N` times
//! - `${a..b}` — pick a number between `a` and `b`
//! - `^` — Curve point multiplication
//! - `*` — Scalar value multiplication
//! - `‖` — concatenation
//! - `m_J` — the order of `J`
//! - `c_J` — co-factor of `J`
//! - `PBKDF_sigma` — password based key derivation function, parameterised by `sigma`
//! - `ssid` — subsession ID
//! - `PRS` — Password Related String
//! - `CI` — Channel Identifier
//! - `lookupW` — the server lookup of the password verifier for the user
//! - `A`, `B` — Public ephemeral values
//! - `u` — scrambling parameter
//! - `k` — multiplier parameter (`k = H(N || g)` in SRP-6a)
//!
//! [1]: https://eprint.iacr.org/2018/286.pdf

pub mod server;
pub mod client;
pub mod database;
pub mod utils;