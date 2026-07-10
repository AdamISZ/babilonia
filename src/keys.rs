//! Party keys. Each side holds a long-term identity key and, per-session, the ephemerals the
//! construction needs (Alice's thimble scalars `h_1,h_2` in `setup`; Bob's funding key `P_b` and
//! hidden claim key `W_b`). The hash-free design has no blinding scalars — `t`/`t_b` are gone.

use rand::RngCore;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};

/// A secret/public keypair on secp256k1.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Keypair {
    pub sk: SecretKey,
    pub pk: PublicKey,
}

impl Keypair {
    /// Fresh random keypair. Seeded from raw bytes (not `generate_keypair`) to stay agnostic
    /// to which `rand` version secp256k1 pulls — bitcoin and secp256k1 disagree in our graph.
    pub fn new<C: secp256k1::Signing>(secp: &Secp256k1<C>) -> Self {
        let mut bytes = [0u8; 32];
        loop {
            rand::thread_rng().fill_bytes(&mut bytes);
            if let Ok(sk) = SecretKey::from_byte_array(bytes) {
                let pk = PublicKey::from_secret_key(secp, &sk);
                return Keypair { sk, pk };
            }
        }
    }

    /// Deterministic keypair from raw secret bytes (test vectors / regtest reproducibility).
    pub fn from_secret_bytes<C: secp256k1::Signing>(
        secp: &Secp256k1<C>,
        bytes: &[u8; 32],
    ) -> crate::Result<Self> {
        let sk = SecretKey::from_byte_array(*bytes)?;
        let pk = PublicKey::from_secret_key(secp, &sk);
        Ok(Keypair { sk, pk })
    }
}

/// The identity keys each party contributes to the `MuSig2(P_a, P_b)` funding/pot key.
#[derive(Clone, Debug)]
pub struct PartyKeys {
    /// `P_a = x_a·G` (Alice) or `P_b = x_b·G` (Bob).
    pub identity: Keypair,
}

impl PartyKeys {
    pub fn new<C: secp256k1::Signing>(secp: &Secp256k1<C>) -> Self {
        PartyKeys {
            identity: Keypair::new(secp),
        }
    }
}
