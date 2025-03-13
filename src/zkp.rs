use std::marker::PhantomData;

use crate::compat::ECCurve;
use elliptic_curve::{group::Curve, point::AffineCoordinates};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub struct SchnorrProof<C: ECCurve> {
    pub big_r: C::AffinePoint,
    pub s: C::Scalar,
    pub curve: PhantomData<C>,
}

/// This is not implemented according to BIP-340
/// simple implementation just for understanding Schnorr Proof
impl<C: ECCurve> SchnorrProof<C> {
    pub fn create_signature(
        private_key: C::Scalar,
        challenge: C::Scalar,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Self {
        let k = C::sample_scalar_constant_time(rng);
        let big_g = C::generator();
        let big_r = (big_g * k).into();
        let s = k + private_key * challenge;
        Self {
            big_r,
            s,
            curve: PhantomData,
        }
    }

    pub fn verify(&self, public_key: C::AffinePoint, challenge: C::Scalar) -> bool {
        let big_r = C::ProjectivePoint::from(self.big_r);
        let s = self.s;
        let c = challenge;
        let big_g = C::generator();

        // s * G = R + c * P
        let left = big_g * s;
        let right = C::ProjectivePoint::from(public_key) * c + big_r;

        left.eq(&right)
    }
}
