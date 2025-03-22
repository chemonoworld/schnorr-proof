pub mod compat;
pub mod zkp;

pub use compat::ECCurve;
pub use zkp::*;

use elliptic_curve::{point::AffineCoordinates, sec1::ToEncodedPoint};
use k256::{AffinePoint, Scalar};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compat::scalar_hash;
    use rand;

    #[test]
    fn test_non_interactive_schnorr_proof() {
        let private_key = Scalar::generate_biased(&mut rand::thread_rng());
        // P = x * G
        let public_key: AffinePoint = (k256::ProjectivePoint::GENERATOR * private_key).into();
        let encoded = public_key.to_encoded_point(false);
        println!("x coordinate: {:?}", encoded.x());
        println!("y coordinate: {:?}", encoded.y());
        println!("y parity: {:?}", public_key.y_is_odd().unwrap_u8());
        println!(
            "compressed: {:?}",
            hex::encode(encoded.compress().as_bytes())
        );

        let message = b"Hello, PDAO!";
        // Fiat-Shamir transform(SHA256 Hash)
        let challenge = scalar_hash(message);
        let proof = SchnorrProof::<k256::Secp256k1>::create_signature(
            private_key,
            challenge,
            &mut rand::thread_rng(),
        );

        let verified = proof.verify(public_key, challenge);
        assert!(verified);
    }

    #[test]
    fn test_schnorr_signature() {
        let mut private_key = Scalar::generate_biased(&mut rand::thread_rng());
        let mut public_key = k256::ProjectivePoint::GENERATOR * private_key;

        // y가 홀수인 경우 부호를 반전시켜 짝수로 만듦
        let affine = public_key.to_affine();
        if affine.y_is_odd().into() {
            // 홀수 y 좌표면 부호를 반전 (scalar를 부정하면 y 좌표도 부정됨)
            private_key = -private_key;
            public_key = k256::ProjectivePoint::GENERATOR * private_key;
        }

        let message = b"Hello, PDAO!";
        let signing_key = k256::schnorr::SigningKey::from(
            k256::SecretKey::from_bytes(&private_key.to_bytes()).unwrap(),
        );

        let k = k256::Secp256k1::sample_scalar_constant_time(&mut rand::thread_rng());

        let signature = signing_key
            .sign_raw(message, k.to_bytes().as_ref())
            .unwrap();
        println!("signature: {:?}", public_key.to_affine());
        println!("signature: {:?}", signature);
        let verifying_key = k256::schnorr::VerifyingKey::try_from(
            k256::PublicKey::from_affine(public_key.to_affine()).unwrap(),
        ).unwrap();
        verifying_key.verify_raw(message, &signature).expect("failed to verify signature");
    }
}
