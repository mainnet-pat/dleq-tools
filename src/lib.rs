#![allow(non_snake_case)]
use curve25519_dalek::edwards::EdwardsPoint;
use ecdsa_fun::fun::Point;
use ecdsa_fun::nonce::Deterministic;
use sigma_fun::ext::dl_secp256k1_ed25519_eq::{CrossCurveDLEQ, CrossCurveDLEQProof};
use sigma_fun::HashTranscript;
use ecdsa_fun::fun::marker::{Mark, NonZero};
use sha2::Sha256;
use conquer_once::Lazy;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use ecdsa_fun::adaptor::EncryptedSignature;
use ecdsa_fun::Signature;
use ecdsa_fun::adaptor::Adaptor;
use ecdsa_fun::ECDSA;
use wasm_bindgen::prelude::wasm_bindgen;
use base58_monero::base58;
use keccak_hash::keccak_256;

pub static CROSS_CURVE_PROOF_SYSTEM: Lazy<
    CrossCurveDLEQ<HashTranscript<Sha256, rand_chacha::ChaCha20Rng>>,
> = Lazy::new(|| {
    CrossCurveDLEQ::<HashTranscript<Sha256, rand_chacha::ChaCha20Rng>>::new(
        (*ecdsa_fun::fun::G).mark::<ecdsa_fun::fun::marker::Normal>(),
        curve25519_dalek::constants::ED25519_BASEPOINT_POINT,
    )
});

/// A DLEQ Proof class to be used in JavaScript
#[wasm_bindgen]
pub struct DleqProof {
    proof: String,
    bitcoinPubKey: String,
    moneroPubKey: String,
}

#[wasm_bindgen]
impl DleqProof {
    /// Create a new DLEQ proof class
    #[wasm_bindgen(constructor)]
    pub fn new(proof: String, bitcoinPubKey: String, moneroPubKey: String) -> Self {
        DleqProof {
            proof,
            bitcoinPubKey,
            moneroPubKey,
        }
    }

    /// Get the proof
    #[wasm_bindgen(getter)]
    pub fn proof(&self) -> String {
        self.proof.clone()
    }

    /// Set the proof
    #[wasm_bindgen(setter)]
    pub fn set_proof(&mut self, proof: String) {
        self.proof = proof;
    }

    /// Get the bitcoin public key
    #[wasm_bindgen(getter)]
    pub fn bitcoinPubKey(&self) -> String {
        self.bitcoinPubKey.clone()
    }

    /// Set the bitcoin public key
    #[wasm_bindgen(setter)]
    pub fn set_bitcoinPubKey(&mut self, bitcoinPubKey: String) {
        self.bitcoinPubKey = bitcoinPubKey;
    }

    /// Get the monero public key
    #[wasm_bindgen(getter)]
    pub fn moneroPubKey(&self) -> String {
        self.moneroPubKey.clone()
    }

    /// Set the monero public key
    #[wasm_bindgen(setter)]
    pub fn set_moneroPubKey(&mut self, moneroPubKey: String) {
        self.moneroPubKey = moneroPubKey;
    }
}

/// Generate a DLEQ proof
///
/// Generate a DLEQ proof that a private key `moneroPrivateKey` on Ed25519 curve is the same as a private key on Secp256k1 curve
/// # Arguments
/// * `moneroPrivateKey` private key on Ed25519 curve
/// # Returns
/// * `dleqProof` DLEQ proof, containing the proof and the public keys on both curves
#[wasm_bindgen]
pub fn getDleqProof(moneroPrivateKey: String) -> DleqProof {
    let moneroPrivateKey = hex::decode(moneroPrivateKey).unwrap();
    let moneroPrivateKey: Scalar = bincode::deserialize(&moneroPrivateKey).unwrap();

    let mut rng = rand::thread_rng();
    let (proof, (bitcoinPubKey, moneroPubKey)) = CROSS_CURVE_PROOF_SYSTEM.prove(&moneroPrivateKey, &mut rng);
    let proof = bincode::serialize(&proof).unwrap();

    let bitcoinPubKey = bincode::serialize(&bitcoinPubKey).unwrap();

    let moneroPubKey = bincode::serialize(&moneroPubKey).unwrap();

    return DleqProof::new(hex::encode(&proof), hex::encode(&bitcoinPubKey), hex::encode(&moneroPubKey));
}

/// Verify a DLEQ proof
///
/// Verify that two public keys on different curves are derived from the same private key given `proof`
/// # Arguments
/// * `dleqProof` DLEQ proof, containing the proof and the public keys on both curves
/// # Returns
/// * `true` if the proof is valid, `false` otherwise
#[wasm_bindgen]
pub fn verifyDleqProof(dleqProof: &DleqProof) -> bool {
    // decode proof and pubkeys
    let proof = hex::decode(dleqProof.proof()).unwrap();
    let proof: CrossCurveDLEQProof = bincode::deserialize(&proof).unwrap();

    let bitcoinPubKey = hex::decode(dleqProof.bitcoinPubKey()).unwrap();
    let bitcoinPubKey: Point = bincode::deserialize(&bitcoinPubKey).unwrap();

    let moneroPubKey = hex::decode(dleqProof.moneroPubKey()).unwrap();
    let moneroPubKey: EdwardsPoint = bincode::deserialize(&moneroPubKey).unwrap();

    // verify proof
    let result = CROSS_CURVE_PROOF_SYSTEM.verify(&proof, (bitcoinPubKey, moneroPubKey));
    return result;
}

/// Generate a random monero private key
/// # Returns
/// * `moneroPrivKey` private key on Ed25519 curve
#[wasm_bindgen]
pub fn getRandomMoneroPrivKey() -> String {
    let mut rng = rand::thread_rng();
    let randomScalar = Scalar::random(&mut rng);
    let encoded: String = hex::encode(&bincode::serialize(&randomScalar).unwrap());
    return encoded;
}

/// Add two monero private keys
/// # Returns
/// * `moneroPrivKey` private key on Ed25519 curve
#[wasm_bindgen]
pub fn addMoneroPrivKeys(privKeyA: String, privKeyB: String) -> String {
    let privKeyA = hex::decode(privKeyA).unwrap();
    let privKeyA: Scalar = bincode::deserialize(&privKeyA).unwrap();

    let privKeyB = hex::decode(privKeyB).unwrap();
    let privKeyB: Scalar = bincode::deserialize(&privKeyB).unwrap();

    let sum = privKeyA + privKeyB;
    let encoded: String = hex::encode(&bincode::serialize(&sum).unwrap());
    return encoded;
}

/// Get the monero public key from a monero private key
/// # Arguments
/// * `moneroPrivKey` private key on Ed25519 curve
/// # Returns
/// * `moneroPubKey` public key corresponding to the private key on Ed25519 curve
#[wasm_bindgen]
pub fn getMoneroPubKey(moneroPrivKey: String) -> String {
    let moneroPrivKey = hex::decode(moneroPrivKey).unwrap();
    let moneroPrivKey: Scalar = bincode::deserialize(&moneroPrivKey).unwrap();
    let pubkey = &moneroPrivKey * &ED25519_BASEPOINT_TABLE;
    let encoded: String = hex::encode(&bincode::serialize(&pubkey).unwrap());
    return encoded;
}

/// Add two monero public keys
/// # Returns
/// * `moneroPubKey` public key corresponding to the sum of the two public keys on Ed25519 curve
#[wasm_bindgen]
pub fn addMoneroPubKeys(pubKeyA: String, pubKeyB: String) -> String {
    let pubKeyA = hex::decode(pubKeyA).unwrap();
    let pubKeyA: EdwardsPoint = bincode::deserialize(&pubKeyA).unwrap();

    let pubKeyB = hex::decode(pubKeyB).unwrap();
    let pubKeyB: EdwardsPoint = bincode::deserialize(&pubKeyB).unwrap();

    let sum = pubKeyA + pubKeyB;
    let encoded: String = hex::encode(&bincode::serialize(&sum).unwrap());
    return encoded;
}

/// Create an standard address which is valid on the given network.
///
/// # Arguments
/// * `network` - The network to create the address for.
/// * `pubKeySpend` - The public spend key.
/// * `pubKeyView` - The public view key.
///
/// # Returns
/// * `Address` - The standard address.
#[wasm_bindgen]
pub fn getMoneroAddress(network: String, pubKeySpend: String, pubKeyView: String) -> String {
    // 18 -> Mainnet, 53 -> Testnet, 24 -> Stagenet
    let network: u8 = match network.as_str() {
        "mainnet" => 18,
        "stagenet" => 24,
        "testnet" => 53,
        _ => return "".to_string(),
    };
    let pubKeySpend = hex::decode(pubKeySpend).unwrap();
    let pubKeySpend: EdwardsPoint = bincode::deserialize(&pubKeySpend).unwrap();

    let pubKeyView = hex::decode(pubKeyView).unwrap();
    let pubKeyView: EdwardsPoint = bincode::deserialize(&pubKeyView).unwrap();

    let mut bytes = vec![network];
    bytes.extend_from_slice(pubKeySpend.compress().as_bytes().as_slice());
    bytes.extend_from_slice(pubKeyView.compress().as_bytes().as_slice());

    let mut checksum = [0u8; 32];
    keccak_256(bytes.as_slice(), &mut checksum);
    bytes.extend_from_slice(&checksum[0..4]);

    let encoded = base58::encode(bytes.as_slice()).unwrap();
    return encoded;
}

/// Generate a random bitcoin private key
/// # Returns
/// * `bitcoinPrivKey` private key on Secp256k1 curve
#[wasm_bindgen]
pub fn getRandomBitcoinPrivKey() -> String {
    let mut rng = rand::thread_rng();
    let randomScalar = ecdsa_fun::fun::Scalar::random(&mut rng);
    let encoded: String = hex::encode(&bincode::serialize(&randomScalar).unwrap());
    return encoded;
}

/// Get the bitcoin public key from a bitcoin private key
/// # Arguments
/// * `bitcoinPrivKey` private key on Secp256k1 curve
/// # Returns
/// * `bitcoinPubKey` public key corresponding to the private key on Secp256k1 curve
#[wasm_bindgen]
pub fn getBitcoinPubKey(bitcoinPrivKey: String) -> String {
    let bitcoinPrivKey = hex::decode(bitcoinPrivKey).unwrap();
    let bitcoinPrivKey: ecdsa_fun::fun::Scalar = bincode::deserialize(&bitcoinPrivKey).unwrap();
    let ecdsa = ECDSA::<()>::default();
    let pubkey = ecdsa.verification_key_for(&bitcoinPrivKey);
    let encoded: String = hex::encode(&bincode::serialize(&pubkey).unwrap());
    return encoded;
}

/// Convert a monero private key to a bitcoin private key
/// # Arguments
/// * `moneroPrivkey` private key on Ed25519 curve
/// # Returns
/// * `bitcoinPrivKey` private key on Secp256k1 curve
#[wasm_bindgen]
pub fn toBitcoinPrivKey(moneroPrivkey: String) -> String {
    let decode = hex::decode(moneroPrivkey).unwrap();
    let s_a: Scalar = bincode::deserialize(&decode).unwrap();

    let mut bytes = s_a.to_bytes();

    // secp256kfun interprets scalars as big endian
    bytes.reverse();
    let a: ecdsa_fun::fun::Scalar = ecdsa_fun::fun::Scalar::from_bytes(bytes)
        // .expect("will never overflow since ed25519 order is lower")
        .unwrap()
        .mark::<NonZero>()
        // .expect("must not be zero");
        .unwrap();

    let encoded: String = hex::encode(&bincode::serialize(&a).unwrap());
    return encoded;
}

/// Convert a bitcoin private key to a monero private key
/// # Arguments
/// * `bitcoinPrivKey` private key on Secp256k1 curve
/// # Returns
/// * `moneroPrivKey` private key on Ed25519 curve
#[wasm_bindgen]
pub fn toMoneroPrivKey(bitcoinPrivKey: String) -> String {
    let decode = hex::decode(bitcoinPrivKey).unwrap();
    let a: ecdsa_fun::fun::Scalar = bincode::deserialize(&decode).unwrap();

    let mut bytes = a.to_bytes();

    // secp256kfun interprets scalars as big endian
    bytes.reverse();
    let privateKey: Scalar = Scalar::from_bytes_mod_order(bytes);
    let encoded: String = hex::encode(&bincode::serialize(&privateKey).unwrap());
    return encoded;
}

/// Decrypt an adaptor signature.
/// # Arguments
/// * `privKey` private key of the verifier
/// * `adaptorSignature` encrypted adaptor signature
/// # Returns
/// * `signature` decrypted signature which can be verified with `verifyEncryptedSignature`.
/// `recoverPrivateKey` can be used to recover the private key from the signature.
#[wasm_bindgen]
pub fn decryptSignature(privKey: String, adaptorSignature: String) -> String {
    let privkey = hex::decode(privKey).unwrap();
    let privkey: ecdsa_fun::fun::Scalar = bincode::deserialize(&privkey).unwrap();

    let encsig: Vec<u8> = hex::decode(adaptorSignature).unwrap();
    let encsig: EncryptedSignature = bincode::deserialize(&encsig).unwrap();

    let adaptor = Adaptor::<HashTranscript<Sha256>, Deterministic<Sha256>>::default();

    let signature = adaptor.decrypt_signature(&privkey, encsig);

    let encoded: String = hex::encode(&bincode::serialize(&signature).unwrap());
    return encoded;
}

/// Verify an adaptor signature.
/// # Arguments
/// * `verificationPubKey` public key of the verifier
/// * `pubKey` public key of the signer who produced this signature for verifier
/// * `digest` message digest
/// * `adaptorSig` encrypted adaptor signature
/// # Returns
/// * `true` if the signature is valid, `false` otherwise
#[wasm_bindgen]
pub fn verifyEncryptedSignature(verificationPubKey: String, pubKey: String, digest: String, adaptorSig: String) -> bool {
    let verificationPubKey = hex::decode(verificationPubKey).unwrap();
    let verificationPubKey: ecdsa_fun::fun::Point = bincode::deserialize(&verificationPubKey).unwrap();

    let pubKey = hex::decode(pubKey).unwrap();
    let pubKey: ecdsa_fun::fun::Point = bincode::deserialize(&pubKey).unwrap();

    let digest: Vec<u8> = hex::decode(digest).unwrap();

    let adaptorSig = hex::decode(adaptorSig).unwrap();
    let adaptorSig: EncryptedSignature = bincode::deserialize(&adaptorSig).unwrap();

    let adaptor = Adaptor::<HashTranscript<Sha256>, Deterministic<Sha256>>::default();

    return adaptor.verify_encrypted_signature(
        &verificationPubKey,
        &pubKey,
        &digest.try_into().unwrap(),
        &adaptorSig
    );
}

/// Recover the private key from an adaptor signature
///
/// Recover the private key from an adaptor signature `adaptorSig` for a counterparty holding `pubKey` using `dataSig`.
/// # Arguments
/// * `pubKey` public key of the counterparty
/// * `sig` signature decrypted from `adaptorSig` with `decryptSignature`
/// * `adaptorSig` encrypted adaptor signature
/// # Returns
/// * `privKey` private key recovered from the adaptor or empty string if the `sig` and `adaptorSig` are not related
#[wasm_bindgen]
pub fn recoverPrivateKey(pubKey: String, sig: String, adaptorSig: String) -> String {
    let pubkey = hex::decode(pubKey).unwrap();
    let pubkey: Point = bincode::deserialize(&pubkey).unwrap();

    let sig = hex::decode(sig).unwrap();
    let sig: Signature = bincode::deserialize(&sig).unwrap();

    let adaptorSig = hex::decode(adaptorSig).unwrap();
    let adaptorSig: EncryptedSignature = bincode::deserialize(&adaptorSig).unwrap();

    let adaptor = Adaptor::<HashTranscript<Sha256>, Deterministic<Sha256>>::default();

    let s = adaptor
        .recover_decryption_key(&pubkey, &sig, &adaptorSig);

    if s.is_none() {
        return String::from("");
    }

    let encoded: String = hex::encode(&bincode::serialize(&s.unwrap()).unwrap());
    return encoded;
}

/// Create an encryted signature A.K.A. "adaptor signature"
///
/// Create an adaptor signature of a message `digest` for a counterparty holding `pubKey` using signer's `privKey`.
///
/// # Arguments
/// * `privKey` private key of the signer
/// * `pubKey` public key of the counterparty
/// * `digest` message digest
///
/// # Returns
/// * `encsig` encrypted signature
#[wasm_bindgen]
pub fn makeAdaptorSignature(privKey: String, pubKey: String, digest: String) -> String {
    let adaptor = Adaptor::<
        HashTranscript<Sha256, rand_chacha::ChaCha20Rng>,
        Deterministic<Sha256>,
    >::default();

    let privKey = hex::decode(privKey).unwrap();
    let privKey: ecdsa_fun::fun::Scalar = bincode::deserialize(&privKey).unwrap();

    let pubKey = hex::decode(pubKey).unwrap();
    let pubKey: Point = bincode::deserialize(&pubKey).unwrap();

    let digest: Vec<u8> = hex::decode(digest).unwrap();

    let result = adaptor.encrypted_sign(&privKey, &pubKey, &digest.try_into().unwrap());

    let encoded: String = hex::encode(&bincode::serialize(&result).unwrap());
    return encoded;
}

/// Make an ECDSA DER signature
///
/// Make an ECDSA DER signature of a message `digest` using signer's `privKey`.
/// # Arguments
/// * `privKey` private key of the signer
/// * `digest` message digest
/// # Returns
/// * `sig` ECDSA DER signature
#[wasm_bindgen]
pub fn sign(privKey: String, digest: String) -> String {
    let privKey = hex::decode(privKey).unwrap();
    let privKey: ecdsa_fun::fun::Scalar = bincode::deserialize(&privKey).unwrap();

    let digest = hex::decode(digest).unwrap();

    let ecdsa = ECDSA::<Deterministic<Sha256>>::default();

    let result = ecdsa.sign(&privKey, &digest.try_into().unwrap());

    let encoded: String = hex::encode(&bincode::serialize(&result).unwrap());
    return encoded;
}

#[cfg(test)]
mod tests {
    use crate::{decryptSignature, getBitcoinPubKey, getDleqProof, getMoneroAddress, getMoneroPubKey, getRandomMoneroPrivKey, makeAdaptorSignature, recoverPrivateKey, toBitcoinPrivKey, toMoneroPrivKey, verifyDleqProof, verifyEncryptedSignature};

    #[test]
    fn testPrivKeyConversion() {
        let moneroPrivKey = getRandomMoneroPrivKey();
        let bitcoinPrivKey = toBitcoinPrivKey(moneroPrivKey.clone());
        let moneroPrivKey2 = toMoneroPrivKey(bitcoinPrivKey.clone());
        assert_eq!(moneroPrivKey, moneroPrivKey2);
        return;
    }

    #[test]
    fn testAddressEncodingMainnet() {
        let publicSpendKey = "e383746871e5669059f45ab9d418df546c3d807a4158fd4c8d2b063a8023e237".to_string();
        let pulicViewKey = "03092ba141ca3b0bee9879dbb8a33020581563f9ec0972045ac632c762c4bdf7".to_string();
        let expectedAddress = "4AFAnp94fXjR9PaTDgnnxWF81Qh7ufjxpDoeQEi7DtEdACgfmsYER8E2zkpSsztJhu6Qn8PEHFop51jFCzz8qWngUsiKT48".to_string();
        assert_eq!(getMoneroAddress("mainnet".to_string(), publicSpendKey, pulicViewKey), expectedAddress);
    }

    #[test]
    fn testAddressEncodingTestnet() {
        let publicSpendKey = "e383746871e5669059f45ab9d418df546c3d807a4158fd4c8d2b063a8023e237".to_string();
        let pulicViewKey = "03092ba141ca3b0bee9879dbb8a33020581563f9ec0972045ac632c762c4bdf7".to_string();
        let expectedAddress = "A1niH4oKwtqR9PaTDgnnxWF81Qh7ufjxpDoeQEi7DtEdACgfmsYER8E2zkpSsztJhu6Qn8PEHFop51jFCzz8qWngUyhAtbe".to_string();
        assert_eq!(getMoneroAddress("testnet".to_string(), publicSpendKey, pulicViewKey), expectedAddress);
    }

    #[test]
    fn testAddressEncodingStagenet() {
        let publicSpendKey = "e383746871e5669059f45ab9d418df546c3d807a4158fd4c8d2b063a8023e237".to_string();
        let pulicViewKey = "03092ba141ca3b0bee9879dbb8a33020581563f9ec0972045ac632c762c4bdf7".to_string();
        let expectedAddress = "5ATCsf42K8qR9PaTDgnnxWF81Qh7ufjxpDoeQEi7DtEdACgfmsYER8E2zkpSsztJhu6Qn8PEHFop51jFCzz8qWngUwN6q1R".to_string();
        assert_eq!(getMoneroAddress("stagenet".to_string(), publicSpendKey, pulicViewKey), expectedAddress);
    }

    #[test]
    fn testAddressEncodingWrongNetwork() {
        let publicSpendKey = "e383746871e5669059f45ab9d418df546c3d807a4158fd4c8d2b063a8023e237".to_string();
        let pulicViewKey = "03092ba141ca3b0bee9879dbb8a33020581563f9ec0972045ac632c762c4bdf7".to_string();
        let expectedAddress = "".to_string();
        assert_eq!(getMoneroAddress("".to_string(), publicSpendKey, pulicViewKey), expectedAddress);
    }

    #[test]
    fn SwapWorkflowTest() {
        // Alice has XMR, wants BCH.
        // Bob has BCH, wants XMR.

        // Alice and Bob generate their one-time monero private keys
        let aMonero = getRandomMoneroPrivKey();
        let bMonero = getRandomMoneroPrivKey();

        // Alice and Bob get their one-time monero public keys
        let aPubMonero = getMoneroPubKey(aMonero.clone());
        let bPubMonero = getMoneroPubKey(bMonero.clone());

        // Alice and Bob get their one-time bitcoin private keys from their monero private keys
        let aBitcoin = toBitcoinPrivKey(aMonero.clone());
        let bBitcoin = toBitcoinPrivKey(bMonero.clone());

        // Alice and Bob generate their one-time monero public keys
        let aPubBitcoin = getBitcoinPubKey(aBitcoin.clone());
        let bPubBitcoin = getBitcoinPubKey(bBitcoin.clone());

        // Alice generates her proof
        let aProof = getDleqProof(aMonero.clone());

        // Bob receives Alice's PubKeys and verifies Alice's proof
        assert!(verifyDleqProof(&aProof));
        assert!(aPubMonero == aProof.moneroPubKey());
        assert!(aPubBitcoin == aProof.bitcoinPubKey());

        // Bob generates his proof
        let bProof = getDleqProof(bMonero.clone());

        // Alice receives Bob's PubKeys verifies Bob's proof
        assert!(verifyDleqProof(&bProof));
        assert!(bPubMonero == bProof.moneroPubKey());
        assert!(bPubBitcoin == bProof.bitcoinPubKey());

        // Alice and Bob will work with the same message digest
        let digest = "02151f141aa73ee2073da862879cb5947ef9d90f71f771ceba9a3008aa1ed8cf".to_string();

        // https://gitlab.com/0353F40E/cross-chain-swap-ves/-/blob/dfc96dbad839d2021b8910af85e66f0c775427c6/contracts/v4-XMR/swaplock.cash#
        // Bob locks his BCH in a smart contract, which requires Alice to submit Bob's signature on the agreed digest
        // Alice observes the contract creation transaction
        // Alice sends her XMR to an address with Public view key A+B = Alice public view key + Bob public view key, from which she can not spend
        // Alice sends Bob the details of the transaction: transaction hash, transaction key and the destination address

        // Bob generates an adaptor signature and transmits it to Alice
        let encryptedSignature = makeAdaptorSignature(bBitcoin.clone(), aPubBitcoin.clone(), digest.clone());

        // Alice verifies the signature with her public key
        assert!(verifyEncryptedSignature(bPubBitcoin.clone(), aPubBitcoin.clone(), digest, encryptedSignature.clone()));

        // She decrypts the adaptor signature with her private key and recovers Bob's data signature
        let signature = decryptSignature(bBitcoin.clone(), encryptedSignature.clone());

        // She then submits this signature to claim Bob's BCH locked in a smart contract
        // Bob observes the transaction and recovers Alice's private key from the signature
        let recovered = recoverPrivateKey(bPubBitcoin, signature, encryptedSignature);

        assert_eq!(recovered, bBitcoin);

        // Bob now knows Alice's private key and can combine XMR key parts to claim the funds behind A+B address
        // Bob never leaked his private key, so Alice would never claim her XMR back
    }
}
