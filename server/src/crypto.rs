/*!
Crypto things
*/
use ring::aead::BoundKey;

/// ring requires an implementor of `NonceSequence`,
/// which if a wrapping trait around `ring::aead::Nonce`.
/// We have to make a wrapper that can pass ownership
/// of the nonce exactly once.
struct OneNonceSequence {
    inner: Option<ring::aead::Nonce>,
}
impl OneNonceSequence {
    fn new(inner: ring::aead::Nonce) -> Self {
        Self { inner: Some(inner) }
    }
}

impl ring::aead::NonceSequence for OneNonceSequence {
    fn advance(&mut self) -> std::result::Result<ring::aead::Nonce, ring::error::Unspecified> {
        self.inner.take().ok_or(ring::error::Unspecified)
    }
}

/// Return a `Vec` of secure random bytes of size `n`
pub fn rand_bytes(n: usize) -> crate::Result<Vec<u8>> {
    use ring::rand::SecureRandom;
    let mut buf = vec![0; n];
    let sysrand = ring::rand::SystemRandom::new();
    sysrand
        .fill(&mut buf)
        .map_err(|_| "Error getting random bytes")?;
    Ok(buf)
}

pub fn new_nonce() -> crate::Result<Vec<u8>> {
    rand_bytes(12)
}

pub fn hmac_sign(s: &str) -> String {
    // using a 32 byte key
    let s_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &crate::CONFIG.enc_key.as_bytes());
    let tag = ring::hmac::sign(&s_key, s.as_bytes());
    hex::encode(&tag)
}

/// Return the SHA256 hash of `bytes`
pub fn hash(bytes: &[u8]) -> Vec<u8> {
    let alg = &ring::digest::SHA256;
    let digest = ring::digest::digest(alg, bytes);
    Vec::from(digest.as_ref())
}

/// Encrypt `bytes` with the given `nonce` and `pass`
///
/// `bytes` are encrypted using AES_256_GCM, `nonce` is expected to be
/// 12-bytes, and `pass` 32-bytes
pub fn encrypt<'a>(bytes: &[u8], nonce: &[u8], pass: &[u8]) -> crate::Result<Vec<u8>> {
    let alg = &ring::aead::AES_256_GCM;
    let nonce = ring::aead::Nonce::try_assume_unique_for_key(nonce)
        .map_err(|_| "Encryption nonce not unique")?;
    let nonce = OneNonceSequence::new(nonce);
    let key = ring::aead::UnboundKey::new(alg, pass).map_err(|_| "Error building sealing key")?;
    let mut key = ring::aead::SealingKey::new(key, nonce);
    let mut in_out = bytes.to_vec();
    key.seal_in_place_append_tag(ring::aead::Aad::empty(), &mut in_out)
        .map_err(|_| "Failed encrypting bytes")?;
    Ok(in_out)
}

/// Decrypt `bytes` with the given `nonce` and `pass`
///
/// `bytes` are decrypted using AES_256_GCM, `nonce` is expected to be
/// 12-bytes, and `pass` 32-bytes
pub fn decrypt<'a>(bytes: &'a mut [u8], nonce: &[u8], pass: &[u8]) -> crate::Result<&'a [u8]> {
    let alg = &ring::aead::AES_256_GCM;
    let nonce = ring::aead::Nonce::try_assume_unique_for_key(nonce)
        .map_err(|_| "Decryption nonce not unique")?;
    let nonce = OneNonceSequence::new(nonce);
    let key = ring::aead::UnboundKey::new(alg, pass).map_err(|_| "Error build opening key")?;
    let mut key = ring::aead::OpeningKey::new(key, nonce);
    let out_slice = key
        .open_in_place(ring::aead::Aad::empty(), bytes)
        .map_err(|_| "Failed decrypting bytes")?;
    Ok(out_slice)
}
