//! Low-level cryptographic primitives for lispm-auth. Binary Lisp arguments and
//! results are hexadecimal strings; passwords are UTF-8 Emacs strings.
use anyhow::anyhow;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use emacs::{defun, Env, Result};
use zeroize::Zeroizing;

emacs::plugin_is_GPL_compatible!();

#[emacs::module(name = "lispm-auth-native")]
fn init(_: &Env) -> Result<()> {
    Ok(())
}

// v1 fixes Argon2id v19 to m=65536 KiB, t=3, p=1 and a 32-byte output.
// Wrapped key: "LAW" || version || salt[16] || nonce[24] || ciphertext[48].
// Item:        "LAI" || version || nonce[24] || ciphertext+tag[16..].
// The header is authenticated, and item IDs are additionally authenticated.
const WRAP_HEADER: &[u8; 4] = b"LAW\x01";
const ITEM_HEADER: &[u8; 4] = b"LAI\x01";
const KEY_LEN: usize = 32;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0; N];
    getrandom::getrandom(&mut bytes).map_err(|e| anyhow!("random generation failed: {e}"))?;
    Ok(bytes)
}

fn decode(text: &str) -> Result<Zeroizing<Vec<u8>>> {
    Ok(Zeroizing::new(
        hex::decode(text).map_err(|_| anyhow!("invalid hexadecimal string"))?,
    ))
}

fn key_from_hex(text: &str) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let bytes = decode(text)?;
    let key: [u8; KEY_LEN] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("key must be 32 bytes"))?;
    Ok(Zeroizing::new(key))
}

fn derive(password: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let params =
        Params::new(65536, 3, 1, Some(KEY_LEN)).map_err(|_| anyhow!("invalid KDF parameters"))?;
    let mut key = Zeroizing::new([0; KEY_LEN]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password, salt, key.as_mut())
        .map_err(|_| anyhow!("password derivation failed"))?;
    Ok(key)
}

fn cipher(key: &[u8; KEY_LEN]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(key.into())
}

fn wrap(key: &[u8; KEY_LEN], password: &[u8]) -> Result<Vec<u8>> {
    let salt = random::<SALT_LEN>()?;
    let nonce = random::<NONCE_LEN>()?;
    let wrapping_key = derive(password, &salt)?;
    let mut out = Vec::with_capacity(4 + SALT_LEN + NONCE_LEN + KEY_LEN + TAG_LEN);
    out.extend_from_slice(WRAP_HEADER);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    let encrypted = cipher(&wrapping_key)
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: key,
                aad: &out,
            },
        )
        .map_err(|_| anyhow!("key wrapping failed"))?;
    out.extend_from_slice(&encrypted);
    Ok(out)
}

fn unwrap(encoded: &[u8], password: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    const PREFIX: usize = 4 + SALT_LEN + NONCE_LEN;
    if encoded.len() != PREFIX + KEY_LEN + TAG_LEN || !encoded.starts_with(WRAP_HEADER) {
        return Err(anyhow!("invalid wrapped key encoding"));
    }
    let wrapping_key = derive(password, &encoded[4..4 + SALT_LEN])?;
    let plaintext = cipher(&wrapping_key)
        .decrypt(
            XNonce::from_slice(&encoded[4 + SALT_LEN..PREFIX]),
            Payload {
                msg: &encoded[PREFIX..],
                aad: &encoded[..PREFIX],
            },
        )
        .map_err(|_| anyhow!("key authentication failed"))?;
    Ok(Zeroizing::new(plaintext))
}

fn encrypt(key: &[u8; KEY_LEN], id: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let nonce = random::<NONCE_LEN>()?;
    let mut out = Vec::with_capacity(4 + NONCE_LEN + plaintext.len() + TAG_LEN);
    out.extend_from_slice(ITEM_HEADER);
    out.extend_from_slice(&nonce);
    let mut aad = Vec::with_capacity(out.len() + id.len());
    aad.extend_from_slice(&out);
    aad.extend_from_slice(id);
    let encrypted = cipher(key)
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow!("item encryption failed"))?;
    out.extend_from_slice(&encrypted);
    Ok(out)
}

fn decrypt(key: &[u8; KEY_LEN], id: &[u8], encoded: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    const PREFIX: usize = 4 + NONCE_LEN;
    if encoded.len() < PREFIX + TAG_LEN || !encoded.starts_with(ITEM_HEADER) {
        return Err(anyhow!("invalid encrypted item encoding"));
    }
    let mut aad = Vec::with_capacity(PREFIX + id.len());
    aad.extend_from_slice(&encoded[..PREFIX]);
    aad.extend_from_slice(id);
    let plaintext = cipher(key)
        .decrypt(
            XNonce::from_slice(&encoded[4..PREFIX]),
            Payload {
                msg: &encoded[PREFIX..],
                aad: &aad,
            },
        )
        .map_err(|_| anyhow!("item authentication failed"))?;
    Ok(Zeroizing::new(plaintext))
}

/// Return a newly generated 32-byte key encoded as hex.
#[defun]
fn random_key() -> Result<String> {
    Ok(hex::encode(Zeroizing::new(random::<KEY_LEN>()?)))
}

/// Wrap KEY-HEX using UTF-8 PASSWORD and return a versioned hex blob.
#[defun]
fn wrap_key(key_hex: String, password: String) -> Result<String> {
    let key_hex = Zeroizing::new(key_hex);
    let password = Zeroizing::new(password);
    Ok(hex::encode(wrap(
        &*key_from_hex(&key_hex)?,
        password.as_bytes(),
    )?))
}

/// Unwrap BLOB-HEX using UTF-8 PASSWORD and return the key as hex.
#[defun]
fn unwrap_key(blob_hex: String, password: String) -> Result<String> {
    let password = Zeroizing::new(password);
    Ok(hex::encode(unwrap(
        &decode(&blob_hex)?,
        password.as_bytes(),
    )?))
}

/// Encrypt PLAINTEXT-HEX with KEY-HEX, binding ID-HEX as associated data.
#[defun]
fn encrypt_item(key_hex: String, id_hex: String, plaintext_hex: String) -> Result<String> {
    let key_hex = Zeroizing::new(key_hex);
    let plaintext_hex = Zeroizing::new(plaintext_hex);
    Ok(hex::encode(encrypt(
        &*key_from_hex(&key_hex)?,
        &decode(&id_hex)?,
        &decode(&plaintext_hex)?,
    )?))
}

/// Authenticate and decrypt BLOB-HEX with KEY-HEX and ID-HEX.
#[defun]
fn decrypt_item(key_hex: String, id_hex: String, blob_hex: String) -> Result<String> {
    let key_hex = Zeroizing::new(key_hex);
    Ok(hex::encode(decrypt(
        &*key_from_hex(&key_hex)?,
        &decode(&id_hex)?,
        &decode(&blob_hex)?,
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_wrap_round_trip_and_tampering() {
        let key = [42; KEY_LEN];
        let blob = wrap(&key, b"password").unwrap();
        assert_eq!(unwrap(&blob, b"password").unwrap().as_slice(), key);
        assert!(unwrap(&blob, b"wrong").is_err());
        for i in 0..blob.len() {
            let mut bad = blob.clone();
            bad[i] ^= 1;
            assert!(unwrap(&bad, b"password").is_err(), "byte {i}");
        }
        assert!(unwrap(&blob[..blob.len() - 1], b"password").is_err());
        let mut extra = blob.clone();
        extra.push(0);
        assert!(unwrap(&extra, b"password").is_err());
    }

    #[test]
    fn item_round_trip_and_tampering() {
        let key = [7; KEY_LEN];
        for message in [&b""[..], &b"secret\0bytes"[..]] {
            let blob = encrypt(&key, b"id", message).unwrap();
            assert_eq!(decrypt(&key, b"id", &blob).unwrap().as_slice(), message);
            assert!(decrypt(&key, b"other", &blob).is_err());
            assert!(decrypt(&[8; KEY_LEN], b"id", &blob).is_err());
            for i in 0..blob.len() {
                let mut bad = blob.clone();
                bad[i] ^= 1;
                assert!(decrypt(&key, b"id", &bad).is_err(), "byte {i}");
            }
            assert!(decrypt(&key, b"id", &blob[..blob.len() - 1]).is_err());
            let mut extra = blob.clone();
            extra.push(0);
            assert!(decrypt(&key, b"id", &extra).is_err());
        }
    }

    #[test]
    fn boundary_and_randomness() {
        assert!(decode("xyz").is_err());
        assert!(decode("0").is_err());
        assert!(key_from_hex("00").is_err());
        assert_ne!(random::<KEY_LEN>().unwrap(), random::<KEY_LEN>().unwrap());
        let key = [1; KEY_LEN];
        assert_ne!(
            encrypt(&key, b"id", b"data").unwrap(),
            encrypt(&key, b"id", b"data").unwrap()
        );
    }
}
