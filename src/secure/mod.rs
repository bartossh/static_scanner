pub mod errors;

use hex::ToHex;
use errors::SecureError;
use openssl::{hash::{hash, MessageDigest}, pkey::{PKey, Private}, rsa::Rsa, sign::Signer};


/// Guard is responisble for security and  provides signature for DTO.
///
pub struct Guard {
    pkey: PKey<Private>,
}

#[inline(always)]
fn try_pkey_form_pem(pem: &str) -> Result<PKey<Private>, SecureError> {
    Ok(PKey::from_rsa(Rsa::private_key_from_pem(pem.as_bytes())?)?)
}

impl Guard {
    /// Creates new signer from given pem private key.
    ///
    #[inline(always)]
    pub fn new(pem: &str) -> Result<Self, SecureError> {
        let pkey = try_pkey_form_pem(pem)?;
        Ok(Self{ pkey })
    }

    /// Signs the buf of data returning a signature.
    ///
    #[inline(always)]
    pub fn sign(&self, buf: &[u8]) -> Result<Vec<u8>, SecureError> {
        let mut signer = Signer::new(MessageDigest::sha3_512(), &self.pkey)?;
        signer.update(buf)?;
        Ok(signer.sign_to_vec()?)
    }
}

/// Calculates secure hash using sha3-256.
///
#[inline(always)]
pub fn secure_hash(data: &[u8]) -> Result<Vec<u8>, SecureError> {
    Ok(hash(MessageDigest::sha3_512(), data)?.to_vec())
}

/// Converts bytes to hex string.
///
#[inline(always)]
pub fn to_hex_str(data: &[u8]) -> String {
    data.encode_hex::<String>()
}
