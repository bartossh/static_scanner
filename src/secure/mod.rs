pub mod errors;

use core::str;
use std::{fs::File, io::Read};
use std::io::Write;
use hex::ToHex;
use std::path::PathBuf;
use errors::SecureError;
use openssl::{hash::{hash, MessageDigest}, pkey::{PKey, Private, Public}, rsa::Rsa, sign::Signer};

pub const RSA_KEY_SIZE: u32 = 4096;

/// Guard is responisble for security and  provides signature for DTO.
///
pub struct Guard {
    priv_key: PKey<Private>,
    pub_key: PKey<Public>,
}

#[inline(always)]
fn try_priv_key_form_pem(pem: &str) -> Result<PKey<Private>, SecureError> {
    Ok(PKey::from_rsa(Rsa::private_key_from_pem(pem.as_bytes())?)?)
}

#[inline(always)]
fn try_pub_key_form_pem(pem: &str) -> Result<PKey<Public>, SecureError> {
    Ok(PKey::from_rsa(Rsa::public_key_from_pem(pem.as_bytes())?)?)
}

impl Guard {
    /// Generates new private and public 4096 RSA key.
    ///
    #[inline(always)]
    pub fn generate() -> Result<Self, SecureError> {
        let priv_key = Rsa::generate(RSA_KEY_SIZE)?;
        Self::from_pem_str(&str::from_utf8(&priv_key.private_key_to_pem()?)?, &str::from_utf8(&priv_key.public_key_to_pem()?)?)
    }

    /// Reads private and public key from PEM files.
    /// If the private key is different size than 4096 bits then it is rejected.
    ///
    #[inline(always)]
    pub fn read_from_files(priv_key_path: &PathBuf, pub_key_path: &PathBuf) -> Result<Self, SecureError> {
        let mut priv_f = File::open(priv_key_path)?;
        let mut priv_pem = String::new();
        priv_f.read_to_string(&mut priv_pem)?;

        let mut pub_f = File::open(pub_key_path)?;
        let mut pub_pem = String::new();
        pub_f.read_to_string(&mut pub_pem)?;

        Self::from_pem_str(&priv_pem, &pub_pem)
    }

    /// Signs the buf of data returning a signature.
    ///
    #[inline(always)]
    pub fn sign(&self, buf: &[u8]) -> Result<Vec<u8>, SecureError> {
        let mut signer = Signer::new(MessageDigest::sha3_512(), &self.priv_key)?;
        signer.update(buf)?;
        Ok(signer.sign_to_vec()?)
    }

    /// Get public ke as pem string.
    ///
    #[inline(always)]
    pub fn get_pub_key_pem(&self) -> Result<String, SecureError> {
        Ok(str::from_utf8(&self.pub_key.public_key_to_pem()?)?.to_string())
    }

    /// Calculates public key hash.
    ///
    #[inline(always)]
    pub fn pub_key_hash(&self) -> Result<[u8;64], SecureError> {
        match secure_hash(&self.pub_key.public_key_to_pem()?)?.try_into() {
            Ok(v) => Ok(v),
            Err(e) => Err(SecureError::WithMessage(format!("{:?}", e)))
        }
    }

    /// Saves keys to files at given path.
    ///
    #[inline(always)]
    pub fn save_keys_to_files(&self, priv_path: &PathBuf, pub_path: &PathBuf) -> Result<(), SecureError> {
        let mut priv_f = File::create_new(priv_path)?;
        let mut pub_f = File::create_new(pub_path)?;
        priv_f.write_all(&self.priv_key.private_key_to_pem_pkcs8()?)?;
        pub_f.write_all(&self.pub_key.public_key_to_pem()?)?;
        Ok(())
    }

    /// Creates new signer from given pem private key.
    ///
    #[inline(always)]
    fn from_pem_str(priv_pem: &str, pub_pem: &str) -> Result<Self, SecureError> {
        let priv_key = try_priv_key_form_pem(priv_pem)?;
        let pub_key = try_pub_key_form_pem(pub_pem)?;
        if priv_key.bits() != RSA_KEY_SIZE {
            return Err(SecureError::WithMessage(format!("only {} bits long keys allowed, got {} bits", RSA_KEY_SIZE,  priv_key.bits())))
        }
        Ok(Self{ priv_key, pub_key })
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
