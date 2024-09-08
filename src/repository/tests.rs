use crate::secure::Guard;

use super::*;
use core::str;
use std::fs::read;
use openssl::rsa::Rsa;

const RSA_KEY_SIZE: u32 = 4096;

#[test]
#[cfg_attr(not(feature = "remote"), ignore)]
fn it_should_make_a_succesfull_request() {
    let Ok(cert) = read("./certs/ca-cert.pem") else {
        assert!(false);
        return;
    };
    let Ok(agent) = Http2Agent::new("https://127.0.0.1:8080".to_string(), &cert) else {
        assert!(false);
        return;
    };

    match agent.get_healthz() {
        Ok(()) => assert!(true),
        Err(e) => {
            println!("{:?}", e);
            assert!(false);
        }
    };
}

#[test]
#[cfg_attr(not(feature = "remote"), ignore)]
fn it_should_create_a_new_account() {
    let Ok(cert) = read("./certs/ca-cert.pem") else {
        assert!(false);
        return;
    };
    let Ok(agent) = Http2Agent::new("https://127.0.0.1:8080".to_string(), &cert) else {
        assert!(false);
        return;
    };

    let Ok(rsa) = Rsa::generate(RSA_KEY_SIZE) else {
        assert!(false);
        return;
    };

    let Ok(pem_priv) = rsa.private_key_to_pem() else {
        assert!(false);
        return;
    };

    let Ok(pem_priv_str) = str::from_utf8(&pem_priv) else {
        assert!(false);
        return;
    };

    let Ok(guard) = Guard::new(&pem_priv_str) else {
        assert!(false);
        return;
    };

    let Ok(pem_pub) = rsa.public_key_to_pem() else {
        assert!(false);
        return;
    };

    let Ok(pem_pub_str) = str::from_utf8(&pem_pub) else {
        assert!(false);
        return;
    };


    let Ok(signature) = guard.sign(&pem_pub) else {
        assert!(false);
        return;
    };

    let Ok(signature) = signature.try_into() else {
        assert!(false);
        return;
    };

    let create_account = CreateAccountDto {
        public_pem_key: pem_pub_str.to_string(),
        signature,
    };

    match agent.create_account(&create_account) {
        Ok(()) => assert!(true),
        Err(e) => {
            println!("{:?}", e);
            assert!(false);
        }
    };
}
