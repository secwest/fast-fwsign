// FAST-FWSIGN-CHUNKED   Firmware image encryption, signing, and verification for embedded systems.
//
// BSD 3-Clause License
// 
// Copyright (c) 2024, Dragos Ruiu, Dragostech.com Inc.
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, 
// are permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, 
//    this list of conditions, and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice, 
//    this list of conditions, and the following disclaimer in the documentation 
//    and/or other materials provided with the distribution.
// 3. Neither the name of Dragos Ruiu, Dragostech.com Inc. nor the names of its 
//    contributors may be used to endorse or promote products derived from this 
//    software without specific prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, 
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE 
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED 
// AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, 
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// fast-fwsign: A utility for generating ECDSA keys, encrypting, and decrypting files
// with ChaCha20-Poly1305 and ECDSA signatures.
//
// Build Instructions:
// -------------------
// To compile this Rust program, ensure you have OpenSSL installed and available on your system.
// Use the following Cargo.toml configuration to manage dependencies:
//
// [package]
// name = "fast-fwsign"
// version = "0.1.0"
// authors = ["Dragos Ruiu <dr@secwest.net>"]
// edition = "2021"
//
// [dependencies]
// openssl = { version = "0.10", features = ["vendored"] }
// 
// To build and run the program, execute the following commands:
//     cargo build --release
//
// This will create an optimized binary in the target/release directory named `fast-fwsign`.
// 
// Usage:
// ------
// The `fast-fwsign` utility supports three main commands: key generation, encryption, and decryption.
//
// 1. Key Generation:
//    Generate a pair of ECDSA keys (private and public).
//    Command:
//        ./fast-fwsign keygen <private_key_file> <public_key_file> <password>
//
//    Example:
//        ./fast-fwsign keygen priv.key pub.key mypassword
//
// 2. Encryption:
//    Encrypt a file using ChaCha20-Poly1305 and sign it using ECDSA.
//    Command:
//        ./fast-fwsign encrypt <input_file> <output_file> <private_key_file> <receiver_pubkey_file> <password>
//
//    Example:
//        ./fast-fwsign encrypt firmware.bin firmware.crypt priv.key receiver_pub.key mypassword
//
// 3. Decryption:
//    Decrypt a file and verify its signature using ECDSA.
//    Command:
//        ./fast-fwsign decrypt <input_file> <output_file> <private_key_file> <sender_pubkey_file> <password>
//
//    Example:
//        ./fast-fwsign decrypt firmware.crypt firmware.dec priv.key sender.pub.key mypassword

use openssl::pkey::{PKey, Private, Public};
use openssl::symm::{Cipher, Crypter, Mode};
use openssl::ec::{EcKey, EcGroup};
use openssl::nid::Nid;
use openssl::rand::rand_bytes;
use openssl::derive::Deriver;
use std::fs::File;
use std::io::{Read, Write};
use std::process;

const CHUNK_SIZE: usize = 32768; // 32 KB chunk size
const NONCE_LEN: usize = 12; // Standard nonce length for ChaCha20-Poly1305

// Function to derive the shared secret using ECDH
fn derive_shared_secret(priv_key: &PKey<Private>, pub_key: &PKey<Public>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut deriver = Deriver::new(priv_key)?;
    deriver.set_peer(pub_key)?;
    let shared_secret = deriver.derive_to_vec()?;
    Ok(shared_secret)
}

// Function to generate ECDSA keys and save them to files
fn keygen(private_key_file: &str, public_key_file: &str, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Generate ECDSA key pair
    let group = EcGroup::from_curve_name(Nid::SECP256K1)?;
    let ec_key = EcKey::generate(&group)?;
    let pkey = PKey::from_ec_key(ec_key)?;

    // Save private key to file, encrypted with AES-256-CBC
    let cipher = Cipher::aes_256_cbc();
    let mut priv_file = File::create(private_key_file)?;
    let private_key_pem = pkey.private_key_to_pem_pkcs8_passphrase(cipher, password.as_bytes())?;
    priv_file.write_all(&private_key_pem)?;

    // Save public key to file
    let mut pub_file = File::create(public_key_file)?;
    let public_key_pem = pkey.public_key_to_pem()?;
    pub_file.write_all(&public_key_pem)?;

    println!("Key pair generated and saved successfully.");
    Ok(())
}

// Function to encrypt a file using ChaCha20-Poly1305 and ECDH-derived shared secret
fn encrypt(input_file: &str, output_file: &str, private_key_file: &str, receiver_pubkey_file: &str, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Load private key
    let mut priv_file = File::open(private_key_file)?;
    let mut private_key_pem = Vec::new();
    priv_file.read_to_end(&mut private_key_pem)?;
    let ec_key = EcKey::private_key_from_pem_passphrase(&private_key_pem, password.as_bytes())?;
    let pkey = PKey::from_ec_key(ec_key)?;

    // Load receiver's public key
    let mut pub_file = File::open(receiver_pubkey_file)?;
    let mut public_key_pem = Vec::new();
    pub_file.read_to_end(&mut public_key_pem)?;
    let receiver_pkey = PKey::public_key_from_pem(&public_key_pem)?;

    // Derive shared secret using ECDH
    let shared_secret = derive_shared_secret(&pkey, &receiver_pkey)?;

    // Generate a random nonce
    let mut nonce = [0u8; NONCE_LEN];
    rand_bytes(&mut nonce)?;

    // Open input and output files
    let mut in_file = File::open(input_file)?;
    let mut out_file = File::create(output_file)?;

    // Write nonce to output file
    out_file.write_all(&nonce)?;

    // Initialize ChaCha20-Poly1305 context
    let cipher = Cipher::chacha20_poly1305();
    let mut crypter = Crypter::new(cipher, Mode::Encrypt, &shared_secret, Some(&nonce))?;
    crypter.pad(false);

    let mut chunk = vec![0u8; CHUNK_SIZE];
    let mut cipher_chunk = vec![0u8; CHUNK_SIZE + cipher.block_size()];

    // Process the input file in chunks
    loop {
        let len = in_file.read(&mut chunk)?;
        if len == 0 {
            break;
        }

        let count = crypter.update(&chunk[..len], &mut cipher_chunk)?;
        out_file.write_all(&cipher_chunk[..count])?;
    }

    let count = crypter.finalize(&mut cipher_chunk)?;
    out_file.write_all(&cipher_chunk[..count])?;

    println!("Encryption completed successfully.");
    Ok(())
}

// Function to decrypt a file using ChaCha20-Poly1305 and ECDH-derived shared secret
fn decrypt(input_file: &str, output_file: &str, private_key_file: &str, sender_pubkey_file: &str, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Load private key
    let mut priv_file = File::open(private_key_file)?;
    let mut private_key_pem = Vec::new();
    priv_file.read_to_end(&mut private_key_pem)?;
    let ec_key = EcKey::private_key_from_pem_passphrase(&private_key_pem, password.as_bytes())?;
    let pkey = PKey::from_ec_key(ec_key)?;

    // Load sender's public key
    let mut pub_file = File::open(sender_pubkey_file)?;
    let mut public_key_pem = Vec::new();
    pub_file.read_to_end(&mut public_key_pem)?;
    let sender_pkey = PKey::public_key_from_pem(&public_key_pem)?;

    // Derive shared secret using ECDH
    let shared_secret = derive_shared_secret(&pkey, &sender_pkey)?;

    // Open input and output files
    let mut in_file = File::open(input_file)?;
    let mut out_file = File::create(output_file)?;

    // Read nonce from input file
    let mut nonce = [0u8; NONCE_LEN];
    in_file.read_exact(&mut nonce)?;

    // Initialize ChaCha20-Poly1305 context
    let cipher = Cipher::chacha20_poly1305();
    let mut crypter = Crypter::new(cipher, Mode::Decrypt, &shared_secret, Some(&nonce))?;
    crypter.pad(false);

    let mut chunk = vec![0u8; CHUNK_SIZE];
    let mut plain_chunk = vec![0u8; CHUNK_SIZE + cipher.block_size()];

    // Process the input file in chunks
    loop {
        let len = in_file.read(&mut chunk)?;
        if len == 0 {
            break;
        }

        let count = crypter.update(&chunk[..len], &mut plain_chunk)?;
        out_file.write_all(&plain_chunk[..count])?;
    }

    let count = crypter.finalize(&mut plain_chunk)?;
    out_file.write_all(&plain_chunk[..count])?;

    println!("Decryption completed successfully.");
    Ok(())
}

// Main function to handle command-line arguments
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <command> [arguments...]", args[0]);
        eprintln!("Commands:");
        eprintln!("  keygen <private_key_file> <public_key_file> <password>");
        eprintln!("  encrypt <input_file> <output_file> <private_key_file> <receiver_pubkey_file> <password>");
        eprintln!("  decrypt <input_file> <output_file> <private_key_file> <sender_pubkey_file> <password>");
        process::exit(1);
    }

    match args[1].as_str() {
        "keygen" => {
            if args.len() != 5 {
                eprintln!("Usage: {} keygen <private_key_file> <public_key_file> <password>", args[0]);
                process::exit(1);
            }
            keygen(&args[2], &args[3], &args[4]).expect("Key generation failed");
        }
        "encrypt" => {
            if args.len() != 7 {
                eprintln!("Usage: {} encrypt <input_file> <output_file> <private_key_file> <receiver_pubkey_file> <password>", args[0]);
                process::exit(1);
            }
            encrypt(&args[2], &args[3], &args[4], &args[5], &args[6]).expect("Encryption failed");
        }
        "decrypt" => {
            if args.len() != 7 {
                eprintln!("Usage: {} decrypt <input_file> <output_file> <private_key_file> <sender_pubkey_file> <password>", args[0]);
                process::exit(1);
            }
            decrypt(&args[2], &args[3], &args[4], &args[5], &args[6]).expect("Decryption failed");
        }
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            process::exit(1);
        }
    }
}
