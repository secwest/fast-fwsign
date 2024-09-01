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
use openssl::ec::EcKey;
use openssl::ec::EcGroup;
use openssl::nid::Nid;
use openssl::sign::{Signer, Verifier};
use openssl::rand::rand_bytes;
use openssl::derive::Deriver;
use openssl::hash::MessageDigest;
use std::fs::File;
use std::io::{Read, Write, Seek, SeekFrom};
use std::process;


const CHUNK_SIZE: usize = 32768; // 32 KB chunk size
const NONCE_LEN: usize = 12; // Standard nonce length for ChaCha20-Poly1305
const MAX_SIG_LEN: usize = 256; // Maximum expected signature length

// Error handling function
fn handle_errors(message: &str) {
    eprintln!("Error: {}", message);
    process::exit(1);
}

// Function to print buffer content in hex for debugging
fn print_buffer_hex(label: &str, buf: &[u8]) {
    print!("{}: ", label);
    for byte in buf {
        print!("{:02x}", byte);
    }
    println!();
}

// Function to generate ECDSA keys and save them to files
fn keygen(private_key_file: &str, public_key_file: &str, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let ec_key = EcKey::generate(&group)?;
    let pkey = PKey::from_ec_key(ec_key)?;

    let cipher = Cipher::aes_256_cbc();
    let mut priv_file = File::create(private_key_file)?;
    let private_key_pem = pkey.private_key_to_pem_pkcs8_passphrase(cipher, password.as_bytes())?;
    priv_file.write_all(&private_key_pem)?;

    let mut pub_file = File::create(public_key_file)?;
    let public_key_pem = pkey.public_key_to_pem()?;
    pub_file.write_all(&public_key_pem)?;

    println!("Key pair generated and saved successfully.");
    Ok(())
}

// Function to derive a shared secret using ECDH
fn derive_shared_secret(priv_key: &EcKey<Private>, pub_key: &PKey<Public>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let pkey = PKey::from_ec_key(priv_key.to_owned())?;
    let mut derive_ctx = Deriver::new(&pkey)?;
    derive_ctx.set_peer(pub_key)?;
    Ok(derive_ctx.derive_to_vec()?)
}

// Function to encrypt a file using ChaCha20-Poly1305 and ECDH-derived shared secret
fn encrypt(input_file: &str, output_file: &str, private_key_file: &str, receiver_pubkey_file: &str, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut priv_file = File::open(private_key_file)?;
    let mut private_key_pem = Vec::new();
    priv_file.read_to_end(&mut private_key_pem)?;
    let priv_key = EcKey::private_key_from_pem_passphrase(&private_key_pem, password.as_bytes())?;

    let mut pub_file = File::open(receiver_pubkey_file)?;
    let mut public_key_pem = Vec::new();
    pub_file.read_to_end(&mut public_key_pem)?;
    let receiver_pubkey = PKey::public_key_from_pem(&public_key_pem)?;

    let shared_secret = derive_shared_secret(&priv_key, &receiver_pubkey)?;
    println!("Shared secret derived successfully.");
    print_buffer_hex("Shared secret", &shared_secret);

    let mut nonce = [0u8; NONCE_LEN];
    rand_bytes(&mut nonce)?;
    println!("Nonce generated successfully:");
    print_buffer_hex("Nonce", &nonce);

    let mut in_file = File::open(input_file)?;
    let mut out_file = File::create(output_file)?;

    out_file.write_all(&nonce)?;

    let cipher = Cipher::chacha20_poly1305();
    let mut crypter = Crypter::new(cipher, Mode::Encrypt, &shared_secret, Some(&nonce))?;
    crypter.pad(false);

    let mut chunk = vec![0u8; CHUNK_SIZE];
    let mut cipher_chunk = vec![0u8; CHUNK_SIZE + cipher.block_size()];
    let mut total_read = 0;

    loop {
        let len = in_file.read(&mut chunk)?;
        if len == 0 {
            break;
        }

        total_read += len;
        let count = crypter.update(&chunk[..len], &mut cipher_chunk)?;
        out_file.write_all(&cipher_chunk[..count])?;
        print!(".");
        std::io::stdout().flush().unwrap();
    }

    let count = crypter.finalize(&mut cipher_chunk)?;
    out_file.write_all(&cipher_chunk[..count])?;
    println!("\nEncryption completed successfully. Total bytes read: {}", total_read);

    let pkey = PKey::from_ec_key(priv_key)?;
    let mut md_ctx = Signer::new(MessageDigest::sha256(), &pkey)?;
    out_file.seek(SeekFrom::Start(NONCE_LEN as u64))?;
    let mut buffer = vec![0u8; CHUNK_SIZE];
    loop {
        let read_len = out_file.read(&mut buffer)?;
        if read_len == 0 {
            break;
        }
        md_ctx.update(&buffer[..read_len])?;
    }

    let sig = md_ctx.sign_to_vec()?;
    let sig_len_net = (sig.len() as u32).to_be_bytes(); // Convert to network byte order
    out_file.write_all(&sig)?;
    out_file.write_all(&sig_len_net)?;

    println!("Signature generated, length: {} bytes.", sig.len());
    print_buffer_hex("Generated signature", &sig);
    println!("File encrypted and signed successfully.");
    Ok(())
}

// Function to decrypt a file using ChaCha20-Poly1305 and ECDH-derived shared secret
fn decrypt(input_file: &str, output_file: &str, private_key_file: &str, sender_pubkey_file: &str, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut priv_file = File::open(private_key_file)?;
    let mut private_key_pem = Vec::new();
    priv_file.read_to_end(&mut private_key_pem)?;
    let priv_key = EcKey::private_key_from_pem_passphrase(&private_key_pem, password.as_bytes())?;

    let mut pub_file = File::open(sender_pubkey_file)?;
    let mut public_key_pem = Vec::new();
    pub_file.read_to_end(&mut public_key_pem)?;
    let sender_pubkey = PKey::public_key_from_pem(&public_key_pem)?;

    let shared_secret = derive_shared_secret(&priv_key, &sender_pubkey)?;
    println!("Shared secret derived successfully.");
    print_buffer_hex("Shared secret", &shared_secret);

    let mut in_file = File::open(input_file)?;
    let mut out_file = File::create(output_file)?;

    let mut nonce = [0u8; NONCE_LEN];
    in_file.read_exact(&mut nonce)?;
    println!("Nonce read:");
    print_buffer_hex("Nonce", &nonce);

    let file_size = in_file.metadata()?.len();
    let sig_len = {
        let mut buf = [0u8; 4];
        in_file.seek(SeekFrom::End(-4))?;
        in_file.read_exact(&mut buf)?;
        u32::from_be_bytes(buf) as usize // Convert from network byte order
    };

    println!("Read signature length: {}", sig_len);
    if sig_len == 0 || sig_len > MAX_SIG_LEN {
        handle_errors("Invalid signature length detected");
    }

    in_file.seek(SeekFrom::End(-(sig_len as i64 + 4)))?;
    let mut sig = vec![0u8; sig_len];
    in_file.read_exact(&mut sig)?;
    print_buffer_hex("Signature", &sig);

    let ciphertext_len = file_size as usize - NONCE_LEN - sig_len - 4;
    if ciphertext_len <= 0 {
        handle_errors("Invalid ciphertext length calculated");
    }

    println!("File size: {}, Ciphertext length: {}, Signature length: {}", file_size, ciphertext_len, sig_len);

    in_file.seek(SeekFrom::Start(NONCE_LEN as u64))?;
    let cipher = Cipher::chacha20_poly1305();
    let mut crypter = Crypter::new(cipher, Mode::Decrypt, &shared_secret, Some(&nonce))?;
    crypter.pad(false);

    let mut chunk = vec![0u8; CHUNK_SIZE];
    let mut plain_chunk = vec![0u8; CHUNK_SIZE + cipher.block_size()];
    let mut total_read = 0;

    while total_read < ciphertext_len {
        let len = in_file.read(&mut chunk)?;
        if len == 0 {
            break;
        }

        total_read += len;
        let count = crypter.update(&chunk[..len], &mut plain_chunk)?;
        out_file.write_all(&plain_chunk[..count])?;
        print!(".");
        std::io::stdout().flush().unwrap();
    }

    let count = crypter.finalize(&mut plain_chunk)?;
    out_file.write_all(&plain_chunk[..count])?;
    println!("\nDecryption completed successfully. Total bytes processed: {}", total_read);

    let mut md_ctx = Verifier::new(MessageDigest::sha256(), &sender_pubkey)?;
    out_file.seek(SeekFrom::Start(0))?;
    let mut buffer = vec![0u8; CHUNK_SIZE];
    loop {
        let read_len = out_file.read(&mut buffer)?;
        if read_len == 0 {
            break;
        }
        md_ctx.update(&buffer[..read_len])?;
    }

    if md_ctx.verify(&sig)? {
        println!("Signature verification successful.");
    } else {
        handle_errors("Failed to verify signature");
    }

    println!("File decrypted and verified successfully.");
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
