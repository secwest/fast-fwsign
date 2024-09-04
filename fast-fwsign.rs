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

/ fast-fwsign: A utility for generating ECDSA keys, encrypting, and decrypting files
// with ChaCha20-Poly1305 and ECDSA signatures.
//
// Build and Setup Instructions:
// ------------------------------
// This program is written in Rust and uses Cargo as its package manager. Follow these steps
// to set up and build the project. Ensure you have Rust (at least version 1.56.0) and Cargo installed.
//
// 1. Install Rust and Cargo:
//    If Rust and Cargo are not installed, you can install them using the official installation script:
//        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
//    Follow the on-screen instructions to complete the installation. Verify the installation with:
//        rustc --version
//
// 2. Install OpenSSL Development Libraries:
//    This project depends on OpenSSL for cryptographic functions. Install OpenSSL development libraries.
//    On Debian-based systems, you can install them using:
//        sudo apt-get install libssl-dev
//    For other operating systems, use the appropriate package manager to install OpenSSL development libraries.
//
// 3. Create a New Rust Project:
//    Choose a directory where you want to create your Rust project. Open a terminal and run:
//        mkdir fast-fwsign
//        cd fast-fwsign
//    This creates a directory named `fast-fwsign` and navigates into it.
//
//    Initialize a new Rust project using Cargo:
//        cargo init
//    This command creates a basic Rust project structure with a `Cargo.toml` file and a `src` directory.
//
// 4. Configure Cargo.toml File:
//    Open the `Cargo.toml` file in your preferred text editor and add the following content:
//    
//        [package]
//        name = "fast-fwsign"
//        version = "0.1.0"
//        authors = ["Dragos Ruiu <dr@secwest.net>"]
//        edition = "2021"
//
//        [dependencies]
//        openssl = { version = "0.10", features = ["vendored"] }
//    
//    This configuration specifies the package information and the dependencies required for the project.
//
// 5. Write the Rust Code:
//    Replace the contents of `src/main.rs` with the provided Rust code, including the updated version
//    with comments and explanations. Use a text editor to open `src/main.rs` and paste the full code.
//
// 6. Compile and Build the Project:
//    To compile the project and generate the binary, run the following command:
//        cargo build --release
//    This will build the project in release mode, creating an optimized binary located in the `target/release` directory.
//
// 7. Running the Program:
//    Once the project is built, you can run the program using the generated binary. Below are examples:
//
//    - Key Generation:
//        ./target/release/fast-fwsign keygen priv.key pub.key mypassword
//        This command generates a private key (`priv.key`) and a public key (`pub.key`) with `mypassword` as the private key password.
//
//    - Encryption:
//        ./target/release/fast-fwsign encrypt firmware.bin firmware.crypt priv.key receiver_pub.key mypassword
//        Replace `firmware.bin` with the input file to encrypt, `firmware.crypt` as the output file, and use the appropriate key files.
//
//    - Decryption:
//        ./target/release/fast-fwsign decrypt firmware.crypt firmware.dec priv.key sender.pub.key mypassword
//        Replace `firmware.crypt` with the encrypted file, `firmware.dec` with the output file, and use the appropriate key files.
//
// 8. Troubleshooting and Tips:
//    - If you encounter issues with OpenSSL during compilation, ensure that OpenSSL is correctly installed and accessible.
//      You might need to set environment variables like `OPENSSL_DIR` to point to your OpenSSL installation.
//    - Use `cargo clean` if you need to clean the project and rebuild it from scratch.
//    - Refer to Rust documentation and OpenSSL crate documentation for more advanced usage and configurations.
//
use openssl::ec::{EcGroup, EcKey};
use openssl::pkey::PKey;
use openssl::rand::rand_bytes;
use openssl::sign::{Signer, Verifier};
use openssl::symm::{decrypt, encrypt, Cipher};
use std::fs::File;
use std::io::{self, Read, Write, Seek, SeekFrom};
use std::process::exit;
use std::env;

const CHUNK_SIZE: usize = 32768; // Define a larger chunk size (32k) for processing
const NONCE_SIZE: usize = 12;    // Nonce size for ChaCha20-Poly1305

// Error handling function
fn handle_errors(message: &str) {
    eprintln!("Error: {}", message);
    exit(1);
}

// Print buffer content in hex for debugging
fn print_buffer_hex(label: &str, buf: &[u8]) {
    print!("{}: ", label);
    for byte in buf {
        print!("{:02x}", byte);
    }
    println!();
}

// Function to generate ECDSA keys and save to files
fn keygen(private_key_file: &str, public_key_file: &str, password: &str) -> Result<(), io::Error> {
    // ECDSA (Elliptic Curve Digital Signature Algorithm):
    // Purpose: Provides digital signatures for verifying data integrity and authenticity.
    // Reason for Selection: ECDSA offers a high level of security with shorter key sizes compared to traditional algorithms like RSA.
    // Security: ECDSA is resistant to attacks that exploit key size. A 256-bit ECDSA key offers comparable security to a 3072-bit RSA key.

    let group = EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
    let key = EcKey::generate(&group).unwrap();

    // Save private key with password protection using AES-256-CBC
    // AES-256-CBC:
    // Purpose: Used for encrypting private keys with a password.
    // Security: AES-256 provides robust protection against brute-force attacks due to its large key size.
    let private_key_pem = key.private_key_to_pem_passphrase(openssl::symm::Cipher::aes_256_cbc(), password.as_bytes()).unwrap();
    let mut priv_file = File::create(private_key_file)?;
    priv_file.write_all(&private_key_pem)?;

    // Save public key
    let public_key_pem = key.public_key_to_pem().unwrap();
    let mut pub_file = File::create(public_key_file)?;
    pub_file.write_all(&public_key_pem)?;

    println!("Key pair generated and saved successfully.");
    Ok(())
}

// Function to encrypt a file using ChaCha20-Poly1305 and ECDH
fn encrypt_file(input_file: &str, output_file: &str, private_key_file: &str, receiver_pubkey_file: &str, password: &str) -> Result<(), io::Error> {
    // Load sender's private key
    let priv_key = EcKey::private_key_from_pem_passphrase(&std::fs::read(private_key_file)?, password.as_bytes()).unwrap();
    let receiver_pub_key = EcKey::public_key_from_pem(&std::fs::read(receiver_pubkey_file)?).unwrap();

    let sender_pkey = PKey::from_ec_key(priv_key).unwrap();
    let receiver_pkey = PKey::from_ec_key(receiver_pub_key).unwrap();

    // Derive shared secret using ECDH (Elliptic Curve Diffie-Hellman)
    // ECDH (Elliptic Curve Diffie-Hellman):
    // Purpose: Used for key exchange to securely derive a shared secret between parties.
    // Reason for Selection: ECDH provides secure key exchange based on elliptic curves, enabling the establishment of a shared secret key without direct transmission.
    // Security: ECDH offers strong security against eavesdropping and man-in-the-middle attacks.
    let mut derive_ctx = openssl::derive::Deriver::new(&sender_pkey).unwrap();
    derive_ctx.set_peer(&receiver_pkey).unwrap();
    let shared_secret = derive_ctx.derive_to_vec().unwrap();

    println!("Shared secret derived successfully.");
    print_buffer_hex("Shared secret", &shared_secret);

    // Generate random nonce for ChaCha20-Poly1305 encryption
    // ChaCha20-Poly1305:
    // Purpose: Provides authenticated encryption (confidentiality and integrity).
    // Reason for Selection: ChaCha20-Poly1305 is a modern, high-performance authenticated encryption algorithm.
    // Security: ChaCha20-Poly1305 is secure against a wide range of cryptographic attacks, including differential cryptanalysis and side-channel attacks.
    let mut nonce = [0u8; NONCE_SIZE];
    rand_bytes(&mut nonce).unwrap();

    println!("Nonce generated successfully:");
    print_buffer_hex("Nonce", &nonce);

    let mut in_file = File::open(input_file)?;
    let mut out_file = File::create(output_file)?;
    out_file.write_all(&nonce)?;

    let cipher = Cipher::chacha20_poly1305();
    let mut chunk = vec![0u8; CHUNK_SIZE];

    // Initialize signing context for ECDSA signature
    let mut md_ctx = Signer::new(openssl::hash::MessageDigest::sha256(), &sender_pkey).unwrap();
    let mut total_read = 0;

    // Process the input file in chunks
    loop {
        let len = in_file.read(&mut chunk)?;
        if len == 0 { break; }
        total_read += len;

        let ciphertext = encrypt(cipher, &shared_secret, Some(&nonce), &chunk[..len]).unwrap();
        out_file.write_all(&ciphertext)?;

        md_ctx.update(&ciphertext).unwrap();
        print!("."); // Print a period for each block processed
        io::stdout().flush().unwrap();
    }

    println!("\nEncryption completed successfully. Total bytes read: {}", total_read);

    // Generate and append the ECDSA signature to the output file
    let signature = md_ctx.sign_to_vec().unwrap();
    println!("Generated signature:");
    print_buffer_hex("Generated signature", &signature);

    out_file.write_all(&signature)?;
    out_file.write_all(&(signature.len() as u32).to_be_bytes())?;

    println!("File encrypted and signed successfully.");
    Ok(())
}

// Function to decrypt a file using ChaCha20-Poly1305 and ECDH
fn decrypt_file(input_file: &str, output_file: &str, private_key_file: &str, sender_pubkey_file: &str, password: &str) -> Result<(), io::Error> {
    // Load receiver's private key
    let priv_key = EcKey::private_key_from_pem_passphrase(&std::fs::read(private_key_file)?, password.as_bytes()).unwrap();
    let sender_pub_key = EcKey::public_key_from_pem(&std::fs::read(sender_pubkey_file)?).unwrap();

    let receiver_pkey = PKey::from_ec_key(priv_key).unwrap();
    let sender_pkey = PKey::from_ec_key(sender_pub_key).unwrap();

    // Derive shared secret using ECDH
    let mut derive_ctx = openssl::derive::Deriver::new(&receiver_pkey).unwrap();
    derive_ctx.set_peer(&sender_pkey).unwrap();
    let shared_secret = derive_ctx.derive_to_vec().unwrap();

    println!("Shared secret derived successfully.");
    print_buffer_hex("Shared secret", &shared_secret);

    // Open input and output files
    let mut in_file = File::open(input_file)?;
    let mut out_file = File::create(output_file)?;

    // Read nonce from input file
    let mut nonce = [0u8; NONCE_SIZE];
    in_file.read_exact(&mut nonce)?;

    println!("Nonce read:");
    print_buffer_hex("Nonce", &nonce);

    // Get file size and calculate signature length
    let file_size = in_file.seek(SeekFrom::End(0))?;
    let sig_len_offset = file_size - 4;
    in_file.seek(SeekFrom::Start(sig_len_offset))?;

    let mut sig_len_buf = [0u8; 4];
    in_file.read_exact(&mut sig_len_buf)?;
    let sig_len = u32::from_be_bytes(sig_len_buf) as usize;

    let sig_start = sig_len_offset - sig_len as u64;
    in_file.seek(SeekFrom::Start(sig_start))?;
    let mut signature = vec![0u8; sig_len];
    in_file.read_exact(&mut signature)?;

    println!("Read signature:");
    print_buffer_hex("Signature", &signature);

    let ciphertext_len = sig_start as usize - NONCE_SIZE;

    println!("File size: {}, Ciphertext length: {}, Signature length: {}", file_size, ciphertext_len, sig_len);

    in_file.seek(SeekFrom::Start(NONCE_SIZE as u64))?;

    let cipher = Cipher::chacha20_poly1305();
    let mut chunk = vec![0u8; CHUNK_SIZE];

    // Initialize verification context for ECDSA signature
    let mut md_ctx = Verifier::new(openssl::hash::MessageDigest::sha256(), &sender_pkey).unwrap();
    let mut total_read = 0;

    // Process the input file in chunks
    loop {
        let len = in_file.read(&mut chunk)?;
        if len == 0 { break; }
        let remaining = ciphertext_len - total_read;
        let len_to_read = if len > remaining { remaining } else { len };

        let ciphertext_chunk = &chunk[..len_to_read];
        let plaintext = decrypt(cipher, &shared_secret, Some(&nonce), ciphertext_chunk).unwrap();

        out_file.write_all(&plaintext)?;
        md_ctx.update(ciphertext_chunk).unwrap();

        total_read += len_to_read;
        if total_read >= ciphertext_len {
            break;
        }

        print!("."); // Print a period for each block processed
        io::stdout().flush().unwrap();
    }

    println!("\nDecryption completed successfully. Total bytes processed: {}", total_read);

    // Verify the signature
    println!("Verifying signature against the computed hash...");
    if md_ctx.verify(&signature).is_err() {
        eprintln!("Failed to verify signature.");
        exit(1);
    }

    println!("Signature verification successful.");
    println!("File decrypted and verified successfully.");
    Ok(())
}

// Main function to handle command-line arguments
fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <command> [arguments...]", args[0]);
        eprintln!("Commands:");
        eprintln!("  keygen <private_key_file> <public_key_file> <password>");
        eprintln!("  encrypt <input_file> <output_file> <private_key_file> <receiver_pubkey_file> <password>");
        eprintln!("  decrypt <input_file> <output_file> <private_key_file> <sender_pubkey_file> <password>");
        exit(1);
    }

    match args[1].as_str() {
        "keygen" if args.len() == 5 => {
            keygen(&args[2], &args[3], &args[4]).unwrap_or_else(|e| handle_errors(&e.to_string()));
        }
        "encrypt" if args.len() == 7 => {
            encrypt_file(&args[2], &args[3], &args[4], &args[5], &args[6]).unwrap_or_else(|e| handle_errors(&e.to_string()));
        }
        "decrypt" if args.len() == 7 => {
            decrypt_file(&args[2], &args[3], &args[4], &args[5], &args[6]).unwrap_or_else(|e| handle_errors(&e.to_string()));
        }
        _ => {
            eprintln!("Invalid command or arguments.");
            exit(1);
        }
    }
}
