/*
 * FAST-FWSIGN-CHUNKED   Firmware image encryption, signing, and verification for embedded systems.
 *
 * BSD 3-Clause License
 * 
 * Copyright (c) 2024, Dragos Ruiu, Dragostech.com Inc.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without modification, 
 * are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, 
 *    this list of conditions, and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, 
 *    this list of conditions, and the following disclaimer in the documentation 
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of Dragos Ruiu, Dragostech.com Inc. nor the names of its 
 *    contributors may be used to endorse or promote products derived from this 
 *    software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, 
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE 
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED 
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, 
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * fast-fwsign: A utility for generating ECDSA keys, encrypting, and decrypting files
 * with ChaCha20-Poly1305 and ECDSA signatures.
 *
 * Compilation Instructions:
 * -------------------------
 * To compile this utility, ensure that the OpenSSL development libraries are installed.
 *
 * For Debian/Ubuntu:
 *     sudo apt-get install libssl-dev
 *
 * For Red Hat/CentOS:
 *     sudo yum install openssl-devel
 *
 * For macOS (using Homebrew):
 *     brew install openssl
 *
 * For Windows: Use a package manager like vcpkg or download OpenSSL binaries and configure the paths.
 *
 * Compile the code using gcc:
 *     gcc -o fast-fwsign fast-fwsign.c -lssl -lcrypto
 *
 * Usage:
 * ------
 * The `fast-fwsign` utility supports three main commands: key generation, encryption, and decryption.
 *
 * 1. Key Generation:
 *    Generate a pair of ECDSA keys (private and public).
 *    Command:
 *        ./fast-fwsign keygen <private_key_file> <public_key_file> <password>
 *
 *    Example:
 *        ./fast-fwsign keygen priv.key pub.key mypassword
 *
 * 2. Encryption:
 *    Encrypt a file using ChaCha20-Poly1305 and sign it using ECDSA.
 *    Command:
 *        ./fast-fwsign encrypt <input_file> <output_file> <private_key_file> <receiver_pubkey_file> <password>
 *
 *    Example:
 *        ./fast-fwsign encrypt firmware.bin firmware.crypt priv.key receiver_pub.key mypassword
 *
 * 3. Decryption:
 *    Decrypt a file and verify its signature using ECDSA.
 *    Command:
 *        ./fast-fwsign decrypt <input_file> <output_file> <private_key_file> <sender_pubkey_file> <password>
 *
 *    Example:
 *        ./fast-fwsign decrypt firmware.crypt firmware.dec priv.key sender_pub.key mypassword
 *
 * Notes:
 * ------
 * - Ensure private keys are stored securely and use strong, unique passwords.
 * - Each encryption operation uses a random nonce to ensure unique ciphertexts.
 * - Verify signatures after decryption to maintain data integrity and authenticity.
 */

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>  // For fixed-size integer types
#include <arpa/inet.h>  // For htonl and ntohl

#define CHUNK_SIZE 32768  // Define a larger chunk size (32k) for processing

// Error handling function
void handle_errors(const char *message) {
    fprintf(stderr, "Error: %s\n", message);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

// Print buffer content in hex for debugging
void print_buffer_hex(const char *label, const unsigned char *buf, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

// Function to generate ECDSA keys and save to files
void keygen(const char *private_key_file, const char *public_key_file, const char *password) {
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    FILE *priv_file = NULL, *pub_file = NULL;

    // Create a context for key generation
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pctx) handle_errors("Failed to create EVP_PKEY_CTX");

    // Initialize key generation context
    if (EVP_PKEY_keygen_init(pctx) <= 0) handle_errors("Failed to initialize keygen context");

    // Set the EC curve NID_X9_62_prime256v1 (P-256)
    // ECDSA (Elliptic Curve Digital Signature Algorithm):
    // Purpose: Provides digital signatures for verifying data integrity and authenticity.
    // Reason for Selection: ECDSA offers a high level of security with shorter key sizes compared to traditional algorithms like RSA.
    // This efficiency makes it suitable for modern applications where computational resources may be limited.
    // Security: ECDSA is resistant to attacks that exploit key size. A 256-bit ECDSA key offers comparable security to a 3072-bit RSA key.
    // It's also resistant to common attacks, including those leveraging factorization and discrete logarithms.
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0)
        handle_errors("Failed to set curve for keygen");

    // Generate the key pair
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) handle_errors("Failed to generate key pair");

    // Save private key with password protection using AES-256-CBC
    // AES-256-CBC:
    // Purpose: Used for encrypting private keys with a password.
    // Reason for Selection: AES-256-CBC is a widely accepted and trusted encryption standard.
    // While CBC mode has potential vulnerabilities (such as padding oracle attacks), it is safe for this use case,
    // as the private key encryption involves a random salt and a securely derived IV.
    // Security: AES-256 provides robust protection against brute-force attacks due to its large key size.
    // The use of CBC mode here is mitigated by appropriate handling of IV and padding, reducing vulnerability to practical exploitation.
    priv_file = fopen(private_key_file, "w");
    if (!priv_file) handle_errors("Failed to open private key file for writing");

    if (!PEM_write_PKCS8PrivateKey(priv_file, pkey, EVP_aes_256_cbc(), NULL, 0, 0, (void *)password)) {
        handle_errors("Failed to write private key");
    }
    fclose(priv_file);

    // Save public key
    pub_file = fopen(public_key_file, "w");
    if (!pub_file) handle_errors("Failed to open public key file for writing");

    if (!PEM_write_PUBKEY(pub_file, pkey)) handle_errors("Failed to write public key");
    fclose(pub_file);

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    printf("Key pair generated and saved successfully.\n");
}

// Function to encrypt a file using ChaCha20-Poly1305 and ECDH
void encrypt(const char *input_file, const char *output_file, const char *private_key_file,
             const char *receiver_pubkey_file, const char *password) {
    EVP_PKEY *sender_privkey = NULL, *receiver_pubkey = NULL;
    EVP_PKEY_CTX *derive_ctx = NULL;
    FILE *in_file = NULL, *out_file = NULL, *priv_file = NULL, *pub_file = NULL;
    unsigned char shared_secret[32], nonce[12], *sig = NULL, *chunk = NULL, *cipher_chunk = NULL;
    size_t secret_len = sizeof(shared_secret), sig_len;
    int len, cipher_len;
    EVP_CIPHER_CTX *cipher_ctx = NULL;
    EVP_MD_CTX *md_ctx = NULL;

    // Load sender private key
    priv_file = fopen(private_key_file, "r");
    if (!priv_file) handle_errors("Failed to open private key file");

    sender_privkey = PEM_read_PrivateKey(priv_file, NULL, NULL, (void *)password);
    if (!sender_privkey) handle_errors("Failed to read private key");
    fclose(priv_file);

    // Load receiver public key
    pub_file = fopen(receiver_pubkey_file, "r");
    if (!pub_file) handle_errors("Failed to open receiver public key file");

    receiver_pubkey = PEM_read_PUBKEY(pub_file, NULL, NULL, NULL);
    if (!receiver_pubkey) handle_errors("Failed to read receiver public key");
    fclose(pub_file);

    // Derive shared secret using ECDH (Elliptic Curve Diffie-Hellman)
    // ECDH (Elliptic Curve Diffie-Hellman):
    // Purpose: Used for key exchange to securely derive a shared secret between parties.
    // Reason for Selection: ECDH provides secure key exchange based on elliptic curves, enabling the establishment of a shared secret key without direct transmission.
    // It is more efficient than non-elliptic curve Diffie-Hellman.
    // Security: ECDH offers strong security against eavesdropping and man-in-the-middle attacks.
    // The elliptic curve variant ensures robust protection with shorter key lengths, which is advantageous for both performance and security.
    derive_ctx = EVP_PKEY_CTX_new(sender_privkey, NULL);
    if (!derive_ctx) handle_errors("Failed to create context for shared secret derivation");

    if (EVP_PKEY_derive_init(derive_ctx) <= 0) handle_errors("Failed to initialize key derivation");
    if (EVP_PKEY_derive_set_peer(derive_ctx, receiver_pubkey) <= 0) handle_errors("Failed to set peer key");

    if (EVP_PKEY_derive(derive_ctx, shared_secret, &secret_len) <= 0) handle_errors("Failed to derive shared secret");

    printf("Shared secret derived successfully.\n");
    print_buffer_hex("Shared secret", shared_secret, secret_len);

    // Generate random nonce for ChaCha20-Poly1305 encryption
    // ChaCha20-Poly1305:
    // Purpose: Provides authenticated encryption (confidentiality and integrity).
    // Reason for Selection: ChaCha20-Poly1305 is a modern, high-performance authenticated encryption algorithm.
    // It is resistant to known vulnerabilities affecting older ciphers like AES when used in certain modes (e.g., CBC with predictable IVs).
    // Security: ChaCha20-Poly1305 is secure against a wide range of cryptographic attacks, including differential cryptanalysis and side-channel attacks.
    // Its design minimizes implementation errors and is suitable for software implementations on various platforms.
    if (!RAND_bytes(nonce, sizeof(nonce))) handle_errors("Failed to generate random nonce");

    printf("Nonce generated successfully: ");
    print_buffer_hex("Nonce", nonce, sizeof(nonce));

    // Open input and output files
    in_file = fopen(input_file, "rb");
    if (!in_file) handle_errors("Failed to open input file");

    out_file = fopen(output_file, "wb");
    if (!out_file) handle_errors("Failed to open output file");

    // Write nonce to output file
    fwrite(nonce, 1, sizeof(nonce), out_file);

    // Initialize encryption context
    cipher_ctx = EVP_CIPHER_CTX_new();
    if (!cipher_ctx) handle_errors("Failed to create cipher context");

    if (EVP_EncryptInit_ex(cipher_ctx, EVP_chacha20_poly1305(), NULL, shared_secret, nonce) <= 0) handle_errors("Failed to initialize encryption");

    // Allocate memory for chunks
    chunk = malloc(CHUNK_SIZE);
    cipher_chunk = malloc(CHUNK_SIZE + 16); // Additional space for Poly1305 tag
    if (!chunk || !cipher_chunk) handle_errors("Failed to allocate memory for chunks");

    // Process the input file in chunks
    size_t total_read = 0;
    while ((len = fread(chunk, 1, CHUNK_SIZE, in_file)) > 0) {
        total_read += len;
        if (EVP_EncryptUpdate(cipher_ctx, cipher_chunk, &cipher_len, chunk, len) <= 0)
            handle_errors("Failed to encrypt chunk");
        fwrite(cipher_chunk, 1, cipher_len, out_file);

        printf(".");  // Print a period for each block processed
        fflush(stdout);
    }

    if (EVP_EncryptFinal_ex(cipher_ctx, cipher_chunk, &cipher_len) <= 0) handle_errors("Failed to finalize encryption");
    fwrite(cipher_chunk, 1, cipher_len, out_file);

    printf("\nEncryption completed successfully. Total bytes read: %zu\n", total_read);

    // Clean up
    EVP_CIPHER_CTX_free(cipher_ctx);
    free(chunk);
    free(cipher_chunk);

    // Sign the entire ciphertext using ECDSA
    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) handle_errors("Failed to create message digest context");

    sig = malloc(EVP_PKEY_size(sender_privkey));
    if (!sig) handle_errors("Failed to allocate memory for signature");

    if (EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, sender_privkey) <= 0) handle_errors("Failed to initialize signature");

    // Reopen the output file for reading to compute the signature over the entire ciphertext
    fclose(out_file);
    out_file = fopen(output_file, "rb+");  // Open for reading and writing
    fseek(out_file, sizeof(nonce), SEEK_SET); // Skip nonce
    unsigned char buffer[CHUNK_SIZE];
    size_t read_len;
    while ((read_len = fread(buffer, 1, CHUNK_SIZE, out_file)) > 0) {
        if (EVP_DigestSignUpdate(md_ctx, buffer, read_len) <= 0) handle_errors("Failed to update signature");
    }

    if (EVP_DigestSignFinal(md_ctx, sig, &sig_len) <= 0) handle_errors("Failed to finalize signature");

    printf("Signature generated, length: %zu bytes.\n", sig_len);
    print_buffer_hex("Generated signature", sig, sig_len);

    // Use uint32_t to store signature length consistently
    uint32_t sig_len_net = htonl((uint32_t)sig_len); // Network byte order for consistent storage

    // Move to the end of the file to write the signature and signature length
    fseek(out_file, 0, SEEK_END);

    // Write signature to output file
    size_t written = fwrite(sig, 1, sig_len, out_file);
    if (written != sig_len) {
        handle_errors("Failed to write signature to file");
    }

    // Write signature length to output file
    written = fwrite(&sig_len_net, sizeof(sig_len_net), 1, out_file);
    if (written != 1) {
        handle_errors("Failed to write signature length to file");
    }

    // Flush the output file to ensure all data is written
    fflush(out_file);

    // Print the current file pointer position after writing signature length
    long current_pos = ftell(out_file);
    printf("File pointer position after writing signature length and signature: %ld\n", current_pos);

    EVP_MD_CTX_free(md_ctx);

    fclose(in_file);
    fclose(out_file);

    free(sig);
    EVP_PKEY_free(sender_privkey);
    EVP_PKEY_free(receiver_pubkey);
    EVP_PKEY_CTX_free(derive_ctx);

    printf("File encrypted and signed successfully.\n");
}

// Function to decrypt a file using ChaCha20-Poly1305 and ECDH
void decrypt(const char *input_file, const char *output_file, const char *private_key_file,
             const char *sender_pubkey_file, const char *password) {
    EVP_PKEY *receiver_privkey = NULL, *sender_pubkey = NULL;
    EVP_PKEY_CTX *derive_ctx = NULL;
    FILE *in_file = NULL, *out_file = NULL, *priv_file = NULL, *pub_file = NULL;
    unsigned char shared_secret[32], nonce[12], *sig = NULL, *chunk = NULL, *plain_chunk = NULL;
    size_t secret_len = sizeof(shared_secret), sig_len, file_size, total_read = 0;
    int len, plain_len;
    EVP_CIPHER_CTX *cipher_ctx = NULL;
    EVP_MD_CTX *md_ctx = NULL;

    // Load receiver private key
    priv_file = fopen(private_key_file, "r");
    if (!priv_file) handle_errors("Failed to open private key file");

    receiver_privkey = PEM_read_PrivateKey(priv_file, NULL, NULL, (void *)password);
    if (!receiver_privkey) handle_errors("Failed to read private key");
    fclose(priv_file);

    // Load sender public key
    pub_file = fopen(sender_pubkey_file, "r");
    if (!pub_file) handle_errors("Failed to open sender public key file");

    sender_pubkey = PEM_read_PUBKEY(pub_file, NULL, NULL, NULL);
    if (!sender_pubkey) handle_errors("Failed to read sender public key");
    fclose(pub_file);

    // Derive shared secret using ECDH
    derive_ctx = EVP_PKEY_CTX_new(receiver_privkey, NULL);
    if (!derive_ctx) handle_errors("Failed to create context for shared secret derivation");

    if (EVP_PKEY_derive_init(derive_ctx) <= 0) handle_errors("Failed to initialize key derivation");
    if (EVP_PKEY_derive_set_peer(derive_ctx, sender_pubkey) <= 0) handle_errors("Failed to set peer key");

    if (EVP_PKEY_derive(derive_ctx, shared_secret, &secret_len) <= 0) handle_errors("Failed to derive shared secret");

    printf("Shared secret derived successfully.\n");
    print_buffer_hex("Shared secret", shared_secret, secret_len);

    // Open input and output files
    in_file = fopen(input_file, "rb");
    if (!in_file) handle_errors("Failed to open input file");

    out_file = fopen(output_file, "wb");
    if (!out_file) handle_errors("Failed to open output file");

    // Read nonce from input file
    fread(nonce, 1, sizeof(nonce), in_file);

    printf("Nonce read: ");
    print_buffer_hex("Nonce", nonce, sizeof(nonce));

    // Get the total file size to calculate ciphertext and signature lengths
    fseek(in_file, 0, SEEK_END);
    file_size = ftell(in_file);

    // Use uint32_t to read signature length consistently
    uint32_t sig_len_net;

    // Move to the last 4 bytes of the file to read the signature length
    fseek(in_file, -(long)sizeof(sig_len_net), SEEK_END);
    fread(&sig_len_net, sizeof(sig_len_net), 1, in_file);
    sig_len = ntohl(sig_len_net); // Convert from network byte order

    printf("Read signature length: %zu\n", sig_len);

    // Move back by the signature length to read the signature
    fseek(in_file, -(long)(sizeof(sig_len_net) + sig_len), SEEK_END);
    sig = malloc(sig_len);
    if (!sig) handle_errors("Failed to allocate memory for signature");
    fread(sig, 1, sig_len, in_file);

    printf("Read signature: ");
    print_buffer_hex("Signature", sig, sig_len);

    // Calculate ciphertext length
    size_t ciphertext_len = file_size - sizeof(nonce) - sizeof(sig_len_net) - sig_len;

    if (ciphertext_len <= 0) handle_errors("Invalid ciphertext length calculated");

    printf("File size: %zu, Ciphertext length: %zu, Signature length: %zu\n", file_size, ciphertext_len, sig_len);

    // Seek back to just after the nonce to start reading ciphertext
    fseek(in_file, sizeof(nonce), SEEK_SET);

    // Allocate memory for chunks
    chunk = malloc(CHUNK_SIZE);
    plain_chunk = malloc(CHUNK_SIZE);
    if (!chunk || !plain_chunk) handle_errors("Failed to allocate memory for chunks");

    // Initialize decryption context
    cipher_ctx = EVP_CIPHER_CTX_new();
    if (!cipher_ctx) handle_errors("Failed to create cipher context");

    if (EVP_DecryptInit_ex(cipher_ctx, EVP_chacha20_poly1305(), NULL, shared_secret, nonce) <= 0)
        handle_errors("Failed to initialize decryption");

    // Initialize message digest context for verification
    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) handle_errors("Failed to create message digest context");

    if (EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, sender_pubkey) <= 0)
        handle_errors("Failed to initialize verification");

    // Process the input file in chunks
    while (total_read < ciphertext_len) {
        len = fread(chunk, 1, CHUNK_SIZE, in_file);
        if (len <= 0) handle_errors("Failed to read chunk from input file");

        // Adjust the last chunk length if necessary
        if (total_read + len > ciphertext_len) {
            len = ciphertext_len - total_read;
        }

        total_read += len;

        // Decrypt the chunk
        if (EVP_DecryptUpdate(cipher_ctx, plain_chunk, &plain_len, chunk, len) <= 0)
            handle_errors("Failed to decrypt chunk");
        fwrite(plain_chunk, 1, plain_len, out_file);

        // Update signature verification
        if (EVP_DigestVerifyUpdate(md_ctx, chunk, len) <= 0)
            handle_errors("Failed to update verification");

        printf(".");  // Print a period for each block processed
        fflush(stdout);
    }

    if (EVP_DecryptFinal_ex(cipher_ctx, plain_chunk, &plain_len) <= 0)
        handle_errors("Failed to finalize decryption");
    fwrite(plain_chunk, 1, plain_len, out_file);

    printf("\nDecryption completed successfully. Total bytes processed: %zu\n", total_read);

    // Verify the signature
    if (EVP_DigestVerifyFinal(md_ctx, sig, sig_len) <= 0) {
        handle_errors("Failed to verify signature");
    }

    printf("Signature verification successful.\n");

    EVP_CIPHER_CTX_free(cipher_ctx);
    EVP_MD_CTX_free(md_ctx);

    fclose(in_file);
    fclose(out_file);

    free(chunk);
    free(plain_chunk);
    free(sig);
    EVP_PKEY_free(receiver_privkey);
    EVP_PKEY_free(sender_pubkey);
    EVP_PKEY_CTX_free(derive_ctx);

    printf("File decrypted and verified successfully.\n");
}

// Main function to handle command-line arguments
int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <command> [arguments...]\n", argv[0]);
        fprintf(stderr, "Commands:\n");
        fprintf(stderr, "  keygen <private_key_file> <public_key_file> <password>\n");
        fprintf(stderr, "  encrypt <input_file> <output_file> <private_key_file> <receiver_pubkey_file> <password>\n");
        fprintf(stderr, "  decrypt <input_file> <output_file> <private_key_file> <sender_pubkey_file> <password>\n");
        return EXIT_FAILURE;
    }

    if (strcmp(argv[1], "keygen") == 0) {
        if (argc != 5) {
            fprintf(stderr, "Usage: %s keygen <private_key_file> <public_key_file> <password>\n", argv[0]);
            return EXIT_FAILURE;
        }
        keygen(argv[2], argv[3], argv[4]);
    } else if (strcmp(argv[1], "encrypt") == 0) {
        if (argc != 7) {
            fprintf(stderr, "Usage: %s encrypt <input_file> <output_file> <private_key_file> <receiver_pubkey_file> <password>\n", argv[0]);
            return EXIT_FAILURE;
        }
        encrypt(argv[2], argv[3], argv[4], argv[5], argv[6]);
    } else if (strcmp(argv[1], "decrypt") == 0) {
        if (argc != 7) {
            fprintf(stderr, "Usage: %s decrypt <input_file> <output_file> <private_key_file> <sender_pubkey_file> <password>\n", argv[0]);
            return EXIT_FAILURE;
        }
        decrypt(argv[2], argv[3], argv[4], argv[5], argv[6]);
    } else {
        fprintf(stderr, "Unknown command: %s\n", argv[1]);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
