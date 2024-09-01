
# Firmware update file encryption for embedded devices using modern cryptographic best practices: key generation, encryption, signing, and verification using OpenSSL 3+ libssl and libcrypto.

The fast-fwsign utility was developed to meet critical security requirements for firmware integrity, confidentiality, and authentication. It ensures that firmware is protected against unauthorized modifications by using ECDSA for digital signatures, which verifies the authenticity and integrity of the firmware. To maintain confidentiality and prevent unauthorized access or reverse engineering, the utility employs ChaCha20-Poly1305 for encrypting firmware, safeguarding it from eavesdropping and tampering during distribution. The private keys used for signing are securely stored by encrypting them with a password using AES-256-CBC, mitigating the risk of key compromise. These measures collectively protect firmware at rest, in transit, and during deployment, ensuring that only trusted firmware can be installed and executed on devices from authenticated sources with cryptographic attestation, thus preventing malicious code execution and maintaining system security. It uses separate keys for encryption and decryption to ensure that even if the device is compromised the firmware image generation system won't be.

By a funny coincidence I found myself explaining the requirements for encrypting and signing firmware updates for the third time in two weeks on separate projects (including an audit report on Friday), and I realized that I can probably code up the source code to do the required functions as quickly as i can explain all the requirements. (In reality it took a few hours longer to debug and fully test it, but I had already gone down that path already...) I recently was looking at similar cryptographic problems for some other work I was doing on Linux WireGuard VPNs so these processes were fresh in mind, so I took advantage of that to code up what is needed for secure firmware updates in an easy to deploy utility for public use.

In any case, this is a question I find myself repeatedly answering on device audits, and explaining how you need separate keys for encrypting the firmware and signature verification to ensure that if a device is compromised the attacker can't use the keys stored on the unit to create firmware for other similar devices. We then get into a discussion of private and public keys and Diffie-Helman key exchanges and other more technical crypto topics. The other point of concern is handling the encryption keys and having another layer of security on the keys at rest to further limit compromise in an incident.

So to that end, to save everyone time and simplify that explanation, I wrote a utility that leverages the OpenSSL cryptography libraries - to avoid roll your own crypto, which leverage the widely audited and verified cryptography implementations in its libcrypto libraries - that implements modern cryptographic best practices for firmware distribution and installation verification.

This is a BSD licensed (to allow use in commercial products) utility written in C to perform the functions needed using current cryptographic algorithm choices suitable for smaller embedded device CPU SoC's, as well as a version of the utility/code that processes the encryption and decryption in smaller data chunks allowing devices to process image files much bigger than their potentially limited available memory at this source code repository. You'll find more documentation about what this code does and why below. I have done a fair bit of testing and trust the implementation because it leverages the well tested OpenSSL code, but by all means I encourage folks to get this audited by others, because while I  am pretty familiar with this topic, I am merely human and better verification and auditing is just good engineering. 

So I've done most of the heavy cryptography lifting for building a secure firmware update system for you here, BUT THIS IS NOT COMPLETE.
Left as tasks for the implementor are three other aspects of firmware updates that need to be covered:

1. Logging and monitoring of firmware updates. To provide an audit trail in case of security incidents.
2. Version numbering and anti-rollback mechanisms, so an attacker can't re-install an old vulnerable version of firmware.
3. Provision of backup keys and a means of invalidating the main key in case of a signing key compromise.

You can use this cryptographic core utility I have provided to achieve all of the above, but it will require other device specific logic that is beyond the scope of this utility.
Please use this code as you see best fit.

## **Compilation and Usage Instructions for `fast-fwsign`**

### **Compilation Instructions**

 **Install OpenSSL Development Libraries**: Ensure that the OpenSSL development libraries are installed on your system. This is required for compiling programs that use OpenSSL functions. You can install them using the package manager for your operating system:

 **For Debian/Ubuntu**:  `sudo apt-get update`

 `sudo apt-get install libssl-dev`

 **For Red Hat/CentOS**:  `sudo yum install openssl-devel`

 **For macOS** (using Homebrew):  `brew install openssl`

 **For Windows**: You might need to use a package manager like `vcpkg` or download OpenSSL binaries and include the appropriate paths in your compilation command.



 **Compile the Code**: Assuming you have saved the provided code in a file named `fast-fwsign.c`, compile the code using `gcc` with the OpenSSL library:  `gcc -o fast-fwsign fast-fwsign.c -lssl -lcrypto`

 The `-o fast-fwsign` flag specifies the output executable file name.

 The `-lssl -lcrypto` flags link the OpenSSL libraries required by the code.



 **Ensure the Compilation was Successful**:

  After running the compilation command, you should see a new executable named `fast-fwsign` in your current directory. Run the executable without arguments to check the usage message:  `./fast-fwsign`

 If the utility runs and displays a usage message, the compilation was successful.




 ### **Usage Instructions**

 The `fast-fwsign` utility supports three main operations: generating ECDSA key pairs, encrypting a file, and decrypting a file.


 #### **1\. Generating ECDSA Key Pairs**

 To generate a pair of ECDSA keys (private and public), use the `keygen` command:

 `./fast-fwsign keygen <private_key_file> <public_key_file> <password>`

*  `<private_key_file>`: Path to save the generated private key file (e.g., `priv.key`).

*  `<public_key_file>`: Path to save the generated public key file (e.g., `pub.key`).

*  `<password>`: Password to encrypt the private key.

 #### **Example**:

 `./fast-fwsign keygen priv.key pub.key mypassword`

 This command generates a private key encrypted with the password `mypassword` and a corresponding public key.

 
 #### **2\. Encrypting a File**

 To encrypt a file using ChaCha20-Poly1305 and sign it using ECDSA, use the `encrypt` command:

 `./fast-fwsign encrypt <input_file> <output_file> <private_key_file> <receiver_pubkey_file> <password>`
 
*  `<input_file>`: Path to the file you want to encrypt (e.g., `firmware.bin`).

*  `<output_file>`: Path to save the encrypted output file (e.g., `firmware.crypt`).

*  `<private_key_file>`: Sender’s private key file for deriving the shared secret and signing the data.

*  `<receiver_pubkey_file>`: Receiver’s public key file for deriving the shared secret.

*  `<password>`: Password to decrypt the sender’s private key.

 #### **Example**:

 `./fast-fwsign encrypt firmware.bin firmware.crypt priv.key receiver_pub.key mypassword`

 This command encrypts `firmware.bin`, signs it, and saves the result in `firmware.crypt`.

 
 #### **3\. Decrypting a File**

 To decrypt a file and verify its signature, use the `decrypt` command:

 `./fast-fwsign decrypt <input_file> <output_file> <private_key_file> <sender_pubkey_file> <password>`
 
*  `<input_file>`: Path to the file you want to decrypt (e.g., `firmware.crypt`).

*  `<output_file>`: Path to save the decrypted output file (e.g., `firmware.dec`).

*  `<private_key_file>`: Receiver’s private key file for deriving the shared secret.

*  `<sender_pubkey_file>`: Sender’s public key file for verifying the signature.

*  `<password>`: Password to decrypt the receiver’s private key.

 #### **Example**:

 `./fast-fwsign decrypt firmware.crypt firmware.dec priv.key sender_pub.key mypassword`

 This command decrypts `firmware.crypt`, verifies the signature using the sender's public key, and saves the result in `firmware.dec`.

 
 
 ### **Notes and Best Practices**

*  **Key Management**: Keep your private keys secure and use strong, unique passwords. Compromise of a private key would allow an attacker to decrypt data and impersonate the key owner.

*  **Nonces**: Each encryption operation uses a new, random nonce. Do not reuse nonces with the same key, as this can compromise the security of ChaCha20-Poly1305.

*  **Error Handling**: The utility will print detailed error messages and exit if any operation fails. These messages can help diagnose issues such as incorrect file paths, mismatched keys, or incorrect passwords.

*  **Signature Verification**: Always verify the signature after decryption to ensure the authenticity and integrity of the data.

 #### **Example Workflow**

 Generate key pairs for both the sender and receiver:  
 
 `./fast-fwsign keygen sender_priv.key sender_pub.key senderpass`

 `./fast-fwsign keygen receiver_priv.key receiver_pub.key receiverpass`

 Encrypt the firmware file: 
 
 `./fast-fwsign encrypt firmware.bin firmware.crypt sender_priv.key receiver_pub.key senderpass`

 Decrypt and verify the firmware file:  
 
 `./fast-fwsign decrypt firmware.crypt firmware.dec receiver_priv.key sender_pub.key receiverpass`

 By following these instructions, you can securely encrypt and sign firmware files, ensuring their integrity and authenticity during distribution and deployment.

  

##    **Firmware Encryption and Signing Utility \- Cryptography Description**

1. **Elliptic Curve Cryptography (ECC)**:  
   * **Elliptic Curve Diffie-Hellman (ECDH) for Key Exchange**:  
     * **Purpose**: ECDH is used to securely derive a shared secret between two parties (the sender and the receiver) without actually transmitting the secret itself. This shared secret is then used as a key for symmetric encryption (ChaCha20-Poly1305 in this case).  
     * **Why ECC**: ECC offers the same level of security as non-elliptic curve cryptography with much smaller key sizes. This makes it faster and more efficient, especially in environments where computational power and bandwidth are limited. For example, a 256-bit ECDH key provides security comparable to a 3072-bit RSA key.  
     * **How it Works in the Code**: The sender uses their private key and the receiver’s public key to derive the shared secret. The receiver does the reverse during decryption, using their private key and the sender’s public key to derive the same shared secret. This mutual exchange is secure due to the mathematical hardness of the elliptic curve discrete logarithm problem, which makes deriving the shared secret without access to the private key computationally infeasible.  
2. **Authenticated Encryption with Associated Data (AEAD) \- ChaCha20-Poly1305**:  
   * **Purpose**: Provides both confidentiality (encryption) and integrity/authentication (via a MAC) for the data. ChaCha20 is a stream cipher, while Poly1305 is a message authentication code. Together, they form an AEAD cipher mode, which ensures that the data has not been tampered with and remains confidential.  
   * **Why ChaCha20-Poly1305**:  
     * **Performance**: ChaCha20 is designed to be efficient on software platforms, especially where hardware AES acceleration is not available. It is faster and more resistant to side-channel attacks compared to traditional ciphers like AES in certain configurations (e.g., AES-CBC).  
     * **Security**: ChaCha20 is resistant to known cryptographic attacks such as differential cryptanalysis. Poly1305 provides a strong MAC that ensures the integrity and authenticity of the data. If any bit of the ciphertext is altered, Poly1305 will detect this change.  
     * **How it Works in the Code**:  
       * The shared secret derived from ECDH is used as the key for ChaCha20-Poly1305.  
       * A random nonce is generated for each encryption operation to ensure that the same plaintext encrypted multiple times will result in different ciphertexts. This nonce is written at the beginning of the output file and is required for decryption.  
       * The plaintext is processed in chunks, encrypted using ChaCha20, and authenticated using Poly1305. The encrypted chunks are written to the output file.  
3. **Elliptic Curve Digital Signature Algorithm (ECDSA)**:  
   * **Purpose**: ECDSA provides a way to digitally sign data, ensuring that it has not been tampered with and authenticating the origin of the data. It is particularly useful in scenarios where data integrity and authenticity are critical.  
   * **Why ECDSA**:  
     * **Efficiency**: Similar to ECDH, ECDSA offers strong security with shorter key sizes. This results in faster computations and reduced storage requirements.  
     * **Security**: ECDSA is secure against a wide range of attacks, including those exploiting the discrete logarithm problem. With a 256-bit key, it offers a high level of security suitable for most applications.  
     * **How it Works in the Code**:  
       * After encrypting the file, ECDSA is used to sign the ciphertext. This ensures that the entire content has been encrypted and authenticated.  
       * The sender's private key is used to generate the signature over the ciphertext.  
       * During decryption, the receiver uses the sender's public key to verify the signature. This step ensures that the ciphertext has not been altered and that it was indeed signed by the sender.  
4. **Nonce (Number Used Once)**:  
   * **Purpose**: A nonce is a unique number used only once for a specific operation. It prevents replay attacks and ensures that the same plaintext encrypted multiple times results in different ciphertexts.  
   * **Why Nonces are Critical**:  
     * **Uniqueness**: By using a unique nonce for each encryption, the system ensures that even if the same plaintext is encrypted with the same key, the resulting ciphertext will be different. This prevents attackers from deducing information about the plaintext based on repeated patterns in the ciphertext.  
     * **Randomness**: A random nonce is crucial to ensure security. If nonces were predictable, it could lead to vulnerabilities.  
     * **How it Works in the Code**:  
       * A 12-byte nonce is generated using a cryptographically secure random number generator (`RAND_bytes`).  
       * This nonce is written at the beginning of the output file and is required for the decryption process to reconstruct the state of the ChaCha20-Poly1305 cipher.  
5. **Integrity and Authentication**:  
   * **Why Authentication Matters**: Encryption provides confidentiality, but without authentication, an attacker could alter the ciphertext. AEAD modes like ChaCha20-Poly1305 provide both encryption and a method to check the integrity and authenticity of the data, protecting against unauthorized modifications.  
   * **Signature Verification**: After decrypting, the code verifies the ECDSA signature to confirm that the data originated from the expected sender and has not been tampered with. If the signature does not match, decryption is aborted, and an error is raised.

### **Security Benefits of This Approach**

* **Confidentiality**: ChaCha20-Poly1305 ensures that only parties with the derived shared secret can decrypt the data.  
* **Integrity**: Poly1305 detects any unauthorized changes to the ciphertext. If the data has been tampered with, decryption fails.  
* **Authentication**: ECDSA signatures verify the sender’s identity and the integrity of the data, ensuring that the message has not been altered since it was signed.  
* **Efficiency**: Using ECC (ECDH and ECDSA) allows for strong security with reduced computational overhead compared to RSA or other non-ECC methods. ChaCha20-Poly1305 is designed to be efficient and fast, especially in software implementations.




# **Chunked Algorithm Version**

The chunked version of this utility allows processing files larger than main memory on limited resource systems. Provided code encrypts the input file using the ChaCha20-Poly1305 algorithm in blocks and calculates the signature over the entire file using ECDSA. Here's how the process works step-by-step for both encryption and signature calculation, ensuring that both operations are correctly handled even when the file is processed in chunks:

### **Encryption with ChaCha20-Poly1305 in Blocks**

1. **Initialization:**  
   * A shared secret is derived using Elliptic Curve Diffie-Hellman (ECDH) between the sender's private key and the receiver's public key. This shared secret is used as the encryption key.  
   * A random nonce (12 bytes) is generated using `RAND_bytes()`. The nonce is crucial for ChaCha20-Poly1305 to ensure unique encryption for each message.  
2. **Preparing to Encrypt:**  
   * The input file is opened for reading, and the output file is opened for writing.  
   * The nonce is written to the beginning of the output file. This nonce will be needed during decryption to correctly decrypt the ciphertext.  
3. **Chunked Encryption:**  
   * The input file is processed in chunks of size `CHUNK_SIZE` (32 KB in this case).  
   * For each chunk:  
     * The chunk is read from the input file.  
     * `EVP_EncryptUpdate()` is called with the chunk data. This function encrypts the chunk and appends the result to the output file.  
     * A period (`.`) is printed to indicate each processed block, providing visual feedback during encryption.  
4. **Finalizing Encryption:**  
   * After all chunks have been processed, `EVP_EncryptFinal_ex()` is called to finalize the encryption. This function handles any remaining data that may not fit into a complete block and writes the final encrypted data to the output file.  
   * The total bytes read and processed are printed to provide an overview of the encryption process.

### **Signature Calculation over the Entire File**

1. **Initialization for Signing:**  
   * A message digest context is created using `EVP_MD_CTX_new()`.  
   * `EVP_DigestSignInit()` initializes the digest context for signing using the sender's private key and the SHA-256 hash function. This sets up the context to prepare for a signing operation.  
2. **Reopening and Processing the File:**  
   * After writing the encrypted chunks to the output file, the file is reopened in read/write mode (`rb+`). This is necessary to read back the encrypted data for signing without losing the position at the end of the file.  
   * The file pointer is set just after the nonce (using `fseek(out_file, sizeof(nonce), SEEK_SET);`) to skip the nonce and begin reading the encrypted data.  
3. **Reading in Chunks for Signature:**  
   * The entire encrypted data is read in chunks (again using `CHUNK_SIZE`) from the output file.  
   * For each chunk, `EVP_DigestSignUpdate()` is called. This function updates the digest context with the chunk data. By doing this repeatedly for each chunk, the context accumulates a hash of the entire encrypted data.  
   * This approach ensures that the signature is calculated over the entire file, not just one block at a time.  
4. **Finalizing the Signature:**  
   * After processing all chunks, `EVP_DigestSignFinal()` is called. This function produces the signature using the accumulated hash and the sender's private key.  
   * The signature is then written to the output file, followed by its length (stored in network byte order) for consistent reading during decryption.

### **Decryption and Verification**

1. **Decryption:**  
   * Similar to encryption, decryption is done in chunks. The nonce is read from the start of the file, and the shared secret is derived using ECDH.  
   * The input file is processed in chunks, decrypting each chunk with `EVP_DecryptUpdate()` and writing the plaintext to the output file.  
   * After all chunks are processed, `EVP_DecryptFinal_ex()` finalizes the decryption.  
2. **Signature Verification:**  
   * A message digest context is initialized for verification using `EVP_DigestVerifyInit()`.  
   * As with signing, the entire encrypted data is read in chunks, and `EVP_DigestVerifyUpdate()` updates the digest context with each chunk.  
   * Finally, `EVP_DigestVerifyFinal()` is called to verify the signature against the accumulated hash. If verification fails, the decryption process raises an error.

### **How This Approach Ensures Integrity and Security**

* **Chunked Processing:** The file is processed in chunks, both for encryption and for updating the digest for the signature. This allows the handling of large files that do not fit into memory. The signature update occurs in parallel with encryption, ensuring consistency in the data being encrypted and signed.  
* **Signature Over Entire File:** The signature calculation accumulates the hash over all chunks, ensuring that any change in any part of the file would be detected. This integrity check protects against tampering.  
* **Nonce for Uniqueness:** The nonce ensures that even if the same plaintext is encrypted multiple times with the same key, the ciphertext will be different each time, providing semantic security.




# **How Key Password Cryptography Works in `fast-fwsign`**

1. **Private Key Encryption with Password**:  
   * When generating ECDSA key pairs using the `keygen` command, the private key is encrypted with a password before being saved to a file.  
   * **Encryption Mechanism**: The private key is encrypted using the AES-256-CBC (Advanced Encryption Standard in Cipher Block Chaining mode) algorithm. The encryption is performed using the password provided by the user.  
   * **Process**:  
     * The key generation function first creates an elliptic curve key pair.  
     * The private key, before being saved to a file, is encrypted using the provided password.  
     * During encryption, a random salt and an initialization vector (IV) are generated. These values are used along with the password in a key derivation function (KDF), typically PBKDF2 the default in OpenSSL, to derive a strong encryption key.  
     * AES-256-CBC is then used with this derived key to encrypt the private key, ensuring that only someone with the correct password can decrypt and use the private key.  
2. **Decryption of Private Key**:  
   * During operations like encryption and decryption of data files, the private key needs to be read and used. Since the private key is stored in an encrypted form, it must first be decrypted.  
   * **Process**:  
     * The user provides the password, which is used in conjunction with the salt to derive the same encryption key that was used for encryption.  
     * The derived key, along with the stored IV, is used with AES-256-CBC to decrypt the private key file, making the private key available for cryptographic operations (e.g., signing, deriving shared secrets).

     

# **Why Encrypt Private Keys at Rest?**

#### **Protection Against Unauthorized Access**:  
   * **Threat Model**: Private key files might be accessible to attackers who gain unauthorized access to the file system. Without encryption, these keys could be directly misused to decrypt data, impersonate the key owner, or sign malicious information.  
   * **Password Protection**: By encrypting the private key with a password, unauthorized users cannot easily access or misuse the key, even if they manage to obtain the encrypted file.  
#### **Compliance with Security Standards**:  
   * Encrypting private keys at rest is recommended by various security standards and best practices, such as PCI-DSS and NIST guidelines. It helps prevent unauthorized access and ensures compliance with regulatory requirements, which often mandate that sensitive data be protected.  
#### **Mitigation of Key Extraction Attacks**:  
   * Even if attackers obtain the encrypted private key file, they must still crack the password, or extract the separately stored password to access the key. 
   * Using a salt and multiple iterations in the KDF process helps protect against brute-force and dictionary attacks, ensuring that even if an attacker has powerful resources, the process remains secure.  
#### **Maintaining Data Integrity and Authenticity**:  
   * Encrypting private keys with passwords ensures that only authorized individuals can decrypt, sign, or use them, preserving the integrity and authenticity of the data.  
   * This measure prevents unauthorized users from tampering with the data, as they would not have access to the necessary cryptographic keys.  
#### **Usability and Security Balance**:  
   * Password-based encryption provides a convenient way for users to protect their keys while maintaining ease of use. It allows users to protect their keys with passwords they know, while benefiting from strong cryptographic protection.  
   * Implementing policies for password complexity and rotation can further enhance security over time.

## **Why AES-256-CBC is Acceptable in This Use Case**

#### **AES-256-CBC Overview**:  
   * **AES (Advanced Encryption Standard)**: AES is a widely accepted and trusted encryption standard. AES-256 refers to using a 256-bit key, providing a high level of security.  
   * **CBC (Cipher Block Chaining) Mode**: In CBC mode, each block of plaintext is XORed with the previous ciphertext block before being encrypted. An initialization vector (IV) is used to ensure that identical plaintext blocks do not result in identical ciphertext blocks.  
#### **Security Concerns with CBC**:  
   * CBC mode can be vulnerable to certain types of attacks, such as padding oracle attacks if not implemented correctly. These attacks exploit the predictable nature of padding bytes to decrypt messages without knowing the encryption key.  
   * However, these vulnerabilities are typically associated with scenarios where the attacker can manipulate the ciphertext and observe the decryption errors, which is not the case here.
#### **Why CBC is Acceptable for Key Encryption**:  
   * **Controlled Environment**: The private key file is stored in a controlled environment, and there is no exposure to external manipulation or decryption attempts that would enable padding oracle attacks.  
   * **Single Encryption Operation**: The private key is encrypted once and stored securely. The file is not subject to multiple encryptions or modifications that could introduce vulnerabilities.  
   * **Additional Protection Layers**: The use of a strong, randomly generated IV and a high-entropy password provides sufficient protection. The IV ensures that each encryption operation results in different ciphertext, even if the same key and plaintext are used. A securely derived key using PBKDF2 further reduces the risk of attacks.  
   * **Simplicity and Compatibility**: AES-256-CBC is well-supported and widely implemented, making it a practical choice for encrypting private keys. It strikes a balance between security, simplicity, and performance, which is suitable for this use case.

   
