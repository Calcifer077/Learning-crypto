## 🔒 Cryptography Operations in Node.js

---

### **1. Hashing and Password Security**

Hashing is a **one-way** function that converts data into a fixed-length string (a digest) that cannot be reversed. This is primarily used for securing sensitive data like passwords.

#### **Core Hashing Concepts**

- **Properties of Hash Functions**:
  - **Deterministic:** Same input $\rightarrow$ Same output.
  - **Fixed Length:** Output size is constant, regardless of input size.
  - **One-Way:** Computationally infeasible to reverse.
  - **Avalanche Effect:** Small input change $\rightarrow$ Significant output change.
- **Security for Passwords (Key Concepts)**:
  - **Salting:** A **unique random string** added to the password _before_ hashing to ensure different users with the same password have different hashes. This prevents **rainbow table** attacks.
  - **Key Stretching/Work Factor:** Intentionally making the hashing process slow (e.g., via iteration count) to prevent fast **brute-force attacks**.

#### **Steps to Hash and Verify a Password**

This example uses `crypto.scryptSync` which incorporates key stretching for security.

1.  **Hash the Password for Storage:**

    - Generate a unique, random **salt** (e.g., 16 bytes, converted to hex).
    - Use `crypto.scryptSync(password, salt, keylen)` to create the hash. `keylen` determines the output size (e.g., 64 bytes).
    - Store both the **hash** and the **salt** securely in the database.

2.  **Verify a Login Attempt:**
    - Retrieve the user's stored **salt** and **hash** from the database.
    - Use the same hashing function: `crypto.scryptSync(password_from_login, stored_salt, keylen)`.
    - Compare the **newly generated hash** with the **stored hash**. If they are identical, the password is correct.

---

### **2. Symmetric Encryption (AES-256-CBC)**

Symmetric encryption uses a **single, shared secret key** for both encryption and decryption. It's fast and suitable for bulk data encryption.

#### **Key Concepts (AES-256-CBC)**

- **Algorithm:** **AES (Advanced Encryption Standard)**, a widely accepted standard.
- **Key Size:** **256** bits (32 bytes) for high security.
- **Mode of Operation (CBC):** **Cipher Block Chaining** links the encryption of each data block to the previous one.
- **Initialization Vector (IV):** A **random, unique, 16-byte** value required for CBC mode. It prevents the same plaintext from encrypting to the same ciphertext, which defends against **replay attacks**. The IV does **not** need to be secret but must be unique for every operation and sent with the ciphertext.

#### **Steps to Encrypt and Decrypt Data**

1.  **Preparation (Key Generation):**

    - Generate a secure, 32-byte key (256 bits). Use a function like `crypto.scryptSync` for key derivation from a password, ensuring a strong key.

2.  **Encryption:**

    - Generate a new, random 16-byte **IV**.
    - Create a cipher engine using `crypto.createCipheriv('aes-256-cbc', key, iv)`.
    - Encrypt the data using `cipher.update()` and finalize with `cipher.final()`.
    - Send the **ciphertext** and the **IV** to the recipient.

3.  **Decryption:**
    - The recipient uses the shared **key** and the received **IV** to create a decipher engine using `crypto.createDecipheriv('aes-256-cbc', key, Buffer.from(iv, 'hex'))`.
    - Decrypt the data using `decipher.update()` and finalize with `decipher.final()`. This step automatically removes any padding.

---

### **3. Asymmetric Encryption (RSA)**

Asymmetric encryption, or public-key cryptography, uses a mathematically linked pair of keys: a **Public Key** and a **Private Key**. It is primarily used for **confidentiality** and **digital signatures**.

#### **Key Pair Roles**

- **Public Key:** Shared publicly. Used by the sender to **encrypt** and by anyone to **verify** a digital signature.
- **Private Key:** Kept secret. Used by the recipient to **decrypt** and by the owner to **create** a digital signature.
  - _Analogy:_ Public Key is a mailbox slot (anyone can put a message in); Private Key is the key to open the mailbox (only the owner can retrieve the message).

#### **Steps for Encryption and Decryption (Confidentiality)**

1.  **Key Generation:**

    - Generate an RSA key pair, typically with a **modulus length of 2048 bits** or higher.

2.  **Encryption (Sender):**

    - The sender obtains the recipient's **Public Key** (e.g., Alice's Public Key).
    - The sender uses this **Public Key** to encrypt the plaintext message using `crypto.publicEncrypt()`.
    - A padding scheme (e.g., `RSA_PKCS1_OAEP_PADDING`) is used to add random data, ensuring the same plaintext yields different ciphertext each time.

3.  **Decryption (Recipient - Alice):**
    - Alice receives the ciphertext.
    - Alice uses her own **Private Key** to decrypt the message using `crypto.privateDecrypt()`. Only her Private Key can reverse the encryption done by her Public Key.
    - The padding scheme must match the one used during encryption.

#### **Hybrid Encryption (For Large Data)**

Asymmetric encryption is significantly **slower** than symmetric encryption. For large data, a **hybrid approach** is used:

1.  Generate a random **symmetric key**.
2.  Encrypt the large data with the **symmetric key**.
3.  Encrypt the **symmetric key** with the recipient's **Public Key** (this is the only asymmetric step).
4.  Send both the encrypted data and the encrypted symmetric key.

---

### **4. HMAC (Hash-based Message Authentication Code)**

HMAC combines a cryptographic hash function (like SHA-256) with a **secret key** to provide both **data integrity** and **authentication**. It does _not_ encrypt the message.

#### **HMAC Security Properties**

- **Authenticity:** Only parties with the **secret key** can generate a valid HMAC.
- **Message Integrity:** Any change to the message results in a different HMAC.

#### **Steps to Create and Verify an HMAC Signature**

1.  **Create Signature (Sender):**

    - Both parties must share a **secret key**.
    - The sender uses `crypto.createHmac(algorithm, key)` (e.g., `sha256`).
    - The message is fed into the algorithm using `hmac.update()`.
    - The final signature (digest) is calculated using `hmac.digest('hex')`.
    - The sender sends the original **message** along with the **signature**.

2.  **Verify Signature (Receiver):**
    - The receiver uses the received message and their copy of the **secret key** to locally generate an **expected signature** using the exact same steps.
    - The received signature is compared with the expected signature using **`crypto.timingSafeEqual()`**.
      - **_Note on Timing Attacks:_** Simple `===` comparisons are vulnerable to **timing attacks**, where an attacker uses small differences in response time to guess characters. `crypto.timingSafeEqual()` prevents this by ensuring the comparison always takes a constant amount of time, regardless of where the mismatch occurs.
    - If the comparison is true, the message is authenticated and has not been tampered with.

---

### **Security Best Practices**
When using the Crypto module, keep these best practices in mind:

1. **Use modern algorithms:** Avoid MD5, SHA-1, and other outdated algorithms
2. **Secure key management:** Store keys securely, rotate them regularly, and never hardcode them
3. **Use random IVs:** Generate a new random IV for each encryption operation
4. **Add authentication:** Use authenticated encryption modes like GCM when possible
5. **Constant-time comparisons:** Always use crypto.timingSafeEqual() for comparing security-critical values
6. **Key derivation:** Use appropriate key derivation functions like scrypt, bcrypt, or PBKDF2 for password-based keys
7. **Stay updated:** Keep Node.js updated to get security fixes and support for newer algorithms
8. **Follow standards:** Adhere to established cryptographic standards and protocols

---

References: https://www.w3schools.com/nodejs/nodejs_crypto.asp and gemini