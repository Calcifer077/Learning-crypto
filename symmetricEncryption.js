// Symmetric encryption uses the same key for both encryption and decryption.
// It's generally faster than asymmetric encryption and is ideal for:
// 1. Bulk data encryption
// 2. Database encryption
// 3. Filesystem encryption
// 4. Secure messaging (combined with key exchange)

// Common Symmetric Algorithms
// AES-256, ChaCha20, 3DES, Blowfish
// Use AES.

// AES (Advanced Encryption Standard)
const crypto = require("crypto");

// AES-256-CBC
// AES -> widely accepted standard for symmetric encryption
// 256 -> Specifies key size in bits (32 bytes)
// CBC (Cipher Block Chaining) -> The mode of operation. It links the encryption of each data block to the previous one, making the resulting ciphertext highly resistant to simple patterns.

// Function to encrypt data
function encrypt(text, key) {
  // Generate a random initialization vector.
  // Always generate a new random IV for each encryption operation.
  // It is a 16-byte (128-bit) random value required for the CBC mode.
  // The IV ensures that even if you encrypt the exact same message multiple times with the same key, the resulting ciphertext will be different each time. This prevents an attacker from immediately knowing if a message has been repeated (known as a replay attack).
  // The IV does not need to be secret, but it must be unique and random for every encryption operation.
  const iv = crypto.randomBytes(16);

  // Create cipher with AES-256-CBC, creates encryption engine
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);

  // Encrypt the data
  // cipher.update -> encrypts the main body of the message.
  // Arguments -> (text to be encrypted, input format, output format).
  let encrypted = cipher.update(text, "utf8", "hex");
  console.log("ENCRYPTED", encrypted);

  // Finalizes the encryption. Handles any remaining data and applies padding to ensure message length is a multiple of 16 (block size).
  encrypted += cipher.final("hex");

  // Return both the encrypted data and the IV
  return {
    iv: iv.toString("hex"),
    encryptedData: encrypted,
  };
}

// Function to decrypt data
function decrypt(encryptedData, iv, key) {
  // Create decipher
  // Arguments -> (Algorithm, key, IV), they must be same as encryption.
  // IV is converted from string to binary.
  const decipher = crypto.createDecipheriv(
    "aes-256-cbc",
    key,
    Buffer.from(iv, "hex")
  );

  // Decrypt the data
  // Arguments -> (data to be decrypted, input format, output format).
  let decrypted = decipher.update(encryptedData, "hex", "utf8");

  // Automatically removes any padding added during the encryption process.
  decrypted += decipher.final("utf8");

  return decrypted;
}

// Example usage
// Note: In a real application, use a properly generated and securely stored key
// Arguments -> (password, salt, keylen)
const salt = crypto.randomBytes(16).toString("hex");

// Not converting to 'hex' as 'AES-256-CBC' requires 256 bits as key.
const key = crypto.scryptSync("secretPassword", salt, 32); // 32 bytes = 256 bits
const message = "This is a secret message";

// Encrypt
const { iv, encryptedData } = encrypt(message, key);
console.log("Salt:", salt);
console.log("key:", key);
console.log("Original:", message);
console.log("Encrypted:", encryptedData);
console.log("IV:", iv);

// Decrypt
const decrypted = decrypt(encryptedData, iv, key);
console.log("Decrypted:", decrypted);
