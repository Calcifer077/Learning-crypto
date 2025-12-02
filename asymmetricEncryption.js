// Asymmetric Encryption
// Asymmetric encryption (public-key cryptography) uses a pair of mathematically related keys:
// Public Key: Can be shared publicly, used for encryption and for verifying digital signatures.
// Private Key: Must be kept secret, used for decryption, and for creating digital signatures.

// Common Use Cases
// 1. Secure key exchange (e.g., TLS/SSL handshake)
// 2. Digital signatures
// 3. Email encryption (PGP/GPG)
// 4. Blockchain and cryptocurrencies

// How Asymmetric Encryption works?
// The primary use of this system is to ensure confidentiality—that only the intended recipient can read a message.

// 1. Encryption
// Sender Action: The sender wants to send a secret message to Alice. They first obtain Alice's Public Key.

// The sender uses Alice's Public Key to encrypt the plaintext message.

// The result is ciphertext, which is sent to Alice.

// 2. Decryption
// Receiver Action (Alice): Alice receives the ciphertext.

// Alice uses her own Private Key to decrypt the message.

// Because the two keys are linked, Alice's Private Key is the only key that can reverse the encryption done by her Public Key, successfully recovering the original plaintext.

// Analogy: Think of a public key as a mailbox slot (anyone can put a message in) and the private key as the key to the mailbox (only the owner can open and retrieve the message).

// Performance Note: Asymmetric encryption is much slower than symmetric encryption.

// For encrypting large amounts of data, use a hybrid approach:

// 1. Generate a random symmetric key
// 2. Encrypt your data with the symmetric key
// 3. Encrypt the symmetric key with the recipient's public key
// 4. Send both the encrypted data and encrypted key

// RSA (Rivest-Shamir-Adleman)
const crypto = require("crypto");

// Generate RSA key pair
function generateKeyPair() {
  // 'rsa' is the algorithm used, and 2048 is size of key which is the current recommendation.
  return crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048, // Key size in bits
    // Below are both public and private keys with their formats and types.
    // 'pem' -> Privacy enhanced mail is a standard text-based format for storing and transferring cryptographic keys.
    // 'spki' -> Subject public key Info is a common standard for encoding public key
    // 'pkcs8' -> standard format for encoding private keys
    publicKeyEncoding: {
      type: "spki",
      format: "pem",
    },
    privateKeyEncoding: {
      type: "pkcs8",
      format: "pem",
    },
  });
}

// Encrypt with public key
function encryptWithPublicKey(text, publicKey) {
  // Converts given text to binary.
  const buffer = Buffer.from(text, "utf8");

  // Core functino for encrypting data using public key.
  const encrypted = crypto.publicEncrypt(
    {
      key: publicKey,
      // padding adds random data before encryption to ensure the same plaintext encrypts to a different ciphertext every time.
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    },
    buffer
  );

  // Converted back to string.
  return encrypted.toString("base64");
}

// Decrypt with private key
function decryptWithPrivateKey(encryptedText, privateKey) {
  const buffer = Buffer.from(encryptedText, "base64");

  // core function for decrypting data using the private key.
  const decrypted = crypto.privateDecrypt(
    {
      key: privateKey,
      // uses the same padding scheme as used during the encryption process. If the padding schemes don't match, the decryption will fail.
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    },
    buffer
  );

  // Converted to 'utf-8' text encoding.
  return decrypted.toString("utf8");
}

// Generate keys
const { publicKey, privateKey } = generateKeyPair();
console.log("Public Key:", publicKey.substring(0, 50) + "...");
console.log("Private Key:", privateKey.substring(0, 50) + "...");

// Example usage
const message = "This message is encrypted with RSA";
const encrypted = encryptWithPublicKey(message, publicKey);
console.log("Encrypted:", encrypted.substring(0, 50) + "...");

const decrypted = decryptWithPrivateKey(encrypted, privateKey);
console.log("Decrypted:", decrypted);
