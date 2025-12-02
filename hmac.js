// HMAC ( Hash-based Message Authentication Code )
// HMAC is a specific type of message authentication code (MAC) involving a cryptographic hash function and a secret cryptographic key. It provides both data integrity and authentication.

// When to use HMAC:
// API request verification
// Secure cookies and sessions
// Data integrity checks
// Webhook verification

// HMAC Security Properties
// Message Integrity: Any change to the message will produce a different HMAC
// Authenticity: Only parties with the secret key can generate valid HMACs
// No Encryption: HMAC doesn't encrypt the message, only verifies its integrity

const crypto = require("crypto");

// Secret key
// const secretKey = "mySecretKey";

// Create an HMAC
// const hmac = crypto.createHmac("sha256", secretKey);

// Update with data
// hmac.update("Hello, World!");

// Get the digest
// const hmacDigest = hmac.digest("hex");
// console.log("HMAC:", hmacDigest);

// HMAC for message verification

// Function to create an HMAC for a message
function createSignature(message, key) {
  // 'createHmac' -> crates a HMAC
  // Arguments (algorithm used, secret key know only to sender and reciver)
  const hmac = crypto.createHmac("sha256", key);

  // Updating the HMAC with message, feeding message into HMAC algorithm. Algorithm internally mixes the secret key and message to calculate the hash.
  hmac.update(message);

  // finalizes the calculation and returns resulting message converted to hexadecimal string.
  return hmac.digest("hex");
}

// Function to verify a message's signature
function verifySignature(message, signature, key) {
  // Creating a signature again
  const expectedSignature = createSignature(message, key);

  // 'Buffer.from' -> converts hexadecimal string back into a binary buffer.
  // 'crypto.timingSafeEqual' -> compares two buffers.

  // We could also have used simple '===' but why this 'crypto.timingSafeEqual'?
  // '===' are made for speed and they return false for the first character that wasn't matched. This can lead to a timing attack by attacker.
  // Timing attack -> The attacker can check the response time from your server and pinpoint the first character which didn't match and brute force for that character.
  // 'timingSafeEqual' -> prevents this by ensuring that the comparison always takes the exact same amount of time, regardless of where the difference occur or how long the buffers are. This neutralizes the timing attack vulnerability.

  return crypto.timingSafeEqual(
    Buffer.from(signature, "hex"),
    Buffer.from(expectedSignature, "hex")
  );
}

// Example usage
const secretKey = "verySecretKey";
const message = "Important message to verify";

// Sender creates a signature
const signature = createSignature(message, secretKey);
console.log("Message:", message);
console.log("Signature:", signature);

// Receiver verifies the signature
try {
  const isValid = verifySignature(message, signature, secretKey);
  console.log("Signature valid:", isValid); // true

  // Try with a tampered message
  const isInvalid = verifySignature("Tampered message", signature, secretKey);
  console.log("Tampered message valid:", isInvalid); // false
} catch (error) {
  console.error("Verification error:", error.message);
}

// How the above thing work?
// Sender: uses 'createSignature' to generate the signature and sends the message along with the signature to the receiver.
// Receiver:
// 1. They receive the message and the received signature.
// 2. They run the exact same function using the received message and their own copy of the secret key to generate a new signature and gets a expected signature.
// 3. Secure comparison using 'timingSafeEqual'
// 4. If above step gives true:
//  Message is authenticate (originated from someone who possess the secret key) and integrity (message has not been tampered during transit)
// If false:
// message was altered by a third party, message was send by an unauthorized party that does not possess the secret key.
