const crypto = require("crypto");

// Hashing is a one-way mathematical function that turns data into a string of nondescript (unmemorable) text that cannot be reversed or decoded.
// Used to keep sensitive information and data secure.

// Properties of hash function
// Deterministic: Same input always produces the same output
// Fixed Length: Output is always the same size regardless of input size
// One-Way: Extremely difficult to reverse the process
// Avalanche Effect: Small changes in input produce significant changes in output

// Create a SHA-256 hash of a string.
const hash = crypto
  .createHash("sha256")
  .update(
    "This will be hashediojiojiojoi iogrjhae pobih eproh apg haepro hpaov harpo vapero h"
  )
  .digest("hex");

console.log("SHA-256 Hash:", hash);

// 'createHash()' -> creates a hash object with the specified algorithm
// 'update()' -> updates the hash content with the given data
// 'digest()' -> calculates the digest and outputs it in the specified format

// Common hash algorithms
// MD5 (not recommended for security-critical applications), use 'md5'
// SHA-1 (not recommended for security-critical applications), use 'sha1'
// SHA-256, use 'sha256'
// SHA-512, use 'sha512'

// Key concepts for Password Security
// 1. Salting: Add a unique random value to each password before hashing
// 2. Key Stretching: Make the hashing process intentionally slow to prevent brute-force attacks
// 3. Work Factor: Control how computationally intensive the hashing process is

// What is a salt?
// A salt is a random string that is unique to each user. It's combined with the password before hashing to ensure that even if two users have the same password, their hashes will be different. This prevents attackers from using precomputed tables (like rainbow tables) to crack multiple passwords at once.
