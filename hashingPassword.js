const crypto = require("crypto");

function hashPassword(password) {
  // creating randomBytes
  const salt = crypto.randomBytes(16).toString("hex");

  // Creating hash.
  // Arguments (password provided by user, salt (random bytes), key length in bytes)
  // Than we convert it to hexadecimal string.
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");

  return { salt, hash };
}

// Doing the same thing as above and creating a hash.
// If the hash created by us and provided to the function are same than both passwords (feeded by user just now, the one which was used to made original hash) are correct
function verifyPassword(password, salt, hash) {
  const hashedPassword = crypto.scryptSync(password, salt, 64).toString("hex");
  return hashedPassword === hash;
}

// Example usage
const password = "mySecurePassword";

// Hash the password for storage
const { salt, hash } = hashPassword(password);
console.log("Salt:", salt);
console.log("Hash:", hash);

// Verify a login attempt
const isValid = verifyPassword(password, salt, hash);
console.log("Password valid:", isValid); // true

const isInvalid = verifyPassword("wrongPassword", salt, hash);
console.log("Wrong password valid:", isInvalid); // false

// For production, use libraries like bcrpt or argon2 for things like secure password handling.
