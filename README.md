# SecureText 🛡️

SecureText is a simple, yet powerful, client-side text encryption and decryption tool. It allows you to protect your sensitive messages using industry-standard cryptographic algorithms, all within your web browser.

## ✨ Key Features

- **Client-Side Processing**: All encryption and decryption happen locally in your browser. Your sensitive data and passwords never leave your machine.
- **AES-GCM Encryption**: Uses 256-bit AES-GCM (Galois/Counter Mode) for robust security and data integrity.
- **PBKDF2 Key Derivation**: Derives encryption keys from passwords using PBKDF2 with 100,000 iterations of SHA-256 and a random salt.
- **Password Hashing**: Stores a SHA-256 hash of the password within the encrypted message to provide immediate feedback on incorrect passwords.
- **Clean & Responsive UI**: Built with Tailwind CSS for a modern, mobile-friendly experience.

## 🚀 How to Use

### Encrypting a Message
1. Type or paste your message into the **Original Text** area.
2. Enter a secret password (minimum 8 characters) in the **Secret Key / Password** field.
3. Click **Encrypt Text**.
4. Copy the resulting **Encrypted Output** and share it securely.

### Decrypting a Message
1. Paste the encrypted code into the **Encrypted Text** area.
2. Enter the corresponding password in the **Secret Key / Password** field.
3. Click **Decrypt Text**.
4. Your original message will appear in the **Decrypted Original Text** area.

## 🛠️ Tech Stack

- **HTML5**: Semi-semantic structure.
- **Tailwind CSS**: Modern utility-first styling.
- **Vanilla JavaScript**: Logic and UI interaction.
- **Web Crypto API**: High-performance, browser-native cryptographic operations.

## 🛡️ Security Details

- **Algorithm**: `AES-GCM` (256-bit)
- **Key Derivation**: `PBKDF2` with `SHA-256`
- **Iterations**: `100,000`
- **Components included in output**: `[Salt(16b)][IV(12b)][PasswordHash(32b)][EncryptedData]`

## 📦 Local Setup

Since SecureText is a static web application, no installation is required.

1. Clone or download the repository.
2. Open `index.html` in any modern web browser.

---

*Note: For maximum security, always use strong, unique passwords and be cautious when sharing encrypted data over insecure channels.*
