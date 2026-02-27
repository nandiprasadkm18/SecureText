// DOM element references
const encryptButton = document.getElementById('encrypt-button');
const decryptButton = document.getElementById('decrypt-button');
const copyEncryptedButton = document.getElementById('copy-encrypted-button');
const copyDecryptedButton = document.getElementById('copy-decrypted-button');
const alertModal = document.getElementById('alert-modal');
const alertMessage = document.getElementById('alert-message');

// --- Utility Functions ---

// Display a custom message to the user
function showMessage(message, isError = false) {
    alertMessage.textContent = message;
    alertModal.className = `fixed top-5 right-5 text-white py-2 px-4 rounded-lg shadow-lg opacity-100 transform translate-y-0 transition-all duration-300 ${isError ? 'bg-red-500' : 'bg-emerald-500'}`;
    setTimeout(() => {
        alertModal.style.opacity = '0';
        alertModal.style.transform = 'translateY(0.5rem)';
    }, 3000);
}

// Convert a string to an ArrayBuffer
function str2ab(str) {
    return new TextEncoder().encode(str);
}

// Convert an ArrayBuffer to a string
function ab2str(buf) {
    return new TextDecoder().decode(buf);
}

// Convert an ArrayBuffer to a Base64 string
function ab2b64(ab) {
    return btoa(String.fromCharCode.apply(null, new Uint8Array(ab)));
}

// Convert a Base64 string to an ArrayBuffer
function b642ab(b64) {
    const byteString = atob(b64);
    const bytes = new Uint8Array(byteString.length);
    for (let i = 0; i < byteString.length; i++) {
        bytes[i] = byteString.charCodeAt(i);
    }
    return bytes.buffer;
}

// Create a SHA-256 hash of the password for verification
async function getPasswordHash(password) {
    const encoded = str2ab(password);
    return await window.crypto.subtle.digest('SHA-256', encoded);
}

// Compare two ArrayBuffers to see if they are identical
function compareArrayBuffers(buf1, buf2) {
    if (buf1.byteLength !== buf2.byteLength) return false;
    const view1 = new Uint8Array(buf1);
    const view2 = new Uint8Array(buf2);
    for (let i = 0; i < view1.length; i++) {
        if (view1[i] !== view2[i]) return false;
    }
    return true;
}


// --- Core Cryptography Functions ---

// Get a crypto key from a password using PBKDF2
async function getKey(password, salt) {
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        str2ab(password),
        "PBKDF2",
        false,
        ["deriveKey"]
    );
    return window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 100000,
            hash: "SHA-256",
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
}

// Encrypt text using a password and store its hash
async function encryptText(text, password) {
    try {
        const salt = window.crypto.getRandomValues(new Uint8Array(16));
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const passwordHash = await getPasswordHash(password); // Create password hash

        const key = await getKey(password, salt);
        const encryptedContent = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            key,
            str2ab(text)
        );

        // Combine salt, iv, password hash, and encrypted content into a single base64 string
        const combined = new Uint8Array(salt.length + iv.length + passwordHash.byteLength + encryptedContent.byteLength);
        let offset = 0;
        combined.set(salt, offset);
        offset += salt.length;
        combined.set(iv, offset);
        offset += iv.length;
        combined.set(new Uint8Array(passwordHash), offset);
        offset += passwordHash.byteLength;
        combined.set(new Uint8Array(encryptedContent), offset);

        return ab2b64(combined.buffer);

    } catch (error) {
        console.error("Encryption failed:", error);
        showMessage("Encryption failed. See console for details.", true);
        return null;
    }
}

// Decrypt text by first verifying the password hash
async function decryptText(encryptedTextB64, password) {
    try {
        const combined = b642ab(encryptedTextB64);
        
        // Extract salt, iv, stored hash, and encrypted content
        const salt = combined.slice(0, 16);
        const iv = combined.slice(16, 28);
        const storedHash = combined.slice(28, 60); // SHA-256 is 32 bytes
        const encryptedContent = combined.slice(60);

        // Hash the entered password and compare it to the stored hash
        const enteredPasswordHash = await getPasswordHash(password);
        if (!compareArrayBuffers(storedHash, enteredPasswordHash)) {
            showMessage("Decryption failed. The password provided is incorrect.", true);
            return null;
        }

        // If hashes match, proceed with decryption
        const key = await getKey(password, salt);
        const decryptedContent = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            key,
            encryptedContent
        );

        return ab2str(decryptedContent);
    } catch (error) {
        console.error("Decryption failed:", error);
        // This message now primarily handles corrupted data, as the password was already verified.
        showMessage("Decryption failed. The encrypted text may be corrupt.", true);
        return null;
    }
}

// --- Event Listeners ---

// Handle encryption with password validation
encryptButton.addEventListener('click', async () => {
    const text = document.getElementById('encrypt-text').value;
    const password = document.getElementById('encrypt-password').value;
    const output = document.getElementById('encrypt-output');

    if (!text || !password) {
        showMessage("Please provide both text and a password to encrypt.", true);
        return;
    }

    // Check for password length
    if (password.length < 3) {
        showMessage("Password must be at least 8 characters long.", true);
        return;
    }
    
    encryptButton.disabled = true;
    encryptButton.textContent = 'Encrypting...';

    const encrypted = await encryptText(text, password);
    
    if (encrypted) {
        output.value = encrypted;
        copyEncryptedButton.disabled = false;
        showMessage("Encryption successful!", false);
    }

    encryptButton.disabled = false;
    encryptButton.textContent = 'Encrypt Text';
});

// Handle decryption
decryptButton.addEventListener('click', async () => {
    const encryptedText = document.getElementById('decrypt-text').value;
    const password = document.getElementById('decrypt-password').value;
    const output = document.getElementById('decrypt-output');
    
    if (!encryptedText || !password) {
        showMessage("Please provide both encrypted text and a password to decrypt.", true);
        return;
    }

    decryptButton.disabled = true;
    decryptButton.textContent = 'Decrypting...';

    const decrypted = await decryptText(encryptedText, password);

    if (decrypted !== null) { // Check for null, as empty string is a valid decryption
        output.value = decrypted;
        copyDecryptedButton.disabled = false;
        showMessage("Decryption successful!", false);
    }
    
    decryptButton.disabled = false;
    decryptButton.textContent = 'Decrypt Text';
});

// Handle copying encrypted text
copyEncryptedButton.addEventListener('click', () => {
    const output = document.getElementById('encrypt-output');
    const originalText = copyEncryptedButton.textContent;
    output.select();
    try {
        document.execCommand('copy');
        copyEncryptedButton.textContent = 'Copied!';
        showMessage("Encrypted text copied to clipboard.", false);
    } catch (err) {
         showMessage("Failed to copy text.", true);
    }
    setTimeout(() => { copyEncryptedButton.textContent = originalText; }, 2000);
});

// Handle copying decrypted text
copyDecryptedButton.addEventListener('click', () => {
    const output = document.getElementById('decrypt-output');
    const originalText = copyDecryptedButton.textContent;
    output.select();
     try {
        document.execCommand('copy');
        copyDecryptedButton.textContent = 'Copied!';
        showMessage("Decrypted text copied to clipboard.", false);
    } catch (err) {
         showMessage("Failed to copy text.", true);
    }
    setTimeout(() => { copyDecryptedButton.textContent = originalText; }, 2000);
});