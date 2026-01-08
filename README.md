# 🛡️ shhcrypt
"Your secrets, shh...ed by Rust."

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/CipherStray/shhcrypt/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-v1.70+-orange.svg)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/platform-linux-lightgrey.svg?logo=linux&logoColor=white)](https://github.com/CipherStray/shhcrypt)
[![Security](https://img.shields.io/badge/security-memory--safe-brightgreen.svg)](https://www.rust-lang.org/)
[![Mirrors](https://img.shields.io/badge/mirrors-GitLab%20%7C%20Codeberg-orange.svg)](https://codeberg.org/CipherStray/shhcrypt)

**Memory-safe file encryption vault for the terminal.** `shhcrypt` combines **Argon2id** password hashing with **AES-GCM 256-bit** encryption to ensure your data stays private. No logs, no tracking, just pure encryption.

---

## 🛠 What is shhcrypt?

`shhcrypt` is a modern, high-performance command-line tool designed to keep your sensitive data locked away from prying eyes. Unlike standard tools, it prioritizes **privacy** and **secure deletion** of original files.

### 🔍 Core Features Explained:

* **🛡️ Military-Grade Encryption:** Uses `AES-256-GCM`. This doesn't just encrypt; it also checks if the file has been tampered with.
* **🔑 Brute-Force Shield:** Uses `Argon2id` (winner of the Password Hashing Competition). It makes it incredibly slow for attackers to guess your password.
* **🧹 3-Pass Secure Wipe:** After encryption, `shhcrypt` overwrites the original file with random data 3 times before removal.
* **📦 Directory Vaults:** Automatically packs and compresses entire folders into `.shh` vaults.
* **💨 Zero-Dependency Feel:** Built with Rust for maximum speed and memory safety.

---

## 📥 Installation

Install using Cargo. Choose the source that fits your privacy needs:


# From GitHub (Primary)
```bash
cargo install --git https://github.com/CipherStray/shhcrypt --force
```

# From GitLab (Secure Mirror)
```bash
cargo install --git https://gitlab.com/CipherStray/shhcrypt --force
```

# From Codeberg (Privacy-Focused Mirror)
```bash
cargo install --git https://codeberg.org/CipherStray/shhcrypt --force
```
After installation, simply type shhcrypt in your terminal to start.

## 📖 How to Use

1. **Launch:** Type `shhcrypt` in your terminal.
2. **TARGET:** Just **drag and drop** your file or folder into the terminal window (or type the path).
3. **KEY:** Enter your secure password (it stays hidden while you type).
4. **Auto-Detection:** - Normal file/folder ➔ **ENCRYPT** (to `.shh`)
   - `.shh` file ➔ **DECRYPT** (to original)
 
   [!WARNING] The original file is securely wiped after the process. There is no "Forgot Password" or "Data Recovery" option. Lose your key, lose your data.

---

### 🚀 Technical Highlights

| Aspect | Implementation | Impact |
| :--- | :--- | :--- |
| **Core** | Rust v1.70+ | Zero memory leaks and high-speed execution. |
| **Cipher** | AES-GCM-256 | Military-grade encryption with integrity checks. |
| **Vaults** | Zstd / Tar | High compression ratio for directory encryption. |
| **Hardening** | Argon2id | Industry-standard protection against brute-force. |
| **Anti-Forensics** | 3-Pass Wipe | Securely shreds files, making recovery impossible. |

---

## 💬 Connect Safely

I'm open to collaboration, bug reports, and tech discussions. To maintain high privacy, I use **SimpleX Chat**—the only platform that doesn't use user IDs or collect metadata.

| Reach Me | Link |
| :--- | :--- |
| **SimpleX** | [🔒 Start a Secure Chat](https://smp10.simplex.im/a#uoMWPbnbK6znqtoTxpjA7bmbH0qpKKggkzdwRvxD-7I) |

> [!IMPORTANT]
> When you click the link, you'll see my welcome message. Feel free to leave a note; I'll get back to you once I review the request.

---
Developed with ❤️ by CipherStray
