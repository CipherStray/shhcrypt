# 🛡️ shhcrypt

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/CipherStray/shhcrypt/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-v1.70+-orange.svg)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/platform-linux-lightgrey.svg?logo=linux&logoColor=white)](https://github.com/CipherStray/shhcrypt)
[![Security](https://img.shields.io/badge/security-memory--safe-brightgreen.svg)](https://www.rust-lang.org/)
[![TUI](https://img.shields.io/badge/interface-TUI-blueviolet.svg)](https://github.com/CipherStray/shhcrypt)

**Memory-safe file encryption vault for the terminal.** `shhcrypt` combines **Argon2id** password hashing with **AES-GCM 256-bit** encryption to ensure your data stays private. No logs, no tracking, just pure encryption.

---

## 🛠 What is shhcrypt?

`shhcrypt` is a modern, high-performance command-line tool designed to keep your sensitive data locked away from prying eyes. Unlike standard tools, it prioritizes **privacy** and **secure deletion** of original files.

### 🔍 Core Features Explained:

* **🛡️ Military-Grade Encryption:** Uses `AES-256-GCM` (Galois/Counter Mode). This doesn't just encrypt; it also checks if the file has been tampered with.
* **🔑 Brute-Force Shield:** Uses `Argon2id` (winner of the Password Hashing Competition). It makes it incredibly slow and expensive for attackers to guess your password.
* **🧹 3-Pass Secure Wipe:** When you encrypt a file, `shhcrypt` doesn't just delete the original. It overwrites it with random data 3 times before removal, making it nearly impossible to recover.
* **📦 Directory Vaults:** Can handle entire folders. It packs them into a compressed `.shh` vault automatically.
* **💨 Zero-Dependency Feel:** Built with Rust, meaning it's fast, lightweight, and won't crash due to memory leaks.

---

Install directly using Cargo (Rust's package manager):
## 🐧 Optimized for Linux

`shhcrypt` is designed to be a lightweight, zero-bloat security tool for the Linux terminal.

### 🚀 Fast Install

```bash
cargo install --git https://github.com/CipherStray/shhcrypt --force
```
After installation, simply type shhcrypt in your terminal to start.
📖 How to Use

 1. Launch: Type shhcrypt in any terminal.

 2. TARGET: Enter the path to your file or folder (e.g., Documents/my_secrets).

 3. KEY: Enter your secure password (it will stay hidden while you type).

 4. Automatic Detection:

  If you select a normal file/folder, it will ENCRYPT it into a .shh file.

  If you select a .shh file, it will DECRYPT it back to its original form.

  ⚠️ Warning: The original file is securely wiped after the process. Always remember your password; there is no recovery option for lost keys.

🔒 Security Specifications

  Symmetric Encryption: AES-256-GCM (Authenticated Encryption)

  Key Derivation (KDF): Argon2id (World-class security)

  Memory Safety: Powered by Rust Standard

  Secure Erasure: 3-Pass Random Overwrite

  Data Integrity: AEAD Verification (Anti-tampering)

📜 License

This project is licensed under the MIT License. It's open-source and free to use.

Developed with ❤️ by CipherStray
