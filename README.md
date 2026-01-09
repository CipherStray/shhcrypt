🛡️ shhcrypt (Vibecoded with Gemini 🤖)

"Your secrets, shh...ed by Rust."

   [!CAUTION] IMPORTANT SECURITY NOTICE: This project was developed through "vibecoding" with Gemini (LLM). A recent community audit on Reddit has identified critical security vulnerabilities (Salt/Pepper confusion, Path Traversal risks, and unsafe temp file handling).

   DO NOT USE THIS FOR SENSITIVE DATA. This repository is now a learning journey. I am currently refactoring the code to address these issues manually.

🛠 What is shhcrypt?

shhcrypt started as an experiment to see how far a terminal-based encryption tool could go using AI assistance. It aims to provide a fast, lightweight way to encrypt files and folders using AES-GCM 256-bit and Argon2id.
🔍 Current State:

   🦀 Built with Rust: Leveraging Rust's speed, currently undergoing a complete security hardening.

   🧪 Learning Process: I am actively refactoring the code to fix the issues pointed out by the community.

   🧹 Secure Wipe: The tool includes a 3-pass secure wipe feature (under review for symlink safety).

📥 Installation

Install only for educational or review purposes:
```bash
cargo install --git https://codeberg.org/CipherStray/shhcrypt --force
```
📖 The "Vibecoding" Disclaimer

I want to be 100% transparent: I am a solo developer using LLMs (Gemini) to bridge the gap between ideas and implementation. While the "vibes" were high, the technical depth of cryptography requires manual verification and rigorous testing.

The Refactoring Roadmap:

   [ ] Implement proper per-password Salt (fixing static Pepper).

   [ ] Ensure safe temp file handling (no plaintext on disk).

   [ ] Fix Path Traversal risks during directory extraction.

   [ ] Add a comprehensive #[test] suite.

📬 Contact

If you have technical advice or want to discuss the refactoring process:

    Email: cipherstray@proton.me

Developed with ❤️ by CipherStray
