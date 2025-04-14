# Java Cryptography Suite: RSA, AES-128, SHA-256

This project is a **from-scratch Java implementation** of core cryptographic primitives: **RSA encryption and signing**, **AES-128 symmetric encryption**, and **SHA-256 hashing**, adhering closely to the specifications in [RFC 8017](https://datatracker.ietf.org/doc/html/rfc8017), [NIST FIPS 197](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf), and [NIST FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).

## 🧠 Features

- **RSA (2048-bit keys)**: Key generation, encryption/decryption, and digital signature support using `BigInteger` math.
- **AES-128**: Fully manual implementation of symmetric encryption—**no hardware acceleration** or library shortcuts.
- **SHA-256**: Bitwise-accurate hashing engine following official NIST specs.
- **Sender/Receiver model**: Demonstrates secure communication using combined encryption/signing.
- **Shell Scripts**: For automated message testing (`tester.sh`, `nc_tester.sh`).

## 🧱 Project Structure

KeyGen/        # RSA key generation and SHA-256 hashing
Sender/        # AES/RSA encryption and signing
Receiver/      # Decryption and signature verification
tester.sh      # Script to automate message sending/receiving
README.md      # This file

## 🔍 File Highlights

- `KeyGen/Keygen.java`: Generates RSA key pairs.
- `Sender/Sender.java`: Encrypts files using AES-128, signs them using RSA.
- `Receiver/Receiver.java`: Verifies the signature and decrypts the file.
- `AES128_Sym.java`: Manual AES cipher core (in both sender and receiver).
- `RSA_Custom.java`: RSA implementation for both encryption and digital signatures.
- `SHA256_Sum.java`: 256-bit hash generator.

## ⚠ Performance Note

AES encryption is **educational** rather than optimized—it is intentionally slow to help with algorithm comprehension. This suite prioritizes transparency over speed.

## 🛠️ Requirements

- Java 8+
- Terminal or shell (for scripts)

## 📚 Educational Value

Perfect for students or engineers seeking a deeper understanding of cryptographic fundamentals and how they interact in secure systems.

## 📎 License

MIT License
