# Cryptographic Test Vectors

This directory contains authoritative known-answer test vectors for
standardized cryptographic algorithms implemented by CryptoViz.

## Purpose

CryptoViz is an educational cryptography platform. Algorithm output must be
validated against independent, authoritative sources rather than relying only
on implementation-specific round-trip tests.

## Structure

- `aes/` — AES and AES mode vectors
- `des/` — DES and Triple DES vectors
- `sha/` — SHA-family vectors
- `hmac/` — HMAC vectors
- `cmac/` — CMAC vectors
- `kdf/` — PBKDF2 and HKDF vectors
- `ecc/` — ECDSA, Ed25519, Ed448, X25519 and X448 vectors
- `pqc/` — ML-KEM and ML-DSA vectors

## Vector requirements

Every standardized algorithm must have:

1. At least one authoritative known-answer vector.
2. An explicit source and standard.
3. Empty-input coverage where applicable.
4. Multi-block coverage where applicable.
5. Boundary key sizes where applicable.
6. Invalid parameter coverage where applicable.

## Sources

Expected values must be copied from the cited standard or authoritative
validation corpus.

Do not generate expected values using the CryptoViz implementation itself.

## Adding an algorithm

When adding a standardized algorithm:

1. Add its vector suite.
2. Add its coverage entry to `algorithmCoverage.ts`.
3. Include authoritative source metadata.
4. Add edge-case and invalid-parameter coverage.
5. Run the complete test suite locally.

An algorithm without vector coverage must not be merged.