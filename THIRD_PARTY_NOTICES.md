# Third-party notices

The portable Dart algorithm cores are adapted from the following upstream
reference implementations:

- [AIMer](https://github.com/samsungsds-opensource/AIMer/tree/734cc76fa4695ca8c8eaa070508db8ff62205e68), Copyright (c) 2022–2026 SAMSUNG SDS
- [HAETAE](https://github.com/CryptoLabInc/HAETAE/tree/743c31df48183fc8c8a39a4f50a634da1c4af03a), Copyright (c) 2026 Team HAETAE
- [NTRU+](https://github.com/ntruplus/ntruplus/tree/3991b2ae08d6f0008d37e41b8aceaaab27b4ec89), Copyright (c) 2024–2026 NTRU+ TEAM
- [SMAUG-T](https://github.com/CryptoLabInc/SMAUG-T/tree/bbc463cd788eae36c6d155cef667ac9dbd9054cd), Copyright (c) 2026 Team SMAUG-T

These adaptations are distributed under the MIT License. The corresponding
license texts are included in the `LICENSES/` directory.

## Local adaptations

KpqC replaces reference test randomness with operating-system entropy and
adapts the reference algorithms to Dart with explicit fixed-width arithmetic
and byte ordering. Public APIs validate all key, signature, and ciphertext
sizes. Secret values exposed as mutable byte lists can be overwritten by the
caller, and the provided result objects offer best-effort disposal helpers.
