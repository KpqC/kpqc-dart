# Third-party notices

This package includes code from the following upstream reference
implementations:

- [AIMer](https://github.com/samsungsds-opensource/AIMer/tree/5f786ccd572d7bc2f92cf9f662e2c6cab2c45fa2), Copyright (c) 2022–2026 SAMSUNG SDS
- [HAETAE](https://github.com/CryptoLabInc/HAETAE/tree/3130c9e26670a3406af31e2aa73ef73b223acf49), Copyright (c) 2026 Team HAETAE
- [NTRU+](https://github.com/ntruplus/ntruplus/tree/9b607231246fc2eb8b93634ff4bb94ecf1f62c75), Copyright (c) 2024–2026 NTRU+ TEAM
- [SMAUG-T](https://github.com/CryptoLabInc/SMAUG-T/tree/3cd19f3c8531a95c06010846a832b0e8ece4f939), Copyright (c) 2026 Team SMAUG-T

These components are distributed under the MIT License. Their original license
texts are included under `vendor/` and with the package.

## Local adaptations

KpqC replaces reference test randomness with operating-system entropy,
propagates failures across the native boundary, and isolates symbols for each
parameter set. SHA-3 contexts use embedded storage and sensitive state is
cleared where the native API permits. The AIMer NIST notice is preserved in
the vendored license; NIST is acknowledged as the source identified there.
