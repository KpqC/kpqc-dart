# KpqC

KpqC provides safe, synchronous Dart APIs for the AIMer and HAETAE signature
schemes and the NTRU+ and SMAUG-T key encapsulation mechanisms (KEMs).

## Runtime support

- Dart 3.13 or newer
- Dart VM on Linux, macOS, and Windows
- JavaScript compilation with the Dart toolchain

All algorithm cores are implemented in portable Dart. The package has no
native build step or C toolchain dependency.

## Install

```sh
dart pub add kpqc
```

KpqC 0.2.0 uses AIM3. AIMer keys and signatures from the 0.1.x AIM2 release
are not compatible with this version.

## Available schemes

| Algorithm | Type | Exports |
| --- | --- | --- |
| **AIMer** | Signature | `aimer128f`, `aimer128s`, `aimer192f`, `aimer192s`, `aimer256f`, `aimer256s` |
| **HAETAE** | Signature | `haetae2`, `haetae3`, `haetae5` |
| **NTRU+** | KEM | `ntruplus768`, `ntruplus864`, `ntruplus1152` |
| **SMAUG&#8209;T** | KEM | `smaugt128`, `smaugt192`, `smaugt256`, `timer` |

Importing an algorithm family keeps the entry point focused:

```dart
import 'dart:convert';
import 'dart:typed_data';

import 'package:kpqc/aimer.dart';

void main() {
  final payload = Uint8List.fromList(utf8.encode('release-manifest:v3'));
  final keys = aimer128f.generateKeyPair();
  try {
    final proof = aimer128f.sign(payload, keys.secretKey);
    if (!aimer128f.verify(payload, proof, keys.publicKey)) {
      throw StateError('Signature verification failed');
    }
  } finally {
    keys.dispose();
  }
}
```

### Signature contexts

AIMer and HAETAE accept an optional context. A context separates signatures
created for different application purposes and may contain up to 255 bytes.

```dart
import 'dart:convert';
import 'dart:typed_data';

import 'package:kpqc/haetae.dart';

void main() {
  final payload = Uint8List.fromList(utf8.encode('account=42'));
  final context = Uint8List.fromList(utf8.encode('audit-record'));
  final keys = haetae3.generateKeyPair();
  try {
    final signature = haetae3.sign(
      payload,
      keys.secretKey,
      context: context,
    );
    final valid = haetae3.verify(
      payload,
      signature,
      keys.publicKey,
      context: context,
    );
    print(valid); // true
  } finally {
    keys.dispose();
  }
}
```

Verification fails when the supplied context does not match the one used for
signing.

### KEM

A KEM creates a shared secret for a sender and a recipient. The public key may
be distributed; the secret key and resulting shared secret must remain private.

```dart
import 'dart:typed_data';

import 'package:kpqc/smaugt.dart';

void main() {
  final recipient = smaugt192.generateKeyPair();
  try {
    final outbound = smaugt192.encapsulate(recipient.publicKey);
    try {
      // Send outbound.ciphertext to the recipient.
      final inboundSecret = smaugt192.decapsulate(
        outbound.ciphertext,
        recipient.secretKey,
      );
      try {
        print(_sameBytes(inboundSecret, outbound.sharedSecret)); // true
      } finally {
        inboundSecret.fillRange(0, inboundSecret.length, 0);
      }
    } finally {
      outbound.dispose();
    }
  } finally {
    recipient.dispose();
  }
}

bool _sameBytes(Uint8List left, Uint8List right) {
  if (left.length != right.length) return false;
  var difference = 0;
  for (var index = 0; index < left.length; index++) {
    difference |= left[index] ^ right[index];
  }
  return difference == 0;
}
```

## Imports

Each family has a dedicated library:

```dart
import 'package:kpqc/aimer.dart';
import 'package:kpqc/haetae.dart';
import 'package:kpqc/ntruplus.dart';
import 'package:kpqc/smaugt.dart';
```

All named algorithms are also exported from the package root:

```dart
import 'package:kpqc/kpqc.dart';

final SignatureAlgorithm signer = aimer192f;
final KeyEncapsulationAlgorithm kem = ntruplus864;
```

## Data and failures

Inputs and outputs use `Uint8List`. Each algorithm exposes an `id` and a
`sizes` value. Incorrect key or ciphertext lengths throw
`ArgumentError`; implementation failures throw `KpqCException`. Signature
verification returns `false` for an invalid signature.

### Parameter sizes

All sizes are in bytes.

#### Signatures

| Algorithm | Public key | Secret key | Signature |
| --- | ---: | ---: | ---: |
| `aimer128f` | 32 | 48 | 6,944 |
| `aimer128s` | 32 | 48 | 4,704 |
| `aimer192f` | 48 | 72 | 15,408 |
| `aimer192s` | 48 | 72 | 10,320 |
| `aimer256f` | 64 | 96 | 31,360 |
| `aimer256s` | 64 | 96 | 20,224 |
| `haetae2` | 992 | 1,408 | 1,474 |
| `haetae3` | 1,472 | 2,112 | 2,349 |
| `haetae5` | 2,080 | 2,752 | 2,948 |

#### KEMs

| Algorithm | Public key | Secret key | Ciphertext | Shared secret |
| --- | ---: | ---: | ---: | ---: |
| `ntruplus768` | 1,152 | 2,336 | 1,152 | 32 |
| `ntruplus864` | 1,296 | 2,624 | 1,296 | 32 |
| `ntruplus1152` | 1,728 | 3,488 | 1,728 | 32 |
| `smaugt128` | 672 | 832 | 672 | 32 |
| `smaugt192` | 1,088 | 1,312 | 992 | 32 |
| `smaugt256` | 1,440 | 1,728 | 1,376 | 32 |
| `timer` | 672 | 832 | 608 | 32 |

Methods reject values of the wrong size. Signature verification returns `false`
for an invalid signature. NTRU+ rejects an invalid ciphertext. SMAUG-T performs
implicit rejection and returns a replacement secret instead; that value will
not equal the sender's shared secret.

## Known-answer tests

The portable Dart implementations are tested against the known-answer vectors
in [KpqC/kpqc-test-vectors at commit d75490bf824f](https://github.com/KpqC/kpqc-test-vectors/tree/d75490bf824faa4b148cd0b901a2eb13198fe0da).
The test suite validates all 1,600 records across every supported parameter
set. AIMer signing is computationally expensive in portable Dart, so a full
known-answer test run can take considerably longer than the regular tests.

With `kpqc-test-vectors` checked out beside `kpqc-dart`, run:

```sh
KPQC_TEST_VECTORS=../kpqc-test-vectors dart test \
  test/aimer_kat_test.dart \
  test/haetae_kat_test.dart \
  test/ntruplus_kat_test.dart \
  test/smaugt_kat_test.dart
```

## Distribution

The published package contains portable Dart implementations of AIMer, HAETAE,
NTRU+, and SMAUG-T. No native libraries are downloaded or compiled during
installation.

`KeyPair.dispose()` and `EncapsulatedSecret.dispose()` overwrite their secret
byte lists on a best-effort basis. The caller is responsible for clearing the
list returned directly by `decapsulate`.

## Building from source

The Dart SDK is the only build dependency required for normal development:

```sh
dart pub get
dart analyze
dart test
```

## Security

The algorithm cores are portable Dart adaptations of the upstream reference
implementations. This package has not received an independent security audit
and does not provide a constant-time execution guarantee. Assess those
constraints before using it with sensitive production keys.

Third-party licenses and attributions are listed in
[THIRD_PARTY_NOTICES.md](https://github.com/KpqC/kpqc-dart/blob/main/THIRD_PARTY_NOTICES.md).
