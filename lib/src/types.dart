import 'dart:typed_data';

import 'internal/aimer_core.dart';
import 'internal/haetae_core.dart';
import 'internal/haetae_params.dart';
import 'internal/ntruplus_core.dart';
import 'internal/ntruplus_parameters.dart';
import 'internal/smaugt_core.dart';

part 'error.dart';
part 'algorithms/aimer.dart';
part 'algorithms/haetae.dart';
part 'algorithms/ntruplus.dart';
part 'algorithms/smaugt.dart';

typedef _KeyPairResult = ({Uint8List publicKey, Uint8List secretKey});
typedef _EncapsulationResult = ({Uint8List ciphertext, Uint8List sharedSecret});
typedef _KeyPairFunction = _KeyPairResult Function();
typedef _SignFunction = Uint8List Function(
  Uint8List message,
  Uint8List secretKey,
  Uint8List context,
);
typedef _VerifyFunction = bool Function(
  Uint8List message,
  Uint8List signature,
  Uint8List publicKey,
  Uint8List context,
);
typedef _EncapsulateFunction = _EncapsulationResult Function(
  Uint8List publicKey,
);
typedef _DecapsulateFunction = Uint8List Function(
  Uint8List ciphertext,
  Uint8List secretKey,
);

/// A generated public and secret key pair.
final class KeyPair {
  KeyPair._(this.publicKey, this.secretKey);

  /// Public key bytes suitable for distribution.
  final Uint8List publicKey;

  /// Secret key bytes.
  ///
  /// Call [dispose] after use to overwrite this list on a best-effort basis.
  final Uint8List secretKey;

  bool _disposed = false;

  /// Overwrites [secretKey] with zeroes.
  void dispose() {
    if (_disposed) return;
    _wipe(secretKey);
    _disposed = true;
  }

  @override
  String toString() =>
      'KeyPair(publicKey: Uint8List(${publicKey.length}), secretKey: [REDACTED])';
}

/// The result of a KEM operation.
final class EncapsulatedSecret {
  EncapsulatedSecret._(this.ciphertext, this.sharedSecret);

  /// Ciphertext to send to the holder of the secret key.
  final Uint8List ciphertext;

  /// Shared secret bytes.
  ///
  /// Call [dispose] after use to overwrite this list on a best-effort basis.
  final Uint8List sharedSecret;

  bool _disposed = false;

  /// Overwrites [sharedSecret] with zeroes.
  void dispose() {
    if (_disposed) return;
    _wipe(sharedSecret);
    _disposed = true;
  }

  @override
  String toString() =>
      'EncapsulatedSecret(ciphertext: Uint8List(${ciphertext.length}), '
      'sharedSecret: [REDACTED])';
}

/// Byte sizes for a signature parameter set.
final class SignatureSizes {
  /// Creates a signature size description.
  const SignatureSizes({
    required this.publicKey,
    required this.secretKey,
    required this.signature,
  });

  /// Public key size in bytes.
  final int publicKey;

  /// Secret key size in bytes.
  final int secretKey;

  /// Detached signature size in bytes.
  final int signature;

  @override
  String toString() =>
      'SignatureSizes(publicKey: $publicKey, secretKey: $secretKey, '
      'signature: $signature)';
}

/// Byte sizes for a KEM parameter set.
final class KemSizes {
  /// Creates a KEM size description.
  const KemSizes({
    required this.publicKey,
    required this.secretKey,
    required this.ciphertext,
    required this.sharedSecret,
  });

  /// Public key size in bytes.
  final int publicKey;

  /// Secret key size in bytes.
  final int secretKey;

  /// Ciphertext size in bytes.
  final int ciphertext;

  /// Shared secret size in bytes.
  final int sharedSecret;

  @override
  String toString() =>
      'KemSizes(publicKey: $publicKey, secretKey: $secretKey, '
      'ciphertext: $ciphertext, sharedSecret: $sharedSecret)';
}

/// A signature algorithm and parameter set.
final class SignatureAlgorithm {
  const SignatureAlgorithm._({
    required this.id,
    required this.sizes,
    required this._keyPair,
    required this._sign,
    required this._verify,
  });

  /// Stable algorithm identifier.
  final String id;

  /// Parameter sizes in bytes.
  final SignatureSizes sizes;

  final _KeyPairFunction _keyPair;
  final _SignFunction _sign;
  final _VerifyFunction _verify;

  /// Generates a new public and secret key pair using operating-system entropy.
  KeyPair generateKeyPair() {
    final generated = _keyPair();
    _requireCoreLength('public key', generated.publicKey, sizes.publicKey);
    _requireCoreLength('secret key', generated.secretKey, sizes.secretKey);
    return KeyPair._(generated.publicKey, generated.secretKey);
  }

  /// Creates a detached signature.
  ///
  /// [context] separates signatures created for different application
  /// purposes and may contain at most 255 bytes.
  Uint8List sign(Uint8List message, Uint8List secretKey, {Uint8List? context}) {
    _requireLength('secretKey', secretKey.length, sizes.secretKey);
    final actualContext = context ?? Uint8List(0);
    _requireContext(actualContext);

    final signature = _sign(message, secretKey, actualContext);
    _requireCoreLength('signature', signature, sizes.signature);
    return signature;
  }

  /// Verifies a detached signature.
  ///
  /// Returns `false` for an invalid or incorrectly sized signature.
  bool verify(
    Uint8List message,
    Uint8List signature,
    Uint8List publicKey, {
    Uint8List? context,
  }) {
    _requireLength('publicKey', publicKey.length, sizes.publicKey);
    final actualContext = context ?? Uint8List(0);
    _requireContext(actualContext);
    if (signature.length != sizes.signature) return false;

    return _verify(message, signature, publicKey, actualContext);
  }

  @override
  String toString() => id;
}

/// A KEM algorithm and parameter set.
final class KeyEncapsulationAlgorithm {
  const KeyEncapsulationAlgorithm._({
    required this.id,
    required this.sizes,
    required this._keyPair,
    required this._encapsulate,
    required this._decapsulate,
  });

  /// Stable algorithm identifier.
  final String id;

  /// Parameter sizes in bytes.
  final KemSizes sizes;

  final _KeyPairFunction _keyPair;
  final _EncapsulateFunction _encapsulate;
  final _DecapsulateFunction _decapsulate;

  /// Generates a new public and secret key pair using operating-system entropy.
  KeyPair generateKeyPair() {
    final generated = _keyPair();
    _requireCoreLength('public key', generated.publicKey, sizes.publicKey);
    _requireCoreLength('secret key', generated.secretKey, sizes.secretKey);
    return KeyPair._(generated.publicKey, generated.secretKey);
  }

  /// Encapsulates a fresh shared secret for [publicKey].
  EncapsulatedSecret encapsulate(Uint8List publicKey) {
    _requireLength('publicKey', publicKey.length, sizes.publicKey);
    try {
      final encapsulated = _encapsulate(publicKey);
      _requireCoreLength(
        'ciphertext',
        encapsulated.ciphertext,
        sizes.ciphertext,
      );
      _requireCoreLength(
        'shared secret',
        encapsulated.sharedSecret,
        sizes.sharedSecret,
      );
      return EncapsulatedSecret._(
        encapsulated.ciphertext,
        encapsulated.sharedSecret,
      );
    } on StateError {
      throw KpqCException('encapsulation', -1);
    }
  }

  /// Recovers a shared secret from [ciphertext] and [secretKey].
  ///
  /// NTRU+ reports a modified ciphertext as an error. SMAUG-T uses implicit
  /// rejection and returns a replacement secret instead.
  Uint8List decapsulate(Uint8List ciphertext, Uint8List secretKey) {
    _requireLength('ciphertext', ciphertext.length, sizes.ciphertext);
    _requireLength('secretKey', secretKey.length, sizes.secretKey);
    try {
      final sharedSecret = _decapsulate(ciphertext, secretKey);
      _requireCoreLength('shared secret', sharedSecret, sizes.sharedSecret);
      return sharedSecret;
    } on StateError {
      throw KpqCException('decapsulation', -1);
    }
  }

  @override
  String toString() => id;
}

void _requireLength(String input, int actual, int expected) {
  if (actual != expected) {
    throw ArgumentError.value(
      actual,
      input,
      '$input must be $expected bytes, received $actual',
    );
  }
}

void _requireContext(Uint8List context) {
  if (context.length > 255) {
    throw ArgumentError.value(
      context.length,
      'context',
      'context cannot exceed 255 bytes, received ${context.length}',
    );
  }
}

void _requireCoreLength(String output, Uint8List bytes, int expected) {
  if (bytes.length != expected) {
    throw StateError(
      'Cryptographic core returned an invalid $output size: '
      'expected $expected, received ${bytes.length}',
    );
  }
}

void _wipe(Uint8List bytes) => bytes.fillRange(0, bytes.length, 0);
