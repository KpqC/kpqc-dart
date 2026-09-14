import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:meta/meta.dart' show RecordUse;

part 'error.dart';
part 'algorithms/aimer.dart';
part 'algorithms/haetae.dart';
part 'algorithms/ntruplus.dart';
part 'algorithms/smaugt.dart';
part 'native_bindings.dart';

const _allocationFailure = -2;

typedef _KeyPairFunction = int Function(
  Pointer<Uint8> publicKey,
  Pointer<Uint8> secretKey,
);
typedef _SignFunction = int Function(
  Pointer<Uint8> signature,
  Pointer<Size> signatureLength,
  Pointer<Uint8> message,
  int messageLength,
  Pointer<Uint8> context,
  int contextLength,
  Pointer<Uint8> secretKey,
);
typedef _VerifyFunction = int Function(
  Pointer<Uint8> signature,
  int signatureLength,
  Pointer<Uint8> message,
  int messageLength,
  Pointer<Uint8> context,
  int contextLength,
  Pointer<Uint8> publicKey,
);
typedef _EncapsulateFunction = int Function(
  Pointer<Uint8> ciphertext,
  Pointer<Uint8> sharedSecret,
  Pointer<Uint8> publicKey,
);
typedef _DecapsulateFunction = int Function(
  Pointer<Uint8> sharedSecret,
  Pointer<Uint8> ciphertext,
  Pointer<Uint8> secretKey,
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

/// The result of a key-encapsulation operation.
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

/// Byte sizes for a key-encapsulation parameter set.
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
    final publicKey = calloc<Uint8>(sizes.publicKey);
    final secretKey = calloc<Uint8>(sizes.secretKey);
    try {
      final status = _keyPair(publicKey, secretKey);
      if (status != 0) {
        throw KpqCException('key generation', status);
      }
      return KeyPair._(
        _copyFromNative(publicKey, sizes.publicKey),
        _copyFromNative(secretKey, sizes.secretKey),
      );
    } finally {
      _wipeNative(secretKey, sizes.secretKey);
      calloc.free(secretKey);
      calloc.free(publicKey);
    }
  }

  /// Creates a detached signature.
  ///
  /// [context] separates signatures created for different application
  /// purposes and may contain at most 255 bytes.
  Uint8List sign(Uint8List message, Uint8List secretKey, {Uint8List? context}) {
    _requireLength('secretKey', secretKey.length, sizes.secretKey);
    final actualContext = context ?? Uint8List(0);
    _requireContext(actualContext);

    final signature = calloc<Uint8>(sizes.signature);
    final signatureLength = calloc<Size>();
    final nativeMessage = _copyToNative(message);
    final nativeContext = _copyToNative(actualContext);
    final nativeSecretKey = _copyToNative(secretKey);
    try {
      final status = _sign(
        signature,
        signatureLength,
        nativeMessage,
        message.length,
        nativeContext,
        actualContext.length,
        nativeSecretKey,
      );
      if (status != 0) {
        throw KpqCException('signing', status);
      }
      final actualLength = signatureLength.value;
      if (actualLength != sizes.signature) {
        throw StateError(
          'Cryptographic core returned an invalid signature size: '
          'expected ${sizes.signature}, received $actualLength',
        );
      }
      return _copyFromNative(signature, actualLength);
    } finally {
      _wipeNative(nativeSecretKey, secretKey.length);
      _wipeNative(signature, sizes.signature);
      calloc.free(nativeSecretKey);
      calloc.free(nativeContext);
      calloc.free(nativeMessage);
      calloc.free(signatureLength);
      calloc.free(signature);
    }
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

    final nativeSignature = _copyToNative(signature);
    final nativeMessage = _copyToNative(message);
    final nativeContext = _copyToNative(actualContext);
    final nativePublicKey = _copyToNative(publicKey);
    try {
      final status = _verify(
        nativeSignature,
        signature.length,
        nativeMessage,
        message.length,
        nativeContext,
        actualContext.length,
        nativePublicKey,
      );
      if (status == _allocationFailure) {
        throw KpqCException('verification', status);
      }
      return status == 0;
    } finally {
      calloc.free(nativePublicKey);
      calloc.free(nativeContext);
      calloc.free(nativeMessage);
      calloc.free(nativeSignature);
    }
  }

  @override
  String toString() => id;
}

/// A key-encapsulation algorithm and parameter set.
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
    final publicKey = calloc<Uint8>(sizes.publicKey);
    final secretKey = calloc<Uint8>(sizes.secretKey);
    try {
      final status = _keyPair(publicKey, secretKey);
      if (status != 0) {
        throw KpqCException('key generation', status);
      }
      return KeyPair._(
        _copyFromNative(publicKey, sizes.publicKey),
        _copyFromNative(secretKey, sizes.secretKey),
      );
    } finally {
      _wipeNative(secretKey, sizes.secretKey);
      calloc.free(secretKey);
      calloc.free(publicKey);
    }
  }

  /// Encapsulates a fresh shared secret for [publicKey].
  EncapsulatedSecret encapsulate(Uint8List publicKey) {
    _requireLength('publicKey', publicKey.length, sizes.publicKey);
    final ciphertext = calloc<Uint8>(sizes.ciphertext);
    final sharedSecret = calloc<Uint8>(sizes.sharedSecret);
    final nativePublicKey = _copyToNative(publicKey);
    try {
      final status = _encapsulate(ciphertext, sharedSecret, nativePublicKey);
      if (status != 0) {
        throw KpqCException('encapsulation', status);
      }
      return EncapsulatedSecret._(
        _copyFromNative(ciphertext, sizes.ciphertext),
        _copyFromNative(sharedSecret, sizes.sharedSecret),
      );
    } finally {
      _wipeNative(sharedSecret, sizes.sharedSecret);
      calloc.free(nativePublicKey);
      calloc.free(sharedSecret);
      calloc.free(ciphertext);
    }
  }

  /// Recovers a shared secret from [ciphertext] and [secretKey].
  ///
  /// NTRU+ reports a modified ciphertext as an error. SMAUG-T uses implicit
  /// rejection and returns a replacement secret instead.
  Uint8List decapsulate(Uint8List ciphertext, Uint8List secretKey) {
    _requireLength('ciphertext', ciphertext.length, sizes.ciphertext);
    _requireLength('secretKey', secretKey.length, sizes.secretKey);
    final sharedSecret = calloc<Uint8>(sizes.sharedSecret);
    final nativeCiphertext = _copyToNative(ciphertext);
    final nativeSecretKey = _copyToNative(secretKey);
    try {
      final status = _decapsulate(
        sharedSecret,
        nativeCiphertext,
        nativeSecretKey,
      );
      if (status != 0) {
        throw KpqCException('decapsulation', status);
      }
      return _copyFromNative(sharedSecret, sizes.sharedSecret);
    } finally {
      _wipeNative(nativeSecretKey, secretKey.length);
      _wipeNative(sharedSecret, sizes.sharedSecret);
      calloc.free(nativeSecretKey);
      calloc.free(nativeCiphertext);
      calloc.free(sharedSecret);
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

Pointer<Uint8> _copyToNative(Uint8List bytes) {
  final pointer = calloc<Uint8>(bytes.isEmpty ? 1 : bytes.length);
  if (bytes.isNotEmpty) pointer.asTypedList(bytes.length).setAll(0, bytes);
  return pointer;
}

Uint8List _copyFromNative(Pointer<Uint8> pointer, int length) =>
    Uint8List.fromList(pointer.asTypedList(length));

void _wipe(Uint8List bytes) => bytes.fillRange(0, bytes.length, 0);

void _wipeNative(Pointer<Uint8> pointer, int length) {
  if (length != 0) pointer.asTypedList(length).fillRange(0, length, 0);
}
