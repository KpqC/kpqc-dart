part of '../types.dart';

final _haetae2 = SignatureAlgorithm._(
  id: 'haetae-mode2',
  sizes: const SignatureSizes(publicKey: 992, secretKey: 1408, signature: 1474),
  keyPair: () => haetaeGenerateKeyPair(haetae2Parameters),
  sign: (message, secretKey, context) =>
      haetaeSign(haetae2Parameters, message, secretKey, context: context),
  verify: (message, signature, publicKey, context) => haetaeVerify(
    haetae2Parameters,
    signature,
    message,
    publicKey,
    context: context,
  ),
);

/// The HAETAE2 signature parameter set.
SignatureAlgorithm get haetae2 => _haetae2;

final _haetae3 = SignatureAlgorithm._(
  id: 'haetae-mode3',
  sizes: const SignatureSizes(
    publicKey: 1472,
    secretKey: 2112,
    signature: 2349,
  ),
  keyPair: () => haetaeGenerateKeyPair(haetae3Parameters),
  sign: (message, secretKey, context) =>
      haetaeSign(haetae3Parameters, message, secretKey, context: context),
  verify: (message, signature, publicKey, context) => haetaeVerify(
    haetae3Parameters,
    signature,
    message,
    publicKey,
    context: context,
  ),
);

/// The HAETAE3 signature parameter set.
SignatureAlgorithm get haetae3 => _haetae3;

final _haetae5 = SignatureAlgorithm._(
  id: 'haetae-mode5',
  sizes: const SignatureSizes(
    publicKey: 2080,
    secretKey: 2752,
    signature: 2948,
  ),
  keyPair: () => haetaeGenerateKeyPair(haetae5Parameters),
  sign: (message, secretKey, context) =>
      haetaeSign(haetae5Parameters, message, secretKey, context: context),
  verify: (message, signature, publicKey, context) => haetaeVerify(
    haetae5Parameters,
    signature,
    message,
    publicKey,
    context: context,
  ),
);

/// The HAETAE5 signature parameter set.
SignatureAlgorithm get haetae5 => _haetae5;
