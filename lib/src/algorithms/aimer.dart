part of '../types.dart';

final _aimer128f = SignatureAlgorithm._(
  id: 'aimer-128f',
  sizes: const SignatureSizes(publicKey: 32, secretKey: 48, signature: 6944),
  keyPair: () => _aimerKeyPair(aimer128fParameters),
  sign: (message, secretKey, context) =>
      aimerSign(aimer128fParameters, message, secretKey, context),
  verify: (message, signature, publicKey, context) =>
      aimerVerify(aimer128fParameters, message, signature, publicKey, context),
);

/// The AIMer128f signature parameter set.
SignatureAlgorithm get aimer128f => _aimer128f;

final _aimer128s = SignatureAlgorithm._(
  id: 'aimer-128s',
  sizes: const SignatureSizes(publicKey: 32, secretKey: 48, signature: 4704),
  keyPair: () => _aimerKeyPair(aimer128sParameters),
  sign: (message, secretKey, context) =>
      aimerSign(aimer128sParameters, message, secretKey, context),
  verify: (message, signature, publicKey, context) =>
      aimerVerify(aimer128sParameters, message, signature, publicKey, context),
);

/// The AIMer128s signature parameter set.
SignatureAlgorithm get aimer128s => _aimer128s;

final _aimer192f = SignatureAlgorithm._(
  id: 'aimer-192f',
  sizes: const SignatureSizes(publicKey: 48, secretKey: 72, signature: 15408),
  keyPair: () => _aimerKeyPair(aimer192fParameters),
  sign: (message, secretKey, context) =>
      aimerSign(aimer192fParameters, message, secretKey, context),
  verify: (message, signature, publicKey, context) =>
      aimerVerify(aimer192fParameters, message, signature, publicKey, context),
);

/// The AIMer192f signature parameter set.
SignatureAlgorithm get aimer192f => _aimer192f;

final _aimer192s = SignatureAlgorithm._(
  id: 'aimer-192s',
  sizes: const SignatureSizes(publicKey: 48, secretKey: 72, signature: 10320),
  keyPair: () => _aimerKeyPair(aimer192sParameters),
  sign: (message, secretKey, context) =>
      aimerSign(aimer192sParameters, message, secretKey, context),
  verify: (message, signature, publicKey, context) =>
      aimerVerify(aimer192sParameters, message, signature, publicKey, context),
);

/// The AIMer192s signature parameter set.
SignatureAlgorithm get aimer192s => _aimer192s;

final _aimer256f = SignatureAlgorithm._(
  id: 'aimer-256f',
  sizes: const SignatureSizes(publicKey: 64, secretKey: 96, signature: 31360),
  keyPair: () => _aimerKeyPair(aimer256fParameters),
  sign: (message, secretKey, context) =>
      aimerSign(aimer256fParameters, message, secretKey, context),
  verify: (message, signature, publicKey, context) =>
      aimerVerify(aimer256fParameters, message, signature, publicKey, context),
);

/// The AIMer256f signature parameter set.
SignatureAlgorithm get aimer256f => _aimer256f;

final _aimer256s = SignatureAlgorithm._(
  id: 'aimer-256s',
  sizes: const SignatureSizes(publicKey: 64, secretKey: 96, signature: 20224),
  keyPair: () => _aimerKeyPair(aimer256sParameters),
  sign: (message, secretKey, context) =>
      aimerSign(aimer256sParameters, message, secretKey, context),
  verify: (message, signature, publicKey, context) =>
      aimerVerify(aimer256sParameters, message, signature, publicKey, context),
);

/// The AIMer256s signature parameter set.
SignatureAlgorithm get aimer256s => _aimer256s;

_KeyPairResult _aimerKeyPair(AimerParameters parameters) {
  final generated = aimerGenerateKeyPair(parameters);
  return (publicKey: generated.publicKey, secretKey: generated.secretKey);
}
