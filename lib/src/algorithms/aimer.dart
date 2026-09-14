part of '../types.dart';

final _aimer128f = SignatureAlgorithm._(
  id: 'aimer-128f',
  sizes: const SignatureSizes(publicKey: 32, secretKey: 48, signature: 5888),
  keyPair: _aimer128fKeyPair,
  sign: _aimer128fSign,
  verify: _aimer128fVerify,
);

/// The AIMer128f signature parameter set.
@RecordUse()
SignatureAlgorithm get aimer128f => _aimer128f;

final _aimer128s = SignatureAlgorithm._(
  id: 'aimer-128s',
  sizes: const SignatureSizes(publicKey: 32, secretKey: 48, signature: 4160),
  keyPair: _aimer128sKeyPair,
  sign: _aimer128sSign,
  verify: _aimer128sVerify,
);

/// The AIMer128s signature parameter set.
@RecordUse()
SignatureAlgorithm get aimer128s => _aimer128s;

final _aimer192f = SignatureAlgorithm._(
  id: 'aimer-192f',
  sizes: const SignatureSizes(publicKey: 48, secretKey: 72, signature: 13056),
  keyPair: _aimer192fKeyPair,
  sign: _aimer192fSign,
  verify: _aimer192fVerify,
);

/// The AIMer192f signature parameter set.
@RecordUse()
SignatureAlgorithm get aimer192f => _aimer192f;

final _aimer192s = SignatureAlgorithm._(
  id: 'aimer-192s',
  sizes: const SignatureSizes(publicKey: 48, secretKey: 72, signature: 9120),
  keyPair: _aimer192sKeyPair,
  sign: _aimer192sSign,
  verify: _aimer192sVerify,
);

/// The AIMer192s signature parameter set.
@RecordUse()
SignatureAlgorithm get aimer192s => _aimer192s;

final _aimer256f = SignatureAlgorithm._(
  id: 'aimer-256f',
  sizes: const SignatureSizes(publicKey: 64, secretKey: 96, signature: 25120),
  keyPair: _aimer256fKeyPair,
  sign: _aimer256fSign,
  verify: _aimer256fVerify,
);

/// The AIMer256f signature parameter set.
@RecordUse()
SignatureAlgorithm get aimer256f => _aimer256f;

final _aimer256s = SignatureAlgorithm._(
  id: 'aimer-256s',
  sizes: const SignatureSizes(publicKey: 64, secretKey: 96, signature: 17056),
  keyPair: _aimer256sKeyPair,
  sign: _aimer256sSign,
  verify: _aimer256sVerify,
);

/// The AIMer256s signature parameter set.
@RecordUse()
SignatureAlgorithm get aimer256s => _aimer256s;
