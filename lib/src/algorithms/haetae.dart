part of '../types.dart';

final _haetae2 = SignatureAlgorithm._(
  id: 'haetae-mode2',
  sizes: const SignatureSizes(publicKey: 992, secretKey: 1408, signature: 1474),
  keyPair: _haetae2KeyPair,
  sign: _haetae2Sign,
  verify: _haetae2Verify,
);

/// The HAETAE2 signature parameter set.
@RecordUse()
SignatureAlgorithm get haetae2 => _haetae2;

final _haetae3 = SignatureAlgorithm._(
  id: 'haetae-mode3',
  sizes: const SignatureSizes(
    publicKey: 1472,
    secretKey: 2112,
    signature: 2349,
  ),
  keyPair: _haetae3KeyPair,
  sign: _haetae3Sign,
  verify: _haetae3Verify,
);

/// The HAETAE3 signature parameter set.
@RecordUse()
SignatureAlgorithm get haetae3 => _haetae3;

final _haetae5 = SignatureAlgorithm._(
  id: 'haetae-mode5',
  sizes: const SignatureSizes(
    publicKey: 2080,
    secretKey: 2752,
    signature: 2948,
  ),
  keyPair: _haetae5KeyPair,
  sign: _haetae5Sign,
  verify: _haetae5Verify,
);

/// The HAETAE5 signature parameter set.
@RecordUse()
SignatureAlgorithm get haetae5 => _haetae5;
