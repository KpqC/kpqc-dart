part of '../types.dart';

final _smaugt128 = KeyEncapsulationAlgorithm._(
  id: 'SMAUG-T128',
  sizes: const KemSizes(
    publicKey: 672,
    secretKey: 832,
    ciphertext: 672,
    sharedSecret: 32,
  ),
  keyPair: () => _smaugTKeyPair(smaugT128Parameters),
  encapsulate: (publicKey) =>
      _smaugTEncapsulate(smaugT128Parameters, publicKey),
  decapsulate: (ciphertext, secretKey) =>
      smaugTDecapsulate(smaugT128Parameters, ciphertext, secretKey),
);

/// The SMAUG-T128 KEM parameter set.
KeyEncapsulationAlgorithm get smaugt128 => _smaugt128;

final _smaugt192 = KeyEncapsulationAlgorithm._(
  id: 'SMAUG-T192',
  sizes: const KemSizes(
    publicKey: 1088,
    secretKey: 1312,
    ciphertext: 992,
    sharedSecret: 32,
  ),
  keyPair: () => _smaugTKeyPair(smaugT192Parameters),
  encapsulate: (publicKey) =>
      _smaugTEncapsulate(smaugT192Parameters, publicKey),
  decapsulate: (ciphertext, secretKey) =>
      smaugTDecapsulate(smaugT192Parameters, ciphertext, secretKey),
);

/// The SMAUG-T192 KEM parameter set.
KeyEncapsulationAlgorithm get smaugt192 => _smaugt192;

final _smaugt256 = KeyEncapsulationAlgorithm._(
  id: 'SMAUG-T256',
  sizes: const KemSizes(
    publicKey: 1440,
    secretKey: 1728,
    ciphertext: 1376,
    sharedSecret: 32,
  ),
  keyPair: () => _smaugTKeyPair(smaugT256Parameters),
  encapsulate: (publicKey) =>
      _smaugTEncapsulate(smaugT256Parameters, publicKey),
  decapsulate: (ciphertext, secretKey) =>
      smaugTDecapsulate(smaugT256Parameters, ciphertext, secretKey),
);

/// The SMAUG-T256 KEM parameter set.
KeyEncapsulationAlgorithm get smaugt256 => _smaugt256;

final _timer = KeyEncapsulationAlgorithm._(
  id: 'TiMER',
  sizes: const KemSizes(
    publicKey: 672,
    secretKey: 832,
    ciphertext: 608,
    sharedSecret: 32,
  ),
  keyPair: () => _smaugTKeyPair(timerParameters),
  encapsulate: (publicKey) => _smaugTEncapsulate(timerParameters, publicKey),
  decapsulate: (ciphertext, secretKey) =>
      smaugTDecapsulate(timerParameters, ciphertext, secretKey),
);

/// The TiMER KEM parameter set.
KeyEncapsulationAlgorithm get timer => _timer;

_KeyPairResult _smaugTKeyPair(SmaugTParameters parameters) {
  final generated = smaugTGenerateKeyPair(parameters);
  return (publicKey: generated.publicKey, secretKey: generated.secretKey);
}

_EncapsulationResult _smaugTEncapsulate(
  SmaugTParameters parameters,
  Uint8List publicKey,
) {
  final encapsulated = smaugTEncapsulate(parameters, publicKey);
  return (
    ciphertext: encapsulated.ciphertext,
    sharedSecret: encapsulated.sharedSecret,
  );
}
