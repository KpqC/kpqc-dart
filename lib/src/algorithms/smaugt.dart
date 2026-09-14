part of '../types.dart';

final _smaugt128 = KeyEncapsulationAlgorithm._(
  id: 'SMAUG-T128',
  sizes: const KemSizes(
    publicKey: 672,
    secretKey: 832,
    ciphertext: 672,
    sharedSecret: 32,
  ),
  keyPair: _smaugt128KeyPair,
  encapsulate: _smaugt128Encapsulate,
  decapsulate: _smaugt128Decapsulate,
);

/// The SMAUG-T128 key-encapsulation parameter set.
@RecordUse()
KeyEncapsulationAlgorithm get smaugt128 => _smaugt128;

final _smaugt192 = KeyEncapsulationAlgorithm._(
  id: 'SMAUG-T192',
  sizes: const KemSizes(
    publicKey: 1088,
    secretKey: 1312,
    ciphertext: 992,
    sharedSecret: 32,
  ),
  keyPair: _smaugt192KeyPair,
  encapsulate: _smaugt192Encapsulate,
  decapsulate: _smaugt192Decapsulate,
);

/// The SMAUG-T192 key-encapsulation parameter set.
@RecordUse()
KeyEncapsulationAlgorithm get smaugt192 => _smaugt192;

final _smaugt256 = KeyEncapsulationAlgorithm._(
  id: 'SMAUG-T256',
  sizes: const KemSizes(
    publicKey: 1440,
    secretKey: 1728,
    ciphertext: 1376,
    sharedSecret: 32,
  ),
  keyPair: _smaugt256KeyPair,
  encapsulate: _smaugt256Encapsulate,
  decapsulate: _smaugt256Decapsulate,
);

/// The SMAUG-T256 key-encapsulation parameter set.
@RecordUse()
KeyEncapsulationAlgorithm get smaugt256 => _smaugt256;

final _timer = KeyEncapsulationAlgorithm._(
  id: 'TiMER',
  sizes: const KemSizes(
    publicKey: 672,
    secretKey: 832,
    ciphertext: 608,
    sharedSecret: 32,
  ),
  keyPair: _timerKeyPair,
  encapsulate: _timerEncapsulate,
  decapsulate: _timerDecapsulate,
);

/// The TiMER key-encapsulation parameter set.
@RecordUse()
KeyEncapsulationAlgorithm get timer => _timer;
