part of '../types.dart';

final _ntruplus768 = KeyEncapsulationAlgorithm._(
  id: 'NTRU+768',
  sizes: const KemSizes(
    publicKey: 1152,
    secretKey: 2336,
    ciphertext: 1152,
    sharedSecret: 32,
  ),
  keyPair: _ntruplus768KeyPair,
  encapsulate: _ntruplus768Encapsulate,
  decapsulate: _ntruplus768Decapsulate,
);

/// The NTRU+768 key-encapsulation parameter set.
@RecordUse()
KeyEncapsulationAlgorithm get ntruplus768 => _ntruplus768;

final _ntruplus864 = KeyEncapsulationAlgorithm._(
  id: 'NTRU+864',
  sizes: const KemSizes(
    publicKey: 1296,
    secretKey: 2624,
    ciphertext: 1296,
    sharedSecret: 32,
  ),
  keyPair: _ntruplus864KeyPair,
  encapsulate: _ntruplus864Encapsulate,
  decapsulate: _ntruplus864Decapsulate,
);

/// The NTRU+864 key-encapsulation parameter set.
@RecordUse()
KeyEncapsulationAlgorithm get ntruplus864 => _ntruplus864;

final _ntruplus1152 = KeyEncapsulationAlgorithm._(
  id: 'NTRU+1152',
  sizes: const KemSizes(
    publicKey: 1728,
    secretKey: 3488,
    ciphertext: 1728,
    sharedSecret: 32,
  ),
  keyPair: _ntruplus1152KeyPair,
  encapsulate: _ntruplus1152Encapsulate,
  decapsulate: _ntruplus1152Decapsulate,
);

/// The NTRU+1152 key-encapsulation parameter set.
@RecordUse()
KeyEncapsulationAlgorithm get ntruplus1152 => _ntruplus1152;
