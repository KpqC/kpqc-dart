part of '../types.dart';

final _ntruplus768 = _ntruPlusAlgorithm(
  id: 'NTRU+768',
  sizes: const KemSizes(
    publicKey: 1152,
    secretKey: 2336,
    ciphertext: 1152,
    sharedSecret: 32,
  ),
  parameters: ntruPlus768Parameters,
);

/// The NTRU+768 KEM parameter set.
KeyEncapsulationAlgorithm get ntruplus768 => _ntruplus768;

final _ntruplus864 = _ntruPlusAlgorithm(
  id: 'NTRU+864',
  sizes: const KemSizes(
    publicKey: 1296,
    secretKey: 2624,
    ciphertext: 1296,
    sharedSecret: 32,
  ),
  parameters: ntruPlus864Parameters,
);

/// The NTRU+864 KEM parameter set.
KeyEncapsulationAlgorithm get ntruplus864 => _ntruplus864;

final _ntruplus1152 = _ntruPlusAlgorithm(
  id: 'NTRU+1152',
  sizes: const KemSizes(
    publicKey: 1728,
    secretKey: 3488,
    ciphertext: 1728,
    sharedSecret: 32,
  ),
  parameters: ntruPlus1152Parameters,
);

/// The NTRU+1152 KEM parameter set.
KeyEncapsulationAlgorithm get ntruplus1152 => _ntruplus1152;

KeyEncapsulationAlgorithm _ntruPlusAlgorithm({
  required String id,
  required KemSizes sizes,
  required NtruPlusParameters parameters,
}) => KeyEncapsulationAlgorithm._(
  id: id,
  sizes: sizes,
  keyPair: () {
    final generated = ntruPlusGenerateKeyPair(parameters);
    return (publicKey: generated.publicKey, secretKey: generated.secretKey);
  },
  encapsulate: (publicKey) {
    final encapsulated = ntruPlusEncapsulate(parameters, publicKey);
    return (
      ciphertext: encapsulated.ciphertext,
      sharedSecret: encapsulated.sharedSecret,
    );
  },
  decapsulate: (ciphertext, secretKey) =>
      ntruPlusDecapsulate(parameters, ciphertext, secretKey),
);
