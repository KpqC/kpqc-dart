import 'dart:typed_data';

import 'entropy.dart';
import 'fips202.dart';
import 'ntruplus_ntt.dart';
import 'ntruplus_parameters.dart';
import 'ntruplus_poly.dart';

final class NtruPlusKeyPair {
  const NtruPlusKeyPair(this.publicKey, this.secretKey);

  final Uint8List publicKey;
  final Uint8List secretKey;
}

final class NtruPlusEncapsulation {
  const NtruPlusEncapsulation(this.ciphertext, this.sharedSecret);

  final Uint8List ciphertext;
  final Uint8List sharedSecret;
}

final class _GeneratedSecret {
  const _GeneratedSecret(this.polynomial, this.inverse);

  final Int16List polynomial;
  final Int16List inverse;
}

_GeneratedSecret? _generateSecret(
  NtruPlusParameters parameters,
  Uint8List coins,
  int constant,
) {
  final polynomial = ntruPlusSampleCenteredBinomial(
    parameters,
    shake256(coins, parameters.n ~/ 4),
  );
  for (var index = 0; index < polynomial.length; index++) {
    polynomial[index] *= 3;
  }
  polynomial[0] += constant;
  ntruPlusNtt(parameters, polynomial, copy: false);
  final inverse = ntruPlusInvertPolynomial(parameters, polynomial);
  return inverse == null ? null : _GeneratedSecret(polynomial, inverse);
}

NtruPlusKeyPair ntruPlusGenerateKeyPair(NtruPlusParameters parameters) {
  _GeneratedSecret? first;
  _GeneratedSecret? second;
  do {
    first = _generateSecret(parameters, randomBytes(32), 1);
  } while (first == null);
  do {
    second = _generateSecret(parameters, randomBytes(32), 0);
  } while (second == null);

  final publicPolynomial = ntruPlusMultiplyPolynomials(
    parameters,
    second.polynomial,
    first.inverse,
  );
  final inversePublicPolynomial = ntruPlusMultiplyPolynomials(
    parameters,
    first.polynomial,
    second.inverse,
  );
  final publicKey = ntruPlusSerializePolynomial(parameters, publicPolynomial);
  final firstBytes = ntruPlusSerializePolynomial(parameters, first.polynomial);
  final inverseBytes = ntruPlusSerializePolynomial(
    parameters,
    inversePublicPolynomial,
  );
  final publicHash = ntruPlusHashF(publicKey);
  final secretKey = Uint8List(parameters.secretKeyBytes)
    ..setRange(0, firstBytes.length, firstBytes)
    ..setRange(
      firstBytes.length,
      firstBytes.length + inverseBytes.length,
      inverseBytes,
    )
    ..setRange(
      2 * parameters.polynomialBytes,
      2 * parameters.polynomialBytes + publicHash.length,
      publicHash,
    );
  return NtruPlusKeyPair(publicKey, secretKey);
}

NtruPlusEncapsulation ntruPlusEncapsulate(
  NtruPlusParameters parameters,
  Uint8List publicKey,
) => ntruPlusEncapsulateWithCoins(
  parameters,
  publicKey,
  randomBytes(parameters.n ~/ 8),
);

NtruPlusEncapsulation ntruPlusEncapsulateWithCoins(
  NtruPlusParameters parameters,
  Uint8List publicKey,
  Uint8List coins,
) {
  if (publicKey.length != parameters.polynomialBytes) {
    throw ArgumentError.value(publicKey.length, 'publicKey');
  }
  if (coins.length != parameters.n ~/ 8) {
    throw ArgumentError.value(coins.length, 'coins');
  }
  final decodedPublicKey = ntruPlusDeserializePolynomial(parameters, publicKey);
  if (!decodedPublicKey.canonical) {
    throw StateError('invalid NTRU+ public key encoding');
  }
  final message = ntruPlusEncapsulationMessage(coins, publicKey);
  final expanded = ntruPlusHashH(parameters, [message]);
  final randomPolynomial = ntruPlusSampleCenteredBinomial(
    parameters,
    Uint8List.sublistView(expanded, 32),
  );
  ntruPlusNtt(parameters, randomPolynomial, copy: false);
  final encodedRandom = ntruPlusSerializePolynomial(
    parameters,
    randomPolynomial,
  );
  final pad = ntruPlusHashG(parameters, encodedRandom);
  final encodedMessage = ntruPlusEncodeSotp(parameters, message, pad);
  ntruPlusNtt(parameters, encodedMessage, copy: false);
  final ciphertextPolynomial = ntruPlusMultiplyPolynomials(
    parameters,
    decodedPublicKey.polynomial,
    randomPolynomial,
    encodedMessage,
  );
  return NtruPlusEncapsulation(
    ntruPlusSerializePolynomial(parameters, ciphertextPolynomial),
    Uint8List.fromList(expanded.sublist(0, 32)),
  );
}

Uint8List ntruPlusDecapsulate(
  NtruPlusParameters parameters,
  Uint8List ciphertext,
  Uint8List secretKey,
) {
  final polynomialBytes = parameters.polynomialBytes;
  if (ciphertext.length != polynomialBytes ||
      secretKey.length != parameters.secretKeyBytes) {
    throw ArgumentError('invalid NTRU+ input length');
  }
  final decodedCiphertext = ntruPlusDeserializePolynomial(
    parameters,
    ciphertext,
  );
  final decodedFirst = ntruPlusDeserializePolynomial(
    parameters,
    Uint8List.sublistView(secretKey, 0, polynomialBytes),
  );
  final decodedInversePublic = ntruPlusDeserializePolynomial(
    parameters,
    Uint8List.sublistView(secretKey, polynomialBytes, 2 * polynomialBytes),
  );
  if (!decodedCiphertext.canonical ||
      !decodedFirst.canonical ||
      !decodedInversePublic.canonical) {
    throw StateError('invalid NTRU+ polynomial encoding');
  }

  final messageProduct = ntruPlusMultiplyPolynomials(
    parameters,
    decodedCiphertext.polynomial,
    decodedFirst.polynomial,
  );
  ntruPlusInverseNtt(parameters, messageProduct, copy: false);
  final messagePolynomial = ntruPlusCenteredModThree(messageProduct);
  final transformed = ntruPlusNtt(parameters, messagePolynomial);
  for (var index = 0; index < transformed.length; index++) {
    transformed[index] =
        decodedCiphertext.polynomial[index] - transformed[index];
  }
  final recoveredRandom = ntruPlusMultiplyPolynomials(
    parameters,
    transformed,
    decodedInversePublic.polynomial,
  );
  final encodedRandom = ntruPlusSerializePolynomial(
    parameters,
    recoveredRandom,
  );
  final pad = ntruPlusHashG(parameters, encodedRandom);
  final decoded = ntruPlusDecodeSotp(parameters, messagePolynomial, pad);
  final publicHash = Uint8List.sublistView(
    secretKey,
    2 * polynomialBytes,
    2 * polynomialBytes + 32,
  );
  final expanded = ntruPlusHashH(parameters, [decoded.message, publicHash]);
  final expectedRandom = ntruPlusSampleCenteredBinomial(
    parameters,
    Uint8List.sublistView(expanded, 32),
  );
  ntruPlusNtt(parameters, expectedRandom, copy: false);
  if (!decoded.valid ||
      !ntruPlusEqualPolynomialEncodings(recoveredRandom, expectedRandom)) {
    throw StateError('NTRU+ decapsulation failed');
  }
  return Uint8List.fromList(expanded.sublist(0, 32));
}
