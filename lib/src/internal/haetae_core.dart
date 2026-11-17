import 'dart:typed_data';

import 'entropy.dart';
import 'fips202.dart';
import 'haetae_fft.dart';
import 'haetae_math.dart';
import 'haetae_packing.dart';
import 'haetae_params.dart';
import 'haetae_poly.dart';
import 'haetae_sampler.dart';

typedef HaetaeKeyPair = ({Uint8List publicKey, Uint8List secretKey});

HaetaeParameters haetaeParametersForMode(int mode) => switch (mode) {
  2 => haetae2Parameters,
  3 => haetae3Parameters,
  5 => haetae5Parameters,
  _ => throw ArgumentError.value(mode, 'mode', 'unsupported HAETAE mode'),
};

Uint8List _digest(
  Iterable<Uint8List> values, [
  int length = HaetaeParameters.crhBytes,
]) {
  final shake = shake256Stream();
  for (final value in values) {
    shake.absorb(value);
  }
  final output = Uint8List(length);
  shake.squeeze(output);
  return output;
}

Uint8List _prefixContext(Uint8List context) =>
    Uint8List.fromList([context.length, ...context]);

List<List<int>> _addNegativeHintModulus(
  HaetaeParameters parameters,
  List<List<int>> value,
) {
  final modulus = (HaetaeParameters.doubleQ - 2) ~/ parameters.alphaHint;
  final output = haetaeCloneVector(value);
  for (final polynomial in output) {
    for (var index = 0; index < polynomial.length; index++) {
      if (polynomial[index] < 0) polynomial[index] += modulus;
    }
  }
  return output;
}

HaetaeKeyPair haetaeGenerateKeyPair(HaetaeParameters parameters) {
  final expanded = shake256(
    randomBytes(HaetaeParameters.seedBytes),
    2 * HaetaeParameters.seedBytes + HaetaeParameters.crhBytes,
  );
  final matrixSeed = Uint8List.fromList(
    expanded.sublist(0, HaetaeParameters.seedBytes),
  );
  final secretSeed = Uint8List.fromList(
    expanded.sublist(
      HaetaeParameters.seedBytes,
      HaetaeParameters.seedBytes + HaetaeParameters.crhBytes,
    ),
  );
  final key = Uint8List.fromList(
    expanded.sublist(HaetaeParameters.seedBytes + HaetaeParameters.crhBytes),
  );
  final matrix = haetaeExpandMatrix(parameters, matrixSeed, false);
  final publicRandom = parameters.mode == 5
      ? null
      : haetaeExpandPublicVector(parameters, matrixSeed);
  var counter = 0;
  for (;;) {
    final secret = haetaeExpandSecret(parameters, secretSeed, counter);
    final first = secret.first;
    final second = secret.second;
    counter += parameters.m + parameters.k;
    if (parameters.mode == 5 &&
        haetaeSecretSingularValue(parameters, first, second) >
            parameters.gamma * parameters.gamma * HaetaeParameters.n) {
      continue;
    }
    var publicVector = haetaeMultiplyMatrix(
      matrix,
      haetaeTransformVector(first),
    );
    if (parameters.mode == 5) {
      final transformedSecond = haetaeTransformVector(second);
      publicVector = haetaeConditionalAddQ(
        haetaeDoubleNegateMontgomery(
          haetaeAddVectors(
            haetaeConvertFromMontgomery(publicVector),
            transformedSecond,
          ),
        ),
      );
    } else {
      publicVector = haetaeFreezeVector(
        haetaeAddVectors(
          haetaeAddVectors(haetaeInverseTransformVector(publicVector), second),
          publicRandom!,
        ),
      );
      final decomposition = haetaePublicKeyDecompose(publicVector);
      publicVector = decomposition.high;
      for (var vector = 0; vector < second.length; vector++) {
        for (var index = 0; index < HaetaeParameters.n; index++) {
          second[vector][index] -= decomposition.low[vector][index];
        }
      }
      if (haetaeSecretSingularValue(parameters, first, second) >
          parameters.gamma * parameters.gamma * HaetaeParameters.n) {
        continue;
      }
    }
    final publicKey = haetaePackPublicKey(parameters, matrixSeed, publicVector);
    final secretKey = haetaePackSecretKey(
      parameters,
      publicKey,
      first,
      second,
      key,
    );
    return (publicKey: publicKey, secretKey: secretKey);
  }
}

Uint8List haetaeSign(
  HaetaeParameters parameters,
  Uint8List message,
  Uint8List secretKey, {
  Uint8List? context,
}) {
  final actualContext = context ?? Uint8List(0);
  if (secretKey.length != parameters.secretKeyBytes ||
      actualContext.length > 255) {
    throw ArgumentError('invalid HAETAE signing input');
  }
  final unpacked = haetaeUnpackSecretKey(parameters, secretKey);
  final publicKey = Uint8List.fromList(
    secretKey.sublist(0, parameters.publicKeyBytes),
  );
  final messageDigest = _digest([
    publicKey,
    _prefixContext(actualContext),
    message,
  ]);
  final seed = _digest([
    unpacked.key,
    randomBytes(HaetaeParameters.seedBytes),
    messageDigest,
  ]);
  final transformedFirst = haetaeTransformVector(unpacked.first);
  final transformedSecond = haetaeTransformVector(unpacked.second);
  final b0Limit =
      parameters.b0Squared *
      HaetaeParameters.fixedScale *
      HaetaeParameters.fixedScale;
  final b1Limit =
      parameters.b1Squared *
      HaetaeParameters.fixedScale *
      HaetaeParameters.fixedScale;
  var counter = 0;
  for (;;) {
    final sampled = haetaeSampleHyperball(parameters, seed, counter);
    counter = sampled.nextNonce;
    final roundedFirst = haetaeRoundFixed(sampled.first);
    final roundedSecond = haetaeRoundFixed(sampled.second);
    final roundedFirstZero = roundedFirst[0];
    var product = haetaeInverseTransformVector(
      haetaeMultiplyMatrix(
        unpacked.matrix,
        haetaeTransformVector(roundedFirst),
      ),
    );
    product = haetaeAddVectors(product, haetaeDoubleVector(roundedSecond));
    product = haetaeFreezeVector2Q(
      haetaeRecoverCrtVector(product, roundedFirstZero),
    );
    final highBits = haetaeHintHighBits(parameters, product);
    final parity = haetaeLeastSignificantBits(roundedFirstZero);
    final packed = haetaeConcatenate([
      haetaePackHighBits(parameters, highBits),
      haetaePackBits(parity, 1),
    ]);
    final challenge = haetaeChallenge(
      parameters,
      packed,
      Uint8List.fromList(messageDigest.sublist(0, HaetaeParameters.seedBytes)),
    );
    final transformedChallenge = haetaeTransform(challenge);
    final challengeFirst = haetaeZeroVector(parameters.l);
    challengeFirst[0] = challenge;
    for (var index = 1; index < parameters.l; index++) {
      challengeFirst[index] = haetaeInverseTransform(
        haetaePointwise(transformedFirst[index - 1], transformedChallenge),
      );
    }
    final challengeSecond = haetaeInverseTransformVector(
      haetaeMultiplyPolynomialVector(transformedSecond, transformedChallenge),
    );
    final signBit = sampled.bit & 1;
    final first = haetaeAddFixedSignedInteger(
      sampled.first,
      challengeFirst,
      signBit,
    );
    final second = haetaeAddFixedSignedInteger(
      sampled.second,
      challengeSecond,
      signBit,
    );
    if (haetaeSquaredNorm([first, second]) > b1Limit) continue;
    if ((sampled.bit & 2) != 0 &&
        haetaeSquaredNorm([
              haetaeDoubleMinusFixedVectors(first, sampled.first),
              haetaeDoubleMinusFixedVectors(second, sampled.second),
            ]) <
            b0Limit) {
      continue;
    }
    final roundedZ1 = haetaeRoundFixed(first);
    final roundedZ2 = haetaeRoundFixed(second);
    final hintBase = haetaeHintHighBits(
      parameters,
      haetaeFreezeVector2Q(
        haetaeSubtractVectors(product, haetaeDoubleVector(roundedZ2)),
      ),
    );
    final hint = _addNegativeHintModulus(
      parameters,
      haetaeSubtractVectors(highBits, hintBase),
    );
    final low = haetaeZeroVector(roundedZ1.length);
    final high = haetaeZeroVector(roundedZ1.length);
    for (var index = 0; index < roundedZ1.length; index++) {
      final decomposition = haetaeDecomposePolynomial(roundedZ1[index]);
      low[index] = decomposition.low;
      high[index] = decomposition.high;
    }
    final signature = haetaePackSignature(
      parameters,
      challenge,
      low,
      high,
      hint,
    );
    if (signature != null) return signature;
  }
}

bool haetaeVerify(
  HaetaeParameters parameters,
  Uint8List signature,
  Uint8List message,
  Uint8List publicKey, {
  Uint8List? context,
}) {
  final actualContext = context ?? Uint8List(0);
  if (publicKey.length != parameters.publicKeyBytes ||
      actualContext.length > 255) {
    return false;
  }
  final decoded = haetaeUnpackSignature(parameters, signature);
  if (decoded == null) return false;
  final matrix = haetaeUnpackPublicKey(parameters, publicKey);
  final first = haetaeZeroVector(parameters.l);
  for (var index = 0; index < first.length; index++) {
    first[index] = haetaeComposePolynomial(
      decoded.highBits[index],
      decoded.lowBits[index],
    );
  }
  var norm = haetaeSquaredNorm([first]);
  final difference = haetaeSubtract(first[0], decoded.challenge);
  final parity = haetaeLeastSignificantBits(difference);
  var product = haetaeInverseTransformVector(
    haetaeMultiplyMatrix(matrix, haetaeTransformVector(first)),
  );
  product = haetaeFreezeVector2Q(haetaeRecoverCrtVector(product, parity));
  final recoveredHigh = haetaeNormalizeHint(
    parameters,
    haetaeAddVectors(haetaeHintHighBits(parameters, product), decoded.hint),
  );
  var second = haetaeSubtractVectors(
    haetaeMultiplyByAlpha(parameters, recoveredHigh),
    product,
  );
  second[0] = haetaeAdd(second[0], parity);
  second = haetaeDivideVectorBy2(haetaeReduceVector2Q(second));
  norm += haetaeSquaredNorm([second]);
  if (norm > parameters.b2Squared) return false;
  final packed = haetaeConcatenate([
    haetaePackHighBits(parameters, recoveredHigh),
    haetaePackBits(parity, 1),
  ]);
  final messageDigest = _digest([
    publicKey,
    _prefixContext(actualContext),
    message,
  ]);
  final expected = haetaeChallenge(
    parameters,
    packed,
    Uint8List.fromList(messageDigest.sublist(0, HaetaeParameters.seedBytes)),
  );
  var differenceMask = 0;
  for (var index = 0; index < expected.length; index++) {
    differenceMask |= expected[index] ^ decoded.challenge[index];
  }
  return differenceMask == 0;
}
