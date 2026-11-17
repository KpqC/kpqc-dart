import 'dart:typed_data';

import 'fips202.dart';
import 'haetae_math.dart';
import 'haetae_ntt.dart';
import 'haetae_params.dart';

typedef HaetaeDecomposition = ({List<int> high, List<int> low});
typedef HaetaeVectorDecomposition = ({
  List<List<int>> high,
  List<List<int>> low,
});
typedef HaetaeSecretVectors = ({List<List<int>> first, List<List<int>> second});

List<int> haetaeAdd(List<int> left, List<int> right) => List<int>.generate(
  HaetaeParameters.n,
  (index) => left[index] + right[index],
  growable: false,
);

List<int> haetaeSubtract(List<int> left, List<int> right) => List<int>.generate(
  HaetaeParameters.n,
  (index) => left[index] - right[index],
  growable: false,
);

List<int> haetaePointwise(List<int> left, List<int> right) =>
    List<int>.generate(
      HaetaeParameters.n,
      (index) => haetaeMontgomeryReduce(left[index] * right[index]),
      growable: false,
    );

List<int> haetaePointwiseAccumulate(
  List<List<int>> left,
  List<List<int>> right,
) {
  final output = List<int>.filled(HaetaeParameters.n, 0);
  for (var vector = 0; vector < left.length; vector++) {
    for (var index = 0; index < output.length; index++) {
      output[index] += haetaeMontgomeryReduce(
        left[vector][index] * right[vector][index],
      );
    }
  }
  return output;
}

List<int> haetaeTransform(List<int> value) {
  final output = List<int>.from(value);
  haetaeNtt(output);
  return output;
}

List<int> haetaeInverseTransform(List<int> value) {
  final output = List<int>.from(value);
  haetaeInverseNtt(output);
  return output;
}

List<List<int>> haetaeTransformVector(List<List<int>> value) =>
    value.map(haetaeTransform).toList(growable: false);

List<List<int>> haetaeInverseTransformVector(List<List<int>> value) =>
    value.map(haetaeInverseTransform).toList(growable: false);

List<int> haetaeFreezePolynomial(List<int> value) =>
    value.map(haetaeFreeze).toList(growable: false);

List<int> haetaeFreezePolynomial2Q(List<int> value) =>
    value.map(haetaeFreeze2Q).toList(growable: false);

List<int> haetaeCenteredPolynomial2Q(List<int> value) =>
    value.map(haetaeCenteredMod2Q).toList(growable: false);

HaetaeDecomposition haetaeDecomposePolynomial(List<int> value) {
  final high = List<int>.filled(HaetaeParameters.n, 0);
  final low = List<int>.filled(HaetaeParameters.n, 0);
  for (var index = 0; index < value.length; index++) {
    final parts = haetaeDecomposeZ1(value[index]);
    high[index] = parts.$1;
    low[index] = parts.$2;
  }
  return (high: high, low: low);
}

List<int> haetaeComposePolynomial(List<int> high, List<int> low) =>
    List<int>.generate(
      HaetaeParameters.n,
      (index) => high[index] * 256 + low[index],
      growable: false,
    );

List<int> haetaeLeastSignificantBits(List<int> value) => List<int>.generate(
  HaetaeParameters.n,
  (index) => value[index] & 1,
  growable: false,
);

List<int> haetaeFromCrt(List<int> modQ, List<int>? mod2) =>
    List<int>.generate(HaetaeParameters.n, (index) {
      final parity = mod2 == null ? 0 : mod2[index];
      return modQ[index] + (HaetaeParameters.q & -((modQ[index] ^ parity) & 1));
    }, growable: false);

Shake haetaeStream(int bits, Uint8List seed, int nonce) {
  final shake = bits == 128 ? shake128Stream() : shake256Stream();
  shake.absorb(seed);
  shake.absorb(Uint8List.fromList([nonce, nonce >>> 8]));
  return shake;
}

List<int> haetaeSampleUniform(Uint8List seed, int nonce) {
  final output = List<int>.filled(HaetaeParameters.n, 0);
  final shake = haetaeStream(128, seed, nonce);
  final buffer = Uint8List(168);
  var count = 0;
  while (count < output.length) {
    shake.squeeze(buffer);
    for (
      var offset = 0;
      offset + 1 < buffer.length && count < output.length;
      offset += 2
    ) {
      final candidate = buffer[offset] | buffer[offset + 1] << 8;
      if (candidate < HaetaeParameters.q) output[count++] = candidate;
    }
  }
  return output;
}

List<int> haetaeSampleEta(Uint8List seed, int nonce) {
  final output = List<int>.filled(HaetaeParameters.n, 0);
  final shake = haetaeStream(256, seed, nonce);
  final buffer = Uint8List(136);
  var count = 0;
  while (count < output.length) {
    shake.squeeze(buffer);
    for (final item in buffer) {
      var value = item;
      if (value >= 243) continue;
      for (var digit = 0; digit < 5 && count < output.length; digit++) {
        final remainder = value % 3;
        output[count++] = remainder == 2 ? -1 : remainder;
        value ~/= 3;
      }
      if (count == output.length) break;
    }
  }
  return output;
}

List<List<List<int>>> haetaeExpandMatrix(
  HaetaeParameters parameters,
  Uint8List seed,
  bool includeFirst,
) => List<List<List<int>>>.generate(parameters.k, (row) {
  final offset = includeFirst ? 1 : 0;
  final result = haetaeZeroVector(parameters.m + offset);
  for (var column = 0; column < parameters.m; column++) {
    result[column + offset] = haetaeSampleUniform(seed, (row << 8) + column);
  }
  return result;
}, growable: false);

List<List<int>> haetaeExpandPublicVector(
  HaetaeParameters parameters,
  Uint8List seed,
) {
  var nonce = (parameters.k << 8) + parameters.m;
  return List<List<int>>.generate(
    parameters.k,
    (_) => haetaeSampleUniform(seed, nonce++),
    growable: false,
  );
}

HaetaeSecretVectors haetaeExpandSecret(
  HaetaeParameters parameters,
  Uint8List seed,
  int nonce,
) {
  final first = List<List<int>>.generate(
    parameters.m,
    (_) => haetaeSampleEta(seed, nonce++),
    growable: false,
  );
  final second = List<List<int>>.generate(
    parameters.k,
    (_) => haetaeSampleEta(seed, nonce++),
    growable: false,
  );
  return (first: first, second: second);
}

List<List<int>> haetaeMultiplyMatrix(
  List<List<List<int>>> matrix,
  List<List<int>> input,
) => matrix
    .map((row) => haetaePointwiseAccumulate(row, input))
    .toList(growable: false);

List<List<int>> haetaeAddVectors(List<List<int>> left, List<List<int>> right) =>
    List<List<int>>.generate(
      left.length,
      (index) => haetaeAdd(left[index], right[index]),
      growable: false,
    );

List<List<int>> haetaeSubtractVectors(
  List<List<int>> left,
  List<List<int>> right,
) => List<List<int>>.generate(
  left.length,
  (index) => haetaeSubtract(left[index], right[index]),
  growable: false,
);

List<List<int>> haetaeDoubleVector(List<List<int>> value) => value
    .map((polynomial) => polynomial.map((item) => item * 2).toList())
    .toList(growable: false);

List<List<int>> haetaeNegateVector(List<List<int>> value, int bit) {
  final factor = 1 - 2 * bit;
  return value
      .map((polynomial) => polynomial.map((item) => item * factor).toList())
      .toList(growable: false);
}

HaetaeVectorDecomposition haetaePublicKeyDecompose(List<List<int>> value) {
  final high = haetaeZeroVector(value.length);
  final low = haetaeZeroVector(value.length);
  for (var vector = 0; vector < value.length; vector++) {
    for (var index = 0; index < value[vector].length; index++) {
      final parts = haetaeDecomposePublicKey(value[vector][index]);
      high[vector][index] = parts.$1;
      low[vector][index] = parts.$2;
    }
  }
  return (high: high, low: low);
}

List<List<int>> haetaeHintHighBits(
  HaetaeParameters parameters,
  List<List<int>> value,
) => value
    .map(
      (polynomial) => polynomial
          .map(
            (item) => haetaeDecomposeHint(
              item,
              parameters.alphaHint,
              parameters.logAlphaHint,
            ),
          )
          .toList(),
    )
    .toList(growable: false);

List<int> haetaeChallenge(
  HaetaeParameters parameters,
  Uint8List packed,
  Uint8List digest,
) {
  final output = List<int>.filled(HaetaeParameters.n, 0);
  final shake = shake256Stream()
    ..absorb(packed)
    ..absorb(digest);
  if (parameters.mode == 5) {
    final random = Uint8List(HaetaeParameters.seedBytes);
    shake.squeeze(random);
    var popcount = 0;
    for (final item in random) {
      var value = item;
      while (value != 0) {
        popcount += value & 1;
        value >>>= 1;
      }
    }
    final mask = popcount < 128
        ? 0
        : popcount > 128
        ? 0xff
        : -(random[0] & 1) & 0xff;
    for (var index = 0; index < output.length; index++) {
      output[index] = ((random[index >>> 3] ^ mask) >>> (index & 7)) & 1;
    }
    return output;
  }
  final random = Uint8List(136);
  shake.squeeze(random);
  var position = 0;
  for (
    var index = HaetaeParameters.n - parameters.tau;
    index < HaetaeParameters.n;
    index++
  ) {
    int selected;
    do {
      if (position == random.length) {
        shake.squeeze(random);
        position = 0;
      }
      selected = random[position++];
    } while (selected > index);
    output[index] = output[selected];
    output[selected] = 1;
  }
  return output;
}

List<List<int>> haetaeRecoverCrtVector(
  List<List<int>> modQ,
  List<int> firstMod2,
) => List<List<int>>.generate(
  modQ.length,
  (index) => haetaeFromCrt(modQ[index], index == 0 ? firstMod2 : null),
  growable: false,
);

List<List<int>> haetaeReduceVector2Q(List<List<int>> value) =>
    value.map(haetaeCenteredPolynomial2Q).toList(growable: false);

List<List<int>> haetaeFreezeVector(List<List<int>> value) =>
    value.map(haetaeFreezePolynomial).toList(growable: false);

List<List<int>> haetaeFreezeVector2Q(List<List<int>> value) =>
    value.map(haetaeFreezePolynomial2Q).toList(growable: false);

List<List<int>> haetaeMultiplyByAlpha(
  HaetaeParameters parameters,
  List<List<int>> value,
) => value
    .map(
      (polynomial) =>
          polynomial.map((item) => item * parameters.alphaHint).toList(),
    )
    .toList(growable: false);

List<List<int>> haetaeDivideVectorBy2(List<List<int>> value) => value
    .map((polynomial) => polynomial.map((item) => item >> 1).toList())
    .toList(growable: false);

List<List<int>> haetaeNormalizeHint(
  HaetaeParameters parameters,
  List<List<int>> value,
) {
  final modulus = (HaetaeParameters.doubleQ - 2) ~/ parameters.alphaHint;
  return value
      .map(
        (polynomial) => polynomial.map((item) {
          final result = item % modulus;
          return result < 0 ? result + modulus : result;
        }).toList(),
      )
      .toList(growable: false);
}

List<List<int>> haetaeMultiplyPolynomialVector(
  List<List<int>> value,
  List<int> factor,
) => value
    .map((polynomial) => haetaePointwise(polynomial, factor))
    .toList(growable: false);

List<List<int>> haetaeConvertFromMontgomery(List<List<int>> value) => value
    .map(
      (polynomial) => polynomial
          .map((item) => haetaeMontgomeryReduce(item * 4214))
          .toList(),
    )
    .toList(growable: false);

List<List<int>> haetaeDoubleNegateMontgomery(List<List<int>> value) => value
    .map(
      (polynomial) => polynomial
          .map((item) => haetaeMontgomeryReduce(item * -28642))
          .toList(),
    )
    .toList(growable: false);

List<List<int>> haetaeConditionalAddQ(List<List<int>> value) => value
    .map(
      (polynomial) => polynomial
          .map((item) => item < 0 ? item + HaetaeParameters.q : item)
          .toList(),
    )
    .toList(growable: false);

List<List<int>> haetaeZeroVector(int length) => List<List<int>>.generate(
  length,
  (_) => List<int>.filled(HaetaeParameters.n, 0),
  growable: false,
);

List<List<int>> haetaeCloneVector(List<List<int>> value) =>
    value.map((item) => List<int>.from(item)).toList(growable: false);

Uint8List haetaeConcatenate(Iterable<Uint8List> values) {
  final result = BytesBuilder(copy: false);
  for (final value in values) {
    result.add(value);
  }
  return result.takeBytes();
}
