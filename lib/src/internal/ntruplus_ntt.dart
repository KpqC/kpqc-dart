import 'dart:typed_data';

import 'ntruplus_parameters.dart';

const _q = 3457;
const _qInverse = 12929;
const _montgomeryR = -147;
const _montgomeryRInverse = -682;
const _montgomeryRSquared = 867;
const _omega = -886;
const _zMinusZ5Inverse = -1665;
const _barrettMultiplier = ((1 << 26) + _q ~/ 2) ~/ _q;

int _int16(int value) => value.toSigned(16);

int montgomeryReduce(int value) {
  final factor = (value * _qInverse).toSigned(16);
  return ((value - factor * _q) >> 16).toSigned(16);
}

int barrettReduce(int value) {
  final input = _int16(value);
  final quotient = (_barrettMultiplier * input + (1 << 25)) >> 26;
  return (input - quotient * _q).toSigned(16);
}

int _multiplyField(int left, int right) => montgomeryReduce(left * right);

int _invertField(int value) {
  var t0 = _multiplyField(value, value);
  t0 = _multiplyField(t0, t0);
  t0 = _multiplyField(t0, t0);
  t0 = _multiplyField(t0, t0);
  var t1 = _multiplyField(t0, value);
  t0 = _multiplyField(t0, t0);
  t0 = _multiplyField(t0, t0);
  t0 = _multiplyField(t0, t0);
  t1 = _multiplyField(t0, t1);
  t0 = _multiplyField(t1, t0);
  t1 = _multiplyField(t0, t1);
  t1 = _multiplyField(t1, t0);
  t0 = _multiplyField(t1, t1);
  t0 = _multiplyField(t0, t0);
  t0 = _multiplyField(t0, t1);
  return _multiplyField(_montgomeryRInverse, t0);
}

Int16List ntruPlusNtt(
  NtruPlusParameters parameters,
  Int16List value, {
  bool copy = true,
}) {
  final result = copy ? Int16List.fromList(value) : value;
  final n = parameters.n;
  var twiddleIndex = 1;
  var zetaOne = parameters.zetas[twiddleIndex++];

  for (var index = 0; index < n ~/ 2; index++) {
    final product = _multiplyField(zetaOne, result[index + n ~/ 2]);
    final base = result[index];
    result[index + n ~/ 2] = base + result[index + n ~/ 2] - product;
    result[index] = base + product;
  }

  for (var step = n ~/ 6; step >= parameters.ternaryEnd; step ~/= 3) {
    for (var start = 0; start < n; start += 3 * step) {
      zetaOne = parameters.zetas[twiddleIndex++];
      final zetaTwo = parameters.zetas[twiddleIndex++];
      for (var index = start; index < start + step; index++) {
        final base = result[index];
        final first = _multiplyField(zetaOne, result[index + step]);
        final second = _multiplyField(zetaTwo, result[index + 2 * step]);
        final third = _multiplyField(_omega, first - second);
        result[index + 2 * step] = base - first - third;
        result[index + step] = base - second + third;
        result[index] = base + first + second;
      }
    }
  }

  for (
    var step = parameters.binaryStart;
    step >= parameters.degree;
    step >>= 1
  ) {
    for (var start = 0; start < n; start += 2 * step) {
      zetaOne = parameters.zetas[twiddleIndex++];
      for (var index = start; index < start + step; index++) {
        final base = result[index];
        final product = _multiplyField(zetaOne, result[index + step]);
        if (parameters.mode == 768) {
          result[index + step] = base - product;
          result[index] = base + product;
        } else {
          result[index + step] = barrettReduce(base - product);
          result[index] = barrettReduce(base + product);
        }
      }
    }
  }

  if (parameters.mode == 768) {
    for (var index = 0; index < n; index++) {
      result[index] = barrettReduce(result[index]);
    }
  }
  return result;
}

Int16List ntruPlusInverseNtt(
  NtruPlusParameters parameters,
  Int16List value, {
  bool copy = true,
}) {
  final result = copy ? Int16List.fromList(value) : value;
  final n = parameters.n;
  var twiddleIndex = parameters.zetas.length - 1;

  for (
    var step = parameters.degree;
    step <= parameters.binaryStart;
    step <<= 1
  ) {
    for (var start = 0; start < n; start += 2 * step) {
      final zeta = parameters.zetas[twiddleIndex--];
      for (var index = start; index < start + step; index++) {
        final upper = result[index + step];
        result[index + step] = _multiplyField(zeta, upper - result[index]);
        result[index] = barrettReduce(result[index] + upper);
      }
    }
  }

  for (var step = parameters.ternaryEnd; step <= n ~/ 6; step *= 3) {
    for (var start = 0; start < n; start += 3 * step) {
      final zetaTwo = parameters.zetas[twiddleIndex--];
      final zetaOne = parameters.zetas[twiddleIndex--];
      for (var index = start; index < start + step; index++) {
        final base = result[index];
        final middle = result[index + step];
        final upper = result[index + 2 * step];
        final first = _multiplyField(_omega, middle - base);
        result[index + step] = _multiplyField(zetaOne, upper - base + first);
        result[index + 2 * step] = _multiplyField(
          zetaTwo,
          upper - middle - first,
        );
        result[index] = parameters.mode == 768
            ? base + middle + upper
            : barrettReduce(base + middle + upper);
      }
    }
  }

  for (var index = 0; index < n ~/ 2; index++) {
    final lower = result[index];
    final upper = result[index + n ~/ 2];
    final sum = lower + upper;
    final difference = _multiplyField(_zMinusZ5Inverse, lower - upper);
    result[index] = _multiplyField(parameters.inverseN, sum - difference);
    result[index + n ~/ 2] = _multiplyField(parameters.inverseTwoN, difference);
  }
  return result;
}

int _prepareBase3(Int16List numerators, Int16List input, int offset, int zeta) {
  var first = montgomeryReduce(input[offset + 1] * input[offset + 2]);
  var second = montgomeryReduce(input[offset + 2] * input[offset + 2]);
  final third = montgomeryReduce(
    input[offset + 1] * input[offset + 1] - input[offset] * input[offset + 2],
  );
  first = montgomeryReduce(input[offset] * input[offset] - first * zeta);
  second = montgomeryReduce(second * zeta - input[offset] * input[offset + 1]);
  var denominator = montgomeryReduce(
    third * input[offset + 1] + second * input[offset + 2],
  );
  denominator = montgomeryReduce(denominator * zeta + first * input[offset]);
  numerators[offset] = first;
  numerators[offset + 1] = second;
  numerators[offset + 2] = third;
  return denominator;
}

int _prepareBase4(Int16List numerators, Int16List input, int offset, int zeta) {
  var first = montgomeryReduce(
    input[offset + 2] * input[offset + 2] -
        2 * input[offset + 1] * input[offset + 3],
  );
  var second = montgomeryReduce(input[offset + 3] * input[offset + 3]);
  first = montgomeryReduce(input[offset] * input[offset] + first * zeta);
  second = montgomeryReduce(
    input[offset + 1] * input[offset + 1] +
        second * zeta -
        2 * input[offset] * input[offset + 2],
  );
  final third = montgomeryReduce(second * zeta);
  final denominator = montgomeryReduce(first * first - second * third);
  numerators[offset] = montgomeryReduce(
    input[offset] * first + input[offset + 2] * third,
  );
  numerators[offset + 1] = -montgomeryReduce(
    input[offset + 3] * third + input[offset + 1] * first,
  );
  numerators[offset + 2] = montgomeryReduce(
    input[offset + 2] * first + input[offset] * second,
  );
  numerators[offset + 3] = -montgomeryReduce(
    input[offset + 1] * second + input[offset + 3] * first,
  );
  return denominator;
}

Int16List? _invertBatch(Int16List values) {
  final prefixes = Int16List(values.length);
  var product = _montgomeryR;
  for (var index = 0; index < values.length; index++) {
    if (values[index] == 0) return null;
    prefixes[index] = product;
    product = _multiplyField(product, values[index]);
  }
  var inverse = _invertField(product);
  final output = Int16List(values.length);
  for (var index = values.length - 1; index >= 0; index--) {
    output[index] = _multiplyField(inverse, prefixes[index]);
    inverse = _multiplyField(inverse, values[index]);
  }
  return output;
}

Int16List? ntruPlusInvertPolynomial(
  NtruPlusParameters parameters,
  Int16List input,
) {
  final numerators = Int16List(parameters.n);
  final segments = parameters.n ~/ parameters.degree;
  final denominators = Int16List(segments);
  final zetaOffset = parameters.zetas.length ~/ 2;
  for (var segment = 0; segment < segments; segment++) {
    final offset = segment * parameters.degree;
    final baseZeta = parameters.zetas[zetaOffset + (segment >> 1)];
    final zeta = (segment & 1) == 0 ? baseZeta : -baseZeta;
    denominators[segment] = parameters.degree == 3
        ? _prepareBase3(numerators, input, offset, zeta)
        : _prepareBase4(numerators, input, offset, zeta);
  }
  final inverses = _invertBatch(denominators);
  if (inverses == null) return null;
  final output = Int16List(parameters.n);
  for (var segment = 0; segment < segments; segment++) {
    final offset = segment * parameters.degree;
    for (var index = 0; index < parameters.degree; index++) {
      output[offset + index] = montgomeryReduce(
        numerators[offset + index] * inverses[segment],
      );
    }
  }
  return output;
}

void _multiplyBase3Into(
  Int16List output,
  Int16List left,
  Int16List right,
  int offset,
  int zeta,
  Int16List? add,
) {
  var first = montgomeryReduce(
    left[offset + 2] * right[offset + 1] + left[offset + 1] * right[offset + 2],
  );
  var second = montgomeryReduce(left[offset + 2] * right[offset + 2]);
  first = montgomeryReduce(first * zeta + left[offset] * right[offset]);
  second = montgomeryReduce(
    second * zeta +
        left[offset] * right[offset + 1] +
        left[offset + 1] * right[offset],
  );
  final third = montgomeryReduce(
    left[offset + 2] * right[offset] +
        left[offset + 1] * right[offset + 1] +
        left[offset] * right[offset + 2],
  );
  final values = <int>[first, second, third];
  for (var index = 0; index < 3; index++) {
    output[offset + index] = add == null
        ? montgomeryReduce(values[index] * _montgomeryRSquared)
        : montgomeryReduce(
            add[offset + index] * _montgomeryR +
                values[index] * _montgomeryRSquared,
          );
  }
}

void _multiplyBase4Into(
  Int16List output,
  Int16List left,
  Int16List right,
  int offset,
  int zeta,
  Int16List? add,
) {
  final t0 = montgomeryReduce(
    left[offset + 1] * right[offset + 3] +
        left[offset + 2] * right[offset + 2] +
        left[offset + 3] * right[offset + 1],
  );
  final t1 = montgomeryReduce(
    left[offset + 2] * right[offset + 3] + left[offset + 3] * right[offset + 2],
  );
  final t2 = montgomeryReduce(left[offset + 3] * right[offset + 3]);
  final values = <int>[
    montgomeryReduce(t0 * zeta + left[offset] * right[offset]),
    montgomeryReduce(
      t1 * zeta +
          left[offset] * right[offset + 1] +
          left[offset + 1] * right[offset],
    ),
    montgomeryReduce(
      t2 * zeta +
          left[offset] * right[offset + 2] +
          left[offset + 1] * right[offset + 1] +
          left[offset + 2] * right[offset],
    ),
    montgomeryReduce(
      left[offset] * right[offset + 3] +
          left[offset + 1] * right[offset + 2] +
          left[offset + 2] * right[offset + 1] +
          left[offset + 3] * right[offset],
    ),
  ];
  for (var index = 0; index < 4; index++) {
    output[offset + index] = add == null
        ? montgomeryReduce(values[index] * _montgomeryRSquared)
        : montgomeryReduce(
            add[offset + index] * _montgomeryR +
                values[index] * _montgomeryRSquared,
          );
  }
}

Int16List ntruPlusMultiplyPolynomials(
  NtruPlusParameters parameters,
  Int16List left,
  Int16List right, [
  Int16List? add,
]) {
  final output = Int16List(parameters.n);
  final block = 2 * parameters.degree;
  final zetaOffset = parameters.zetas.length ~/ 2;
  for (
    var offset = 0, index = 0;
    offset < parameters.n;
    offset += block, index++
  ) {
    final zeta = parameters.zetas[zetaOffset + index];
    if (parameters.degree == 3) {
      _multiplyBase3Into(output, left, right, offset, zeta, add);
      _multiplyBase3Into(output, left, right, offset + 3, -zeta, add);
    } else {
      _multiplyBase4Into(output, left, right, offset, zeta, add);
      _multiplyBase4Into(output, left, right, offset + 4, -zeta, add);
    }
  }
  return output;
}
