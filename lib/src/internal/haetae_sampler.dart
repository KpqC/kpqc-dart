import 'dart:typed_data';

import 'haetae_math.dart';
import 'haetae_params.dart';
import 'haetae_poly.dart';

final _mask64 = (BigInt.one << 64) - BigInt.one;
final _sign64 = BigInt.one << 63;
final _u48 = (BigInt.one << 48) - BigInt.one;

BigInt _u64(BigInt value) => value & _mask64;
BigInt _j64(BigInt value) {
  final reduced = _u64(value);
  return reduced >= _sign64 ? reduced - (BigInt.one << 64) : reduced;
}

BigInt _ushr(BigInt value, int shift) => _u64(value) >> shift;
BigInt _jAdd(BigInt left, BigInt right) => _j64(left + right);
BigInt _jMul(BigInt left, BigInt right) => _j64(left * right);
BigInt _jXor(BigInt left, BigInt right) => _j64(_u64(left) ^ _u64(right));

final class _Fixed96 {
  const _Fixed96(this.low, this.high);
  final BigInt low;
  final BigInt high;
}

final class _HyperConstants {
  const _HyperConstants(
    this.startCube,
    this.startTimesThreeHalves,
    this.scalar,
  );
  final _Fixed96 startCube;
  final _Fixed96 startTimesThreeHalves;
  final BigInt scalar;
}

final class _Product {
  const _Product(this.low, this.high);
  final BigInt low;
  final BigInt high;
}

final class _CdtEntry {
  const _CdtEntry(this.upper, this.middle, this.lower);
  final int upper;
  final int middle;
  final int lower;
}

final class _GaussianCandidate {
  const _GaussianCandidate(this.accepted, this.sample, this.square);
  final bool accepted;
  final BigInt sample;
  final _Fixed96 square;
}

final class _GaussianSamples {
  const _GaussianSamples(this.samples, this.signs, this.squareSum);
  final List<BigInt> samples;
  final Uint8List signs;
  final _Fixed96 squareSum;
}

final class HaetaeHyperballSample {
  const HaetaeHyperballSample(
    this.first,
    this.second,
    this.bit,
    this.nextNonce,
  );
  final List<List<int>> first;
  final List<List<int>> second;
  final int bit;
  final int nextNonce;
}

final _mode2Hyper = _HyperConstants(
  _Fixed96(
    BigInt.parse('770077e2e41a', radix: 16),
    BigInt.parse('1162', radix: 16),
  ),
  _Fixed96(
    BigInt.parse('693861ad937b', radix: 16),
    BigInt.parse('9caa56', radix: 16),
  ),
  BigInt.from(2643021496320),
);
final _mode3Hyper = _HyperConstants(
  _Fixed96(
    BigInt.parse('1a2935cfae68', radix: 16),
    BigInt.parse('978', radix: 16),
  ),
  _Fixed96(
    BigInt.parse('7ad215218533', radix: 16),
    BigInt.parse('7ff1c9', radix: 16),
  ),
  BigInt.from(4916390789120),
);
final _mode5Hyper = _HyperConstants(
  _Fixed96(
    BigInt.parse('700ff3e8890d', radix: 16),
    BigInt.parse('702', radix: 16),
  ),
  _Fixed96(
    BigInt.parse('5768588eed31', radix: 16),
    BigInt.parse('73bd40', radix: 16),
  ),
  BigInt.from(5997831421952),
);

const _cdtHigh = '''
063a5 0c718 129f6 18bdf 1ec73 24b59 2a83a 302c6 35ab6 3afc7 401be 4506a 49ba1 4e343 52736 5676c
5a3dc 5dc86 61172 642ad 6704c 69a68 6c120 6e496 704ef 72255 73cf1 754f0 76a7c 77dc4 78ef2 79e32
7abaf 7b78f 7c1fb 7cb17 7d304 7d9e4 7dfd4 7e4f0 7e950 7ed0d 7f03b 7f2ec 7f531 7f71a 7f8b3 7fa08
7fb24 7fc0e 7fccf 7fd6e 7fdf0 7fe5a 7feaf 7fef5 7ff2c 7ff59 7ff7d 7ff99 7ffb0 7ffc2 7ffd0 7ffdb
7ffe3 7ffea 7ffef 7fff3 7fff6 7fff8 7fffa 7fffb 7fffd 7fffd 7fffe 7fffe
''';
const _cdtLow = '''
0aa572bc88db1e28 4f3820e69064b2ee d68dc44dd1418704 6587a04d9b97b1dd 9b843ce0a65d0050 02b62cb869003e7d
0d44f194f8bf43c6 faa0c7acb211b4db a11387f7f524be80 18526ca6f2ceb77f 42a01a906b7dad17 32e5337a1966b9a7
6f00f7ac9735f58a 0e6c48f40642ba60 b6192fa1afb5e4ec 7339dba8ffc2fcf5 7746cbe1ac90c9eb b83004341d78466f
781dcca572bb3d8a b880376cc82a5384 9c68a5c477dfecb9 be45ceb02a25fef3 7d1a8ccd208dbaa1 452c002b9085e7db
d7ef361c5551378d 96b4ff49d9e5a8bb d337c94ede732d83 28c75b8d3fe83c38 e05d7bd130fe20e0 6170e60b76d85108
b0e59892414901ff ff05cf70b911f3de 4501460fdfd508c9 f20b1303a2a54906 a7d3badbeb04b20c 05ce666b741b666d
826e689fded20430 5155d1354fcf6ff6 55469226a1d318f6 1c8d3820cfa9cabc e68d83bbf700fc40 b1152d8944042803
4c1e741aabe53700 72b94c56e0f9a967 e7e5a80a79e4539c 9641c5d11feb4d12 b18b71598b73dde0 d9112fb5a7904d7e
3a4f57cbefabc820 b314025fd5022976 f2a2b228aab1981b 996ce1e60378cd98 570ec64b38e3ca90 0657269615dcd7c6
c7360038bdc85312 167fa02a57a8ae1a e380fab2ea9b2bef a36e6abd6509b5a2 62bfcf1d6ba81c37 d4946e8bf96caa93
603e6262ea8cda2d 2d18c8b333ae9203 2ccdedb5a7718d61 24333ecab8497c0a b2e06eb33bf2b7d9 59a5f6c550dfe7e2
800548f3927f906e 78cac146b573bc40 85e6dadec4b6aff1 dba17dfa17def8ec a33f84d06ce20a93 fd2fe967c5186746
02d37ecd7e9b180f c7efafa8bd33f0bb 5bda826341e791cc ca6c1c6ce045599f 1cc02c0faa9a526e 59d002901a4a4e52
86ecbd139ce07540 a81f9f15ffb47f4c c075b17481687af0 d23ad13e68301c65 df27955fae1c84cb e884cdb07368c266
ef46d4f897fc83f6 f4227e46663ec049 f79d091c1b5aff07 fa183c533c3890a6 fbdb8a602066b0f2 fd1af06df3db86b7
fdfc1a818587e2aa fe9a37a348ac2a93 ff08d0797970dbfe ff55df73fd7a00bc ff8b5aa573bca5ce ffb053c109f51681
ffc9c9bd39a036ec ffdb40bd4ee1f846 ffe72fa859b20a4a ffef4edda93d266d fff4d07a9fb0d4e0 fff88868ef31b1cc
fffb08c16a3f5f0c fffcb5d30be5cabf fffdd43465d95fe6 fffe929a538ad2fa ffff10b1c2119732 ffff63df8795a2c9
ffff9a87a0a9f2af ffffbe4df6f0f4a9 ffffd5a10f204910 ffffe4c6f1668b32 ffffee939680bfaf fffff4e4216290db
fffff8f1c044613e fffffb892dc2b174 fffffd2fb4188608 fffffe3bc0a56eba fffffee523b218c6 ffffff4fc31097e3
ffffff929d76dbeb ffffffbc5e7c0350 ffffffd6586c6684 ffffffe6716865f7 fffffff0613c76e2 fffffff67d62ab64
fffffffa3b6664c0 fffffffc83e13d66 fffffffde713ef71 fffffffebe18936f ffffffff3fbfc997 ffffffff8d9fa29a
ffffffffbc372590 ffffffffd7fb7dfd ffffffffe87747f9 fffffffff2368b89 fffffffff7f44d88 fffffffffb52a49b
fffffffffd4a9ffb fffffffffe700579 ffffffffff1a287f ffffffffff7c6f06 ffffffffffb4fa99 ffffffffffd56300
ffffffffffe7e364 fffffffffff268d7 fffffffffff85e8e fffffffffffbbb6f fffffffffffd9f49 fffffffffffeae2c
ffffffffffff453d ffffffffffff9928 ffffffffffffc797 ffffffffffffe12f ffffffffffffef3c fffffffffffff6eb
fffffffffffffb1b fffffffffffffd60 fffffffffffffe9a ffffffffffffff43 ffffffffffffff9e ffffffffffffffce
ffffffffffffffe7 fffffffffffffff4 fffffffffffffffb fffffffffffffffe
''';

final _cdt = _createCdt();

List<_CdtEntry> _createCdt() {
  final highs = _cdtHigh.trim().split(RegExp(r'\s+'));
  final lows = _cdtLow.trim().split(RegExp(r'\s+'));
  return List<_CdtEntry>.generate(lows.length, (index) {
    final low = BigInt.parse(lows[index], radix: 16);
    final high = index < highs.length
        ? int.parse(highs[index], radix: 16)
        : 0x7ffff;
    return _CdtEntry(
      high,
      ((low >> 32) & BigInt.from(0xffffffff)).toInt(),
      (low & BigInt.from(0xffffffff)).toInt(),
    );
  }, growable: false);
}

_HyperConstants _constants(int mode) => mode == 2
    ? _mode2Hyper
    : mode == 3
    ? _mode3Hyper
    : _mode5Hyper;

_Fixed96 _normalize(_Fixed96 value) =>
    _Fixed96(_u64(value.low) & _u48, _jAdd(value.high, _ushr(value.low, 48)));

_Fixed96 _conditionalNegate(_Fixed96 value, BigInt sign) {
  final mask = -sign;
  return _normalize(
    _Fixed96(
      _jAdd(_jXor(value.low, mask & _u48), sign),
      _jXor(value.high, mask),
    ),
  );
}

_Fixed96 _addFixed(_Fixed96 left, _Fixed96 right) =>
    _Fixed96(_jAdd(left.low, right.low), _jAdd(left.high, right.high));

_Fixed96 _subtractFixed(_Fixed96 left, _Fixed96 right) =>
    _addFixed(left, _conditionalNegate(right, BigInt.one));

_Fixed96 _subtractThreeHalves(_Fixed96 value) {
  final negative = _conditionalNegate(value, BigInt.one);
  return _normalize(
    _Fixed96(negative.low, _jAdd(negative.high, BigInt.from(3) << 27)),
  );
}

BigInt _unsignedMultiplyHigh(BigInt left, BigInt right) =>
    _j64((_u64(left) * _u64(right)) >> 64);

_Product _multiply48(BigInt left, BigInt right) {
  final low = _jMul(left, right);
  final high = _unsignedMultiplyHigh(left, right);
  return _Product(_u64(low) & _u48, _jXor(_j64(high << 16), _ushr(low, 48)));
}

_Fixed96 _multiplyFixed(_Fixed96 left, _Fixed96 right) {
  final lowProduct = _multiply48(left.low, right.low);
  var low = _jAdd(
    lowProduct.high,
    _ushr(_jAdd(_ushr(lowProduct.low, 47), BigInt.one), 1),
  );
  final cross = _multiply48(left.low, right.high);
  low = _jAdd(low, cross.low);
  var high = cross.high;
  final cross2 = _multiply48(left.high, right.low);
  low = _jAdd(low, cross2.low);
  high = _jAdd(high, cross2.high);
  low = _jAdd(low, BigInt.one << 27);
  low = _ushr(low, 28);
  low = _jAdd(low, _j64(high << 20) & _u48);
  high = _ushr(high, 28);
  final upperLow = _jMul(left.high, right.high);
  final upperHigh = _unsignedMultiplyHigh(left.high, right.high);
  low = _jAdd(low, _j64(upperLow << 20) & _u48);
  high = _jAdd(high, _jAdd(_ushr(upperLow, 28), _j64(upperHigh << 36)));
  return _normalize(_Fixed96(low, high));
}

_Fixed96 _squareFixed(_Fixed96 value) {
  final lowProduct = _multiply48(value.low, value.low);
  var low = _jAdd(_ushr(lowProduct.low, 48), lowProduct.high);
  final cross = _multiply48(value.low, value.high);
  low = _jAdd(low, _j64(cross.low << 1));
  var high = _j64(cross.high << 1);
  low = _ushr(low, 28);
  low = _jAdd(low, _j64(high << 20) & _u48);
  high = _ushr(high, 28);
  final upperLow = _jMul(value.high, value.high);
  final upperHigh = _unsignedMultiplyHigh(value.high, value.high);
  low = _jAdd(low, _j64(upperLow << 20) & _u48);
  high = _jAdd(high, _jAdd(_ushr(upperLow, 28), _j64(upperHigh << 36)));
  return _normalize(_Fixed96(low, high));
}

_Fixed96 _multiplyUnsignedSigned(_Fixed96 value, _Fixed96 signed) {
  final sign = _ushr(signed.high, 63);
  final absolute = _conditionalNegate(signed, sign);
  return _conditionalNegate(_multiplyFixed(absolute, value), sign);
}

_Fixed96 _multiplyFixedHigh(_Fixed96 value, BigInt scalar) {
  final lower = _multiply48(value.low, scalar);
  final upper = _multiply48(value.high, scalar);
  var high = _jAdd(lower.high, upper.low);
  var low = _jAdd(lower.low, BigInt.one << 27);
  low = _ushr(low, 28);
  low = _jAdd(low, _j64(high << 20) & _u48);
  high = _ushr(high, 28);
  high = _jAdd(high, _j64(upper.high << 20));
  return _normalize(_Fixed96(low, high));
}

_Fixed96 _inverseSquareRoot(int mode, _Fixed96 half) {
  final spec = _constants(mode);
  var result = _subtractFixed(
    spec.startTimesThreeHalves,
    _multiplyFixed(half, spec.startCube),
  );
  for (var iteration = 0; iteration < 6; iteration++) {
    final factor = _subtractThreeHalves(
      _multiplyFixed(half, _squareFixed(result)),
    );
    result = _multiplyUnsignedSigned(result, factor);
  }
  return result;
}

BigInt _signedMultiplyHigh48(BigInt left, BigInt right) {
  final sign = left >> 63;
  final magnitude = _jAdd(_jXor(left, sign), -sign);
  final low = _jMul(magnitude, right);
  final high = _unsignedMultiplyHigh(magnitude, right);
  var quotient = _j64(_j64(high << 16) | _ushr(low, 48));
  final remainder = _u64(low) & _u48;
  final nonzeroRemainder = _ushr(_j64(remainder | _u64(-remainder)), 63);
  quotient = _jAdd(quotient, nonzeroRemainder & (_u64(~sign) & BigInt.one));
  return _jAdd(_jXor(quotient, sign), -sign);
}

BigInt _approximateExponential(BigInt value) {
  var result = BigInt.from(55868746);
  result = _jAdd(_signedMultiplyHigh48(result, value), BigInt.from(-743564434));
  result = _jAdd(_signedMultiplyHigh48(result, value), BigInt.from(6953427278));
  result = _jAdd(
    _signedMultiplyHigh48(result, value),
    BigInt.from(-55833338892),
  );
  result = _jAdd(
    _signedMultiplyHigh48(result, value),
    BigInt.from(390932311155),
  );
  result = _jAdd(
    _signedMultiplyHigh48(result, value),
    BigInt.from(-2345623661771),
  );
  result = _jAdd(
    _signedMultiplyHigh48(result, value),
    BigInt.from(11728123872951),
  );
  result = _jAdd(
    _signedMultiplyHigh48(result, value),
    BigInt.from(-46912496106200),
  );
  result = _jAdd(
    _signedMultiplyHigh48(result, value),
    BigInt.from(140737488354861),
  );
  result = _jAdd(
    _signedMultiplyHigh48(result, value),
    BigInt.from(-281474976710650),
  );
  return _jAdd(
    _signedMultiplyHigh48(result, value),
    BigInt.from(281474976710657),
  );
}

int _readLittleEndian32(Uint8List input, int offset) =>
    input[offset] |
    input[offset + 1] << 8 |
    input[offset + 2] << 16 |
    input[offset + 3] << 24;

BigInt _littleEndian48(Uint8List input, int offset) {
  var output = BigInt.zero;
  for (var index = 0; index < 6; index++) {
    output |= BigInt.from(input[offset + index]) << (8 * index);
  }
  return output;
}

int _sampleGaussian83(int lower, int middle, int upper) {
  var start = 0;
  var end = _cdt.length;
  while (start < end) {
    final index = (start + end) >>> 1;
    final item = _cdt[index];
    final isLower =
        item.upper < upper ||
        item.upper == upper &&
            (item.middle < middle ||
                item.middle == middle && item.lower < lower);
    if (isLower) {
      start = index + 1;
    } else {
      end = index;
    }
  }
  return start;
}

_GaussianCandidate _gaussianCandidate(Uint8List random) {
  final lower = _readLittleEndian32(random, 0);
  final middle = _readLittleEndian32(random, 4);
  final upper = random[8] | random[9] << 8 | (random[10] & 7) << 16;
  final rejection = _littleEndian48(random, 11);
  final x = _sampleGaussian83(lower, middle, upper);
  final value = _Fixed96(
    _littleEndian48(random, 17),
    BigInt.from(random[23] | random[24] << 8 | random[25] << 16 | x << 24),
  );
  var sample = _ushr(_jAdd(_ushr(value.low, 15), BigInt.one), 1);
  sample = _jAdd(sample, _j64(value.high << 32));
  final square = _squareFixed(value);
  var exponent = _jAdd(square.high, BigInt.from(-x * x * (1 << 20)));
  exponent = _j64(_j64(exponent << 20) | _ushr(square.low, 28));
  exponent = _ushr(_jAdd(exponent, BigInt.one), 1);
  final even = rejection ^ (rejection & BigInt.one);
  final accepted =
      even < _u64(_approximateExponential(exponent)) &&
      (sample != BigInt.zero || (rejection & BigInt.one) != BigInt.zero);
  return _GaussianCandidate(accepted, sample, square);
}

_GaussianSamples _sampleGaussianN(
  Uint8List seed,
  int nonce,
  int length,
  _Fixed96 initialSquareSum,
) {
  final shake = haetaeStream(256, seed, nonce);
  final signs = Uint8List(length ~/ 8);
  shake.squeeze(signs);
  final samples = <BigInt>[];
  var squareSum = initialSquareSum;
  final random = Uint8List(26);
  while (samples.length < length) {
    shake.squeeze(random);
    final candidate = _gaussianCandidate(random);
    if (!candidate.accepted) continue;
    squareSum = _Fixed96(
      _jAdd(squareSum.low, candidate.square.low),
      _jAdd(squareSum.high, candidate.square.high),
    );
    samples.add(
      samples.length < HaetaeParameters.n || length == HaetaeParameters.n
          ? candidate.sample
          : BigInt.zero,
    );
  }
  return _GaussianSamples(
    List<BigInt>.generate(HaetaeParameters.n, (index) => samples[index]),
    signs,
    _normalize(squareSum),
  );
}

int _multiplyRound13(BigInt value, _Fixed96 factor, int sign) {
  final fixed = _Fixed96(
    _j64((_u64(value) & BigInt.from(0xffffffff)) << 16),
    _ushr(value, 32),
  );
  final product = _multiplyFixed(fixed, factor);
  final rounded = _ushr(_jAdd(product.high, BigInt.one << 14), 15).toInt();
  return sign == 0 ? rounded : -rounded;
}

HaetaeHyperballSample haetaeSampleHyperball(
  HaetaeParameters parameters,
  Uint8List seed,
  int nonce,
) {
  final dimension = parameters.l + parameters.k;
  final spec = _constants(parameters.mode);
  final normLimit =
      parameters.b0Squared *
      HaetaeParameters.fixedScale *
      HaetaeParameters.fixedScale;
  var next = nonce;
  for (;;) {
    var squareSum = _Fixed96(BigInt.zero, BigInt.zero);
    final samples = <List<BigInt>>[];
    final signs = <Uint8List>[];
    for (var index = 0; index < dimension; index++) {
      final generated = _sampleGaussianN(
        seed,
        next++,
        index < 2 ? HaetaeParameters.n + 1 : HaetaeParameters.n,
        squareSum,
      );
      samples.add(generated.samples);
      signs.add(generated.signs);
      squareSum = generated.squareSum;
    }
    var low = _ushr(_jAdd(squareSum.low, BigInt.one), 1);
    low = _jAdd(low, (squareSum.high & BigInt.one) << 47);
    squareSum = _normalize(_Fixed96(low, _ushr(squareSum.high, 1)));
    final factor = _multiplyFixedHigh(
      _inverseSquareRoot(parameters.mode, squareSum),
      spec.scalar,
    );
    final fixed = haetaeZeroVector(dimension);
    for (var vector = 0; vector < fixed.length; vector++) {
      for (var index = 0; index < HaetaeParameters.n; index++) {
        final sign = (signs[vector][index >>> 3] >>> (index & 7)) & 1;
        fixed[vector][index] = _multiplyRound13(
          samples[vector][index],
          factor,
          sign,
        );
      }
    }
    final first = fixed.sublist(0, parameters.l);
    final second = fixed.sublist(parameters.l);
    if (haetaeSquaredNorm([first, second]) <= normLimit) {
      final shake = haetaeStream(256, seed, next);
      final bit = Uint8List(1);
      shake.squeeze(bit);
      return HaetaeHyperballSample(first, second, bit[0], next);
    }
  }
}

List<List<int>> haetaeRoundFixed(List<List<int>> value) => value
    .map((polynomial) => polynomial.map((item) => (item + 4096) >> 13).toList())
    .toList(growable: false);

List<List<int>> haetaeAddFixedSignedInteger(
  List<List<int>> fixed,
  List<List<int>> integer,
  int sign,
) {
  final factor = sign == 0
      ? HaetaeParameters.fixedScale
      : -HaetaeParameters.fixedScale;
  return List<List<int>>.generate(
    fixed.length,
    (vector) => List<int>.generate(
      HaetaeParameters.n,
      (index) => fixed[vector][index] + factor * integer[vector][index],
      growable: false,
    ),
    growable: false,
  );
}

List<List<int>> haetaeDoubleMinusFixedVectors(
  List<List<int>> value,
  List<List<int>> subtrahend,
) => List<List<int>>.generate(
  value.length,
  (vector) => List<int>.generate(
    HaetaeParameters.n,
    (index) => 2 * value[vector][index] - subtrahend[vector][index],
    growable: false,
  ),
  growable: false,
);
