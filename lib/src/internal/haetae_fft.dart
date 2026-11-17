import 'haetae_params.dart';

const _rootQuarter = <(int, int)>[
  (65536, 0),
  (65531, -804),
  (65516, -1608),
  (65492, -2412),
  (65457, -3216),
  (65413, -4019),
  (65358, -4821),
  (65294, -5623),
  (65220, -6424),
  (65137, -7224),
  (65043, -8022),
  (64940, -8820),
  (64827, -9616),
  (64704, -10411),
  (64571, -11204),
  (64429, -11996),
  (64277, -12785),
  (64115, -13573),
  (63944, -14359),
  (63763, -15143),
  (63572, -15924),
  (63372, -16703),
  (63162, -17479),
  (62943, -18253),
  (62714, -19024),
  (62476, -19792),
  (62228, -20557),
  (61971, -21320),
  (61705, -22078),
  (61429, -22834),
  (61145, -23586),
  (60851, -24335),
  (60547, -25080),
  (60235, -25821),
  (59914, -26558),
  (59583, -27291),
  (59244, -28020),
  (58896, -28745),
  (58538, -29466),
  (58172, -30182),
  (57798, -30893),
  (57414, -31600),
  (57022, -32303),
  (56621, -33000),
  (56212, -33692),
  (55794, -34380),
  (55368, -35062),
  (54934, -35738),
  (54491, -36410),
  (54040, -37076),
  (53581, -37736),
  (53114, -38391),
  (52639, -39040),
  (52156, -39683),
  (51665, -40320),
  (51166, -40951),
  (50660, -41576),
  (50146, -42194),
  (49624, -42806),
  (49095, -43412),
  (48559, -44011),
  (48015, -44604),
  (47464, -45190),
  (46906, -45769),
  (46341, -46341),
];

final _rootReal = _createRoots().$1;
final _rootImaginary = _createRoots().$2;
final _reversedIndices = List<int>.generate(
  HaetaeParameters.n,
  (index) => _reverse8(index),
  growable: false,
);

(List<int>, List<int>) _createRoots() {
  final real = List<int>.filled(HaetaeParameters.n, 0);
  final imaginary = List<int>.filled(HaetaeParameters.n, 0);
  for (var index = 0; index < _rootQuarter.length; index++) {
    real[index] = _rootQuarter[index].$1;
    imaginary[index] = _rootQuarter[index].$2;
  }
  for (
    var index = _rootQuarter.length;
    index <= HaetaeParameters.n ~/ 2;
    index++
  ) {
    final mirrored = HaetaeParameters.n ~/ 2 - index;
    real[index] = -imaginary[mirrored];
    imaginary[index] = -real[mirrored];
  }
  for (
    var index = HaetaeParameters.n ~/ 2 + 1;
    index < HaetaeParameters.n;
    index++
  ) {
    final mirrored = HaetaeParameters.n - index;
    real[index] = -real[mirrored];
    imaginary[index] = imaginary[mirrored];
  }
  return (real, imaginary);
}

int _reverse8(int value) {
  var output = 0;
  for (var index = 0; index < 8; index++) {
    output = (output << 1) | ((value >>> index) & 1);
  }
  return output;
}

int _roundedShift16(int value) => (value + 32768) >> 16;
int _roundedSquareShift16(int value) => (value * value + 32768) >> 16;

({List<int> real, List<int> imaginary}) _fftTransform(List<int> input) {
  final real = List<int>.filled(HaetaeParameters.n, 0);
  final imaginary = List<int>.filled(HaetaeParameters.n, 0);
  for (var index = 0; index < input.length; index++) {
    final reversed = _reversedIndices[index];
    real[reversed] = input[index] * _rootReal[index];
    imaginary[reversed] = input[index] * _rootImaginary[index];
  }
  for (var round = 1; round <= 8; round++) {
    final width = 1 << round;
    final half = width >>> 1;
    for (var start = 0; start < HaetaeParameters.n; start += width) {
      for (var offset = 0; offset < half; offset++) {
        final even = start + offset;
        final odd = even + half;
        final rootIndex = offset << (9 - round);
        final rootR = _rootReal[rootIndex];
        final rootI = _rootImaginary[rootIndex];
        final oddR = real[odd];
        final oddI = imaginary[odd];
        final rightR =
            _roundedShift16(rootR * oddR) - _roundedShift16(rootI * oddI);
        final rightI =
            _roundedShift16(rootR * oddI) + _roundedShift16(rootI * oddR);
        final leftR = real[even];
        final leftI = imaginary[even];
        real[even] = leftR + rightR;
        imaginary[even] = leftI + rightI;
        real[odd] = leftR - rightR;
        imaginary[odd] = leftI - rightI;
      }
    }
  }
  return (real: real, imaginary: imaginary);
}

int haetaeSecretSingularValue(
  HaetaeParameters parameters,
  List<List<int>> first,
  List<List<int>> second,
) {
  final sums = List<int>.filled(HaetaeParameters.n, 0);
  for (final group in [first, second]) {
    for (final polynomial in group) {
      final transformed = _fftTransform(polynomial);
      for (var index = 0; index < sums.length; index++) {
        sums[index] +=
            _roundedSquareShift16(transformed.real[index]) +
            _roundedSquareShift16(transformed.imaginary[index]);
      }
    }
  }
  sums.sort();
  final selectedCount = HaetaeParameters.n ~/ parameters.tau + 1;
  final minimum = sums[sums.length - selectedCount];
  var result = 0;
  for (var offset = 0; offset < selectedCount; offset++) {
    final value = sums[sums.length - 1 - offset];
    final factor = value == minimum
        ? HaetaeParameters.n % parameters.tau
        : parameters.tau;
    result += ((value + 0x10200) ~/ 1024) * factor;
  }
  return (result + 32) ~/ 64;
}
