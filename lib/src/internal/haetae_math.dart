import 'haetae_params.dart';

int haetaeMontgomeryReduce(int value) {
  final multiplier = _signed32(value * 940508161);
  return (value - multiplier * HaetaeParameters.q) >> 32;
}

int _signed32(int value) {
  final reduced = value & 0xffffffff;
  return reduced >= 0x80000000 ? reduced - 0x100000000 : reduced;
}

int haetaeFreeze(int value) {
  final result = value % HaetaeParameters.q;
  return result < 0 ? result + HaetaeParameters.q : result;
}

int haetaeCenteredMod2Q(int value) {
  var result = value % HaetaeParameters.doubleQ;
  if (result < -HaetaeParameters.q) result += HaetaeParameters.doubleQ;
  if (result >= HaetaeParameters.q) result -= HaetaeParameters.doubleQ;
  return result;
}

int haetaeFreeze2Q(int value) {
  final result = value % HaetaeParameters.doubleQ;
  return result < 0 ? result + HaetaeParameters.doubleQ : result;
}

(int, int) haetaeDecomposeZ1(int value) {
  var low = value & 255;
  if (low >= 128) low -= 256;
  return ((value + 128) >> 8, low);
}

int haetaeDecomposeHint(int value, int alpha, int logAlpha) {
  final high = (value + alpha ~/ 2) >> logAlpha;
  return high == (HaetaeParameters.doubleQ - 2) ~/ alpha ? 0 : high;
}

(int, int) haetaeDecomposePublicKey(int value) {
  var low = value & 1;
  low -= ((value >> 1) & low) << 1;
  return ((value - low) >> 1, low);
}

int haetaeSquaredNorm(Iterable<List<List<int>>> groups) {
  var sum = 0;
  for (final group in groups) {
    for (final polynomial in group) {
      for (final coefficient in polynomial) {
        sum += coefficient * coefficient;
      }
    }
  }
  return sum;
}
