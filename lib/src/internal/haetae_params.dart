final class HaetaeParameters {
  const HaetaeParameters._({
    required this.mode,
    required this.k,
    required this.l,
    required this.tau,
    required this.b0Squared,
    required this.b1Squared,
    required this.b2Squared,
    required this.gamma,
    required this.baseEncodedHighZ1,
    required this.baseEncodedHint,
    required this.alphaHint,
    required this.polyQBytes,
    required this.poly2EtaBytes,
    required this.publicKeyBytes,
    required this.secretKeyBytes,
    required this.signatureBytes,
  });

  static const n = 256;
  static const q = 64513;
  static const doubleQ = 129026;
  static const seedBytes = 32;
  static const crhBytes = 64;
  static const fixedScale = 8192;

  final int mode;
  final int k;
  final int l;
  int get m => l - 1;
  final int tau;
  final int b0Squared;
  final int b1Squared;
  final int b2Squared;
  final double gamma;
  final int baseEncodedHighZ1;
  final int baseEncodedHint;
  final int alphaHint;
  int get logAlphaHint => alphaHint == 256 ? 8 : 9;
  final int polyQBytes;
  final int poly2EtaBytes;
  final int publicKeyBytes;
  final int secretKeyBytes;
  final int signatureBytes;
}

HaetaeParameters _defineHaetae(
  int mode,
  int k,
  int l,
  int tau,
  double b0,
  double b1,
  double b2,
  double gamma,
  int baseHigh,
  int baseHint,
  int alpha,
  int polyQ,
  int polyEta,
  int signature,
) {
  final publicKey = HaetaeParameters.seedBytes + k * polyQ;
  final secretKey =
      publicKey + (l - 1) * 64 + k * polyEta + HaetaeParameters.seedBytes;
  return HaetaeParameters._(
    mode: mode,
    k: k,
    l: l,
    tau: tau,
    b0Squared: (b0 * b0).toInt(),
    b1Squared: (b1 * b1).toInt(),
    b2Squared: (b2 * b2).toInt(),
    gamma: gamma,
    baseEncodedHighZ1: baseHigh,
    baseEncodedHint: baseHint,
    alphaHint: alpha,
    polyQBytes: polyQ,
    poly2EtaBytes: polyEta,
    publicKeyBytes: publicKey,
    secretKeyBytes: secretKey,
    signatureBytes: signature,
  );
}

final haetae2Parameters = _defineHaetae(
  2,
  2,
  4,
  58,
  9846.02,
  9838.98,
  12777.52,
  48.858,
  132,
  7,
  512,
  480,
  96,
  1474,
);
final haetae3Parameters = _defineHaetae(
  3,
  3,
  6,
  80,
  18314.98,
  18307.70,
  21906.65,
  57.707,
  376,
  127,
  512,
  480,
  96,
  2349,
);
final haetae5Parameters = _defineHaetae(
  5,
  4,
  7,
  128,
  22343.66,
  22334.95,
  24441.49,
  55.13,
  501,
  358,
  256,
  512,
  64,
  2948,
);
