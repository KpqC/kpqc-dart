import 'dart:typed_data';

import 'haetae_encoding.dart';
import 'haetae_params.dart';
import 'haetae_poly.dart';

typedef HaetaeSecretKey = ({
  List<List<List<int>>> matrix,
  List<List<int>> first,
  List<List<int>> second,
  Uint8List key,
});
typedef HaetaeSignature = ({
  List<int> challenge,
  List<List<int>> lowBits,
  List<List<int>> highBits,
  List<List<int>> hint,
});

Uint8List haetaePackBits(List<int> values, int bits) {
  final output = Uint8List(HaetaeParameters.n * bits ~/ 8);
  var accumulator = 0;
  var available = 0;
  var offset = 0;
  for (final coefficient in values) {
    accumulator |= (coefficient & 0xffffffff) << available;
    available += bits;
    while (available >= 8) {
      output[offset++] = accumulator;
      accumulator >>>= 8;
      available -= 8;
    }
  }
  return output;
}

List<int> haetaeUnpackBits(Uint8List input, int bits) {
  final output = List<int>.filled(HaetaeParameters.n, 0);
  var accumulator = 0;
  var available = 0;
  var offset = 0;
  final mask = (1 << bits) - 1;
  for (var index = 0; index < output.length; index++) {
    while (available < bits) {
      accumulator |= input[offset++] << available;
      available += 8;
    }
    output[index] = accumulator & mask;
    accumulator >>>= bits;
    available -= bits;
  }
  return output;
}

Uint8List haetaePackPublicKey(
  HaetaeParameters parameters,
  Uint8List seed,
  List<List<int>> publicVector,
) => haetaeConcatenate([
  seed,
  for (final polynomial in publicVector)
    haetaePackBits(polynomial, parameters.mode == 5 ? 16 : 15),
]);

List<List<List<int>>> haetaeUnpackPublicKey(
  HaetaeParameters parameters,
  Uint8List publicKey,
) {
  final seed = Uint8List.fromList(
    publicKey.sublist(0, HaetaeParameters.seedBytes),
  );
  var offset = HaetaeParameters.seedBytes;
  final bits = parameters.mode == 5 ? 16 : 15;
  final packed = haetaeZeroVector(parameters.k);
  for (var index = 0; index < packed.length; index++) {
    packed[index] = haetaeUnpackBits(
      Uint8List.fromList(
        publicKey.sublist(offset, offset + parameters.polyQBytes),
      ),
      bits,
    );
    offset += parameters.polyQBytes;
  }
  final matrix = haetaeExpandMatrix(parameters, seed, true);
  for (var row = 0; row < matrix.length; row++) {
    for (var column = 1; column < parameters.l; column++) {
      for (var index = 0; index < HaetaeParameters.n; index++) {
        matrix[row][column][index] *= 2;
      }
    }
  }
  if (parameters.mode == 5) {
    for (var row = 0; row < matrix.length; row++) {
      matrix[row][0] = packed[row];
    }
    return matrix;
  }
  final random = haetaeExpandPublicVector(parameters, seed);
  final firstColumn = haetaeTransformVector(
    haetaeDoubleVector(
      haetaeSubtractVectors(random, haetaeDoubleVector(packed)),
    ),
  );
  for (var row = 0; row < matrix.length; row++) {
    matrix[row][0] = firstColumn[row];
  }
  return matrix;
}

Uint8List _packEta(List<int> value) =>
    haetaePackBits(value.map((item) => 1 - item).toList(), 2);
List<int> _unpackEta(Uint8List value) =>
    haetaeUnpackBits(value, 2).map((item) => 1 - item).toList();
Uint8List _packDoubleEta(List<int> value) =>
    haetaePackBits(value.map((item) => 2 - item).toList(), 3);
List<int> _unpackDoubleEta(Uint8List value) =>
    haetaeUnpackBits(value, 3).map((item) => 2 - item).toList();

Uint8List haetaePackSecretKey(
  HaetaeParameters parameters,
  Uint8List publicKey,
  List<List<int>> first,
  List<List<int>> second,
  Uint8List key,
) => haetaeConcatenate([
  publicKey,
  for (final polynomial in first) _packEta(polynomial),
  for (final polynomial in second)
    parameters.mode == 5 ? _packEta(polynomial) : _packDoubleEta(polynomial),
  key,
]);

HaetaeSecretKey haetaeUnpackSecretKey(
  HaetaeParameters parameters,
  Uint8List secretKey,
) {
  final publicKey = Uint8List.fromList(
    secretKey.sublist(0, parameters.publicKeyBytes),
  );
  var offset = parameters.publicKeyBytes;
  final first = haetaeZeroVector(parameters.m);
  for (var index = 0; index < first.length; index++) {
    first[index] = _unpackEta(
      Uint8List.fromList(secretKey.sublist(offset, offset + 64)),
    );
    offset += 64;
  }
  final second = haetaeZeroVector(parameters.k);
  for (var index = 0; index < second.length; index++) {
    final packed = Uint8List.fromList(
      secretKey.sublist(offset, offset + parameters.poly2EtaBytes),
    );
    second[index] = parameters.mode == 5
        ? _unpackEta(packed)
        : _unpackDoubleEta(packed);
    offset += parameters.poly2EtaBytes;
  }
  final key = Uint8List.fromList(
    secretKey.sublist(offset, offset + HaetaeParameters.seedBytes),
  );
  return (
    matrix: haetaeUnpackPublicKey(parameters, publicKey),
    first: first,
    second: second,
    key: key,
  );
}

Uint8List haetaePackHighBits(
  HaetaeParameters parameters,
  List<List<int>> value,
) {
  if (parameters.mode != 5) {
    return haetaeConcatenate([
      for (final polynomial in value)
        Uint8List(HaetaeParameters.n * 9 ~/ 8)
          ..setRange(0, HaetaeParameters.n, polynomial),
    ]);
  }
  return haetaeConcatenate([
    for (final polynomial in value) haetaePackBits(polynomial, 9),
  ]);
}

Uint8List? haetaePackSignature(
  HaetaeParameters parameters,
  List<int> challenge,
  List<List<int>> lowBits,
  List<List<int>> highBits,
  List<List<int>> hint,
) {
  final encodedHigh = haetaeEncodeHighBits(parameters, highBits);
  final encodedHint = haetaeEncodeHint(parameters, hint);
  if (encodedHigh == null ||
      encodedHint == null ||
      encodedHigh.length < parameters.baseEncodedHighZ1 ||
      encodedHigh.length > parameters.baseEncodedHighZ1 + 255 ||
      encodedHint.length < parameters.baseEncodedHint ||
      encodedHint.length > parameters.baseEncodedHint + 255) {
    return null;
  }
  final used =
      HaetaeParameters.seedBytes +
      parameters.l * HaetaeParameters.n +
      2 +
      encodedHigh.length +
      encodedHint.length;
  if (used > parameters.signatureBytes) return null;
  final signature = Uint8List(parameters.signatureBytes);
  for (var index = 0; index < challenge.length; index++) {
    signature[index >>> 3] |= challenge[index] << (index & 7);
  }
  var offset = HaetaeParameters.seedBytes;
  for (final polynomial in lowBits) {
    for (var index = 0; index < polynomial.length; index++) {
      signature[offset + index] = polynomial[index];
    }
    offset += HaetaeParameters.n;
  }
  signature[offset++] = encodedHigh.length - parameters.baseEncodedHighZ1;
  signature[offset++] = encodedHint.length - parameters.baseEncodedHint;
  signature.setRange(offset, offset + encodedHigh.length, encodedHigh);
  offset += encodedHigh.length;
  signature.setRange(offset, offset + encodedHint.length, encodedHint);
  return signature;
}

HaetaeSignature? haetaeUnpackSignature(
  HaetaeParameters parameters,
  Uint8List signature,
) {
  if (signature.length != parameters.signatureBytes) return null;
  final challenge = List<int>.generate(
    HaetaeParameters.n,
    (index) => (signature[index >>> 3] >>> (index & 7)) & 1,
    growable: false,
  );
  var offset = HaetaeParameters.seedBytes;
  final lowBits = haetaeZeroVector(parameters.l);
  for (final polynomial in lowBits) {
    for (var index = 0; index < polynomial.length; index++) {
      polynomial[index] = signature[offset + index] >= 128
          ? signature[offset + index] - 256
          : signature[offset + index];
    }
    offset += HaetaeParameters.n;
  }
  final highLength = signature[offset++] + parameters.baseEncodedHighZ1;
  final hintLength = signature[offset++] + parameters.baseEncodedHint;
  if (offset + highLength + hintLength > signature.length) return null;
  final highBits = haetaeDecodeHighBits(
    parameters,
    Uint8List.fromList(signature.sublist(offset, offset + highLength)),
  );
  if (highBits == null) return null;
  offset += highLength;
  final hint = haetaeDecodeHint(
    parameters,
    Uint8List.fromList(signature.sublist(offset, offset + hintLength)),
  );
  if (hint == null) return null;
  offset += hintLength;
  while (offset < signature.length) {
    if (signature[offset++] != 0) return null;
  }
  return (
    challenge: challenge,
    lowBits: lowBits,
    highBits: highBits,
    hint: hint,
  );
}
