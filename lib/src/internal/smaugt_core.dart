import 'dart:typed_data';

import 'entropy.dart';
import 'fips202.dart';

const _n = 256;
const _tBytes = 32;
const _publicKeySeedBytes = 32;
const _hwtSeedBytes = 616;

final class SmaugTParameters {
  const SmaugTParameters({
    required this.mode,
    required this.k,
    required this.logQ,
    required this.logP,
    required this.logPPrime,
    required this.cbdSeedBytes,
    required this.messageBytes,
    required this.hammingWeight,
    required this.timer,
  });

  final int mode;
  final int k;
  final int logQ;
  final int logP;
  final int logPPrime;
  final int cbdSeedBytes;
  final int messageBytes;
  final int hammingWeight;
  final bool timer;

  int get publicKeyBytes => _publicKeySeedBytes + k * logQ * _n ~/ 8;
  int get pkeSecretKeyBytes => k * _n ~/ 4;
  int get secretKeyBytes => pkeSecretKeyBytes + _tBytes + publicKeyBytes;
  int get ciphertextBytes => k * logP * _n ~/ 8 + logPPrime * _n ~/ 8;
}

const smaugT128Parameters = SmaugTParameters(
  mode: 1,
  k: 2,
  logQ: 10,
  logP: 8,
  logPPrime: 5,
  cbdSeedBytes: 96,
  messageBytes: 32,
  hammingWeight: 70,
  timer: false,
);

const smaugT192Parameters = SmaugTParameters(
  mode: 3,
  k: 3,
  logQ: 11,
  logP: 9,
  logPPrime: 4,
  cbdSeedBytes: 64,
  messageBytes: 32,
  hammingWeight: 88,
  timer: false,
);

const smaugT256Parameters = SmaugTParameters(
  mode: 5,
  k: 4,
  logQ: 11,
  logP: 9,
  logPPrime: 7,
  cbdSeedBytes: 128,
  messageBytes: 32,
  hammingWeight: 87,
  timer: false,
);

const timerParameters = SmaugTParameters(
  mode: 0,
  k: 2,
  logQ: 10,
  logP: 8,
  logPPrime: 3,
  cbdSeedBytes: 96,
  messageBytes: 16,
  hammingWeight: 70,
  timer: true,
);

final class SmaugTKeyPair {
  const SmaugTKeyPair(this.publicKey, this.secretKey);

  final Uint8List publicKey;
  final Uint8List secretKey;
}

final class SmaugTEncapsulation {
  const SmaugTEncapsulation(this.ciphertext, this.sharedSecret);

  final Uint8List ciphertext;
  final Uint8List sharedSecret;
}

int _i16(int value) {
  final reduced = value & 0xffff;
  return reduced >= 0x8000 ? reduced - 0x10000 : reduced;
}

List<List<int>> _zeroVector(int k) => List<List<int>>.generate(
  k,
  (_) => List<int>.filled(_n, 0),
  growable: false,
);

void _packPoly(
  Uint8List output,
  int outputOffset,
  List<int> polynomial,
  int bits,
  bool scaled,
) {
  final length = bits * _n ~/ 8;
  output.fillRange(outputOffset, outputOffset + length, 0);
  final mask = (1 << bits) - 1;
  final shift = 16 - bits;
  var bitPosition = 0;
  for (final coefficient in polynomial) {
    final value = scaled ? (coefficient >> shift) & mask : coefficient & mask;
    for (var bit = 0; bit < bits; bit++) {
      output[outputOffset + (bitPosition >> 3)] |=
          ((value >>> bit) & 1) << (bitPosition & 7);
      bitPosition++;
    }
  }
}

void _unpackPoly(
  List<int> polynomial,
  Uint8List input,
  int inputOffset,
  int bits,
  bool scaled,
) {
  final shift = 16 - bits;
  var bitPosition = 0;
  for (var index = 0; index < polynomial.length; index++) {
    var value = 0;
    for (var bit = 0; bit < bits; bit++) {
      value |=
          ((input[inputOffset + (bitPosition >> 3)] >>> (bitPosition & 7)) &
              1) <<
          bit;
      bitPosition++;
    }
    polynomial[index] = _i16(scaled ? value << shift : value);
  }
}

void _packSecret(Uint8List output, List<List<int>> secret) {
  for (var polynomial = 0; polynomial < secret.length; polynomial++) {
    final offset = polynomial * (_n ~/ 4);
    for (var index = 0; index < _n ~/ 4; index++) {
      var packed = 0;
      for (var item = 0; item < 4; item++) {
        packed |=
            ((1 - secret[polynomial][4 * index + item]) & 3) << (2 * item);
      }
      output[offset + index] = packed;
    }
  }
}

List<List<int>> _unpackSecret(SmaugTParameters parameters, Uint8List input) {
  final secret = _zeroVector(parameters.k);
  for (var polynomial = 0; polynomial < secret.length; polynomial++) {
    final offset = polynomial * (_n ~/ 4);
    for (var index = 0; index < _n ~/ 4; index++) {
      final value = input[offset + index];
      for (var item = 0; item < 4; item++) {
        secret[polynomial][4 * index + item] = 1 - ((value >>> (2 * item)) & 3);
      }
    }
  }
  return secret;
}

void _packVector(
  Uint8List output,
  int outputOffset,
  List<List<int>> vector,
  int bits,
  bool scaled,
) {
  final polynomialBytes = bits * _n ~/ 8;
  for (var index = 0; index < vector.length; index++) {
    _packPoly(
      output,
      outputOffset + index * polynomialBytes,
      vector[index],
      bits,
      scaled,
    );
  }
}

List<List<int>> _unpackVector(
  SmaugTParameters parameters,
  Uint8List input,
  int inputOffset,
  int bits,
  bool scaled,
) {
  final polynomialBytes = bits * _n ~/ 8;
  final vector = _zeroVector(parameters.k);
  for (var index = 0; index < vector.length; index++) {
    _unpackPoly(
      vector[index],
      input,
      inputOffset + index * polynomialBytes,
      bits,
      scaled,
    );
  }
  return vector;
}

void _multiplyAccumulate(List<int> output, List<int> left, List<int> right) {
  for (var i = 0; i < _n; i++) {
    final a = left[i] & 0xffff;
    for (var j = 0; j < _n; j++) {
      final product = a * (right[j] & 0xffff);
      final index = i + j;
      final target = index & (_n - 1);
      output[target] = _i16(
        index < _n
            ? (output[target] & 0xffff) + product
            : (output[target] & 0xffff) - product,
      );
    }
  }
}

List<int> _vectorMultiply(List<List<int>> left, List<List<int>> right) {
  final output = List<int>.filled(_n, 0);
  for (var index = 0; index < left.length; index++) {
    _multiplyAccumulate(output, left[index], right[index]);
  }
  return output;
}

int _shiftLeft16(int value, int shift) => _i16((value & 0xffff) << shift);

List<List<List<int>>> _expandA(SmaugTParameters parameters, Uint8List seed) {
  final matrix = List<List<List<int>>>.generate(
    parameters.k,
    (_) => _zeroVector(parameters.k),
    growable: false,
  );
  final extended = Uint8List(_publicKeySeedBytes + 2)..setAll(0, seed);
  for (var row = 0; row < parameters.k; row++) {
    for (var column = 0; column < parameters.k; column++) {
      extended[_publicKeySeedBytes] = row;
      extended[_publicKeySeedBytes + 1] = column;
      final bytes = shake128(extended, parameters.logQ * _n ~/ 8);
      _unpackPoly(matrix[row][column], bytes, 0, parameters.logQ, true);
    }
  }
  return matrix;
}

int _littleInt(Uint8List input, int offset) =>
    input[offset] |
    input[offset + 1] << 8 |
    input[offset + 2] << 16 |
    input[offset + 3] << 24;

List<int> _sparseCbd(SmaugTParameters parameters, Uint8List bytes) {
  final output = List<int>.filled(_n, 0);
  switch (parameters.cbdSeedBytes) {
    case 96:
      for (var block = 0; block < bytes.length ~/ 3; block++) {
        final value =
            bytes[3 * block] |
            bytes[3 * block + 1] << 8 |
            bytes[3 * block + 2] << 16;
        var present = value & 0x00249249;
        present &= (value >>> 1) & 0x00249249;
        final signs = (value >>> 2) & 0x00249249;
        for (var index = 0; index < 8; index++) {
          final magnitude = (present >>> (3 * index)) & 1;
          output[8 * block + index] = ((signs >>> (3 * index)) & 1) == 0
              ? magnitude
              : -magnitude;
        }
      }
    case 64:
      for (var block = 0; block < bytes.length ~/ 4; block++) {
        final value = _littleInt(bytes, 4 * block);
        for (var index = 0; index < 16; index++) {
          output[16 * block + index] =
              ((value >>> (2 * index)) & 1) - ((value >>> (2 * index + 1)) & 1);
        }
      }
    case 128:
      for (var block = 0; block < bytes.length ~/ 4; block++) {
        final value = _littleInt(bytes, 4 * block);
        var present = value & 0x11111111;
        present |= (value >>> 1) & 0x11111111;
        present &= (value >>> 2) & 0x11111111;
        final signs = (value >>> 3) & 0x11111111;
        for (var index = 0; index < 8; index++) {
          final magnitude = (present >>> (4 * index)) & 1;
          output[8 * block + index] = ((signs >>> (4 * index)) & 1) == 0
              ? magnitude
              : -magnitude;
        }
      }
    default:
      throw ArgumentError('unsupported CBD size');
  }
  return output;
}

List<List<int>> _expandR(SmaugTParameters parameters, Uint8List seed) {
  final output = _zeroVector(parameters.k);
  final extended = Uint8List(33)..setAll(0, seed);
  for (var index = 0; index < output.length; index++) {
    extended[32] = index;
    output[index] = _sparseCbd(
      parameters,
      shake256(extended, parameters.cbdSeedBytes),
    );
  }
  return output;
}

List<int> _gaussianPoly(SmaugTParameters parameters, Uint8List seed) {
  final bytes = shake256(seed, 320);
  final random = List<BigInt>.filled(40, BigInt.zero);
  for (var block = 0; block < 4; block++) {
    for (var column = 0; column < 10; column++) {
      var lane = BigInt.zero;
      for (var row = 0; row < 8; row++) {
        lane |= BigInt.from(bytes[block * 80 + row * 10 + column]) << (8 * row);
      }
      random[block * 10 + column] = lane;
    }
  }
  final output = List<int>.filled(_n, 0);
  final mask64 = (BigInt.one << 64) - BigInt.one;
  for (var block = 0; block < 4; block++) {
    final offset = block * 10;
    final x0 = random[offset];
    final x1 = random[offset + 1];
    final x2 = random[offset + 2];
    final x3 = random[offset + 3];
    final x4 = random[offset + 4];
    final x5 = random[offset + 5];
    final x6 = random[offset + 6];
    final x7 = random[offset + 7];
    final x8 = random[offset + 8];
    final low =
        (x0 & x1 & x2 & x3 & x4 & x5 & x7 & (~x8 & mask64)) |
        (x0 & x3 & x4 & x5 & x6 & x8) |
        (x1 & x3 & x4 & x5 & x6 & x8) |
        (x2 & x3 & x4 & x5 & x6 & x8) |
        ((~x2 & mask64) & (~x3 & mask64) & (~x6 & mask64) & x8) |
        ((~x1 & mask64) & (~x3 & mask64) & (~x6 & mask64) & x8) |
        (x6 & x7 & (~x8 & mask64)) |
        ((~x5 & mask64) & (~x6 & mask64) & x8) |
        ((~x4 & mask64) & (~x6 & mask64) & x8) |
        ((~x7 & mask64) & x8);
    final high =
        (x1 & x2 & x4 & x5 & x7 & x8) |
        (x3 & x4 & x5 & x7 & x8) |
        (x6 & x7 & x8);
    final signs = random[offset + 9];
    for (var bit = 0; bit < 64; bit++) {
      var magnitude =
          (((low >> bit) & BigInt.one).toInt()) |
          (((high >> bit) & BigInt.one).toInt() << 1);
      if (((signs >> bit) & BigInt.one) != BigInt.zero) {
        magnitude = -magnitude;
      }
      output[block * 64 + bit] = _shiftLeft16(magnitude, 16 - parameters.logQ);
    }
  }
  return output;
}

List<List<int>> _gaussianVector(SmaugTParameters parameters, Uint8List seed) {
  final output = _zeroVector(parameters.k);
  final extended = Uint8List(33)..setAll(0, seed);
  for (var index = 0; index < output.length; index++) {
    extended[32] = parameters.k * index;
    output[index] = _gaussianPoly(parameters, extended);
  }
  return output;
}

int _littleShort(Uint8List input, int offset) =>
    input[offset] | input[offset + 1] << 8;

List<int>? _hwt(SmaugTParameters parameters, Uint8List seed) {
  final state = shake256Stream()..absorb(seed);
  final bytes = Uint8List(_hwtSeedBytes);
  state.squeeze(bytes);
  final random = List<int>.generate(
    _hwtSeedBytes ~/ 2,
    (index) => _littleShort(bytes, 2 * index),
    growable: false,
  );
  final shuffled = List<int>.filled(_n, 0);
  var extra = _n;
  for (var index = 0; index < shuffled.length; index++) {
    final range = _n - index;
    final threshold = 0x10000 % range;
    var product = random[index] * range;
    while ((product & 0xffff) < threshold) {
      if (extra >= random.length) return null;
      product = random[extra++] * range;
    }
    shuffled[index] = product >>> 16;
  }
  final signs = Uint8List(_n ~/ 4);
  state.squeeze(signs);
  final output = List<int>.filled(_n, 0);
  var cutoff = _n - parameters.hammingWeight;
  for (var index = 0; index < _n; index++) {
    final selected = (shuffled[index] - cutoff) >> 15;
    cutoff += selected;
    final magnitude = 1 + selected;
    final signByte = signs[((index >> 7) << 4) + (index & 0x0f)];
    final sign = (signByte >>> ((index >> 4) & 7)) & 1;
    output[index] = -magnitude & ((sign << 1) - 1);
  }
  return output;
}

List<List<int>> _expandSecret(SmaugTParameters parameters, Uint8List seed) {
  final output = _zeroVector(parameters.k);
  for (var index = 0; index < output.length; index++) {
    for (var retry = 0; ; retry++) {
      final extended = Uint8List(34)..setAll(0, seed);
      extended[32] = index * parameters.k;
      extended[33] = retry;
      final sample = _hwt(parameters, extended);
      if (sample != null) {
        output[index] = sample;
        break;
      }
    }
  }
  return output;
}

void _matrixVectorSubtract(
  SmaugTParameters parameters,
  List<List<int>> output,
  List<List<List<int>>> matrix,
  List<List<int>> vector,
) {
  final shift = 16 - parameters.logQ;
  for (var row = 0; row < matrix.length; row++) {
    final lowered = _zeroVector(parameters.k);
    for (var item = 0; item < matrix[row].length; item++) {
      for (var index = 0; index < _n; index++) {
        lowered[item][index] = matrix[row][item][index] >> shift;
      }
    }
    final product = _vectorMultiply(lowered, vector);
    for (var index = 0; index < _n; index++) {
      output[row][index] = _i16(
        (output[row][index] & 0xffff) -
            (_shiftLeft16(product[index], shift) & 0xffff),
      );
    }
  }
}

List<List<int>> _transposeMatrixVector(
  SmaugTParameters parameters,
  List<List<List<int>>> matrix,
  List<List<int>> vector,
) {
  final shift = 16 - parameters.logQ;
  final output = _zeroVector(parameters.k);
  for (var column = 0; column < parameters.k; column++) {
    final lowered = _zeroVector(parameters.k);
    for (var row = 0; row < parameters.k; row++) {
      for (var index = 0; index < _n; index++) {
        lowered[row][index] = matrix[row][column][index] >> shift;
      }
    }
    final product = _vectorMultiply(lowered, vector);
    for (var index = 0; index < _n; index++) {
      output[column][index] = _shiftLeft16(product[index], shift);
    }
  }
  return output;
}

void _vectorMultiplyAdd(
  List<int> output,
  List<List<int>> left,
  List<List<int>> right,
  int shift,
) {
  final lowered = _zeroVector(left.length);
  for (var polynomial = 0; polynomial < left.length; polynomial++) {
    for (var index = 0; index < _n; index++) {
      lowered[polynomial][index] = left[polynomial][index] >> shift;
    }
  }
  final product = _vectorMultiply(lowered, right);
  for (var index = 0; index < _n; index++) {
    output[index] = _i16(
      (output[index] & 0xffff) + (_shiftLeft16(product[index], shift) & 0xffff),
    );
  }
}

void _keyPairInternal(
  SmaugTParameters parameters,
  Uint8List publicKey,
  Uint8List secretKey,
  Uint8List rejectionKey,
  Uint8List seed,
) {
  final expanded = sha3512(seed);
  final secretSeed = Uint8List.fromList(expanded.sublist(0, 32));
  final matrixSeed = Uint8List.fromList(expanded.sublist(32, 64));
  final secret = _expandSecret(parameters, secretSeed);
  final matrix = _expandA(parameters, matrixSeed);
  final publicVector = _gaussianVector(parameters, secretSeed);
  _matrixVectorSubtract(parameters, publicVector, matrix, secret);
  publicKey.setRange(0, 32, matrixSeed);
  _packVector(publicKey, 32, publicVector, parameters.logQ, true);
  final pkeBytes = parameters.pkeSecretKeyBytes;
  _packSecret(secretKey, secret);
  secretKey.setRange(pkeBytes, pkeBytes + 32, rejectionKey);
  secretKey.setRange(pkeBytes + 32, secretKey.length, publicKey);
}

final class _PublicParts {
  const _PublicParts(this.matrix, this.vector);

  final List<List<List<int>>> matrix;
  final List<List<int>> vector;
}

_PublicParts _unpackPublic(SmaugTParameters parameters, Uint8List publicKey) {
  final matrixSeed = Uint8List.fromList(publicKey.sublist(0, 32));
  return _PublicParts(
    _expandA(parameters, matrixSeed),
    _unpackVector(parameters, publicKey, 32, parameters.logQ, true),
  );
}

List<int> _encodeMessage(SmaugTParameters parameters, Uint8List message) {
  final output = List<int>.filled(_n, 0);
  if (parameters.timer) {
    for (var index = 0; index < 128; index++) {
      final value = ((message[index >> 3] >>> (index & 7)) & 1) != 0
          ? 32767
          : 0;
      output[index] = value;
      output[index + 128] = value;
    }
  } else {
    for (var index = 0; index < _n; index++) {
      if (((message[index >> 3] >>> (index & 7)) & 1) != 0) {
        output[index] = -32768;
      }
    }
  }
  return output;
}

void _indcpaEncrypt(
  SmaugTParameters parameters,
  Uint8List output,
  Uint8List publicKey,
  Uint8List message,
  Uint8List seed,
) {
  final parts = _unpackPublic(parameters, publicKey);
  final ephemeral = _expandR(parameters, seed);
  final c1 = _transposeMatrixVector(parameters, parts.matrix, ephemeral);
  final shift1 = 16 - parameters.logP;
  final add1 = 1 << (shift1 - 1);
  final mask1 = 0xffff << shift1;
  for (final polynomial in c1) {
    for (var index = 0; index < _n; index++) {
      polynomial[index] =
          (((polynomial[index] & 0xffff) + add1) & mask1) >>> shift1;
    }
  }
  final c2 = _encodeMessage(parameters, message);
  _vectorMultiplyAdd(c2, parts.vector, ephemeral, 16 - parameters.logQ);
  final shift2 = 16 - parameters.logPPrime;
  final add2 = 1 << (shift2 - 1);
  final mask2 = 0xffff << shift2;
  for (var index = 0; index < _n; index++) {
    c2[index] = (((c2[index] & 0xffff) + add2) & mask2) >>> shift2;
  }
  final c1Bytes = parameters.k * parameters.logP * _n ~/ 8;
  _packVector(output, 0, c1, parameters.logP, false);
  _packPoly(output, c1Bytes, c2, parameters.logPPrime, false);
}

int _flipAbs(int value) {
  final difference = _i16((value & 0xffff) - 32767);
  final mask = difference >> 15;
  return ((difference + mask) ^ mask) & 0xffff;
}

Uint8List _decodeMessage(SmaugTParameters parameters, List<int> polynomial) {
  final message = Uint8List(parameters.messageBytes);
  if (parameters.timer) {
    for (var index = 0; index < 128; index++) {
      var value =
          (_flipAbs(polynomial[index]) +
              _flipAbs(polynomial[index + 128]) -
              32767) &
          0xffff;
      value >>>= 15;
      message[index >> 3] |= value << (index & 7);
    }
  } else {
    for (var index = 0; index < _n; index++) {
      final value = _i16((polynomial[index] & 0xffff) + 0x4000);
      message[index >> 3] |= ((value >> 15) & 1) << (index & 7);
    }
  }
  return message;
}

Uint8List _indcpaDecrypt(
  SmaugTParameters parameters,
  Uint8List secretKey,
  Uint8List ciphertext,
) {
  final secret = _unpackSecret(parameters, secretKey);
  final c1Bytes = parameters.k * parameters.logP * _n ~/ 8;
  final c1 = _unpackVector(parameters, ciphertext, 0, parameters.logP, false);
  final delta = List<int>.filled(_n, 0);
  _unpackPoly(delta, ciphertext, c1Bytes, parameters.logPPrime, false);
  for (final polynomial in c1) {
    for (var index = 0; index < _n; index++) {
      polynomial[index] = _shiftLeft16(polynomial[index], 16 - parameters.logP);
    }
  }
  for (var index = 0; index < _n; index++) {
    delta[index] = _shiftLeft16(delta[index], 16 - parameters.logPPrime);
  }
  _vectorMultiplyAdd(delta, c1, secret, 16 - parameters.logP);
  return _decodeMessage(parameters, delta);
}

Uint8List _hashG(Uint8List first, Uint8List second) {
  final state = shake256Stream()
    ..absorb(first)
    ..absorb(second);
  final output = Uint8List(64);
  state.squeeze(output);
  return output;
}

bool _constantTimeEqual(Uint8List left, Uint8List right) {
  if (left.length != right.length) return false;
  var difference = 0;
  for (var index = 0; index < left.length; index++) {
    difference |= left[index] ^ right[index];
  }
  return difference == 0;
}

SmaugTKeyPair smaugTGenerateKeyPair(SmaugTParameters parameters) {
  final publicKey = Uint8List(parameters.publicKeyBytes);
  final secretKey = Uint8List(parameters.secretKeyBytes);
  _keyPairInternal(
    parameters,
    publicKey,
    secretKey,
    randomBytes(32),
    randomBytes(32),
  );
  return SmaugTKeyPair(publicKey, secretKey);
}

SmaugTEncapsulation smaugTEncapsulate(
  SmaugTParameters parameters,
  Uint8List publicKey,
) {
  if (publicKey.length != parameters.publicKeyBytes) {
    throw ArgumentError('invalid public key length');
  }
  final message = randomBytes(parameters.messageBytes);
  final material = _hashG(message, sha3256(publicKey));
  final ciphertext = Uint8List(parameters.ciphertextBytes);
  _indcpaEncrypt(
    parameters,
    ciphertext,
    publicKey,
    message,
    Uint8List.fromList(material.sublist(0, 32)),
  );
  return SmaugTEncapsulation(
    ciphertext,
    Uint8List.fromList(material.sublist(32, 64)),
  );
}

Uint8List smaugTDecapsulate(
  SmaugTParameters parameters,
  Uint8List ciphertext,
  Uint8List secretKey,
) {
  if (ciphertext.length != parameters.ciphertextBytes ||
      secretKey.length != parameters.secretKeyBytes) {
    throw ArgumentError('invalid KEM input length');
  }
  final pkeBytes = parameters.pkeSecretKeyBytes;
  final publicKey = Uint8List.fromList(secretKey.sublist(pkeBytes + _tBytes));
  final message = _indcpaDecrypt(
    parameters,
    Uint8List.fromList(secretKey.sublist(0, pkeBytes)),
    ciphertext,
  );
  final validMaterial = _hashG(message, sha3256(publicKey));
  final expected = Uint8List(parameters.ciphertextBytes);
  _indcpaEncrypt(
    parameters,
    expected,
    publicKey,
    message,
    Uint8List.fromList(validMaterial.sublist(0, 32)),
  );
  final fallbackMaterial = _hashG(
    Uint8List.fromList(secretKey.sublist(pkeBytes, pkeBytes + _tBytes)),
    sha3256(ciphertext),
  );
  return Uint8List.fromList(
    (_constantTimeEqual(ciphertext, expected)
            ? validMaterial
            : fallbackMaterial)
        .sublist(32, 64),
  );
}
