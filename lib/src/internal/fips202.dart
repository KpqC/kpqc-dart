import 'dart:typed_data';

const _shake128Rate = 168;
const _shake256Rate = 136;
const _sha3256Rate = 136;
const _sha3512Rate = 72;

final _mask64 = (BigInt.one << 64) - BigInt.one;

final _roundConstants = <String>[
  '0000000000000001',
  '0000000000008082',
  '800000000000808a',
  '8000000080008000',
  '000000000000808b',
  '0000000080000001',
  '8000000080008081',
  '8000000000008009',
  '000000000000008a',
  '0000000000000088',
  '0000000080008009',
  '000000008000000a',
  '000000008000808b',
  '800000000000008b',
  '8000000000008089',
  '8000000000008003',
  '8000000000008002',
  '8000000000000080',
  '000000000000800a',
  '800000008000000a',
  '8000000080008081',
  '8000000000008080',
  '0000000080000001',
  '8000000080008008',
].map((value) => BigInt.parse(value, radix: 16)).toList(growable: false);

const _rotation = <int>[
  1,
  3,
  6,
  10,
  15,
  21,
  28,
  36,
  45,
  55,
  2,
  14,
  27,
  41,
  56,
  8,
  25,
  43,
  62,
  18,
  39,
  61,
  20,
  44,
];

const _permutation = <int>[
  10,
  7,
  11,
  17,
  18,
  3,
  5,
  16,
  8,
  21,
  24,
  4,
  15,
  23,
  19,
  13,
  12,
  2,
  20,
  14,
  22,
  9,
  6,
  1,
];

final class Shake {
  Shake._(this._rate);

  final int _rate;
  final List<BigInt> _state = List<BigInt>.filled(25, BigInt.zero);
  int _position = 0;
  bool _squeezing = false;

  void absorb(Uint8List input, [int offset = 0, int? length]) {
    if (_squeezing) {
      throw StateError('cannot absorb after finalization');
    }
    final actualLength = length ?? input.length - offset;
    RangeError.checkValidRange(
      offset,
      offset + actualLength,
      input.length,
      'input',
    );
    for (var index = 0; index < actualLength; index++) {
      if (_position == _rate) {
        _permute(_state);
        _position = 0;
      }
      _xorByte(_state, _position++, input[offset + index]);
    }
  }

  void squeeze(Uint8List output, [int offset = 0, int? length]) {
    final actualLength = length ?? output.length - offset;
    RangeError.checkValidRange(
      offset,
      offset + actualLength,
      output.length,
      'output',
    );
    _finish();
    for (var index = 0; index < actualLength; index++) {
      if (_position == _rate) {
        _permute(_state);
        _position = 0;
      }
      output[offset + index] = _readByte(_state, _position++);
    }
  }

  void _finish() {
    if (_squeezing) return;
    if (_position == _rate) {
      _permute(_state);
      _position = 0;
    }
    _xorByte(_state, _position, 0x1f);
    _xorByte(_state, _rate - 1, 0x80);
    _permute(_state);
    _position = 0;
    _squeezing = true;
  }
}

Shake shake128Stream() => Shake._(_shake128Rate);

Shake shake256Stream() => Shake._(_shake256Rate);

Uint8List shake128(Uint8List input, int length) {
  final output = Uint8List(length);
  final state = shake128Stream()..absorb(input);
  state.squeeze(output);
  return output;
}

Uint8List shake256(Uint8List input, int length) {
  final output = Uint8List(length);
  final state = shake256Stream()..absorb(input);
  state.squeeze(output);
  return output;
}

Uint8List sha3256(Uint8List input) => _sha3(input, 32, _sha3256Rate);

Uint8List sha3512(Uint8List input) => _sha3(input, 64, _sha3512Rate);

Uint8List _sha3(Uint8List input, int length, int rate) {
  final state = List<BigInt>.filled(25, BigInt.zero);
  var position = 0;
  for (final value in input) {
    if (position == rate) {
      _permute(state);
      position = 0;
    }
    _xorByte(state, position++, value);
  }
  if (position == rate) {
    _permute(state);
    position = 0;
  }
  _xorByte(state, position, 0x06);
  _xorByte(state, rate - 1, 0x80);
  _permute(state);

  final output = Uint8List(length);
  for (var index = 0; index < output.length; index++) {
    if (index != 0 && index % rate == 0) _permute(state);
    output[index] = _readByte(state, index % rate);
  }
  return output;
}

void _permute(List<BigInt> state) {
  final columns = List<BigInt>.filled(5, BigInt.zero);
  for (final roundConstant in _roundConstants) {
    for (var x = 0; x < 5; x++) {
      columns[x] =
          state[x] ^
          state[x + 5] ^
          state[x + 10] ^
          state[x + 15] ^
          state[x + 20];
    }
    for (var x = 0; x < 5; x++) {
      final delta = columns[(x + 4) % 5] ^ _rotateLeft(columns[(x + 1) % 5], 1);
      for (var y = 0; y < 5; y++) {
        final index = x + 5 * y;
        state[index] = (state[index] ^ delta) & _mask64;
      }
    }

    var carried = state[1];
    for (var index = 0; index < _permutation.length; index++) {
      final destination = _permutation[index];
      final displaced = state[destination];
      state[destination] = _rotateLeft(carried, _rotation[index]);
      carried = displaced;
    }

    for (var y = 0; y < 5; y++) {
      final offset = 5 * y;
      columns.setRange(0, 5, state, offset);
      for (var x = 0; x < 5; x++) {
        state[offset + x] =
            (columns[x] ^
                ((~columns[(x + 1) % 5] & _mask64) & columns[(x + 2) % 5])) &
            _mask64;
      }
    }
    state[0] = (state[0] ^ roundConstant) & _mask64;
  }
}

BigInt _rotateLeft(BigInt value, int distance) =>
    ((value << distance) | (value >> (64 - distance))) & _mask64;

void _xorByte(List<BigInt> state, int position, int value) {
  final lane = position ~/ 8;
  state[lane] =
      (state[lane] ^ (BigInt.from(value & 0xff) << (8 * (position % 8)))) &
      _mask64;
}

int _readByte(List<BigInt> state, int position) =>
    ((state[position ~/ 8] >> (8 * (position % 8))) & BigInt.from(0xff))
        .toInt();
