import 'dart:typed_data';

int _gfMultiply(int left, int right) {
  var a = left;
  var b = right;
  var result = 0;
  for (var index = 0; index < 8; index++) {
    if ((b & 1) != 0) result ^= a;
    a = ((a << 1) ^ ((a & 0x80) != 0 ? 0x11b : 0)) & 0xff;
    b >>= 1;
  }
  return result;
}

int _gfPower(int value, int exponent) {
  var base = value;
  var power = exponent;
  var result = 1;
  while (power != 0) {
    if ((power & 1) != 0) result = _gfMultiply(result, base);
    base = _gfMultiply(base, base);
    power >>= 1;
  }
  return result;
}

int _rotateLeft8(int value, int shift) =>
    ((value << shift) | (value >> (8 - shift))) & 0xff;

int _substitute(int value) {
  final inverse = value == 0 ? 0 : _gfPower(value, 254);
  return inverse ^
      _rotateLeft8(inverse, 1) ^
      _rotateLeft8(inverse, 2) ^
      _rotateLeft8(inverse, 3) ^
      _rotateLeft8(inverse, 4) ^
      0x63;
}

final _sbox = Uint8List.fromList(
  List<int>.generate(256, _substitute, growable: false),
);

List<Uint8List> _roundKeys(Uint8List key) {
  if (key.length != 32) throw ArgumentError.value(key.length, 'key');
  final words = <Uint8List>[
    for (var offset = 0; offset < key.length; offset += 4)
      Uint8List.fromList(key.sublist(offset, offset + 4)),
  ];
  var roundConstant = 1;
  for (var index = 8; index < 60; index++) {
    var temporary = Uint8List.fromList(words[index - 1]);
    if (index % 8 == 0) {
      temporary = Uint8List.fromList([
        _sbox[temporary[1]],
        _sbox[temporary[2]],
        _sbox[temporary[3]],
        _sbox[temporary[0]],
      ]);
      temporary[0] ^= roundConstant;
      roundConstant = _gfMultiply(roundConstant, 2);
    } else if (index % 8 == 4) {
      for (var item = 0; item < temporary.length; item++) {
        temporary[item] = _sbox[temporary[item]];
      }
    }
    words.add(
      Uint8List.fromList(
        List<int>.generate(
          4,
          (item) => words[index - 8][item] ^ temporary[item],
          growable: false,
        ),
      ),
    );
  }
  return List<Uint8List>.generate(15, (round) {
    final output = Uint8List(16);
    for (var word = 0; word < 4; word++) {
      output.setRange(4 * word, 4 * word + 4, words[4 * round + word]);
    }
    return output;
  });
}

void _addRoundKey(Uint8List state, Uint8List key) {
  for (var index = 0; index < state.length; index++) {
    state[index] ^= key[index];
  }
}

void _substituteBytes(Uint8List state) {
  for (var index = 0; index < state.length; index++) {
    state[index] = _sbox[state[index]];
  }
}

Uint8List _shiftRows(Uint8List state) => Uint8List.fromList([
  state[0],
  state[5],
  state[10],
  state[15],
  state[4],
  state[9],
  state[14],
  state[3],
  state[8],
  state[13],
  state[2],
  state[7],
  state[12],
  state[1],
  state[6],
  state[11],
]);

void _mixColumns(Uint8List state) {
  for (var offset = 0; offset < 16; offset += 4) {
    final a = state[offset];
    final b = state[offset + 1];
    final c = state[offset + 2];
    final d = state[offset + 3];
    state[offset] = _gfMultiply(a, 2) ^ _gfMultiply(b, 3) ^ c ^ d;
    state[offset + 1] = a ^ _gfMultiply(b, 2) ^ _gfMultiply(c, 3) ^ d;
    state[offset + 2] = a ^ b ^ _gfMultiply(c, 2) ^ _gfMultiply(d, 3);
    state[offset + 3] = _gfMultiply(a, 3) ^ b ^ c ^ _gfMultiply(d, 2);
  }
}

Uint8List aes256EncryptBlock(Uint8List key, Uint8List block) {
  if (key.length != 32 || block.length != 16) {
    throw ArgumentError('AES-256 requires a 32-byte key and 16-byte block');
  }
  final keys = _roundKeys(key);
  var state = Uint8List.fromList(block);
  _addRoundKey(state, keys[0]);
  for (var round = 1; round < 14; round++) {
    _substituteBytes(state);
    state = _shiftRows(state);
    _mixColumns(state);
    _addRoundKey(state, keys[round]);
  }
  _substituteBytes(state);
  state = _shiftRows(state);
  _addRoundKey(state, keys[14]);
  return state;
}

final class NistAesCtrDrbg {
  NistAesCtrDrbg(Uint8List entropy) {
    if (entropy.length != 48) {
      throw ArgumentError.value(entropy.length, 'entropy');
    }
    _update(entropy);
  }

  NistAesCtrDrbg._(this._key, this._value);

  var _key = Uint8List(32);
  var _value = Uint8List(16);

  NistAesCtrDrbg copy() =>
      NistAesCtrDrbg._(Uint8List.fromList(_key), Uint8List.fromList(_value));

  void _increment() {
    for (var index = _value.length - 1; index >= 0; index--) {
      _value[index] = (_value[index] + 1) & 0xff;
      if (_value[index] != 0) break;
    }
  }

  void _update([Uint8List? provided]) {
    final temporary = Uint8List(48);
    for (var offset = 0; offset < temporary.length; offset += 16) {
      _increment();
      temporary.setRange(offset, offset + 16, aes256EncryptBlock(_key, _value));
    }
    if (provided != null) {
      for (var index = 0; index < temporary.length; index++) {
        temporary[index] ^= provided[index];
      }
    }
    _key = Uint8List.fromList(temporary.sublist(0, 32));
    _value = Uint8List.fromList(temporary.sublist(32));
  }

  Uint8List generate(int length) {
    final output = Uint8List(length);
    for (var offset = 0; offset < length; offset += 16) {
      _increment();
      final block = aes256EncryptBlock(_key, _value);
      final count = length - offset < 16 ? length - offset : 16;
      output.setRange(offset, offset + count, block);
    }
    _update();
    return output;
  }
}
