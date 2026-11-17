import 'dart:typed_data';

import 'fips202.dart';
import 'ntruplus_parameters.dart';

const _q = 3457;

final class DecodedNtruPlusPolynomial {
  const DecodedNtruPlusPolynomial(this.polynomial, this.canonical);

  final Int16List polynomial;
  final bool canonical;
}

final class DecodedNtruPlusSotp {
  const DecodedNtruPlusSotp(this.message, this.valid);

  final Uint8List message;
  final bool valid;
}

Uint8List _domainHash(int tag, Uint8List input, int length) {
  final prefixed = Uint8List(input.length + 1)
    ..[0] = tag
    ..setRange(1, input.length + 1, input);
  return shake256(prefixed, length);
}

Uint8List ntruPlusHashF(Uint8List message) => _domainHash(0, message, 32);

Uint8List ntruPlusHashG(NtruPlusParameters parameters, Uint8List message) =>
    _domainHash(1, message, parameters.n ~/ 4);

Uint8List ntruPlusHashH(
  NtruPlusParameters parameters,
  Iterable<Uint8List> messages,
) {
  final totalLength = messages.fold<int>(0, (sum, value) => sum + value.length);
  final input = Uint8List(totalLength);
  var offset = 0;
  for (final message in messages) {
    input.setRange(offset, offset + message.length, message);
    offset += message.length;
  }
  return _domainHash(2, input, 32 + parameters.n ~/ 4);
}

Int16List ntruPlusSampleCenteredBinomial(
  NtruPlusParameters parameters,
  Uint8List bytes,
) {
  final output = Int16List(parameters.n);
  for (var index = 0; index < parameters.n ~/ 8; index++) {
    var first = bytes[index];
    var second = bytes[index + parameters.n ~/ 8];
    for (var bit = 0; bit < 8; bit++) {
      output[8 * index + bit] = (first & 1) - (second & 1);
      first >>= 1;
      second >>= 1;
    }
  }
  return output;
}

Uint8List ntruPlusSerializePolynomial(
  NtruPlusParameters parameters,
  Int16List polynomial,
) {
  final output = Uint8List(parameters.polynomialBytes);
  for (var index = 0; index < parameters.n ~/ 2; index++) {
    var first = polynomial[2 * index];
    var second = polynomial[2 * index + 1];
    if (first < 0) first += _q;
    if (second < 0) second += _q;
    output[3 * index] = first;
    output[3 * index + 1] = (first >> 8) | (second << 4);
    output[3 * index + 2] = second >> 4;
  }
  return output;
}

DecodedNtruPlusPolynomial ntruPlusDeserializePolynomial(
  NtruPlusParameters parameters,
  Uint8List bytes,
) {
  if (bytes.length != parameters.polynomialBytes) {
    return DecodedNtruPlusPolynomial(Int16List(0), false);
  }
  final polynomial = Int16List(parameters.n);
  var canonical = true;
  for (var index = 0; index < parameters.n ~/ 2; index++) {
    final first = (bytes[3 * index] | (bytes[3 * index + 1] << 8)) & 0xfff;
    final second =
        ((bytes[3 * index + 1] >> 4) | (bytes[3 * index + 2] << 4)) & 0xfff;
    polynomial[2 * index] = first;
    polynomial[2 * index + 1] = second;
    canonical = canonical && first < _q && second < _q;
  }
  return DecodedNtruPlusPolynomial(polynomial, canonical);
}

Int16List ntruPlusEncodeSotp(
  NtruPlusParameters parameters,
  Uint8List message,
  Uint8List pad,
) {
  final input = Uint8List.fromList(pad);
  for (var index = 0; index < parameters.n ~/ 8; index++) {
    input[index] ^= message[index];
  }
  return ntruPlusSampleCenteredBinomial(parameters, input);
}

DecodedNtruPlusSotp ntruPlusDecodeSotp(
  NtruPlusParameters parameters,
  Int16List polynomial,
  Uint8List pad,
) {
  final message = Uint8List(parameters.n ~/ 8);
  var invalid = 0;
  for (var index = 0; index < parameters.n ~/ 8; index++) {
    var first = pad[index];
    var second = pad[index + parameters.n ~/ 8];
    var value = 0;
    for (var bit = 0; bit < 8; bit++) {
      final sum = ((second & 1) + polynomial[8 * index + bit]) & 0xffff;
      invalid |= sum;
      value ^= ((sum ^ first) & 1) << bit;
      first >>= 1;
      second >>= 1;
    }
    message[index] = value;
  }
  final valid = (invalid >> 1) == 0;
  if (!valid) message.fillRange(0, message.length, 0);
  return DecodedNtruPlusSotp(message, valid);
}

int _centeredRemainderThree(int value) {
  var reduced = value;
  if (reduced < 0) reduced += _q;
  reduced -= (_q + 1) ~/ 2;
  if (reduced < 0) reduced += _q;
  reduced -= (_q - 1) ~/ 2;
  final quotient = ((10923 * reduced + (1 << 14)) >> 15) * 3;
  return reduced - quotient;
}

Int16List ntruPlusCenteredModThree(Int16List polynomial) => Int16List.fromList(
  polynomial.map(_centeredRemainderThree).toList(growable: false),
);

bool ntruPlusEqualPolynomialEncodings(Int16List left, Int16List right) {
  var difference = 0;
  for (var index = 0; index < left.length; index++) {
    final a = left[index] < 0 ? left[index] + _q : left[index];
    final b = right[index] < 0 ? right[index] + _q : right[index];
    difference |= a ^ b;
  }
  return difference == 0;
}

Uint8List ntruPlusEncapsulationMessage(Uint8List coins, Uint8List publicKey) {
  final hash = ntruPlusHashF(publicKey);
  return Uint8List(coins.length + hash.length)
    ..setRange(0, coins.length, coins)
    ..setRange(coins.length, coins.length + hash.length, hash);
}
