import 'dart:io';
import 'dart:typed_data';

import 'package:kpqc/src/internal/entropy.dart';
import 'package:kpqc/src/internal/ntruplus_core.dart';
import 'package:kpqc/src/internal/ntruplus_parameters.dart';
import 'package:test/test.dart';

import 'helpers/nist_aes_ctr_drbg.dart';

Uint8List _hex(String value) {
  final output = Uint8List(value.length ~/ 2);
  for (var index = 0; index < output.length; index++) {
    output[index] = int.parse(
      value.substring(2 * index, 2 * index + 2),
      radix: 16,
    );
  }
  return output;
}

List<Map<String, String>> _readVectors(String mode) {
  final vectorRoot = Platform.environment['KPQC_TEST_VECTORS'];
  final path = vectorRoot == null
      ? 'test/kat/ntruplus$mode.rsp'
      : '$vectorRoot/ntruplus/$mode/kat.rsp';
  final vectors = <Map<String, String>>[];
  var fields = <String, String>{};
  for (final line in File(path).readAsLinesSync()) {
    final match = RegExp(r'^([a-z]+) = ([0-9A-Fa-f]*)$').firstMatch(line);
    if (match == null) continue;
    final name = match.group(1)!;
    if (name == 'count' && fields.isNotEmpty) {
      vectors.add(fields);
      fields = <String, String>{};
    }
    fields[name] = match.group(2)!;
  }
  if (fields.isNotEmpty) vectors.add(fields);
  if (vectors.isEmpty) throw StateError('no NTRU+ vectors found in $path');
  return vectors;
}

void main() {
  test('AES-256 helper matches the NIST block vector', () {
    expect(
      aes256EncryptBlock(
        _hex(
          '000102030405060708090a0b0c0d0e0f'
          '101112131415161718191a1b1c1d1e1f',
        ),
        _hex('00112233445566778899aabbccddeeff'),
      ),
      orderedEquals(_hex('8ea2b7ca516745bfeafc49904b496089')),
    );
  });

  final parameterSets = <NtruPlusParameters>[
    ntruPlus768Parameters,
    ntruPlus864Parameters,
    ntruPlus1152Parameters,
  ];

  tearDown(clearTestEntropySource);

  for (final parameters in parameterSets) {
    final vectors = _readVectors('${parameters.mode}');
    test('NTRU+${parameters.mode} matches all ${vectors.length} known-answer '
        'vectors', () {
      for (final vector in vectors) {
        final generator = NistAesCtrDrbg(_hex(vector['seed']!));
        setTestEntropySource(generator.generate);

        final keys = ntruPlusGenerateKeyPair(parameters);
        expect(
          keys.publicKey,
          orderedEquals(_hex(vector['pk']!)),
          reason: 'public key for count ${vector['count']}',
        );
        expect(
          keys.secretKey,
          orderedEquals(_hex(vector['sk']!)),
          reason: 'secret key for count ${vector['count']}',
        );

        final encapsulated = ntruPlusEncapsulate(parameters, keys.publicKey);
        expect(
          encapsulated.ciphertext,
          orderedEquals(_hex(vector['ct']!)),
          reason: 'ciphertext for count ${vector['count']}',
        );
        expect(
          encapsulated.sharedSecret,
          orderedEquals(_hex(vector['ss']!)),
          reason: 'shared secret for count ${vector['count']}',
        );
        expect(
          ntruPlusDecapsulate(
            parameters,
            encapsulated.ciphertext,
            keys.secretKey,
          ),
          orderedEquals(encapsulated.sharedSecret),
          reason: 'decapsulation for count ${vector['count']}',
        );
      }
    });
  }
}
