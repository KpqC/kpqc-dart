import 'dart:io';
import 'dart:typed_data';

import 'package:kpqc/src/internal/entropy.dart';
import 'package:kpqc/src/internal/smaugt_core.dart';
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

List<Map<String, String>> _readVectors(String name) {
  final vectorRoot = Platform.environment['KPQC_TEST_VECTORS'];
  final mode = switch (name) {
    'smaugt128' => 'mode1',
    'smaugt192' => 'mode3',
    'smaugt256' => 'mode5',
    'timer' => 'modet',
    _ => throw ArgumentError.value(name, 'name'),
  };
  final path = vectorRoot == null
      ? 'test/kat/$name.rsp'
      : '$vectorRoot/smaugt/$mode/kat.rsp';
  final vectors = <Map<String, String>>[];
  var fields = <String, String>{};
  for (final line in File(path).readAsLinesSync()) {
    final match = RegExp(r'^([a-z]+) = ([0-9A-Fa-f]*)$').firstMatch(line);
    if (match == null) continue;
    final field = match.group(1)!;
    if (field == 'count' && fields.isNotEmpty) {
      vectors.add(fields);
      fields = <String, String>{};
    }
    fields[field] = match.group(2)!;
  }
  if (fields.isNotEmpty) vectors.add(fields);
  if (vectors.isEmpty) throw StateError('no SMAUG-T vectors found in $path');
  return vectors;
}

void main() {
  final parameterSets = <String, SmaugTParameters>{
    'smaugt128': smaugT128Parameters,
    'smaugt192': smaugT192Parameters,
    'smaugt256': smaugT256Parameters,
    'timer': timerParameters,
  };

  tearDown(clearTestEntropySource);

  for (final entry in parameterSets.entries) {
    final vectors = _readVectors(entry.key);
    test('${entry.key} matches all ${vectors.length} known-answer vectors', () {
      for (final vector in vectors) {
        final generator = NistAesCtrDrbg(_hex(vector['seed']!));
        setTestEntropySource(generator.generate);

        final keys = smaugTGenerateKeyPair(entry.value);
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

        final encapsulated = smaugTEncapsulate(entry.value, keys.publicKey);
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
          smaugTDecapsulate(
            entry.value,
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
