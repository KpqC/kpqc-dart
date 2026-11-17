import 'dart:io';
import 'dart:typed_data';

import 'package:kpqc/src/internal/entropy.dart';
import 'package:kpqc/src/internal/haetae_core.dart';
import 'package:kpqc/src/internal/haetae_params.dart';
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
  final path = vectorRoot == null
      ? 'test/kat/$name.rsp'
      : '$vectorRoot/haetae/mode${name.substring('haetae'.length)}/kat.rsp';
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
  if (vectors.isEmpty) throw StateError('no HAETAE vectors found in $path');
  return vectors;
}

void main() {
  final parameterSets = <String, HaetaeParameters>{
    'haetae2': haetae2Parameters,
    'haetae3': haetae3Parameters,
    'haetae5': haetae5Parameters,
  };

  tearDown(clearTestEntropySource);

  for (final entry in parameterSets.entries) {
    final vectors = _readVectors(entry.key);
    test('${entry.key} matches all ${vectors.length} known-answer vectors', () {
      for (final vector in vectors) {
        final generator = NistAesCtrDrbg(_hex(vector['seed']!));
        setTestEntropySource(generator.generate);
        final message = _hex(vector['msg']!);

        final keys = haetaeGenerateKeyPair(entry.value);
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
        final preview = generator.copy()..generate(32);
        final context = preview.generate(preview.generate(1)[0]);
        expect(
          haetaeVerify(
            entry.value,
            _hex(vector['sig']!),
            message,
            keys.publicKey,
            context: context,
          ),
          isTrue,
          reason: 'known-answer signature for count ${vector['count']}',
        );

        final signature = haetaeSign(
          entry.value,
          message,
          keys.secretKey,
          context: context,
        );
        expect(
          haetaeVerify(
            entry.value,
            signature,
            message,
            keys.publicKey,
            context: context,
          ),
          isTrue,
          reason: 'self-verification for count ${vector['count']}',
        );
        expect(
          signature,
          orderedEquals(_hex(vector['sig']!)),
          reason: 'signature for count ${vector['count']}',
        );
      }
    });
  }
}
