import 'dart:typed_data';

import 'package:kpqc/src/internal/entropy.dart';
import 'package:kpqc/src/internal/ntruplus_core.dart';
import 'package:kpqc/src/internal/ntruplus_parameters.dart';
import 'package:test/test.dart';

void main() {
  final parameterSets = <NtruPlusParameters>[
    ntruPlus768Parameters,
    ntruPlus864Parameters,
    ntruPlus1152Parameters,
  ];

  tearDown(clearTestEntropySource);

  for (final parameters in parameterSets) {
    test('NTRU+${parameters.mode} pure Dart round trip', () {
      var counter = 0;
      setTestEntropySource(
        (length) => Uint8List.fromList(
          List<int>.generate(length, (index) => (counter++ + index) & 0xff),
        ),
      );
      final keys = ntruPlusGenerateKeyPair(parameters);
      final encapsulated = ntruPlusEncapsulate(parameters, keys.publicKey);
      final recovered = ntruPlusDecapsulate(
        parameters,
        encapsulated.ciphertext,
        keys.secretKey,
      );
      expect(recovered, orderedEquals(encapsulated.sharedSecret));
      expect(keys.publicKey, hasLength(parameters.polynomialBytes));
      expect(keys.secretKey, hasLength(parameters.secretKeyBytes));
      expect(encapsulated.ciphertext, hasLength(parameters.polynomialBytes));
    });
  }
}
