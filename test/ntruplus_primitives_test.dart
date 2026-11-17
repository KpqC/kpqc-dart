import 'dart:typed_data';

import 'package:test/test.dart';

import 'package:kpqc/src/internal/ntruplus_parameters.dart';
import 'package:kpqc/src/internal/ntruplus_poly.dart';

void main() {
  final parameterSets = <NtruPlusParameters>[
    ntruPlus768Parameters,
    ntruPlus864Parameters,
    ntruPlus1152Parameters,
  ];

  test('polynomial serialization round-trips every NTRU+ parameter set', () {
    for (final parameters in parameterSets) {
      final polynomial = Int16List.fromList(
        List<int>.generate(
          parameters.n,
          (index) => index.isEven ? index % 3457 : -(index % 3457),
        ),
      );
      final decoded = ntruPlusDeserializePolynomial(
        parameters,
        ntruPlusSerializePolynomial(parameters, polynomial),
      );
      expect(decoded.canonical, isTrue);
      expect(
        decoded.polynomial,
        orderedEquals(
          polynomial.map((value) => value < 0 ? value + 3457 : value),
        ),
      );
    }
  });

  test('non-canonical NTRU+ polynomial encodings are rejected', () {
    final encoded = Uint8List(ntruPlus768Parameters.polynomialBytes)
      ..fillRange(0, 3, 0xff);
    expect(
      ntruPlusDeserializePolynomial(ntruPlus768Parameters, encoded).canonical,
      isFalse,
    );
  });

  test('centered-binomial NTRU+ samples stay ternary', () {
    for (final parameters in parameterSets) {
      final bytes = Uint8List.fromList(
        List<int>.generate(parameters.n ~/ 4, (index) => index & 0xff),
      );
      final sample = ntruPlusSampleCenteredBinomial(parameters, bytes);
      expect(sample, hasLength(parameters.n));
      expect(sample.every((value) => value >= -1 && value <= 1), isTrue);
    }
  });
}
