import 'dart:convert';
import 'dart:typed_data';

import 'package:kpqc/kpqc.dart';
import 'package:test/test.dart';

final _signatures = <SignatureAlgorithm>[
  aimer128f,
  aimer128s,
  aimer192f,
  aimer192s,
  aimer256f,
  aimer256s,
  haetae2,
  haetae3,
  haetae5,
];

final _kems = <KeyEncapsulationAlgorithm>[
  ntruplus768,
  ntruplus864,
  ntruplus1152,
  smaugt128,
  smaugt192,
  smaugt256,
  timer,
];

void main() {
  group('signatures', () {
    for (final algorithm in _signatures) {
      test('${algorithm.id} round trip', () {
        final message = Uint8List.fromList([...utf8.encode('KpqC'), 0, 255]);
        final context = Uint8List.fromList(utf8.encode('test-suite'));
        final keys = algorithm.generateKeyPair();
        final otherKeys = algorithm.generateKeyPair();
        try {
          final signature = algorithm.sign(
            message,
            keys.secretKey,
            context: context,
          );

          expect(keys.publicKey, hasLength(algorithm.sizes.publicKey));
          expect(keys.secretKey, hasLength(algorithm.sizes.secretKey));
          expect(keys.publicKey, isNot(orderedEquals(otherKeys.publicKey)));
          expect(signature, hasLength(algorithm.sizes.signature));
          expect(
            algorithm.verify(
              message,
              signature,
              keys.publicKey,
              context: context,
            ),
            isTrue,
          );

          final altered = Uint8List.fromList(signature)..[0] ^= 0x80;
          expect(
            algorithm.verify(
              message,
              altered,
              keys.publicKey,
              context: context,
            ),
            isFalse,
          );
          expect(
            algorithm.verify(
              Uint8List.fromList(utf8.encode('changed')),
              signature,
              keys.publicKey,
              context: context,
            ),
            isFalse,
          );
          expect(
            algorithm.verify(
              message,
              signature,
              otherKeys.publicKey,
              context: context,
            ),
            isFalse,
          );
          expect(
            algorithm.verify(
              message,
              signature,
              keys.publicKey,
              context: Uint8List.fromList(utf8.encode('other')),
            ),
            isFalse,
          );
          expect(
            algorithm.verify(
              message,
              signature.sublist(1),
              keys.publicKey,
              context: context,
            ),
            isFalse,
          );
          expect(algorithm.verify(message, signature, keys.publicKey), isFalse);

          final maximumContext = Uint8List(255);
          final emptyMessageSignature = algorithm.sign(
            Uint8List(0),
            keys.secretKey,
            context: maximumContext,
          );
          expect(
            algorithm.verify(
              Uint8List(0),
              emptyMessageSignature,
              keys.publicKey,
              context: maximumContext,
            ),
            isTrue,
          );
        } finally {
          otherKeys.dispose();
          keys.dispose();
        }
      });
    }

    for (final algorithm in _signatures) {
      test('${algorithm.id} rejects invalid lengths and context', () {
        expect(
          () => algorithm.sign(
            Uint8List(0),
            Uint8List(algorithm.sizes.secretKey - 1),
          ),
          throwsArgumentError,
        );
        expect(
          () => algorithm.verify(
            Uint8List(0),
            Uint8List(algorithm.sizes.signature),
            Uint8List(algorithm.sizes.publicKey - 1),
          ),
          throwsArgumentError,
        );
        expect(
          () => algorithm.sign(
            Uint8List(0),
            Uint8List(algorithm.sizes.secretKey),
            context: Uint8List(256),
          ),
          throwsArgumentError,
        );
        expect(
          () => algorithm.verify(
            Uint8List(0),
            Uint8List(algorithm.sizes.signature),
            Uint8List(algorithm.sizes.publicKey),
            context: Uint8List(256),
          ),
          throwsArgumentError,
        );
      });
    }
  });

  group('key encapsulation', () {
    for (final algorithm in _kems) {
      test('${algorithm.id} round trip', () {
        final keys = algorithm.generateKeyPair();
        try {
          final outbound = algorithm.encapsulate(keys.publicKey);
          final second = algorithm.encapsulate(keys.publicKey);
          try {
            final recovered = algorithm.decapsulate(
              outbound.ciphertext,
              keys.secretKey,
            );

            expect(keys.publicKey, hasLength(algorithm.sizes.publicKey));
            expect(keys.secretKey, hasLength(algorithm.sizes.secretKey));
            expect(outbound.ciphertext, hasLength(algorithm.sizes.ciphertext));
            expect(
              outbound.sharedSecret,
              hasLength(algorithm.sizes.sharedSecret),
            );
            expect(recovered, orderedEquals(outbound.sharedSecret));
            expect(
              second.ciphertext,
              isNot(orderedEquals(outbound.ciphertext)),
            );
            expect(
              second.sharedSecret,
              isNot(orderedEquals(outbound.sharedSecret)),
            );
            recovered.fillRange(0, recovered.length, 0);

            final altered = Uint8List.fromList(outbound.ciphertext)
              ..[0] ^= 0x80;
            if (algorithm.id.startsWith('NTRU+')) {
              expect(
                () => algorithm.decapsulate(altered, keys.secretKey),
                throwsA(isA<KpqCException>()),
              );
            } else {
              final replacement = algorithm.decapsulate(
                altered,
                keys.secretKey,
              );
              expect(replacement, hasLength(algorithm.sizes.sharedSecret));
              expect(replacement, isNot(orderedEquals(outbound.sharedSecret)));
              replacement.fillRange(0, replacement.length, 0);
            }
          } finally {
            second.dispose();
            outbound.dispose();
          }
        } finally {
          keys.dispose();
        }
      });
    }

    for (final algorithm in _kems) {
      test('${algorithm.id} rejects invalid input lengths', () {
        final keys = algorithm.generateKeyPair();
        try {
          final outbound = algorithm.encapsulate(keys.publicKey);
          try {
            expect(
              () => algorithm.encapsulate(
                Uint8List(algorithm.sizes.publicKey - 1),
              ),
              throwsArgumentError,
            );
            expect(
              () => algorithm.decapsulate(
                Uint8List(algorithm.sizes.ciphertext - 1),
                keys.secretKey,
              ),
              throwsArgumentError,
            );
            expect(
              () => algorithm.decapsulate(
                outbound.ciphertext,
                Uint8List(algorithm.sizes.secretKey - 1),
              ),
              throwsArgumentError,
            );
          } finally {
            outbound.dispose();
          }
        } finally {
          keys.dispose();
        }
      });
    }
  });

  test('secret result objects wipe their storage', () {
    final keys = ntruplus768.generateKeyPair();
    expect(keys.secretKey, isNot(everyElement(0)));
    expect(keys.toString(), isNot(contains(_hex(keys.secretKey))));
    keys.dispose();
    keys.dispose();
    expect(keys.secretKey, everyElement(0));

    final freshKeys = ntruplus768.generateKeyPair();
    try {
      final outbound = ntruplus768.encapsulate(freshKeys.publicKey);
      expect(outbound.sharedSecret, isNot(everyElement(0)));
      expect(outbound.toString(), isNot(contains(_hex(outbound.sharedSecret))));
      outbound.dispose();
      outbound.dispose();
      expect(outbound.sharedSecret, everyElement(0));
    } finally {
      freshKeys.dispose();
    }
  });
}

String _hex(Uint8List bytes) =>
    bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();
