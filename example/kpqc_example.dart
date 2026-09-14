import 'dart:convert';
import 'dart:typed_data';

import 'package:kpqc/kpqc.dart';

void main() {
  final message = Uint8List.fromList(utf8.encode('release-manifest:v3'));
  final signingKeys = aimer128f.generateKeyPair();
  try {
    final signature = aimer128f.sign(message, signingKeys.secretKey);
    final valid = aimer128f.verify(message, signature, signingKeys.publicKey);
    print('signature valid: $valid');
  } finally {
    signingKeys.dispose();
  }

  final recipient = smaugt192.generateKeyPair();
  try {
    final outbound = smaugt192.encapsulate(recipient.publicKey);
    try {
      final recovered = smaugt192.decapsulate(
        outbound.ciphertext,
        recipient.secretKey,
      );
      final matches = _equal(recovered, outbound.sharedSecret);
      print('shared secrets match: $matches');
      recovered.fillRange(0, recovered.length, 0);
    } finally {
      outbound.dispose();
    }
  } finally {
    recipient.dispose();
  }
}

bool _equal(List<int> left, List<int> right) {
  if (left.length != right.length) return false;
  var difference = 0;
  for (var index = 0; index < left.length; index++) {
    difference |= left[index] ^ right[index];
  }
  return difference == 0;
}
