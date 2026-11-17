import 'dart:math';
import 'dart:typed_data';

typedef EntropySource = Uint8List Function(int length);

EntropySource? _testSource;

Uint8List randomBytes(int length) {
  final source = _testSource;
  if (source != null) {
    final output = source(length);
    if (output.length != length) {
      throw StateError(
        'entropy source returned ${output.length} bytes, expected $length',
      );
    }
    return Uint8List.fromList(output);
  }

  final random = Random.secure();
  final output = Uint8List(length);
  for (var index = 0; index < output.length; index++) {
    output[index] = random.nextInt(256);
  }
  return output;
}

void setTestEntropySource(EntropySource source) {
  _testSource = source;
}

void clearTestEntropySource() {
  _testSource = null;
}
