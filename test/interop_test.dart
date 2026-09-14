import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:kpqc/kpqc.dart';
import 'package:test/test.dart';

final _message = Uint8List.fromList([
  ...utf8.encode('Dart/JavaScript/Python'),
  0,
  255,
]);
final _context = Uint8List.fromList(utf8.encode('kpqc-interop'));

final _signatures = <String, SignatureAlgorithm>{
  'aimer128f': aimer128f,
  'aimer128s': aimer128s,
  'aimer192f': aimer192f,
  'aimer192s': aimer192s,
  'aimer256f': aimer256f,
  'aimer256s': aimer256s,
  'haetae2': haetae2,
  'haetae3': haetae3,
  'haetae5': haetae5,
};

final _kems = <String, KeyEncapsulationAlgorithm>{
  'ntruplus768': ntruplus768,
  'ntruplus864': ntruplus864,
  'ntruplus1152': ntruplus1152,
  'smaugt128': smaugt128,
  'smaugt192': smaugt192,
  'smaugt256': smaugt256,
  'timer': timer,
};

void main() {
  final npmEntry = Platform.environment['KPQC_NPM_ENTRY'];
  final python = Platform.environment['KPQC_PYTHON'];

  test(
    'all parameter sets interoperate with npm in both directions',
    () => _checkRuntime(Platform.environment['KPQC_NODE'] ?? 'node', [
      'test/interop.mjs',
      npmEntry!,
    ], 'npm'),
    skip: npmEntry == null
        ? 'Set KPQC_NPM_ENTRY to enable npm interoperability tests.'
        : false,
    timeout: const Timeout(Duration(minutes: 4)),
  );

  test(
    'all parameter sets interoperate with PyPI in both directions',
    () => _checkRuntime(python!, ['test/interop.py'], 'PyPI'),
    skip: python == null
        ? 'Set KPQC_PYTHON to enable PyPI interoperability tests.'
        : false,
    timeout: const Timeout(Duration(minutes: 4)),
  );
}

Future<void> _checkRuntime(
  String executable,
  List<String> arguments,
  String runtime,
) async {
  final exchange = _createRequests();
  try {
    final response = await _runHelper(
      executable,
      arguments,
      jsonEncode(exchange.requests),
      runtime,
    );
    final decoded = jsonDecode(response);
    if (decoded is! List) {
      fail('$runtime helper returned a non-list response');
    }
    expect(decoded, hasLength(exchange.requests.length));

    for (final value in decoded) {
      final result = (value as Map).cast<String, Object?>();
      final name = result['name']! as String;
      final signatureAlgorithm = _signatures[name];
      if (signatureAlgorithm != null) {
        expect(
          signatureAlgorithm.verify(
            _message,
            _decodeHex(result['signature']! as String),
            _decodeHex(result['public_key']! as String),
            context: _context,
          ),
          isTrue,
          reason: '$name rejected the $runtime signature',
        );
        continue;
      }

      final algorithm = _kems[name];
      if (algorithm == null) fail('$runtime returned unknown algorithm $name');
      final recovered = algorithm.decapsulate(
        _decodeHex(result['ciphertext']! as String),
        exchange.kemKeys[name]!.secretKey,
      );
      try {
        expect(
          recovered,
          orderedEquals(_decodeHex(result['shared_secret']! as String)),
          reason: '$name rejected the $runtime ciphertext',
        );
      } finally {
        recovered.fillRange(0, recovered.length, 0);
      }
    }
  } finally {
    for (final keys in exchange.kemKeys.values) {
      keys.dispose();
    }
  }
}

({List<Map<String, String>> requests, Map<String, KeyPair> kemKeys})
_createRequests() {
  final requests = <Map<String, String>>[];
  final kemKeys = <String, KeyPair>{};

  for (final entry in _signatures.entries) {
    final keys = entry.value.generateKeyPair();
    try {
      requests.add({
        'name': entry.key,
        'public_key': _hex(keys.publicKey),
        'message': _hex(_message),
        'context': _hex(_context),
        'signature': _hex(
          entry.value.sign(_message, keys.secretKey, context: _context),
        ),
      });
    } finally {
      keys.dispose();
    }
  }

  for (final entry in _kems.entries) {
    final keys = entry.value.generateKeyPair();
    kemKeys[entry.key] = keys;
    final outbound = entry.value.encapsulate(keys.publicKey);
    try {
      requests.add({
        'name': entry.key,
        'public_key': _hex(keys.publicKey),
        'secret_key': _hex(keys.secretKey),
        'ciphertext': _hex(outbound.ciphertext),
        'shared_secret': _hex(outbound.sharedSecret),
      });
    } finally {
      outbound.dispose();
    }
  }

  return (requests: requests, kemKeys: kemKeys);
}

Future<String> _runHelper(
  String executable,
  List<String> arguments,
  String input,
  String runtime,
) async {
  final process = await Process.start(executable, arguments);
  final stdout = utf8.decoder.bind(process.stdout).join();
  final stderr = utf8.decoder.bind(process.stderr).join();
  Object? writeError;
  try {
    process.stdin.write(input);
    await process.stdin.close();
  } on Object catch (error) {
    writeError = error;
  }

  late final int exitCode;
  try {
    exitCode = await process.exitCode.timeout(const Duration(minutes: 3));
  } on TimeoutException {
    process.kill();
    throw TimeoutException('$runtime interoperability helper timed out');
  }
  final output = await stdout;
  final errors = await stderr;
  if (exitCode != 0) {
    fail('$runtime interoperability helper failed ($exitCode): $errors');
  }
  if (writeError != null) throw writeError;
  return output;
}

String _hex(Uint8List bytes) =>
    bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();

Uint8List _decodeHex(String input) {
  if (input.length.isOdd) throw const FormatException('Odd-length hex');
  return Uint8List.fromList([
    for (var offset = 0; offset < input.length; offset += 2)
      int.parse(input.substring(offset, offset + 2), radix: 16),
  ]);
}
