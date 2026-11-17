import 'dart:typed_data';

import 'entropy.dart';
import 'fips202.dart';

final class AimerParameters {
  const AimerParameters({
    required this.mode,
    required this.bits,
    required this.repetitions,
    required this.parties,
    required this.logParties,
    required this.messagePrefix,
    required this.signatureBytes,
    required this.exponents,
  });

  final int mode;
  final int bits;
  final int repetitions;
  final int parties;
  final int logParties;
  final int messagePrefix;
  final int signatureBytes;
  final List<int> exponents;

  int get fieldBytes => bits ~/ 8;
  int get inputSboxes => exponents.length - 1;
  int get commitmentBytes => 2 * fieldBytes;
  int get publicKeyBytes => 2 * fieldBytes;
  int get secretKeyBytes => 3 * fieldBytes;
  int get tapeBytes => (2 * inputSboxes + 3) * fieldBytes;
  int get proofBytes =>
      logParties * fieldBytes +
      commitmentBytes +
      (2 * inputSboxes + 3) * fieldBytes;
}

const aimer128fParameters = AimerParameters(
  mode: 0,
  bits: 128,
  repetitions: 33,
  parties: 16,
  logParties: 4,
  messagePrefix: 0x00,
  signatureBytes: 6944,
  exponents: [3, 7, 11],
);
const aimer128sParameters = AimerParameters(
  mode: 1,
  bits: 128,
  repetitions: 17,
  parties: 256,
  logParties: 8,
  messagePrefix: 0x10,
  signatureBytes: 4704,
  exponents: [3, 7, 11],
);
const aimer192fParameters = AimerParameters(
  mode: 2,
  bits: 192,
  repetitions: 49,
  parties: 16,
  logParties: 4,
  messagePrefix: 0x20,
  signatureBytes: 15408,
  exponents: [11, 23, 47],
);
const aimer192sParameters = AimerParameters(
  mode: 3,
  bits: 192,
  repetitions: 25,
  parties: 256,
  logParties: 8,
  messagePrefix: 0x30,
  signatureBytes: 10320,
  exponents: [11, 23, 47],
);
const aimer256fParameters = AimerParameters(
  mode: 4,
  bits: 256,
  repetitions: 65,
  parties: 16,
  logParties: 4,
  messagePrefix: 0x40,
  signatureBytes: 31360,
  exponents: [3, 7, 11, 19],
);
const aimer256sParameters = AimerParameters(
  mode: 5,
  bits: 256,
  repetitions: 33,
  parties: 256,
  logParties: 8,
  messagePrefix: 0x50,
  signatureBytes: 20224,
  exponents: [3, 7, 11, 19],
);

final class AimerKeyPair {
  const AimerKeyPair(this.publicKey, this.secretKey);

  final Uint8List publicKey;
  final Uint8List secretKey;
}

final class _Linear {
  const _Linear(this.matrices, this.vectors);

  final List<List<BigInt>> matrices;
  final List<BigInt> vectors;
}

final class _Check {
  const _Check(this.x, this.z, this.a, this.b, this.c);

  final List<BigInt> x;
  final List<BigInt> z;
  final List<BigInt> a;
  final List<BigInt> b;
  final BigInt c;
}

final class _Tape {
  _Tape(AimerParameters parameters)
    : plaintext = BigInt.zero,
      y = List<BigInt>.filled(parameters.inputSboxes, BigInt.zero),
      a = List<BigInt>.filled(parameters.inputSboxes + 1, BigInt.zero),
      c = BigInt.zero;

  BigInt plaintext;
  final List<BigInt> y;
  final List<BigInt> a;
  BigInt c;
}

final class _CommitTape {
  const _CommitTape(this.commitment, this.tape);

  final Uint8List commitment;
  final _Tape tape;
}

final class _AimerHash {
  _AimerHash(AimerParameters parameters)
    : _shake = parameters.bits == 128 ? shake128Stream() : shake256Stream();

  final Shake _shake;

  void update(Uint8List input, [int offset = 0, int? length]) =>
      _shake.absorb(input, offset, length);

  void squeeze(Uint8List output, [int offset = 0, int? length]) =>
      _shake.squeeze(output, offset, length);
}

_AimerHash _prefixedHash(AimerParameters parameters, int prefix) =>
    _AimerHash(parameters)..update(Uint8List.fromList([prefix]));

BigInt _fieldFromBytes(
  AimerParameters parameters,
  Uint8List input,
  int offset,
) {
  var output = BigInt.zero;
  for (var index = 0; index < parameters.fieldBytes; index++) {
    output |= BigInt.from(input[offset + index]) << (8 * index);
  }
  return output;
}

void _fieldToBytes(
  AimerParameters parameters,
  BigInt value,
  Uint8List output,
  int offset,
) {
  for (var index = 0; index < parameters.fieldBytes; index++) {
    output[offset + index] = ((value >> (8 * index)) & BigInt.from(0xff))
        .toInt();
  }
}

Uint8List _fieldBytes(AimerParameters parameters, BigInt value) {
  final output = Uint8List(parameters.fieldBytes);
  _fieldToBytes(parameters, value, output, 0);
  return output;
}

BigInt _fieldMultiply(AimerParameters parameters, BigInt left, BigInt right) {
  var product = BigInt.zero;
  var remaining = right;
  var bit = 0;
  while (remaining != BigInt.zero) {
    if (remaining.isOdd) product ^= left << bit;
    remaining >>= 1;
    bit++;
  }
  final reductions = parameters.bits == 256
      ? const [0, 2, 5, 10]
      : const [0, 1, 2, 7];
  for (
    var position = product.bitLength - 1;
    position >= parameters.bits;
    position--
  ) {
    if (((product >> position) & BigInt.one) == BigInt.zero) continue;
    product ^= BigInt.one << position;
    final base = position - parameters.bits;
    for (final term in reductions) {
      product ^= BigInt.one << (base + term);
    }
  }
  return product;
}

BigInt _fieldSquare(AimerParameters parameters, BigInt value) =>
    _fieldMultiply(parameters, value, value);

BigInt _fieldInverse(AimerParameters parameters, BigInt value) {
  var power = value;
  var output = BigInt.one;
  for (var index = 1; index < parameters.bits; index++) {
    power = _fieldSquare(parameters, power);
    output = _fieldMultiply(parameters, output, power);
  }
  return output;
}

BigInt _matrixVector(
  List<BigInt> matrix,
  BigInt vector,
  AimerParameters parameters,
) {
  var output = BigInt.zero;
  for (var bit = 0; bit < parameters.bits; bit++) {
    if (((vector >> bit) & BigInt.one) != BigInt.zero) {
      output ^= matrix[bit];
    }
  }
  return output;
}

List<BigInt> _squeezeInvertibleMatrix(
  AimerParameters parameters,
  _AimerHash hash,
) {
  final lower = List<BigInt>.filled(parameters.bits, BigInt.zero);
  final upper = List<BigInt>.filled(parameters.bits, BigInt.zero);
  final bytes = Uint8List(parameters.fieldBytes);
  for (var row = 0; row < parameters.bits; row++) {
    hash.squeeze(bytes);
    final random = _fieldFromBytes(parameters, bytes, 0);
    final diagonal = BigInt.one << row;
    final lowerMask =
        ((BigInt.one << parameters.bits) - BigInt.one) ^
        ((BigInt.one << row) - BigInt.one);
    final upperMask = (BigInt.one << row) - BigInt.one;
    lower[row] = (random & lowerMask) | diagonal;
    upper[row] = (random & upperMask) | diagonal;
  }
  return List<BigInt>.generate(
    parameters.bits,
    (row) => _matrixVector(lower, upper[row], parameters),
    growable: false,
  );
}

_Linear _generateLinear(AimerParameters parameters, Uint8List iv) {
  final hash = _AimerHash(parameters)..update(iv);
  final matrices = List<List<BigInt>>.generate(
    2 * parameters.inputSboxes,
    (_) => _squeezeInvertibleMatrix(parameters, hash),
    growable: false,
  );
  final vectors = <BigInt>[];
  final bytes = Uint8List(parameters.fieldBytes);
  for (var index = 0; index <= parameters.inputSboxes; index++) {
    hash.squeeze(bytes);
    vectors.add(_fieldFromBytes(parameters, bytes, 0));
  }
  return _Linear(matrices, vectors);
}

Uint8List? _aimEncrypt(
  AimerParameters parameters,
  Uint8List plaintextBytes,
  Uint8List iv,
) {
  final linear = _generateLinear(parameters, iv);
  final plaintext = _fieldFromBytes(parameters, plaintextBytes, 0);
  final states = List<BigInt>.filled(parameters.inputSboxes, BigInt.zero);
  for (var index = 0; index < states.length; index++) {
    var state =
        _matrixVector(linear.matrices[index], plaintext, parameters) ^
        linear.vectors[index];
    if (state == BigInt.zero) return null;
    final inverse = _fieldInverse(parameters, state);
    for (var power = 0; power < parameters.exponents[index]; power++) {
      state = _fieldSquare(parameters, state);
    }
    state ^= BigInt.one;
    state = _fieldMultiply(parameters, state, inverse);
    states[index] = _matrixVector(
      linear.matrices[index + parameters.inputSboxes],
      state,
      parameters,
    );
  }
  var state = states.reduce((left, right) => left ^ right);
  state ^= linear.vectors[parameters.inputSboxes];
  if (state == BigInt.zero) return null;
  final inverse = _fieldInverse(parameters, state);
  for (
    var power = 0;
    power < parameters.exponents[parameters.inputSboxes];
    power++
  ) {
    state = _fieldSquare(parameters, state);
  }
  state ^= BigInt.one;
  state = _fieldMultiply(parameters, state, inverse) ^ plaintext;
  return _fieldBytes(parameters, state);
}

List<BigInt> _sboxOutputs(
  AimerParameters parameters,
  _Linear linear,
  BigInt plaintext,
  BigInt ciphertext,
) {
  final output = List<BigInt>.filled(parameters.inputSboxes + 1, BigInt.zero);
  for (var index = 0; index < parameters.inputSboxes; index++) {
    var value =
        _matrixVector(linear.matrices[index], plaintext, parameters) ^
        linear.vectors[index];
    final inverse = _fieldInverse(parameters, value);
    for (var power = 0; power < parameters.exponents[index]; power++) {
      value = _fieldSquare(parameters, value);
    }
    value ^= BigInt.one;
    output[index] = _fieldMultiply(parameters, value, inverse);
  }
  output[parameters.inputSboxes] = plaintext ^ ciphertext;
  return output;
}

_Tape _tapeFromBytes(AimerParameters parameters, Uint8List bytes) {
  final tape = _Tape(parameters);
  final size = parameters.fieldBytes;
  var offset = 0;
  tape.plaintext = _fieldFromBytes(parameters, bytes, offset);
  offset += size;
  for (var index = 0; index < tape.y.length; index++, offset += size) {
    tape.y[index] = _fieldFromBytes(parameters, bytes, offset);
  }
  for (var index = 0; index < tape.a.length; index++, offset += size) {
    tape.a[index] = _fieldFromBytes(parameters, bytes, offset);
  }
  tape.c = _fieldFromBytes(parameters, bytes, offset);
  return tape;
}

_Check _aimMpc(
  AimerParameters parameters,
  _Linear linear,
  _Tape tape,
  BigInt ciphertext,
  int party,
) {
  final last = party == parameters.parties - 1;
  final count = parameters.inputSboxes + 1;
  final x = List<BigInt>.filled(count, BigInt.zero);
  final z = List<BigInt>.filled(count, BigInt.zero);
  final b = List<BigInt>.filled(count, BigInt.zero);
  for (var index = 0; index < tape.y.length; index++) {
    b[index] = tape.y[index];
  }
  b[parameters.inputSboxes] =
      tape.plaintext ^ (last ? ciphertext : BigInt.zero);
  for (var index = 0; index < parameters.inputSboxes; index++) {
    x[index] = _matrixVector(
      linear.matrices[index],
      tape.plaintext,
      parameters,
    );
    if (last) x[index] ^= linear.vectors[index];
  }
  for (var index = 0; index < tape.y.length; index++) {
    x[parameters.inputSboxes] ^= _matrixVector(
      linear.matrices[index + parameters.inputSboxes],
      tape.y[index],
      parameters,
    );
  }
  if (last) {
    x[parameters.inputSboxes] ^= linear.vectors[parameters.inputSboxes];
  }
  for (var index = 0; index < count; index++) {
    z[index] = _fieldSquare(parameters, x[index]);
    for (var power = 1; power < parameters.exponents[index]; power++) {
      z[index] = _fieldSquare(parameters, z[index]);
    }
    if (last) z[index] ^= BigInt.one;
  }
  return _Check(x, z, List<BigInt>.from(tape.a), b, tape.c);
}

_CommitTape _commitAndExpandTape(
  AimerParameters parameters,
  Uint8List salt,
  int repetition,
  int party,
  Uint8List seed,
) {
  final hash = _prefixedHash(parameters, 5)
    ..update(salt)
    ..update(Uint8List.fromList([repetition, party]))
    ..update(seed);
  final commitment = Uint8List(parameters.commitmentBytes);
  hash.squeeze(commitment);
  final bytes = Uint8List(parameters.tapeBytes);
  hash.squeeze(bytes);
  return _CommitTape(commitment, _tapeFromBytes(parameters, bytes));
}

List<Uint8List> _expandTree(
  AimerParameters parameters,
  Uint8List salt,
  int repetition,
  Uint8List root,
) {
  final nodes = List<Uint8List>.generate(
    2 * parameters.parties - 1,
    (_) => Uint8List(parameters.fieldBytes),
    growable: false,
  );
  nodes[0].setAll(0, root);
  for (var node = 1; node < parameters.parties; node++) {
    final hash = _prefixedHash(parameters, 4)
      ..update(salt)
      ..update(Uint8List.fromList([repetition, node]))
      ..update(nodes[node - 1]);
    final children = Uint8List(2 * parameters.fieldBytes);
    hash.squeeze(children);
    nodes[2 * node - 1].setRange(0, parameters.fieldBytes, children);
    nodes[2 * node].setRange(
      0,
      parameters.fieldBytes,
      children,
      parameters.fieldBytes,
    );
  }
  return nodes;
}

Uint8List _revealPath(
  AimerParameters parameters,
  List<Uint8List> nodes,
  int covered,
) {
  final output = Uint8List(parameters.logParties * parameters.fieldBytes);
  var index = covered + parameters.parties;
  for (var depth = 0; depth < parameters.logParties; depth++) {
    output.setRange(
      depth * parameters.fieldBytes,
      (depth + 1) * parameters.fieldBytes,
      nodes[(index ^ 1) - 1],
    );
    index >>= 1;
  }
  return output;
}

List<Uint8List> _reconstructTree(
  AimerParameters parameters,
  Uint8List salt,
  Uint8List path,
  int repetition,
  int covered,
) {
  final size = parameters.fieldBytes;
  final nodes = List<Uint8List>.generate(
    2 * parameters.parties - 2,
    (_) => Uint8List(size),
    growable: false,
  );
  for (var depth = 1; depth < parameters.logParties; depth++) {
    final sibling =
        ((covered + parameters.parties) >> (parameters.logParties - depth)) ^ 1;
    nodes[sibling - 2].setRange(
      0,
      size,
      path,
      (parameters.logParties - depth) * size,
    );
    for (var index = 1 << depth; index < 2 << depth; index++) {
      final hash = _prefixedHash(parameters, 4)
        ..update(salt)
        ..update(Uint8List.fromList([repetition, index]))
        ..update(nodes[index - 2]);
      final children = Uint8List(2 * size);
      hash.squeeze(children);
      nodes[2 * index - 2].setRange(0, size, children);
      nodes[2 * index - 1].setRange(0, size, children, size);
    }
  }
  final sibling = (covered + parameters.parties) ^ 1;
  nodes[sibling - 2].setRange(0, size, path);
  return nodes;
}

int _proofStart(AimerParameters parameters, int repetition) =>
    parameters.fieldBytes +
    2 * parameters.commitmentBytes +
    repetition * parameters.proofBytes;

int _missingCommitmentOffset(AimerParameters parameters) =>
    parameters.logParties * parameters.fieldBytes;

int _deltaOffset(AimerParameters parameters) =>
    _missingCommitmentOffset(parameters) + parameters.commitmentBytes;

int _missingAlphaOffset(AimerParameters parameters) =>
    _deltaOffset(parameters) +
    (parameters.inputSboxes + 2) * parameters.fieldBytes;

void _updateFields(
  _AimerHash hash,
  AimerParameters parameters,
  List<BigInt> fields,
) {
  for (final value in fields) {
    hash.update(_fieldBytes(parameters, value));
  }
}

Uint8List _messageDigest(
  AimerParameters parameters,
  Uint8List publicKey,
  Uint8List prefix,
  Uint8List message,
) {
  final hash = _prefixedHash(parameters, parameters.messagePrefix)
    ..update(publicKey)
    ..update(prefix)
    ..update(message);
  final digest = Uint8List(parameters.commitmentBytes);
  hash.squeeze(digest);
  return digest;
}

List<int> _challengedIndices(AimerParameters parameters, Uint8List h2) {
  final hash = _AimerHash(parameters)..update(h2);
  final bytes = Uint8List(parameters.repetitions);
  hash.squeeze(bytes);
  return List<int>.generate(
    parameters.repetitions,
    (index) => bytes[index] & (parameters.parties - 1),
    growable: false,
  );
}

List<BigInt> _fieldsFromBytes(
  AimerParameters parameters,
  Uint8List input,
  int count,
) => List<BigInt>.generate(
  count,
  (index) => _fieldFromBytes(parameters, input, index * parameters.fieldBytes),
  growable: false,
);

bool _equal(Uint8List left, Uint8List right) {
  if (left.length != right.length) return false;
  var difference = 0;
  for (var index = 0; index < left.length; index++) {
    difference |= left[index] ^ right[index];
  }
  return difference == 0;
}

AimerKeyPair aimerGenerateKeyPair(AimerParameters parameters) {
  final size = parameters.fieldBytes;
  for (;;) {
    final plaintext = randomBytes(size);
    final iv = randomBytes(size);
    final ciphertext = _aimEncrypt(parameters, plaintext, iv);
    if (ciphertext == null) continue;
    final publicKey = Uint8List(2 * size)
      ..setRange(0, size, iv)
      ..setRange(size, 2 * size, ciphertext);
    final secretKey = Uint8List(3 * size)
      ..setRange(0, size, plaintext)
      ..setRange(size, 3 * size, publicKey);
    return AimerKeyPair(publicKey, secretKey);
  }
}

Uint8List aimerSign(
  AimerParameters parameters,
  Uint8List message,
  Uint8List secretKey,
  Uint8List context,
) {
  if (context.length > 255 || secretKey.length != parameters.secretKeyBytes) {
    throw ArgumentError('invalid AIMer signing input');
  }
  final size = parameters.fieldBytes;
  final signature = Uint8List(parameters.signatureBytes);
  final randomness = randomBytes(size);
  final prefix = Uint8List(1 + context.length)
    ..[0] = context.length
    ..setRange(1, 1 + context.length, context);
  final publicKey = Uint8List.fromList(secretKey.sublist(size));
  final digest = _messageDigest(parameters, publicKey, prefix, message);
  final plaintext = _fieldFromBytes(parameters, secretKey, 0);
  final ciphertext = _fieldFromBytes(parameters, secretKey, 2 * size);
  final linear = _generateLinear(
    parameters,
    Uint8List.fromList(secretKey.sublist(size, 2 * size)),
  );
  final outputs = _sboxOutputs(parameters, linear, plaintext, ciphertext);

  final seedHash = _prefixedHash(parameters, 3)
    ..update(secretKey, 0, size)
    ..update(digest)
    ..update(randomness);
  seedHash.squeeze(signature, 0, size);
  final salt = Uint8List.fromList(signature.sublist(0, size));
  final roots = Uint8List(parameters.repetitions * size);
  seedHash.squeeze(roots);

  final h1Hash = _prefixedHash(parameters, 1)
    ..update(digest)
    ..update(salt);
  final allNodes = <List<Uint8List>>[];
  final allCommitments = <List<Uint8List>>[];
  final checks = <List<_Check>>[];

  for (var repetition = 0; repetition < parameters.repetitions; repetition++) {
    final nodes = _expandTree(
      parameters,
      salt,
      repetition,
      Uint8List.fromList(
        roots.sublist(repetition * size, (repetition + 1) * size),
      ),
    );
    final commitments = <Uint8List>[];
    final repetitionChecks = <_Check>[];
    final delta = _Tape(parameters);
    final deltaBytes = Uint8List((parameters.inputSboxes + 2) * size);
    for (var party = 0; party < parameters.parties; party++) {
      final expanded = _commitAndExpandTape(
        parameters,
        salt,
        repetition,
        party,
        nodes[party + parameters.parties - 1],
      );
      commitments.add(expanded.commitment);
      final tape = expanded.tape;
      delta.plaintext ^= tape.plaintext;
      for (var index = 0; index < delta.y.length; index++) {
        delta.y[index] ^= tape.y[index];
      }
      for (var index = 0; index < delta.a.length; index++) {
        delta.a[index] ^= tape.a[index];
      }
      delta.c ^= tape.c;
      if (party == parameters.parties - 1) {
        delta.plaintext ^= plaintext;
        _fieldToBytes(parameters, delta.plaintext, deltaBytes, 0);
        tape.plaintext ^= delta.plaintext;
        for (var index = 0; index < parameters.inputSboxes; index++) {
          delta.y[index] ^= outputs[index];
          _fieldToBytes(
            parameters,
            delta.y[index],
            deltaBytes,
            (index + 1) * size,
          );
          tape.y[index] ^= delta.y[index];
        }
        for (var index = 0; index < delta.a.length; index++) {
          delta.c ^= _fieldMultiply(parameters, delta.a[index], outputs[index]);
        }
        _fieldToBytes(
          parameters,
          delta.c,
          deltaBytes,
          (parameters.inputSboxes + 1) * size,
        );
        tape.c ^= delta.c;
      }
      repetitionChecks.add(
        _aimMpc(parameters, linear, tape, ciphertext, party),
      );
    }
    for (final commitment in commitments) {
      h1Hash.update(commitment);
    }
    h1Hash.update(deltaBytes);
    signature.setRange(
      _proofStart(parameters, repetition) + _deltaOffset(parameters),
      _proofStart(parameters, repetition) +
          _deltaOffset(parameters) +
          deltaBytes.length,
      deltaBytes,
    );
    allNodes.add(nodes);
    allCommitments.add(commitments);
    checks.add(repetitionChecks);
  }
  final h1Offset = size;
  h1Hash.squeeze(signature, h1Offset, parameters.commitmentBytes);
  final h1 = Uint8List.fromList(
    signature.sublist(h1Offset, h1Offset + parameters.commitmentBytes),
  );

  final epsilonHash = _AimerHash(parameters)..update(h1);
  final h2Hash = _prefixedHash(parameters, 2)
    ..update(h1)
    ..update(salt);
  final alphaShares = <List<List<BigInt>>>[];
  for (var repetition = 0; repetition < parameters.repetitions; repetition++) {
    final epsilonBytes = Uint8List((parameters.inputSboxes + 1) * size);
    epsilonHash.squeeze(epsilonBytes);
    final epsilons = _fieldsFromBytes(
      parameters,
      epsilonBytes,
      parameters.inputSboxes + 1,
    );
    final alpha = List<BigInt>.filled(parameters.inputSboxes + 1, BigInt.zero);
    final vShares = List<BigInt>.filled(parameters.parties, BigInt.zero);
    final repetitionShares = List<List<BigInt>>.generate(
      parameters.parties,
      (_) => List<BigInt>.filled(parameters.inputSboxes + 1, BigInt.zero),
      growable: false,
    );
    alphaShares.add(repetitionShares);
    for (var party = 0; party < parameters.parties; party++) {
      vShares[party] = checks[repetition][party].c;
      for (var index = 0; index <= parameters.inputSboxes; index++) {
        final value =
            checks[repetition][party].a[index] ^
            _fieldMultiply(
              parameters,
              checks[repetition][party].x[index],
              epsilons[index],
            );
        repetitionShares[party][index] = value;
        alpha[index] ^= value;
        vShares[party] ^= _fieldMultiply(
          parameters,
          checks[repetition][party].z[index],
          epsilons[index],
        );
      }
    }
    for (var party = 0; party < parameters.parties; party++) {
      for (var index = 0; index < alpha.length; index++) {
        vShares[party] ^= _fieldMultiply(
          parameters,
          checks[repetition][party].b[index],
          alpha[index],
        );
      }
    }
    for (final shares in repetitionShares) {
      _updateFields(h2Hash, parameters, shares);
    }
    _updateFields(h2Hash, parameters, vShares);
  }
  final h2Offset = size + parameters.commitmentBytes;
  h2Hash.squeeze(signature, h2Offset, parameters.commitmentBytes);
  final h2 = Uint8List.fromList(
    signature.sublist(h2Offset, h2Offset + parameters.commitmentBytes),
  );
  final challenged = _challengedIndices(parameters, h2);
  for (var repetition = 0; repetition < challenged.length; repetition++) {
    final covered = challenged[repetition];
    final path = _revealPath(parameters, allNodes[repetition], covered);
    final proof = _proofStart(parameters, repetition);
    signature.setRange(proof, proof + path.length, path);
    signature.setRange(
      proof + _missingCommitmentOffset(parameters),
      proof + _missingCommitmentOffset(parameters) + parameters.commitmentBytes,
      allCommitments[repetition][covered],
    );
    final missing = proof + _missingAlphaOffset(parameters);
    for (var index = 0; index <= parameters.inputSboxes; index++) {
      _fieldToBytes(
        parameters,
        alphaShares[repetition][covered][index],
        signature,
        missing + index * size,
      );
    }
  }
  return signature;
}

bool aimerVerify(
  AimerParameters parameters,
  Uint8List message,
  Uint8List signature,
  Uint8List publicKey,
  Uint8List context,
) {
  if (context.length > 255 ||
      signature.length != parameters.signatureBytes ||
      publicKey.length != parameters.publicKeyBytes) {
    return false;
  }
  final size = parameters.fieldBytes;
  final commitmentBytes = parameters.commitmentBytes;
  final salt = Uint8List.fromList(signature.sublist(0, size));
  final h1 = Uint8List.fromList(
    signature.sublist(size, size + commitmentBytes),
  );
  final h2 = Uint8List.fromList(
    signature.sublist(size + commitmentBytes, size + 2 * commitmentBytes),
  );
  final linear = _generateLinear(
    parameters,
    Uint8List.fromList(publicKey.sublist(0, size)),
  );
  final ciphertext = _fieldFromBytes(parameters, publicKey, size);
  final challenged = _challengedIndices(parameters, h2);
  final epsilonHash = _AimerHash(parameters)..update(h1);
  final prefix = Uint8List(1 + context.length)
    ..[0] = context.length
    ..setRange(1, 1 + context.length, context);
  final digest = _messageDigest(parameters, publicKey, prefix, message);
  final h1Hash = _prefixedHash(parameters, 1)
    ..update(digest)
    ..update(salt);
  final h2Hash = _prefixedHash(parameters, 2)
    ..update(h1)
    ..update(salt);

  for (var repetition = 0; repetition < challenged.length; repetition++) {
    final covered = challenged[repetition];
    final proof = _proofStart(parameters, repetition);
    final path = Uint8List.fromList(
      signature.sublist(proof, proof + parameters.logParties * size),
    );
    final nodes = _reconstructTree(parameters, salt, path, repetition, covered);
    final epsilonBytes = Uint8List((parameters.inputSboxes + 1) * size);
    epsilonHash.squeeze(epsilonBytes);
    final epsilons = _fieldsFromBytes(
      parameters,
      epsilonBytes,
      parameters.inputSboxes + 1,
    );
    final alpha = List<BigInt>.filled(parameters.inputSboxes + 1, BigInt.zero);
    final alphaShares = List<List<BigInt>>.generate(
      parameters.parties,
      (_) => List<BigInt>.filled(parameters.inputSboxes + 1, BigInt.zero),
      growable: false,
    );
    final bShares = List<List<BigInt>>.generate(
      parameters.parties,
      (_) => List<BigInt>.filled(parameters.inputSboxes + 1, BigInt.zero),
      growable: false,
    );
    final vShares = List<BigInt>.filled(parameters.parties, BigInt.zero);
    for (var party = 0; party < parameters.parties; party++) {
      if (party == covered) {
        h1Hash.update(
          signature,
          proof + _missingCommitmentOffset(parameters),
          commitmentBytes,
        );
        final missing = proof + _missingAlphaOffset(parameters);
        for (var index = 0; index <= parameters.inputSboxes; index++) {
          alphaShares[party][index] = _fieldFromBytes(
            parameters,
            signature,
            missing + index * size,
          );
          alpha[index] ^= alphaShares[party][index];
        }
        continue;
      }
      final expanded = _commitAndExpandTape(
        parameters,
        salt,
        repetition,
        party,
        nodes[parameters.parties + party - 2],
      );
      h1Hash.update(expanded.commitment);
      final tape = expanded.tape;
      if (party == parameters.parties - 1) {
        var delta = proof + _deltaOffset(parameters);
        tape.plaintext ^= _fieldFromBytes(parameters, signature, delta);
        delta += size;
        for (var index = 0; index < tape.y.length; index++, delta += size) {
          tape.y[index] ^= _fieldFromBytes(parameters, signature, delta);
        }
        tape.c ^= _fieldFromBytes(parameters, signature, delta);
      }
      final check = _aimMpc(parameters, linear, tape, ciphertext, party);
      vShares[party] = check.c;
      for (var index = 0; index <= parameters.inputSboxes; index++) {
        alphaShares[party][index] =
            check.a[index] ^
            _fieldMultiply(parameters, check.x[index], epsilons[index]);
        alpha[index] ^= alphaShares[party][index];
        bShares[party][index] = check.b[index];
        vShares[party] ^= _fieldMultiply(
          parameters,
          check.z[index],
          epsilons[index],
        );
      }
    }
    for (var party = 0; party < parameters.parties; party++) {
      if (party == covered) continue;
      for (var index = 0; index < alpha.length; index++) {
        vShares[party] ^= _fieldMultiply(
          parameters,
          bShares[party][index],
          alpha[index],
        );
      }
      vShares[covered] ^= vShares[party];
    }
    for (final shares in alphaShares) {
      _updateFields(h2Hash, parameters, shares);
    }
    _updateFields(h2Hash, parameters, vShares);
    h1Hash.update(
      signature,
      proof + _deltaOffset(parameters),
      (parameters.inputSboxes + 2) * size,
    );
  }
  final computedH1 = Uint8List(commitmentBytes);
  final computedH2 = Uint8List(commitmentBytes);
  h1Hash.squeeze(computedH1);
  h2Hash.squeeze(computedH2);
  return _equal(computedH1, h1) && _equal(computedH2, h2);
}
