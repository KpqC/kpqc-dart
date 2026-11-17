import 'dart:convert';
import 'dart:typed_data';

import 'package:kpqc/src/internal/fips202.dart';
import 'package:test/test.dart';

void main() {
  final empty = Uint8List(0);

  test('SHA3-256 matches the empty-string vector', () {
    expect(
      _hex(sha3256(empty)),
      'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a',
    );
  });

  test('SHA3-512 matches the empty-string vector', () {
    expect(
      _hex(sha3512(empty)),
      'a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6'
      '15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26',
    );
  });

  test('SHAKE128 supports incremental input and output', () {
    final input = Uint8List.fromList(utf8.encode('abc'));
    final direct = shake128(input, 64);
    final stream = shake128Stream()
      ..absorb(Uint8List.fromList(input.sublist(0, 1)))
      ..absorb(Uint8List.fromList(input.sublist(1)));
    final first = Uint8List(17);
    final second = Uint8List(47);
    stream
      ..squeeze(first)
      ..squeeze(second);

    expect([...first, ...second], orderedEquals(direct));
    expect(
      _hex(direct),
      '5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8'
      '44c50af32acd3f2cdd066568706f509bc1bdde58295dae3f891a9a0fca578378',
    );
  });
}

String _hex(Uint8List value) =>
    value.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();
