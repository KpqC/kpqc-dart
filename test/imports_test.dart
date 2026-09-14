import 'package:kpqc/aimer.dart' as aimer;
import 'package:kpqc/haetae.dart' as haetae;
import 'package:kpqc/kpqc.dart' as kpqc;
import 'package:kpqc/ntruplus.dart' as ntruplus;
import 'package:kpqc/smaugt.dart' as smaugt;
import 'package:test/test.dart';

void main() {
  test('family libraries expose the root algorithm singletons', () {
    expect(identical(aimer.aimer128f, kpqc.aimer128f), isTrue);
    expect(identical(haetae.haetae5, kpqc.haetae5), isTrue);
    expect(identical(ntruplus.ntruplus1152, kpqc.ntruplus1152), isTrue);
    expect(identical(smaugt.timer, kpqc.timer), isTrue);
  });
}
