import 'dart:typed_data';

import 'haetae_params.dart';
import 'haetae_poly.dart';

const _ransByteL = 1 << 23;
const _scaleBits = 10;
const _scale = 1 << _scaleBits;

final class _SymbolRange {
  const _SymbolRange(this.start, this.frequency);
  final int start;
  final int frequency;
}

final class _Encoding {
  const _Encoding(
    this.hint,
    this.hintCut,
    this.hintOffset,
    this.high,
    this.highOffset,
  );
  final List<_SymbolRange> hint;
  final int hintCut;
  final int hintOffset;
  final List<_SymbolRange> high;
  final int highOffset;
}

List<_SymbolRange> _ranges(List<int> values) => List<_SymbolRange>.generate(
  values.length ~/ 2,
  (index) => _SymbolRange(values[2 * index], values[2 * index + 1]),
  growable: false,
);

final _mode2Encoding = _Encoding(
  _ranges([
    0,
    382,
    382,
    246,
    628,
    65,
    693,
    7,
    700,
    1,
    701,
    1,
    702,
    1,
    703,
    1,
    704,
    1,
    705,
    1,
    706,
    7,
    713,
    65,
    778,
    246,
  ]),
  6,
  239,
  _ranges([
    0,
    1,
    1,
    1,
    2,
    1,
    3,
    5,
    8,
    58,
    66,
    246,
    312,
    398,
    710,
    247,
    957,
    59,
    1016,
    5,
    1021,
    1,
    1022,
    1,
    1023,
    1,
  ]),
  6,
);
final _mode3Encoding = _Encoding(
  _ranges([
    0,
    266,
    266,
    213,
    479,
    113,
    592,
    40,
    632,
    9,
    641,
    1,
    642,
    1,
    643,
    1,
    644,
    1,
    645,
    1,
    646,
    1,
    647,
    1,
    648,
    1,
    649,
    9,
    658,
    40,
    698,
    113,
    811,
    213,
  ]),
  8,
  235,
  _ranges([
    0,
    1,
    1,
    1,
    2,
    1,
    3,
    1,
    4,
    8,
    12,
    37,
    49,
    112,
    161,
    216,
    377,
    269,
    646,
    216,
    862,
    112,
    974,
    38,
    1012,
    8,
    1020,
    1,
    1021,
    1,
    1022,
    1,
    1023,
    1,
  ]),
  8,
);
final _mode5Encoding = _Encoding(
  _ranges([
    0,
    122,
    122,
    117,
    239,
    102,
    341,
    81,
    422,
    59,
    481,
    39,
    520,
    23,
    543,
    13,
    556,
    6,
    562,
    3,
    565,
    1,
    566,
    1,
    567,
    1,
    568,
    1,
    569,
    1,
    570,
    1,
    571,
    1,
    572,
    1,
    573,
    1,
    574,
    1,
    575,
    1,
    576,
    1,
    577,
    1,
    578,
    1,
    579,
    3,
    582,
    6,
    588,
    13,
    601,
    24,
    625,
    39,
    664,
    59,
    723,
    81,
    804,
    102,
    906,
    118,
  ]),
  16,
  471,
  _ranges([
    0,
    1,
    1,
    1,
    2,
    1,
    3,
    1,
    4,
    2,
    6,
    13,
    19,
    48,
    67,
    118,
    185,
    204,
    389,
    245,
    634,
    204,
    838,
    118,
    956,
    48,
    1004,
    14,
    1018,
    2,
    1020,
    1,
    1021,
    1,
    1022,
    1,
    1023,
    1,
  ]),
  9,
);

_Encoding _encodingForMode(int mode) => switch (mode) {
  2 => _mode2Encoding,
  3 => _mode3Encoding,
  5 => _mode5Encoding,
  _ => throw ArgumentError('unsupported HAETAE mode'),
};

List<int> _flatten(List<List<int>> value) => [for (final row in value) ...row];

List<List<int>> _reshape(List<int> flat, int count) {
  final output = haetaeZeroVector(count);
  for (var index = 0; index < count; index++) {
    output[index].setRange(
      0,
      HaetaeParameters.n,
      flat,
      index * HaetaeParameters.n,
    );
  }
  return output;
}

Uint8List? _encodeSymbols(List<int> symbols, List<_SymbolRange> distribution) {
  var state = _ransByteL;
  var emitted = Uint8List(symbols.length * 2 + 16);
  var count = 0;
  for (var index = symbols.length - 1; index >= 0; index--) {
    final symbol = symbols[index];
    if (symbol < 0 || symbol >= distribution.length) return null;
    final range = distribution[symbol];
    final maximum = ((_ransByteL >>> _scaleBits) << 8) * range.frequency;
    while (state >= maximum) {
      if (count == emitted.length) {
        final expanded = Uint8List(emitted.length * 2)..setAll(0, emitted);
        emitted = expanded;
      }
      emitted[count++] = state;
      state >>>= 8;
    }
    state =
        state ~/ range.frequency * _scale +
        state % range.frequency +
        range.start;
  }
  final output = Uint8List(4 + count);
  for (var index = 0; index < 4; index++) {
    output[index] = state >>> (8 * index);
  }
  for (var index = 0; index < count; index++) {
    output[4 + index] = emitted[count - 1 - index];
  }
  return output;
}

List<int>? _decodeSymbols(
  Uint8List input,
  int count,
  List<_SymbolRange> distribution,
) {
  if (input.length < 4) return null;
  var state = input[0] | input[1] << 8 | input[2] << 16 | input[3] << 24;
  if (state < _ransByteL || state >= _ransByteL * 256) return null;
  var offset = 4;
  final output = List<int>.filled(count, 0);
  for (var index = 0; index < output.length; index++) {
    final cumulative = state & (_scale - 1);
    var symbol = -1;
    for (var candidate = 0; candidate < distribution.length; candidate++) {
      final range = distribution[candidate];
      if (cumulative >= range.start &&
          cumulative < range.start + range.frequency) {
        symbol = candidate;
        state =
            range.frequency * (state >>> _scaleBits) + cumulative - range.start;
        break;
      }
    }
    if (symbol < 0) return null;
    output[index] = symbol;
    while (state < _ransByteL && offset < input.length) {
      state = state << 8 | input[offset++];
    }
  }
  return state == _ransByteL && offset == input.length ? output : null;
}

Uint8List? haetaeEncodeHint(HaetaeParameters parameters, List<List<int>> hint) {
  final spec = _encodingForMode(parameters.mode);
  final values = _flatten(hint);
  for (var index = 0; index < values.length; index++) {
    final value = values[index];
    if (value > spec.hintCut && value <= spec.hintCut + spec.hintOffset) {
      return null;
    }
    if (value > spec.hintCut + spec.hintOffset) {
      values[index] = value - spec.hintOffset;
    }
  }
  return _encodeSymbols(values, spec.hint);
}

List<List<int>>? haetaeDecodeHint(
  HaetaeParameters parameters,
  Uint8List input,
) {
  final spec = _encodingForMode(parameters.mode);
  final values = _decodeSymbols(
    input,
    parameters.k * HaetaeParameters.n,
    spec.hint,
  );
  if (values == null) return null;
  for (var index = 0; index < values.length; index++) {
    if (values[index] > spec.hintCut) values[index] += spec.hintOffset;
  }
  return _reshape(values, parameters.k);
}

Uint8List? haetaeEncodeHighBits(
  HaetaeParameters parameters,
  List<List<int>> high,
) {
  final spec = _encodingForMode(parameters.mode);
  final values = _flatten(high);
  for (var index = 0; index < values.length; index++) {
    values[index] += spec.highOffset;
  }
  return _encodeSymbols(values, spec.high);
}

List<List<int>>? haetaeDecodeHighBits(
  HaetaeParameters parameters,
  Uint8List input,
) {
  final spec = _encodingForMode(parameters.mode);
  final values = _decodeSymbols(
    input,
    parameters.l * HaetaeParameters.n,
    spec.high,
  );
  if (values == null) return null;
  for (var index = 0; index < values.length; index++) {
    values[index] -= spec.highOffset;
  }
  return _reshape(values, parameters.l);
}
