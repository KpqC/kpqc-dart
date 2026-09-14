import 'package:code_assets/code_assets.dart';
import 'package:hooks/hooks.dart';
import 'package:native_toolchain_c/native_toolchain_c.dart';

const _randomBytes = 'native/csrc/randombytes.c';
const _signatureWrapper = 'native/csrc/signature.c';
const _kemWrapper = 'native/csrc/kem.c';

const _signatureNames = <String>{
  'aimer128f',
  'aimer128s',
  'aimer192f',
  'aimer192s',
  'aimer256f',
  'aimer256s',
  'haetae2',
  'haetae3',
  'haetae5',
};

const _pqcFips202Symbols = <String>[
  'sha3_256',
  'sha3_256_inc_absorb',
  'sha3_256_inc_ctx_clone',
  'sha3_256_inc_ctx_release',
  'sha3_256_inc_finalize',
  'sha3_256_inc_init',
  'sha3_384',
  'sha3_384_inc_absorb',
  'sha3_384_inc_ctx_clone',
  'sha3_384_inc_ctx_release',
  'sha3_384_inc_finalize',
  'sha3_384_inc_init',
  'sha3_512',
  'sha3_512_inc_absorb',
  'sha3_512_inc_ctx_clone',
  'sha3_512_inc_ctx_release',
  'sha3_512_inc_finalize',
  'sha3_512_inc_init',
  'shake128',
  'shake128_absorb',
  'shake128_ctx_clone',
  'shake128_ctx_release',
  'shake128_inc_absorb',
  'shake128_inc_ctx_clone',
  'shake128_inc_ctx_release',
  'shake128_inc_finalize',
  'shake128_inc_init',
  'shake128_inc_squeeze',
  'shake128_squeezeblocks',
  'shake256',
  'shake256_absorb',
  'shake256_ctx_clone',
  'shake256_ctx_release',
  'shake256_inc_absorb',
  'shake256_inc_ctx_clone',
  'shake256_inc_ctx_release',
  'shake256_inc_finalize',
  'shake256_inc_init',
  'shake256_inc_squeeze',
  'shake256_squeezeblocks',
];

const _compactFips202Symbols = <String>[
  'KeccakF_RoundConstants',
  'sha3_256',
  'sha3_512',
  'shake128',
  'shake128_absorb',
  'shake128_absorb_once',
  'shake128_finalize',
  'shake128_init',
  'shake128_squeeze',
  'shake128_squeezeblocks',
  'shake256',
  'shake256_absorb',
  'shake256_absorb_once',
  'shake256_finalize',
  'shake256_init',
  'shake256_squeeze',
  'shake256_squeezeblocks',
];

const _ntruPlusSymbols = <String>[
  'baseinv',
  'basemul',
  'basemul_add',
  'crypto_kem_dec',
  'crypto_kem_enc',
  'crypto_kem_keypair',
  'hash_f',
  'hash_g',
  'hash_h',
  'invntt',
  'ntt',
  'poly_baseinv',
  'poly_basemul',
  'poly_basemul_add',
  'poly_cbd1',
  'poly_crepmod3',
  'poly_frombytes',
  'poly_invntt',
  'poly_ntt',
  'poly_sotp_decode',
  'poly_sotp_encode',
  'poly_sub',
  'poly_tobytes',
  'poly_triple',
  'zetas',
];

const _haetaeSymbols = <String>[
  'brv8',
  'fix_round',
  'hammingWeight_8',
  'polyfixfix_sub',
  'sample_gauss',
  'shake128_stream_init',
  'shake256_absorb_thrice',
  'shake256_absorb_twice',
  'shake256_stream_init',
  'start_cube',
  'start_times_threehalves',
];

void main(List<String> args) async {
  await build(args, (input, output) async {
    for (final library in kpqcLibraries(
      systemLibraries(input.config.code.targetOS),
    )) {
      await library.build(input: input, output: output);
    }
  });
}

List<String> systemLibraries(OS targetOS) => targetOS == OS.windows
    ? const ['bcrypt']
    : targetOS == OS.linux || targetOS == OS.android
    ? const ['m']
    : const <String>[];

Iterable<CLibrary> kpqcLibraries(List<String> libraries) sync* {
  for (final parameter in ['128f', '128s', '192f', '192s', '256f', '256s']) {
    final name = 'aimer$parameter';
    final root = 'vendor/AIMer';
    yield _library(
      name: name,
      sources: [
        _signatureWrapper,
        _randomBytes,
        '$root/aim2.c',
        '$root/hash.c',
        '$root/sign.c',
        '$root/tree.c',
        '$root/field${parameter.substring(0, 3)}.c',
        '$root/common/fips202.c',
      ],
      includes: [root, '$root/common'],
      libraries: libraries,
      defines: {
        'PARAMS': parameter,
        'KPQC_AIMER': '1',
        ..._renames(name, [
          'crypto_sign_keypair_internal',
          'crypto_sign_signature_internal',
          'crypto_sign_verify_internal',
          ..._pqcFips202Symbols,
        ]),
      },
    );
  }

  for (final entry in {
    'haetae2': '0',
    'haetae3': '1',
    'haetae5': '2',
  }.entries) {
    final name = entry.key;
    const root = 'vendor/HAETAE';
    yield _library(
      name: name,
      sources: [
        _signatureWrapper,
        _randomBytes,
        for (final source in [
          'decompose',
          'encoding',
          'fft',
          'fixpoint',
          'ntt',
          'packing',
          'poly',
          'polyfix',
          'polymat',
          'polyvec',
          'reduce',
          'sampler',
          'sign',
          'fips202',
          'symmetric-shake',
        ])
          '$root/src/$source.c',
      ],
      includes: ['$root/include'],
      libraries: libraries,
      defines: {
        'HAETAE_CONFIG_MODE': entry.value,
        ..._renames(name, [..._compactFips202Symbols, ..._haetaeSymbols]),
      },
    );
  }

  for (final parameter in ['768', '864', '1152']) {
    final name = 'ntruplus$parameter';
    final root = 'vendor/NTRUplus/NTRU+$parameter';
    yield _library(
      name: name,
      sources: [
        _kemWrapper,
        _randomBytes,
        '$root/kem.c',
        '$root/ntt.c',
        '$root/poly.c',
        '$root/symmetric.c',
        '$root/fips202/fips202.c',
      ],
      includes: [root],
      libraries: libraries,
      defines: {
        ..._renames(name, [..._ntruPlusSymbols, ..._pqcFips202Symbols]),
      },
    );
  }

  for (final entry in {
    'smaugt128': '0',
    'smaugt192': '1',
    'smaugt256': '2',
    'timer': '3',
  }.entries) {
    final name = entry.key;
    const root = 'vendor/SMAUG-T';
    yield _library(
      name: name,
      sources: [
        _kemWrapper,
        _randomBytes,
        for (final source in [
          'cbd',
          'ciphertext',
          'dg',
          'hash',
          'hwt',
          'indcpa',
          'kem',
          'key',
          'pack',
          'packring',
          'poly',
          'toomcook',
          'verify',
          'fips202',
        ])
          '$root/src/$source.c',
      ],
      includes: ['$root/include'],
      libraries: libraries,
      defines: {
        'SMAUGT_CONFIG_MODE': entry.value,
        ..._renames(name, _compactFips202Symbols),
      },
    );
  }
}

Iterable<String> kpqcSymbols(String name) sync* {
  yield 'kpqc_${name}_keypair';
  if (_signatureNames.contains(name)) {
    yield 'kpqc_${name}_sign';
    yield 'kpqc_${name}_verify';
  } else {
    yield 'kpqc_${name}_encapsulate';
    yield 'kpqc_${name}_decapsulate';
  }
}

CLibrary _library({
  required String name,
  required List<String> sources,
  required List<String> includes,
  required List<String> libraries,
  required Map<String, String?> defines,
}) => CLibrary(
  name: 'kpqc_$name',
  assetName: name,
  sources: sources,
  includes: includes,
  libraries: libraries,
  frameworks: const [],
  std: 'c11',
  defines: {
    'KPQC_PREFIX': 'kpqc_${name}_',
    'randombytes': 'kpqc_${name}_randombytes',
    ...defines,
  },
);

Map<String, String> _renames(String name, Iterable<String> symbols) => {
  for (final symbol in symbols) symbol: 'kpqc_${name}_$symbol',
};
