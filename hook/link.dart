import 'package:code_assets/code_assets.dart';
import 'package:hooks/hooks.dart';
import 'package:native_toolchain_c/native_toolchain_c.dart';
import 'package:record_use/record_use.dart';

import 'build.dart' show kpqcLibraries, kpqcSymbols, systemLibraries;

void main(List<String> args) async {
  await link(args, (input, output) async {
    final recordedUses = input.recordedUses;
    if (recordedUses == null) {
      throw StateError('KpqC link-time asset selection requires Dart 3.13.');
    }
    final libraries = kpqcLibraries(systemLibraries(input.config.code.targetOS))
        .toList();
    const library = Library('package:kpqc/src/types.dart');
    final usedAssets = {
      for (final nativeLibrary in libraries)
        if (recordedUses
                .calls[Getter(nativeLibrary.assetName!, library)]
                ?.isNotEmpty ??
            false)
          nativeLibrary.assetName!,
    };
    for (final nativeLibrary in libraries) {
      await nativeLibrary.link(
        input: input,
        output: output,
        linkerOptions: LinkerOptions.treeshake(
          symbolsToKeep: usedAssets.contains(nativeLibrary.assetName)
              ? kpqcSymbols(nativeLibrary.assetName!)
              : const [],
        ),
      );
    }
  });
}
