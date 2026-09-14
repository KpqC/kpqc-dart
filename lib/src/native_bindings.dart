part of 'types.dart';

@Native<Int32 Function(Pointer<Uint8>, Pointer<Uint8>)>(
  symbol: 'kpqc_aimer128f_keypair',
  assetId: 'package:kpqc/aimer128f',
)
external int _aimer128fKeyPair(
  Pointer<Uint8> publicKey,
  Pointer<Uint8> secretKey,
);

@Native<
  Int32 Function(
    Pointer<Uint8>,
    Pointer<Size>,
    Pointer<Uint8>,
    Size,
    Pointer<Uint8>,
    Size,
    Pointer<Uint8>,
  )
>(symbol: 'kpqc_aimer128f_sign', assetId: 'package:kpqc/aimer128f')
external int _aimer128fSign(
  Pointer<Uint8> signature,
  Pointer<Size> signatureLength,
  Pointer<Uint8> message,
  int messageLength,
  Pointer<Uint8> context,
  int contextLength,
  Pointer<Uint8> secretKey,
);

@Native<
  Int32 Function(
    Pointer<Uint8>,
    Size,
    Pointer<Uint8>,
    Size,
    Pointer<Uint8>,
    Size,
    Pointer<Uint8>,
  )
>(symbol: 'kpqc_aimer128f_verify', assetId: 'package:kpqc/aimer128f')
external int _aimer128fVerify(
  Pointer<Uint8> signature,
  int signatureLength,
  Pointer<Uint8> message,
  int messageLength,
  Pointer<Uint8> context,
  int contextLength,
  Pointer<Uint8> publicKey,
);

@Native<Int32 Function(Pointer<Uint8>, Pointer<Uint8>)>(
  symbol: 'kpqc_aimer128s_keypair',
  assetId: 'package:kpqc/aimer128s',
)
external int _aimer128sKeyPair(
  Pointer<Uint8> publicKey,
  Pointer<Uint8> secretKey,
);

@Native<
  Int32 Function(
    Pointer<Uint8>,
    Pointer<Size>,
    Pointer<Uint8>,
    Size,
    Pointer<Uint8>,
    Size,
    Pointer<Uint8>,
  )
>(symbol: 'kpqc_aimer128s_sign', assetId: 'package:kpqc/aimer128s')
external int _aimer128sSign(
  Pointer<Uint8> signature,
  Pointer<Size> signatureLength,
  Pointer<Uint8> message,
  int messageLength,
  Pointer<Uint8> context,
  int contextLength,
  Pointer<Uint8> secretKey,
);

@Native<
  Int32 Function(
    Pointer<Uint8>,
    Size,
    Pointer<Uint8>,
    Size,
    Pointer<Uint8>,
    Size,
    Pointer<Uint8>,
  )
>(symbol: 'kpqc_aimer128s_verify', assetId: 'package:kpqc/aimer128s')
external int _aimer128sVerify(
  Pointer<Uint8> signature,
  int signatureLength,
  Pointer<Uint8> message,
  int messageLength,
  Pointer<Uint8> context,
  int contextLength,
  Pointer<Uint8> publicKey,
);

@Native<Int32 Function(Pointer<Uint8>, Pointer<Uint8>)>(
  symbol: 'kpqc_aimer192f_keypair',
  assetId: 'package:kpqc/aimer192f',
)
external int _aimer192fKeyPair(
  Pointer<Uint8> publicKey,
  Pointer<Uint8> secretKey,
);

@Native<
  Int32 Function(
    Pointer<Uint8>,
    Pointer<Size>,
    Pointer<Uint8>,
    Size,
    Pointer<Uint8>,
    Size,
    Pointer<Uint8>,
  )
>(symbol: 'kpqc_aimer192f_sign', assetId: 'package:kpqc/aimer192f')
external int _aimer192fSign(
  Pointer<Uint8> signature,
  Pointer<Size> signatureLength,
  Pointer<Uint8> message,
  int messageLength,
  Pointer<Uint8> context,
  int contextLength,
  Pointer<Uint8> secretKey,
);

@Native<
  Int32 Function(
    Pointer<Uint8>,
    Size,
    Pointer<Uint8>,
    Size,
    Pointer<Uint8>,
    Size,
    Pointer<Uint8>,
  )
>(symbol: 'kpqc_aimer192f_verify', assetId: 'package:kpqc/aimer192f')
external int _aimer192fVerify(
  Pointer<Uint8> signature,
  int signatureLength,
  Pointer<Uint8> message,
  int messageLength,
  Pointer<Uint8> context,
  int contextLength,
  Pointer<Uint8> publicKey,
);

@Native<Int32 Function(Pointer<Uint8>, Pointer<Uint8>)>(
  symbol: 'kpqc_aimer192s_keypair',
  assetId: 'package:kpqc/aimer192s',
)
external int _aimer192sKeyPair(
  Pointer<Uint8> publicKey,
  Pointer<Uint8> secretKey,
);

@Native<
  Int32 Function(
    Pointer<Uint8>,
    Pointer<Size>,
    Pointer<Uint8>,
    Size,
    Pointer<Uint8>,
    Size,
    Pointer<Uint8>,
  )
>(symbol: 'kpqc_aimer192s_sign', assetId: 'package:kpqc/aimer192s')
external int _aimer192sSign(
  Pointer<Uint8> signature,
  Pointer<Size> signatureLength,
  Pointer<Uint8> message,
  int messageLength,
  Pointer<Uint8> context,
  int contextLength,
  Pointer<Uint8> secretKey,
);

@Native<
  Int32 Function(
    Pointer<Uint8>,
    Size,
    Pointer<Uint8>,
    Size,
    Pointer<Uint8>,
    Size,
    Pointer<Uint8>,
  )
>(symbol: 'kpqc_aimer192s_verify', assetId: 'package:kpqc/aimer192s')
external int _aimer192sVerify(
  Pointer<Uint8> signature,
  int signatureLength,
  Pointer<Uint8> message,
  int messageLength,
  Pointer<Uint8> context,
  int contextLength,
  Pointer<Uint8> publicKey,
);

@Native<Int32 Function(Pointer<Uint8>, Pointer<Uint8>)>(
  symbol: 'kpqc_aimer256f_keypair',
  assetId: 'package:kpqc/aimer256f',
)
external int _aimer256fKeyPair(
  Pointer<Uint8> publicKey,
  Pointer<Uint8> secretKey,
);

@Native<
  Int32 Function(
    Pointer<Uint8>,
    Pointer<Size>,
    Pointer<Uint8>,
    Size,
    Pointer<Uint8>,
    Size,
    Pointer<Uint8>,
  )
>(symbol: 'kpqc_aimer256f_sign', assetId: 'package:kpqc/aimer256f')
external int _aimer256fSign(
  Pointer<Uint8> signature,
  Pointer<Size> signatureLength,
  Pointer<Uint8> message,
  int messageLength,
  Pointer<Uint8> context,
  int contextLength,
  Pointer<Uint8> secretKey,
);

@Native<
  Int32 Function(
    Pointer<Uint8>,
    Size,
    Pointer<Uint8>,
    Size,
    Pointer<Uint8>,
    Size,
    Pointer<Uint8>,
  )
>(symbol: 'kpqc_aimer256f_verify', assetId: 'package:kpqc/aimer256f')
external int _aimer256fVerify(
  Pointer<Uint8> signature,
  int signatureLength,
  Pointer<Uint8> message,
  int messageLength,
  Pointer<Uint8> context,
  int contextLength,
  Pointer<Uint8> publicKey,
);

@Native<Int32 Function(Pointer<Uint8>, Pointer<Uint8>)>(
  symbol: 'kpqc_aimer256s_keypair',
  assetId: 'package:kpqc/aimer256s',
)
external int _aimer256sKeyPair(
  Pointer<Uint8> publicKey,
  Pointer<Uint8> secretKey,
);

@Native<
  Int32 Function(
    Pointer<Uint8>,
    Pointer<Size>,
    Pointer<Uint8>,
    Size,
    Pointer<Uint8>,
    Size,
    Pointer<Uint8>,
  )
>(symbol: 'kpqc_aimer256s_sign', assetId: 'package:kpqc/aimer256s')
external int _aimer256sSign(
  Pointer<Uint8> signature,
  Pointer<Size> signatureLength,
  Pointer<Uint8> message,
  int messageLength,
  Pointer<Uint8> context,
  int contextLength,
  Pointer<Uint8> secretKey,
);

@Native<
  Int32 Function(
    Pointer<Uint8>,
    Size,
    Pointer<Uint8>,
    Size,
    Pointer<Uint8>,
    Size,
    Pointer<Uint8>,
  )
>(symbol: 'kpqc_aimer256s_verify', assetId: 'package:kpqc/aimer256s')
external int _aimer256sVerify(
  Pointer<Uint8> signature,
  int signatureLength,
  Pointer<Uint8> message,
  int messageLength,
  Pointer<Uint8> context,
  int contextLength,
  Pointer<Uint8> publicKey,
);

@Native<Int32 Function(Pointer<Uint8>, Pointer<Uint8>)>(
  symbol: 'kpqc_haetae2_keypair',
  assetId: 'package:kpqc/haetae2',
)
external int _haetae2KeyPair(
  Pointer<Uint8> publicKey,
  Pointer<Uint8> secretKey,
);

@Native<
  Int32 Function(
    Pointer<Uint8>,
    Pointer<Size>,
    Pointer<Uint8>,
    Size,
    Pointer<Uint8>,
    Size,
    Pointer<Uint8>,
  )
>(symbol: 'kpqc_haetae2_sign', assetId: 'package:kpqc/haetae2')
external int _haetae2Sign(
  Pointer<Uint8> signature,
  Pointer<Size> signatureLength,
  Pointer<Uint8> message,
  int messageLength,
  Pointer<Uint8> context,
  int contextLength,
  Pointer<Uint8> secretKey,
);

@Native<
  Int32 Function(
    Pointer<Uint8>,
    Size,
    Pointer<Uint8>,
    Size,
    Pointer<Uint8>,
    Size,
    Pointer<Uint8>,
  )
>(symbol: 'kpqc_haetae2_verify', assetId: 'package:kpqc/haetae2')
external int _haetae2Verify(
  Pointer<Uint8> signature,
  int signatureLength,
  Pointer<Uint8> message,
  int messageLength,
  Pointer<Uint8> context,
  int contextLength,
  Pointer<Uint8> publicKey,
);

@Native<Int32 Function(Pointer<Uint8>, Pointer<Uint8>)>(
  symbol: 'kpqc_haetae3_keypair',
  assetId: 'package:kpqc/haetae3',
)
external int _haetae3KeyPair(
  Pointer<Uint8> publicKey,
  Pointer<Uint8> secretKey,
);

@Native<
  Int32 Function(
    Pointer<Uint8>,
    Pointer<Size>,
    Pointer<Uint8>,
    Size,
    Pointer<Uint8>,
    Size,
    Pointer<Uint8>,
  )
>(symbol: 'kpqc_haetae3_sign', assetId: 'package:kpqc/haetae3')
external int _haetae3Sign(
  Pointer<Uint8> signature,
  Pointer<Size> signatureLength,
  Pointer<Uint8> message,
  int messageLength,
  Pointer<Uint8> context,
  int contextLength,
  Pointer<Uint8> secretKey,
);

@Native<
  Int32 Function(
    Pointer<Uint8>,
    Size,
    Pointer<Uint8>,
    Size,
    Pointer<Uint8>,
    Size,
    Pointer<Uint8>,
  )
>(symbol: 'kpqc_haetae3_verify', assetId: 'package:kpqc/haetae3')
external int _haetae3Verify(
  Pointer<Uint8> signature,
  int signatureLength,
  Pointer<Uint8> message,
  int messageLength,
  Pointer<Uint8> context,
  int contextLength,
  Pointer<Uint8> publicKey,
);

@Native<Int32 Function(Pointer<Uint8>, Pointer<Uint8>)>(
  symbol: 'kpqc_haetae5_keypair',
  assetId: 'package:kpqc/haetae5',
)
external int _haetae5KeyPair(
  Pointer<Uint8> publicKey,
  Pointer<Uint8> secretKey,
);

@Native<
  Int32 Function(
    Pointer<Uint8>,
    Pointer<Size>,
    Pointer<Uint8>,
    Size,
    Pointer<Uint8>,
    Size,
    Pointer<Uint8>,
  )
>(symbol: 'kpqc_haetae5_sign', assetId: 'package:kpqc/haetae5')
external int _haetae5Sign(
  Pointer<Uint8> signature,
  Pointer<Size> signatureLength,
  Pointer<Uint8> message,
  int messageLength,
  Pointer<Uint8> context,
  int contextLength,
  Pointer<Uint8> secretKey,
);

@Native<
  Int32 Function(
    Pointer<Uint8>,
    Size,
    Pointer<Uint8>,
    Size,
    Pointer<Uint8>,
    Size,
    Pointer<Uint8>,
  )
>(symbol: 'kpqc_haetae5_verify', assetId: 'package:kpqc/haetae5')
external int _haetae5Verify(
  Pointer<Uint8> signature,
  int signatureLength,
  Pointer<Uint8> message,
  int messageLength,
  Pointer<Uint8> context,
  int contextLength,
  Pointer<Uint8> publicKey,
);

@Native<Int32 Function(Pointer<Uint8>, Pointer<Uint8>)>(
  symbol: 'kpqc_ntruplus768_keypair',
  assetId: 'package:kpqc/ntruplus768',
)
external int _ntruplus768KeyPair(
  Pointer<Uint8> publicKey,
  Pointer<Uint8> secretKey,
);

@Native<Int32 Function(Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>)>(
  symbol: 'kpqc_ntruplus768_encapsulate',
  assetId: 'package:kpqc/ntruplus768',
)
external int _ntruplus768Encapsulate(
  Pointer<Uint8> ciphertext,
  Pointer<Uint8> sharedSecret,
  Pointer<Uint8> publicKey,
);

@Native<Int32 Function(Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>)>(
  symbol: 'kpqc_ntruplus768_decapsulate',
  assetId: 'package:kpqc/ntruplus768',
)
external int _ntruplus768Decapsulate(
  Pointer<Uint8> sharedSecret,
  Pointer<Uint8> ciphertext,
  Pointer<Uint8> secretKey,
);

@Native<Int32 Function(Pointer<Uint8>, Pointer<Uint8>)>(
  symbol: 'kpqc_ntruplus864_keypair',
  assetId: 'package:kpqc/ntruplus864',
)
external int _ntruplus864KeyPair(
  Pointer<Uint8> publicKey,
  Pointer<Uint8> secretKey,
);

@Native<Int32 Function(Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>)>(
  symbol: 'kpqc_ntruplus864_encapsulate',
  assetId: 'package:kpqc/ntruplus864',
)
external int _ntruplus864Encapsulate(
  Pointer<Uint8> ciphertext,
  Pointer<Uint8> sharedSecret,
  Pointer<Uint8> publicKey,
);

@Native<Int32 Function(Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>)>(
  symbol: 'kpqc_ntruplus864_decapsulate',
  assetId: 'package:kpqc/ntruplus864',
)
external int _ntruplus864Decapsulate(
  Pointer<Uint8> sharedSecret,
  Pointer<Uint8> ciphertext,
  Pointer<Uint8> secretKey,
);

@Native<Int32 Function(Pointer<Uint8>, Pointer<Uint8>)>(
  symbol: 'kpqc_ntruplus1152_keypair',
  assetId: 'package:kpqc/ntruplus1152',
)
external int _ntruplus1152KeyPair(
  Pointer<Uint8> publicKey,
  Pointer<Uint8> secretKey,
);

@Native<Int32 Function(Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>)>(
  symbol: 'kpqc_ntruplus1152_encapsulate',
  assetId: 'package:kpqc/ntruplus1152',
)
external int _ntruplus1152Encapsulate(
  Pointer<Uint8> ciphertext,
  Pointer<Uint8> sharedSecret,
  Pointer<Uint8> publicKey,
);

@Native<Int32 Function(Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>)>(
  symbol: 'kpqc_ntruplus1152_decapsulate',
  assetId: 'package:kpqc/ntruplus1152',
)
external int _ntruplus1152Decapsulate(
  Pointer<Uint8> sharedSecret,
  Pointer<Uint8> ciphertext,
  Pointer<Uint8> secretKey,
);

@Native<Int32 Function(Pointer<Uint8>, Pointer<Uint8>)>(
  symbol: 'kpqc_smaugt128_keypair',
  assetId: 'package:kpqc/smaugt128',
)
external int _smaugt128KeyPair(
  Pointer<Uint8> publicKey,
  Pointer<Uint8> secretKey,
);

@Native<Int32 Function(Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>)>(
  symbol: 'kpqc_smaugt128_encapsulate',
  assetId: 'package:kpqc/smaugt128',
)
external int _smaugt128Encapsulate(
  Pointer<Uint8> ciphertext,
  Pointer<Uint8> sharedSecret,
  Pointer<Uint8> publicKey,
);

@Native<Int32 Function(Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>)>(
  symbol: 'kpqc_smaugt128_decapsulate',
  assetId: 'package:kpqc/smaugt128',
)
external int _smaugt128Decapsulate(
  Pointer<Uint8> sharedSecret,
  Pointer<Uint8> ciphertext,
  Pointer<Uint8> secretKey,
);

@Native<Int32 Function(Pointer<Uint8>, Pointer<Uint8>)>(
  symbol: 'kpqc_smaugt192_keypair',
  assetId: 'package:kpqc/smaugt192',
)
external int _smaugt192KeyPair(
  Pointer<Uint8> publicKey,
  Pointer<Uint8> secretKey,
);

@Native<Int32 Function(Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>)>(
  symbol: 'kpqc_smaugt192_encapsulate',
  assetId: 'package:kpqc/smaugt192',
)
external int _smaugt192Encapsulate(
  Pointer<Uint8> ciphertext,
  Pointer<Uint8> sharedSecret,
  Pointer<Uint8> publicKey,
);

@Native<Int32 Function(Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>)>(
  symbol: 'kpqc_smaugt192_decapsulate',
  assetId: 'package:kpqc/smaugt192',
)
external int _smaugt192Decapsulate(
  Pointer<Uint8> sharedSecret,
  Pointer<Uint8> ciphertext,
  Pointer<Uint8> secretKey,
);

@Native<Int32 Function(Pointer<Uint8>, Pointer<Uint8>)>(
  symbol: 'kpqc_smaugt256_keypair',
  assetId: 'package:kpqc/smaugt256',
)
external int _smaugt256KeyPair(
  Pointer<Uint8> publicKey,
  Pointer<Uint8> secretKey,
);

@Native<Int32 Function(Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>)>(
  symbol: 'kpqc_smaugt256_encapsulate',
  assetId: 'package:kpqc/smaugt256',
)
external int _smaugt256Encapsulate(
  Pointer<Uint8> ciphertext,
  Pointer<Uint8> sharedSecret,
  Pointer<Uint8> publicKey,
);

@Native<Int32 Function(Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>)>(
  symbol: 'kpqc_smaugt256_decapsulate',
  assetId: 'package:kpqc/smaugt256',
)
external int _smaugt256Decapsulate(
  Pointer<Uint8> sharedSecret,
  Pointer<Uint8> ciphertext,
  Pointer<Uint8> secretKey,
);

@Native<Int32 Function(Pointer<Uint8>, Pointer<Uint8>)>(
  symbol: 'kpqc_timer_keypair',
  assetId: 'package:kpqc/timer',
)
external int _timerKeyPair(Pointer<Uint8> publicKey, Pointer<Uint8> secretKey);

@Native<Int32 Function(Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>)>(
  symbol: 'kpqc_timer_encapsulate',
  assetId: 'package:kpqc/timer',
)
external int _timerEncapsulate(
  Pointer<Uint8> ciphertext,
  Pointer<Uint8> sharedSecret,
  Pointer<Uint8> publicKey,
);

@Native<Int32 Function(Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>)>(
  symbol: 'kpqc_timer_decapsulate',
  assetId: 'package:kpqc/timer',
)
external int _timerDecapsulate(
  Pointer<Uint8> sharedSecret,
  Pointer<Uint8> ciphertext,
  Pointer<Uint8> secretKey,
);
