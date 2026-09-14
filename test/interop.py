"""Bidirectional compatibility helper for the sibling PyPI package."""

import json
import sys

import kpqc


requests = json.load(sys.stdin)
results = []
for request in requests:
    algorithm = getattr(kpqc, request["name"])
    keys = algorithm.generate_key_pair()
    if "signature" in request:
        message = bytes.fromhex(request["message"])
        context = bytes.fromhex(request["context"])
        if not algorithm.verify(
                message,
                bytes.fromhex(request["signature"]),
                bytes.fromhex(request["public_key"]),
                context=context):
            raise RuntimeError(
                f'{request["name"]}: Dart signature rejected by PyPI')
        signature = algorithm.sign(
            message, keys.secret_key, context=context)
        results.append({
            "name": request["name"],
            "public_key": keys.public_key.hex(),
            "signature": signature.hex(),
        })
    else:
        recovered = algorithm.decapsulate(
            bytes.fromhex(request["ciphertext"]),
            bytes.fromhex(request["secret_key"]))
        if recovered.hex() != request["shared_secret"]:
            raise RuntimeError(
                f'{request["name"]}: Dart ciphertext rejected by PyPI')
        outbound = algorithm.encapsulate(bytes.fromhex(request["public_key"]))
        results.append({
            "name": request["name"],
            "ciphertext": outbound.ciphertext.hex(),
            "shared_secret": outbound.shared_secret.hex(),
        })

json.dump(results, sys.stdout)
