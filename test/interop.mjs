// Exchange signatures and ciphertexts with the sibling npm package.
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const entry = process.argv[2];
const kpqc = await import(pathToFileURL(entry).href);
const requests = JSON.parse(readFileSync(0, "utf8"));
const bytes = (hex) => new Uint8Array(Buffer.from(hex, "hex"));
const hex = (value) => Buffer.from(value).toString("hex");
const results = [];
for (const request of requests) {
  const algorithm = kpqc[request.name];
  const keys = await algorithm.generateKeyPair();
  if (request.signature !== undefined) {
    const message = bytes(request.message);
    const options = { context: bytes(request.context) };
    if (!await algorithm.verify(message, bytes(request.signature), bytes(request.public_key), options)) {
      throw new Error(`${request.name}: Dart signature rejected by JS`);
    }
    results.push({
      name: request.name,
      public_key: hex(keys.publicKey),
      signature: hex(await algorithm.sign(message, keys.secretKey, options)),
    });
  } else {
    const recovered = await algorithm.decapsulate(bytes(request.ciphertext), bytes(request.secret_key));
    if (hex(recovered) !== request.shared_secret) {
      throw new Error(`${request.name}: Dart ciphertext rejected by JS`);
    }
    const outbound = await algorithm.encapsulate(bytes(request.public_key));
    results.push({name: request.name, ciphertext: hex(outbound.ciphertext), shared_secret: hex(outbound.sharedSecret)});
  }
}
process.stdout.write(JSON.stringify(results));
