// Dependency-free synchronous FIPS 180-4 SHA-256 over the UTF-8 encoding of a string, exactly as TextEncoder
// encodes it (a lone surrogate becomes U+FFFD). Used only to compute or compare public digests of data that is
// already authenticated (ROOT-build Vault record digests, evidence ids); never for secrecy or key material.
// Synchronous on purpose: zod refinements and pure projections cannot await WebCrypto.

const firstPrimes = (count: number): number[] => {
  const primes: number[] = [];
  for (let candidate = 2; primes.length < count; candidate += 1) {
    if (primes.every((prime) => candidate % prime !== 0)) primes.push(candidate);
  }
  return primes;
};
const fractionBits = (value: number): number => ((value - Math.floor(value)) * 2 ** 32) >>> 0;
const SHA256_INITIAL = Uint32Array.from(firstPrimes(8), (prime) => fractionBits(Math.sqrt(prime)));
const SHA256_ROUND = Uint32Array.from(firstPrimes(64), (prime) => fractionBits(Math.cbrt(prime)));

/** UTF-8 exactly as TextEncoder encodes it (a lone surrogate becomes U+FFFD). */
function utf8Bytes(value: string): Uint8Array {
  const bytes: number[] = [];
  for (let index = 0; index < value.length; index += 1) {
    let code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff && index + 1 < value.length) {
      const next = value.charCodeAt(index + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        code = 0x10000 + ((code - 0xd800) << 10) + (next - 0xdc00);
        index += 1;
      }
    }
    if (code >= 0xd800 && code <= 0xdfff) code = 0xfffd;
    if (code < 0x80) bytes.push(code);
    else if (code < 0x800) bytes.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
    else if (code < 0x10000) bytes.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
    else bytes.push(0xf0 | (code >> 18), 0x80 | ((code >> 12) & 0x3f), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
  }
  return Uint8Array.from(bytes);
}

const rotateRight = (value: number, bits: number): number => (value >>> bits) | (value << (32 - bits));

/** Lowercase hex SHA-256 of the UTF-8 encoding of `value`. */
export function sha256HexUtf8(value: string): string {
  const message = utf8Bytes(value);
  const padded = new Uint8Array((Math.floor((message.length + 8) / 64) + 1) * 64);
  padded.set(message);
  padded[message.length] = 0x80;
  const view = new DataView(padded.buffer);
  const bitLength = message.length * 8;
  view.setUint32(padded.length - 8, Math.floor(bitLength / 2 ** 32));
  view.setUint32(padded.length - 4, bitLength >>> 0);
  const state = Uint32Array.from(SHA256_INITIAL);
  const schedule = new Uint32Array(64);
  for (let offset = 0; offset < padded.length; offset += 64) {
    for (let index = 0; index < 16; index += 1) schedule[index] = view.getUint32(offset + index * 4);
    for (let index = 16; index < 64; index += 1) {
      const back2 = schedule[index - 2]!;
      const back15 = schedule[index - 15]!;
      schedule[index] = (rotateRight(back2, 17) ^ rotateRight(back2, 19) ^ (back2 >>> 10)) + schedule[index - 7]! +
        (rotateRight(back15, 7) ^ rotateRight(back15, 18) ^ (back15 >>> 3)) + schedule[index - 16]!;
    }
    let [a, b, c, d, e, f, g, h] = state as unknown as [number, number, number, number, number, number, number, number];
    for (let index = 0; index < 64; index += 1) {
      const t1 = (h + (rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25)) + ((e & f) ^ (~e & g)) +
        SHA256_ROUND[index]! + schedule[index]!) >>> 0;
      const t2 = ((rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    state[0] = state[0]! + a; state[1] = state[1]! + b; state[2] = state[2]! + c; state[3] = state[3]! + d;
    state[4] = state[4]! + e; state[5] = state[5]! + f; state[6] = state[6]! + g; state[7] = state[7]! + h;
  }
  return Array.from(state, (word) => word.toString(16).padStart(8, "0")).join("");
}
