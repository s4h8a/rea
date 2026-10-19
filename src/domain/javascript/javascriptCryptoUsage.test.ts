import { expect, it } from "vitest";

import { analyzeJavaScriptStaticSource } from "./javascriptStaticAnalysis.js";

const cryptoUsageOf = (source: string) =>
  analyzeJavaScriptStaticSource(source).crypto;

it("flags AES-ECB encryption with a hardcoded key", () => {
  const usages = cryptoUsageOf(
    'const { createCipheriv } = require("node:crypto");\ncreateCipheriv("aes-128-ecb", "0123456789abcdef", null);',
  );
  expect(usages).toEqual([
    expect.objectContaining({
      library: "node-crypto",
      operation: "cipher",
      algorithm: "aes-128-ecb",
      mode: "ecb",
      key_source: "hardcoded-literal",
      iv_source: "absent",
      risks: ["ecb-mode", "hardcoded-key"],
      mechanism: "node-crypto:createCipheriv",
    }),
  ]);
});

it("flags static IVs on AES-CBC decryption", () => {
  const usages = cryptoUsageOf(
    'crypto.createDecipheriv("aes-256-cbc", process.env.KEY, "0000000000000000");',
  );
  expect(usages).toEqual([
    expect.objectContaining({
      library: "node-crypto",
      operation: "decipher",
      mode: "cbc",
      key_source: "code-expression",
      iv_source: "literal",
      risks: ["static-iv", "cbc-without-integrity"],
    }),
  ]);
});

it("keeps random IVs free of the static-IV risk", () => {
  const usages = cryptoUsageOf(
    'crypto.createCipheriv("aes-256-cbc", key, crypto.randomBytes(16));',
  );
  expect(usages).toEqual([
    expect.objectContaining({
      iv_source: "random",
      risks: ["cbc-without-integrity"],
    }),
  ]);
});

it("flags zero-filled GCM nonces", () => {
  const usages = cryptoUsageOf(
    'crypto.createCipheriv("aes-256-gcm", key, Buffer.alloc(12));',
  );
  expect(usages).toEqual([
    expect.objectContaining({
      mode: "gcm",
      iv_source: "static-buffer",
      risks: ["gcm-nonce-reuse"],
    }),
  ]);
});

it("leaves a fully random AES-GCM call site without risks", () => {
  const usages = cryptoUsageOf(
    'crypto.createCipheriv("aes-256-gcm", crypto.randomBytes(32), crypto.randomBytes(12));',
  );
  expect(usages).toEqual([
    expect.objectContaining({
      key_source: "random",
      iv_source: "random",
      risks: [],
    }),
  ]);
});

it("flags deprecated password-derived ciphers", () => {
  const usages = cryptoUsageOf(
    'crypto.createCipher("aes-256-cbc", "passphrase");',
  );
  expect(usages).toEqual([
    expect.objectContaining({
      mechanism: "node-crypto:createCipher",
      key_source: "hardcoded-literal",
      risks: [
        "cbc-without-integrity",
        "hardcoded-key",
        "deterministic-password-cipher",
      ],
    }),
  ]);
});

it("flags CryptoJS ECB modes", () => {
  const usages = cryptoUsageOf(
    "CryptoJS.AES.encrypt(message, key, { mode: CryptoJS.mode.ECB, iv: iv });",
  );
  expect(usages).toEqual([
    expect.objectContaining({
      library: "crypto-js",
      operation: "cipher",
      algorithm: "aes",
      mode: "ecb",
      iv_source: "code-expression",
      risks: ["ecb-mode"],
      mechanism: "crypto-js:AES.encrypt",
    }),
  ]);
});

it("records the CryptoJS default CBC mode", () => {
  const usages = cryptoUsageOf("CryptoJS.AES.decrypt(message, key);");
  expect(usages).toEqual([
    expect.objectContaining({
      operation: "decipher",
      mode: "cbc",
      iv_source: "absent",
      risks: ["cbc-without-integrity"],
    }),
  ]);
});

it("records node-forge AES-CBC cipher creation", () => {
  const usages = cryptoUsageOf('forge.cipher.createCipher("AES-CBC", key);');
  expect(usages).toEqual([
    expect.objectContaining({
      library: "node-forge",
      algorithm: "aes-cbc",
      mode: "cbc",
      iv_source: "unknown",
      risks: ["cbc-without-integrity"],
      mechanism: "node-forge:cipher.createCipher",
    }),
  ]);
});

it("records webcrypto AES-GCM usage with fixed buffers", () => {
  const usages = cryptoUsageOf(
    'crypto.subtle.encrypt({ name: "AES-GCM", iv: new Uint8Array(12) }, key, data);',
  );
  expect(usages).toEqual([
    expect.objectContaining({
      library: "webcrypto",
      algorithm: "aes-gcm",
      mode: "gcm",
      iv_source: "static-buffer",
      risks: ["gcm-nonce-reuse"],
      mechanism: "webcrypto:subtle.encrypt",
    }),
  ]);
});

it("keeps dynamic algorithm selections as unknowns", () => {
  const usages = cryptoUsageOf(
    "crypto.createCipheriv(selectedAlgorithm, key, iv);",
  );
  expect(usages).toEqual([
    expect.objectContaining({
      algorithm: null,
      mode: null,
      risks: [],
      mechanism: "node-crypto:createCipheriv",
    }),
  ]);
});

it("ignores encrypt calls without a recognized cipher entry point", () => {
  expect(cryptoUsageOf("api.encrypt(message, key);")).toEqual([]);
});

it("records the static-syntax limitation when cipher usage is found", () => {
  const analysis = analyzeJavaScriptStaticSource(
    'crypto.createCipheriv("aes-128-ecb", key, null);',
  );
  expect(
    analysis.limitations.some((limitation) =>
      limitation.includes("Cryptographic usage"),
    ),
  ).toBe(true);
});
