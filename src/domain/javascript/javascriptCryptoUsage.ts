import * as t from "@babel/types";

import { addLocatedFinding } from "./javascriptStaticAnalysisFindings.js";
import {
  argumentNode,
  calleeName,
  range,
  stringValue,
} from "./javascriptStaticAnalysisHelpers.js";
import {
  semanticFinalObjectProperty,
  semanticFinalObjectStringProperty,
  staticObjectProperty,
  unwrapJavaScriptExpression,
} from "./javascriptAstValues.js";
import {
  semanticStableInitializer,
  type JavaScriptBindingIndex,
} from "./javascriptSemanticState.js";
import type { JavaScriptFindingContext } from "./javascriptStaticAnalysisState.js";
import type {
  JavaScriptCryptoLibrary,
  JavaScriptCryptoMode,
  JavaScriptCryptoRisk,
  JavaScriptCryptoUsage,
} from "./javascriptStaticAnalysisTypes.js";

/** Call and constructor shapes carrying recognized cipher entry points. */
type CryptoCallable =
  | t.CallExpression
  | t.OptionalCallExpression
  | t.NewExpression;

/** Source form of one key, IV, or nonce argument before risk mapping. */
type SecretSource =
  | "literal"
  | "static-buffer"
  | "random"
  | "code-expression"
  | "absent"
  | "unknown";

/** Cipher modes recognized from algorithm names and library options. */
const CRYPTO_MODES: ReadonlySet<string> = new Set([
  "ecb",
  "cbc",
  "ctr",
  "gcm",
  "cfb",
  "ofb",
  "ccm",
  "ocb",
]);

/** Byte constructors whose numeric size argument yields fixed zero bytes. */
const ZERO_FILLED_CONSTRUCTORS: ReadonlySet<string> = new Set([
  "Uint8Array",
  "Uint16Array",
  "Uint32Array",
  "Int8Array",
  "ArrayBuffer",
]);

/** Cipher call facts assembled before key and IV classification. */
interface CryptoCallFacts {
  readonly library: JavaScriptCryptoLibrary;
  readonly operation: "cipher" | "decipher";
  readonly algorithm: string | null;
  readonly mode: JavaScriptCryptoMode | null;
  readonly key: t.Node | undefined;
  readonly ivSource: SecretSource;
  readonly passwordDerived: boolean;
  readonly mechanism: string;
}

/** Last dotted segment of one recovered callee name. */
const lastSegment = (name: string): string => name.split(".").at(-1) ?? "";

/** Read one call or constructor argument as an inert node. */
const argumentAt = (
  node: CryptoCallable,
  index: number,
): t.Node | undefined => {
  const argument = node.arguments[index];
  return argument === undefined ? undefined : argumentNode(argument);
};

/** Unwrap type-erased expression wrappers before classification. */
const unwrapped = (node: t.Node): t.Node =>
  unwrapJavaScriptExpression(node).node;

/** Read a leading object literal argument when the syntax commits one. */
const objectArgument = (
  node: t.Node | undefined,
): t.ObjectExpression | undefined => {
  if (node === undefined) return undefined;
  const expression = unwrapped(node);
  return t.isObjectExpression(expression) ? expression : undefined;
};

/** Normalize one algorithm name into its committed mode when recognized. */
const parseAlgorithmName = (
  raw: string | undefined,
): {
  readonly algorithm: string | null;
  readonly mode: JavaScriptCryptoMode | null;
} => {
  if (raw === undefined) return { algorithm: null, mode: null };
  const normalized = raw.toLowerCase();
  const match = /^aes(?:-(\d+))?(?:-([a-z0-9]+))?$/u.exec(normalized);
  const suffix = match?.[2];
  return {
    algorithm: normalized,
    mode:
      suffix !== undefined && CRYPTO_MODES.has(suffix)
        ? (suffix as JavaScriptCryptoMode)
        : null,
  };
};

/** Read a committed cipher mode from one option value as source data. */
const modeFromNode = (node: t.Node): JavaScriptCryptoMode | null => {
  const expression = unwrapped(node);
  const token = stringValue(expression) ?? lastSegment(calleeName(expression));
  const normalized = token.toLowerCase();
  return CRYPTO_MODES.has(normalized)
    ? (normalized as JavaScriptCryptoMode)
    : null;
};

/** Whether one argument expression commits exact literal bytes. */
const isLiteralBytes = (node: t.Node | undefined): boolean => {
  if (node === undefined) return false;
  const expression = unwrapped(node);
  return (
    stringValue(expression) !== undefined || t.isArrayExpression(expression)
  );
};

/** Classify one call or constructor that produces key or IV candidate bytes. */
const classifyConstructorSecret = (node: CryptoCallable): SecretSource => {
  const name = calleeName(node.callee);
  const method = lastSegment(name);
  if (t.isNewExpression(node) && ZERO_FILLED_CONSTRUCTORS.has(method)) {
    const first = argumentAt(node, 0);
    const expression = first === undefined ? undefined : unwrapped(first);
    if (expression === undefined || t.isNumericLiteral(expression))
      return "static-buffer";
    return t.isArrayExpression(expression) ? "literal" : "code-expression";
  }
  switch (method) {
    case "randomBytes":
    case "randomFillSync":
    case "randomUUID":
    case "getRandomValues":
    case "random":
      return "random";
    case "alloc":
      return "static-buffer";
    case "allocUnsafe":
      return "unknown";
    case "from":
      return isLiteralBytes(argumentAt(node, 0))
        ? "literal"
        : "code-expression";
    case "parse":
      return name.split(".").includes("enc") &&
        stringValue(argumentAt(node, 0)) !== undefined
        ? "literal"
        : "code-expression";
    default:
      return "code-expression";
  }
};

/** Resolve one identifier reference to a classified constant initializer. */
type SecretResolver = (identifier: t.Identifier) => SecretSource | undefined;

/** Classify one key, IV, or nonce argument expression. */
const classifySecretSource = (
  node: t.Node | undefined,
  resolve?: SecretResolver,
): SecretSource => {
  if (node === undefined) return "unknown";
  const expression = unwrapped(node);
  if (t.isNullLiteral(expression)) return "absent";
  if (stringValue(expression) !== undefined) return "literal";
  if (t.isArrayExpression(expression)) return "literal";
  if (
    t.isCallExpression(expression) ||
    t.isOptionalCallExpression(expression) ||
    t.isNewExpression(expression)
  )
    return classifyConstructorSecret(expression);
  if (t.isIdentifier(expression)) {
    const resolved = resolve?.(expression);
    if (resolved !== undefined) return resolved;
  }
  return "code-expression";
};

/**
 * Resolve one identifier chain to the classified const initializer source.
 * Only immutable single const declarations with one unconditional,
 * non-projected initializer resolve. Read ordering is deliberately not
 * required: an immutable binding cannot produce another value when the read
 * executes, and a read before initialization throws instead of substituting
 * a different source. Chains that do not resolve stay unclassified.
 */
const stableConstSource = (
  reference: t.Identifier,
  index: JavaScriptBindingIndex,
): SecretSource | undefined => {
  const seen = new Set<t.Node>();
  let current: t.Node = reference;
  while (t.isIdentifier(current)) {
    if (seen.has(current)) return undefined;
    seen.add(current);
    const binding = index.bindingForReferenceAt(current);
    if (binding === undefined) return undefined;
    const initializer = semanticStableInitializer(binding, index.bindings);
    if (
      binding.mutable ||
      binding.declarationKinds.size !== 1 ||
      !binding.declarationKinds.has("const") ||
      initializer === undefined ||
      initializer.projection.length !== 0
    )
      return undefined;
    current = unwrapped(initializer.node);
  }
  return classifySecretSource(current);
};

/** Classify the IV or nonce argument of one call site. */
const ivSourceOf = (
  node: t.Node | undefined,
  resolve?: SecretResolver,
): SecretSource =>
  node === undefined ? "absent" : classifySecretSource(node, resolve);

/** Map an internal secret source into the key-source vocabulary. */
const keySourceOf = (
  source: SecretSource,
): JavaScriptCryptoUsage["key_source"] =>
  source === "literal"
    ? "hardcoded-literal"
    : source === "absent"
      ? "unknown"
      : source;

/** Derive the candidate risk factors committed by one call site. */
const cryptoRisksFor = (
  facts: CryptoCallFacts,
  keySecret: SecretSource,
): readonly JavaScriptCryptoRisk[] => {
  const risks: JavaScriptCryptoRisk[] = [];
  const isStatic = (source: SecretSource): boolean =>
    source === "literal" || source === "static-buffer";
  if (facts.mode === "ecb") risks.push("ecb-mode");
  if (
    isStatic(facts.ivSource) &&
    (facts.mode === "cbc" || facts.mode === "ctr")
  )
    risks.push("static-iv");
  if (isStatic(facts.ivSource) && facts.mode === "gcm")
    risks.push("gcm-nonce-reuse");
  if (facts.mode === "cbc") risks.push("cbc-without-integrity");
  if (isStatic(keySecret)) risks.push("hardcoded-key");
  if (facts.passwordDerived) risks.push("deterministic-password-cipher");
  return risks;
};

/** Facts for node:crypto createCipheriv and createDecipheriv call sites. */
const cipherivFacts = (
  node: CryptoCallable,
  name: string,
  operation: "cipher" | "decipher",
  resolve?: SecretResolver,
): CryptoCallFacts => {
  const parsed = parseAlgorithmName(stringValue(argumentAt(node, 0)));
  return {
    library: "node-crypto",
    operation,
    algorithm: parsed.algorithm,
    mode: parsed.mode,
    key: argumentAt(node, 1),
    ivSource: ivSourceOf(argumentAt(node, 2), resolve),
    passwordDerived: false,
    mechanism: `node-crypto:${lastSegment(name)}`,
  };
};

/** Facts for the deprecated password-derived createCipher/createDecipher. */
const passwordCipherFacts = (
  node: CryptoCallable,
  name: string,
  operation: "cipher" | "decipher",
): CryptoCallFacts => {
  const parsed = parseAlgorithmName(stringValue(argumentAt(node, 0)));
  return {
    library: "node-crypto",
    operation,
    algorithm: parsed.algorithm,
    mode: parsed.mode,
    key: argumentAt(node, 1),
    ivSource: "absent",
    passwordDerived: true,
    mechanism: `node-crypto:${lastSegment(name)}`,
  };
};

/** Facts for node-forge cipher.createCipher and createDecipher entries. */
const forgeFacts = (
  node: CryptoCallable,
  operation: "cipher" | "decipher",
): CryptoCallFacts | null => {
  const parsed = parseAlgorithmName(stringValue(argumentAt(node, 0)));
  if (parsed.mode === null) return null;
  return {
    library: "node-forge",
    operation,
    algorithm: parsed.algorithm,
    mode: parsed.mode,
    key: argumentAt(node, 1),
    ivSource: "unknown",
    passwordDerived: false,
    mechanism: `node-forge:cipher.${operation === "cipher" ? "createCipher" : "createDecipher"}`,
  };
};

/** Resolve the mode option of one CryptoJS AES configuration object. */
const cryptoJsMode = (
  config: t.ObjectExpression | undefined,
  configured: boolean,
): JavaScriptCryptoMode | null => {
  if (config === undefined) return configured ? null : "cbc";
  const property = staticObjectProperty(config, "mode");
  if (property.status === "missing") return "cbc";
  return property.status === "explicit"
    ? modeFromNode(property.property.value)
    : null;
};

/** Facts for CryptoJS AES.encrypt and AES.decrypt call sites. */
const cryptoJsFacts = (
  node: CryptoCallable,
  operation: "cipher" | "decipher",
  resolve?: SecretResolver,
): CryptoCallFacts => {
  const configArgument = argumentAt(node, 2);
  const config = objectArgument(configArgument);
  return {
    library: "crypto-js",
    operation,
    algorithm: "aes",
    mode: cryptoJsMode(config, configArgument !== undefined),
    key: argumentAt(node, 1),
    ivSource:
      config === undefined
        ? configArgument === undefined
          ? "absent"
          : "unknown"
        : ivSourceOf(semanticFinalObjectProperty(config, "iv"), resolve),
    passwordDerived: false,
    mechanism: `crypto-js:AES.${operation === "cipher" ? "encrypt" : "decrypt"}`,
  };
};

/** Facts for WebCrypto subtle.encrypt and subtle.decrypt call sites. */
const webCryptoFacts = (
  node: CryptoCallable,
  operation: "cipher" | "decipher",
  resolve?: SecretResolver,
): CryptoCallFacts | null => {
  const algorithm = objectArgument(argumentAt(node, 0));
  if (algorithm === undefined) return null;
  const name = semanticFinalObjectStringProperty(algorithm, "name");
  if (name === undefined || !/^aes-/iu.test(name)) return null;
  const parsed = parseAlgorithmName(name);
  return {
    library: "webcrypto",
    operation,
    algorithm: parsed.algorithm,
    mode: parsed.mode,
    key: argumentAt(node, 1),
    ivSource: ivSourceOf(semanticFinalObjectProperty(algorithm, "iv"), resolve),
    passwordDerived: false,
    mechanism: `webcrypto:subtle.${operation === "cipher" ? "encrypt" : "decrypt"}`,
  };
};

/** Identify one recognized cipher call and assemble its facts. */
const cryptoCallFacts = (
  node: CryptoCallable,
  name: string,
  resolve?: SecretResolver,
): CryptoCallFacts | null => {
  if (t.isNewExpression(node)) return null;
  const segments = name.split(".");
  const method = lastSegment(name);
  const parent = segments.at(-2) ?? "";
  switch (method) {
    case "createCipheriv":
      return cipherivFacts(node, name, "cipher", resolve);
    case "createDecipheriv":
      return cipherivFacts(node, name, "decipher", resolve);
    case "createCipher":
    case "createDecipher": {
      const operation = method === "createCipher" ? "cipher" : "decipher";
      return parent === "cipher"
        ? forgeFacts(node, operation)
        : passwordCipherFacts(node, name, operation);
    }
    case "encrypt":
    case "decrypt": {
      const operation = method === "encrypt" ? "cipher" : "decipher";
      if (parent === "AES") return cryptoJsFacts(node, operation, resolve);
      return parent === "subtle"
        ? webCryptoFacts(node, operation, resolve)
        : null;
    }
    default:
      return null;
  }
};

/** Inspect one AST node and record recognized cipher usage at most once. */
export const inspectCryptoUsageNode = (
  node: t.Node,
  context: JavaScriptFindingContext,
): void => {
  if (!t.isCallExpression(node) && !t.isOptionalCallExpression(node)) return;
  const index = context.bindingIndex;
  const resolve: SecretResolver | undefined =
    index === undefined
      ? undefined
      : (identifier: t.Identifier) => stableConstSource(identifier, index);
  const facts = cryptoCallFacts(node, calleeName(node.callee), resolve);
  if (facts === null) return;
  const keySecret = classifySecretSource(facts.key, resolve);
  addLocatedFinding(context, {
    collection: context.accumulator.crypto,
    key: `crypto:${facts.mechanism}`,
    node,
    value: {
      library: facts.library,
      operation: facts.operation,
      algorithm: facts.algorithm,
      mode: facts.mode,
      key_source: keySourceOf(keySecret),
      iv_source: facts.ivSource,
      risks: cryptoRisksFor(facts, keySecret),
      mechanism: facts.mechanism,
      module_key: null,
      location: range(node),
    },
  });
};
