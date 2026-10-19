import { describe, expect, it } from "vitest";

import type { ArtifactInventorySnapshot } from "../../domain/artifactInventorySnapshot.js";
import type { JavaScriptArtifactFile } from "../../domain/javascript/javascriptArtifactFiles.js";
import { analyzeJavaScriptStaticSource } from "../../domain/javascript/javascriptStaticAnalysis.js";
import type {
  AnalyzedJavaScriptArtifactFile,
  JavaScriptModuleArtifactAnalysis,
} from "./JavaScriptArtifactAnalysisTypes.js";
import { JavaScriptArtifactGraphAccumulator } from "./JavaScriptArtifactGraphAccumulator.js";
import type { JavaScriptArtifactGraphContext } from "./JavaScriptArtifactGraphContext.js";
import { addJavaScriptStaticFindingsSteps } from "./JavaScriptArtifactGraphFindings.js";
import {
  addJavaScriptArtifactFiles,
  createJavaScriptArtifactRootNode,
} from "./JavaScriptArtifactGraphStructure.js";

const SHA256 = "a".repeat(64);
const RISK_LIMITATION =
  "Risk labels are candidate factors derived from static argument syntax; key material, randomness provenance and exploitability remain unproven.";
const MISUSE_SOURCE = [
  'const crypto = require("node:crypto");',
  'crypto.createCipheriv("aes-128-ecb", Buffer.from("0123456789abcdef"), null);',
  "",
].join("\n");
const SAFE_SOURCE = [
  'const crypto = require("node:crypto");',
  'crypto.createCipheriv("aes-256-gcm", crypto.randomBytes(32), crypto.randomBytes(12));',
  "",
].join("\n");

const fileFor = (source: string): JavaScriptArtifactFile => ({
  path: "main.js",
  container_sha256: SHA256,
  sha256: SHA256,
  bytes: source.length,
  inventory_artifact_id: `art_${SHA256}`,
  kind: "javascript",
  unpacked: false,
  text: { included: true, value: source },
});

const analysisFor = (
  entries: readonly AnalyzedJavaScriptArtifactFile[],
): JavaScriptModuleArtifactAnalysis => ({
  files: entries,
  packages: [],
  json_modules: [],
  html_scripts: [],
  html_inline_scripts: [],
  source_maps: [],
  visited_ast_nodes: 0,
  findings: 0,
  modules: 0,
  parse_failures: 0,
  limitations: [],
});

const contextFor = (
  file: JavaScriptArtifactFile,
  analysis: JavaScriptModuleArtifactAnalysis,
): JavaScriptArtifactGraphContext => {
  const accumulator = new JavaScriptArtifactGraphAccumulator();
  const snapshot = {
    manifest: {
      root_artifact_id: `art_${SHA256}`,
      root_sha256: SHA256,
      root_format: "directory",
      manifest_id: `agm_${SHA256}`,
      graph_sha256: SHA256,
    },
    nodes: [{ artifact_id: `art_${SHA256}`, sha256: SHA256, size: 1 }],
  } as unknown as ArtifactInventorySnapshot;
  const fileSet = {
    files: [file],
    unavailable_relevant_files: [],
    containers: [],
    text_bytes_read: file.bytes,
    invalid_utf8_files: 0,
  };
  return {
    accumulator,
    snapshot,
    fileSet,
    analysis,
    directoryPaths: new Set<string>(),
    root: createJavaScriptArtifactRootNode(accumulator, snapshot),
    filesByPath: new Map([[file.path, file]]),
    unanalyzedFiles: undefined,
    fileNodes: new Map(),
    assetNodes: new Map(),
    sourceModuleNodes: new Map(),
    chunkNodes: new Map(),
    moduleNodes: new Map(),
    containerNodes: new Map(),
  };
};

const projectedContext = (source: string): JavaScriptArtifactGraphContext => {
  const file = fileFor(source);
  const context = contextFor(
    file,
    analysisFor([
      {
        file,
        javascript: analyzeJavaScriptStaticSource(source),
        semantic: null,
      },
    ]),
  );
  addJavaScriptArtifactFiles(context);
  expect([...addJavaScriptStaticFindingsSteps(context)].length).toBeGreaterThan(
    0,
  );
  return context;
};

const cryptoNodes = (context: JavaScriptArtifactGraphContext) =>
  context.accumulator.nodes().filter(({ kind }) => kind === "crypto-usage");

describe("static crypto usage projection", () => {
  it("projects one AES-ECB call into a crypto-usage node with candidate risks", () => {
    const context = projectedContext(MISUSE_SOURCE);
    const nodes = cryptoNodes(context);
    expect(nodes).toHaveLength(1);
    const node = nodes[0];
    expect(node?.identity).toMatchObject({
      strategy: "artifact-local-key",
      artifact_sha256: SHA256,
      namespace: "node-crypto:cipher",
    });
    const observation = node?.observations[0];
    expect(observation?.label).toBe("aes-128-ecb");
    expect(observation?.properties).toEqual({
      library: "node-crypto",
      operation: "cipher",
      algorithm: "aes-128-ecb",
      mode: "ecb",
      key_source: "hardcoded-literal",
      iv_source: "absent",
      risks: ["ecb-mode", "hardcoded-key"],
      mechanism: "node-crypto:createCipheriv",
    });
    expect(observation?.evidence).toMatchObject({
      authority: "ast-static-analysis",
      state: "observed",
      confidence: "exact",
      extractor: { operation: "discover-static-crypto-usage" },
    });
    expect(observation?.evidence?.limitations).toContain(RISK_LIMITATION);
  });

  it("links the defining source to the crypto-usage node with a calls edge", () => {
    const context = projectedContext(MISUSE_SOURCE);
    const node = cryptoNodes(context)[0];
    expect(node).toBeDefined();
    const callsEdges = context.accumulator
      .edges()
      .filter(({ relation }) => relation === "calls");
    expect(callsEdges).toHaveLength(1);
    expect(callsEdges[0]?.target_node_id).toBe(node?.node_id);
  });

  it("keeps a randomized-key AES-GCM call free of candidate risks", () => {
    const context = projectedContext(SAFE_SOURCE);
    const nodes = cryptoNodes(context);
    expect(nodes).toHaveLength(1);
    expect(nodes[0]?.observations[0]?.properties).toMatchObject({
      algorithm: "aes-256-gcm",
      mode: "gcm",
      key_source: "random",
      iv_source: "random",
      risks: [],
    });
  });
});
