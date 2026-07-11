// Assemble the self-contained offline FireCash paper wallet: inline the QR lib,
// the wasm-bindgen glue, and the base64-encoded wasm into one HTML file with zero
// external requests. Uses function replacements so `$`/`${` in the sources are
// never treated as replacement patterns.
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");

const QRLIB = "/root/work/firecash-explorer/node_modules/qrcode-generator/dist/qrcode.js";

const template = readFileSync(join(here, "template.html"), "utf8");
const qrlib = readFileSync(QRLIB, "utf8");
const glue = readFileSync(join(root, "pkg", "firecash_signer.js"), "utf8");
const wasmB64 = readFileSync(join(root, "pkg", "firecash_signer_bg.wasm")).toString("base64");

let out = template
  .replace("/*__QRLIB__*/", () => qrlib)
  .replace("/*__GLUE__*/", () => glue)
  .replace("__WASM_B64__", () => wasmB64);

// Sanity: no placeholder survived.
for (const marker of ["/*__QRLIB__*/", "/*__GLUE__*/", "__WASM_B64__"]) {
  if (out.includes(marker)) throw new Error(`placeholder ${marker} not substituted`);
}

const outPath = join(here, "firecash-paper-wallet.html");
writeFileSync(outPath, out);
console.log(`wrote ${outPath} (${(out.length / 1024).toFixed(0)} KiB)`);
