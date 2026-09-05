import { spawn } from "node:child_process";
import { existsSync, rmSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const webRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const outDir = path.join(webRoot, "storybook-static");
const indexHtml = path.join(outDir, "index.html");
const iframeHtml = path.join(outDir, "iframe.html");

rmSync(outDir, { recursive: true, force: true });

const child = spawn(
  "npx",
  ["storybook", "build", "-o", "storybook-static", "--disable-telemetry"],
  {
    cwd: webRoot,
    env: { ...process.env, CI: "1", STORYBOOK_DISABLE_TELEMETRY: "1" },
    stdio: ["ignore", "pipe", "pipe"],
    shell: true,
  },
);

let settled = false;
let previewBuilt = false;

function finish(code) {
  if (settled) return;
  settled = true;
  try {
    child.kill();
  } catch {
    /* ignore */
  }
  process.exit(code);
}

function onChunk(buf) {
  const text = buf.toString();
  process.stdout.write(text);
  if (/Preview built/i.test(text)) {
    previewBuilt = true;
    // Windows Storybook often hangs after a successful Vite build.
    setTimeout(() => {
      const ok = existsSync(indexHtml) && existsSync(iframeHtml);
      finish(ok ? 0 : 1);
    }, 2500);
  }
}

child.stdout?.on("data", onChunk);
child.stderr?.on("data", (buf) => process.stderr.write(buf));

child.on("exit", (code) => {
  if (settled) return;
  const ok = existsSync(indexHtml) && existsSync(iframeHtml);
  finish(ok ? 0 : code ?? 1);
});

setTimeout(() => {
  const ok = previewBuilt && existsSync(indexHtml) && existsSync(iframeHtml);
  finish(ok ? 0 : 1);
}, 180000);
