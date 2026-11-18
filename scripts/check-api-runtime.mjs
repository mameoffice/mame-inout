import { readdir, readFile, realpath } from "node:fs/promises";
import { createRequire } from "node:module";
import { resolve } from "node:path";

// 必要な依存まで除いて認証やDB操作を壊さず、開発用ツールの再混入をビルド時に検出する。
const forbidden = new Set([
  "picomatch", "micromatch", "tinyglobby", "fast-glob", "vitest", "vite",
  "eslint", "typescript", "tsx", "prisma", "next", "@playwright/test", "playwright",
]);
const visited = new Set();

async function packages(directory) {
  let entries;
  try { entries = await readdir(directory, { withFileTypes: true }); }
  catch (error) { if (error.code === "ENOENT") return; throw error; }
  for (const entry of entries) {
    if (entry.name.startsWith(".")) continue;
    const path = resolve(directory, entry.name);
    if (entry.name.startsWith("@")) { await packages(path); continue; }
    const actual = await realpath(path);
    if (visited.has(actual)) continue;
    visited.add(actual);
    const manifest = JSON.parse(await readFile(resolve(actual, "package.json"), "utf8"));
    if (forbidden.has(manifest.name)) throw new Error(`APIの実行時に不要な依存が含まれています: ${manifest.name}`);
    await packages(resolve(actual, "node_modules"));
  }
}

await packages(resolve("node_modules"));
const require = createRequire(resolve("apps/api/package.json"));
for (const name of [
  "better-auth", "@better-auth/core", "@better-auth/passkey", "@better-auth/prisma-adapter",
  "@prisma/client/runtime/client", "@prisma/adapter-pg", "@hono/node-server", "hono", "pg", "zod",
]) require.resolve(name);
