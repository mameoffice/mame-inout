import { execFile } from "node:child_process";
import { appendFile, readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { AuditPolicyError, evaluateAudit, parseAuditOutput } from "./dependency-audit-policy.mjs";

const root = fileURLToPath(new URL("../", import.meta.url));
const execute = promisify(execFile);

async function summary(message) {
  if (process.env.GITHUB_STEP_SUMMARY) await appendFile(process.env.GITHUB_STEP_SUMMARY, `## 依存監査の判定\n\n${message}\n`, "utf8");
}

async function readException() {
  try { return JSON.parse(await readFile(resolve(root, "security/dependency-audit-exception.json"), "utf8")); }
  catch (error) {
    if (error.code === "ENOENT") return null;
    throw new AuditPolicyError("EXCEPTION_INVALID");
  }
}

try {
  // npm自身のCLIをNodeで直接実行し、Windowsでもシェル経由の引数展開を避ける。
  const npm = process.env.npm_execpath || resolve(dirname(process.execPath), "node_modules/npm/bin/npm-cli.js");
  let stdout;
  let exitCode = 0;
  try {
    ({ stdout } = await execute(process.execPath, [npm, "audit", "--audit-level=high", "--json", "--include=dev", "--include=optional", "--include=peer"], { cwd: root, encoding: "utf8", timeout: 120000, maxBuffer: 4 * 1024 * 1024, windowsHide: true }));
  } catch (error) {
    // highを検出した通常の終了1だけを判定へ渡し、通信失敗や強制終了は例外化しない。
    if (error.code !== 1 || error.signal || error.killed) throw new AuditPolicyError("AUDIT_EXECUTION_FAILED");
    stdout = error.stdout;
    exitCode = error.code;
  }
  const report = parseAuditOutput({ stdout, exitCode });
  // エラー本文・stderrは出さず、正常な監査形式と確認できた元の結果だけを残す。
  process.stdout.write(`npm audit 元の終了コード: ${exitCode}\nnpm audit JSON: ${JSON.stringify(report)}\n`);
  const [lockfile, policy] = await Promise.all([readFile(resolve(root, "package-lock.json")), readException()]);
  const result = evaluateAudit({ report, exitCode, lockfile, policy });
  if (result.status === "accepted-exception") {
    const localExpiry = new Intl.DateTimeFormat("ja-JP", { timeZone: "Asia/Tokyo", year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hourCycle: "h23" }).format(new Date(result.expiresAt));
    const message = `未解消のhigh ${result.counts.high}件（原因1件）に承認済みの期限付き例外を適用しました。対象: ${result.advisory}、期限: ${result.expiresAt}（${localExpiry} 日本時間）。脆弱性の修正完了や監査0件を示すものではありません。`;
    process.stdout.write(`${message}\n`);
    if (process.env.GITHUB_ACTIONS === "true") process.stdout.write(`::warning title=依存監査の期限付き例外::${message}\n`);
    await summary(`${message}\n\n元のnpm audit終了コード: **${exitCode}**。機能検証とは別の、例外を含む判定です。`);
  } else {
    const message = result.status === "clean" ? "既知の警告はありません。期限付き例外は適用していません。" : "high以上の警告はありません。期限付き例外は適用していません。";
    process.stdout.write(`${message}\n`);
    await summary(message);
  }
} catch (error) {
  const code = error instanceof AuditPolicyError ? error.code : "AUDIT_POLICY_FAILED";
  const message = `依存監査の判定に失敗しました（${code}）。監査結果・例外の対象・期限を確認してください。`;
  process.stderr.write(`${message}\n`);
  try { await summary(message); } catch { /* 要約を書けない場合も成功にせず、失敗を維持する。 */ }
  process.exitCode = 1;
}
