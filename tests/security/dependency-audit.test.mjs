import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { parseAuditOutput, evaluateAudit } from "../../scripts/dependency-audit-policy.mjs";

const advisoryUrl = "https://github.com/advisories/GHSA-fc5q-39xc-vjpf";
const now = new Date("2026-11-18T00:00:00.000Z");
const expiresAt = "2026-12-01T15:00:00.000Z";
const sha256 = (text) => createHash("sha256").update(text).digest("hex");

function counts(values = {}) {
  const result = { info: 0, low: 0, moderate: 0, high: 0, critical: 0, ...values };
  return { ...result, total: Object.values(result).reduce((sum, value) => sum + value, 0) };
}

function fixture() {
  // 実際の依存一式を複製せず、勧告の根とそれを参照する検査ツールだけを合成する。
  const advisory = {
    source: 1247710, name: "picomatch", dependency: "picomatch", title: "検査用の勧告",
    url: advisoryUrl, severity: "high", range: "<=4.0.7",
  };
  const lockfile = JSON.stringify({
    name: "dependency-audit-fixture", version: "1.0.0", lockfileVersion: 3,
    packages: {
      "": { name: "dependency-audit-fixture", version: "1.0.0", devDependencies: { "fixture-checker": "1.0.0" } },
      "node_modules/fixture-checker": { version: "1.0.0", dev: true, dependencies: { picomatch: "4.0.7" } },
      "node_modules/picomatch": { version: "4.0.7", dev: true },
    },
  });
  const report = {
    auditReportVersion: 2,
    vulnerabilities: {
      picomatch: { name: "picomatch", severity: "high", isDirect: false, via: [advisory], effects: ["fixture-checker"], range: "*", nodes: ["node_modules/picomatch"], fixAvailable: false },
      "fixture-checker": { name: "fixture-checker", severity: "high", isDirect: true, via: ["picomatch"], effects: [], range: "*", nodes: ["node_modules/fixture-checker"], fixAvailable: false },
    },
    metadata: { vulnerabilities: counts({ high: 2 }) },
  };
  const policy = {
    schemaVersion: 1,
    advisory: { id: "GHSA-fc5q-39xc-vjpf", source: advisory.source, name: advisory.name, severity: advisory.severity, url: advisory.url, range: advisory.range },
    owner: "fixture-maintainer", reason: "修正版の確認まで、合成した検査用依存だけを対象にする。",
    residualRisk: "警告が解消したことを意味せず、期限と依存の一致を毎回確認する。",
    expiresAt, lockfileSha256: sha256(lockfile),
    affected: {
      picomatch: { nodes: { "node_modules/picomatch": "4.0.7" }, via: [advisoryUrl] },
      "fixture-checker": { nodes: { "node_modules/fixture-checker": "1.0.0" }, via: ["picomatch"] },
    },
  };
  return { report, policy, lockfile, exitCode: 1 };
}

function evaluate(value, options = {}) {
  return evaluateAudit({ ...value, now, ...options });
}

function isPolicyError(error) {
  assert.equal(error instanceof Error, true);
  assert.equal(typeof error.code, "string");
  assert.notEqual(error.code.length, 0);
  return true;
}

function rejects(value, options) {
  assert.throws(() => evaluate(value, options), isPolicyError);
}

function changeLock(value, change) {
  const lock = JSON.parse(value.lockfile);
  change(lock);
  value.lockfile = JSON.stringify(lock);
}

test("対象の勧告だけに至る既知の依存経路を期限内に限定して受け入れる", () => {
  const value = fixture();
  const result = evaluate(value);
  assert.equal(result.status, "accepted-exception");
  assert.deepEqual(result.counts, counts({ high: 2 }));
  assert.equal(result.expiresAt, expiresAt);
});

test("ロックの同じUTF-8内容をBufferで受け取っても判定できる", () => {
  const value = fixture();
  value.lockfile = Buffer.from(value.lockfile, "utf8");
  assert.equal(evaluate(value).status, "accepted-exception");
});

test("同じパッケージに別の勧告が混ざる場合は例外の対象に含めない", () => {
  const value = fixture();
  value.report.vulnerabilities.picomatch.via.push({ ...value.report.vulnerabilities.picomatch.via[0], source: 1247711, url: "https://github.com/advisories/GHSA-2345-6789-cfgh" });
  rejects(value);
});

for (const field of ["source", "name", "dependency", "severity", "range", "url"]) {
  test(`勧告の${field}が承認内容から変わる場合は再確認を要求する`, () => {
    const value = fixture();
    const advisory = value.report.vulnerabilities.picomatch.via[0];
    advisory[field] = field === "source" ? advisory.source + 1 : `${advisory[field]}-changed`;
    rejects(value);
  });
}

test("対象外の新しいhighを既存の例外で覆い隠さない", () => {
  const value = fixture();
  value.report.vulnerabilities["other-checker"] = {
    name: "other-checker", severity: "high", isDirect: false, via: [{ ...value.report.vulnerabilities.picomatch.via[0], name: "other-checker", dependency: "other-checker", source: 1247711, url: "https://github.com/advisories/GHSA-2345-6789-cfgh" }],
    effects: [], range: "*", nodes: ["node_modules/other-checker"], fixAvailable: false,
  };
  value.report.metadata.vulnerabilities = counts({ high: 3 });
  rejects(value);
});

test("criticalへの変化は同じ経路でも受け入れない", () => {
  const value = fixture();
  value.report.vulnerabilities["fixture-checker"].severity = "critical";
  value.report.metadata.vulnerabilities = counts({ high: 1, critical: 1 });
  rejects(value);
});

test("同名パッケージでも新しい配置先は自動で例外に追加しない", () => {
  const value = fixture();
  value.report.vulnerabilities.picomatch.nodes.push("node_modules/fixture-checker/node_modules/picomatch");
  rejects(value);
});

test("同じ勧告でも承認済みの依存経路へ直接追加すると再確認を要求する", () => {
  const value = fixture();
  value.report.vulnerabilities["fixture-checker"].via.push({ ...value.report.vulnerabilities.picomatch.via[0] });
  rejects(value);
});

test("ロックファイルの変更を内容の再承認なしに受け入れない", () => {
  const value = fixture();
  changeLock(value, (lock) => { lock.name = "changed-fixture"; });
  rejects(value);
});

test("ロックのハッシュが一致しても承認した配置先のバージョン不一致を拒否する", () => {
  const value = fixture();
  changeLock(value, (lock) => { lock.packages["node_modules/picomatch"].version = "4.0.6"; });
  value.policy.lockfileSha256 = sha256(value.lockfile);
  rejects(value);
});

test("ロックのハッシュが一致しても承認した配置先の欠落を拒否する", () => {
  const value = fixture();
  changeLock(value, (lock) => { delete lock.packages["node_modules/picomatch"]; });
  value.policy.lockfileSha256 = sha256(value.lockfile);
  rejects(value);
});

test("対象勧告へ至る経路があっても循環する依存経路を許可しない", () => {
  const value = fixture();
  // 許可側にも同じ辺を加え、単なる一覧差分ではなく循環の拒否を検査する。
  value.report.vulnerabilities.picomatch.via.push("fixture-checker");
  value.policy.affected.picomatch.via.push("fixture-checker");
  rejects(value);
});

test("viaの参照先が監査結果に存在しない場合は失敗する", () => {
  const value = fixture();
  value.report.vulnerabilities["fixture-checker"].via = ["missing-checker"];
  value.policy.affected["fixture-checker"].via = ["missing-checker"];
  rejects(value);
});

test("勧告へ至らない空のviaを例外として受け入れない", () => {
  const value = fixture();
  value.report.vulnerabilities["fixture-checker"].via = [];
  value.policy.affected["fixture-checker"].via = [];
  rejects(value);
});

test("viaの未知の値を文字列や勧告とみなさない", () => {
  const value = fixture();
  value.report.vulnerabilities["fixture-checker"].via = [7];
  rejects(value);
});

test("監査結果の件数とmetadataが一致しない場合は失敗する", () => {
  const value = fixture();
  value.report.metadata.vulnerabilities = counts({ high: 1 });
  rejects(value);
});

test("正常終了なのにhighが報告された矛盾を受け入れない", () => {
  rejects(fixture(), { exitCode: 0 });
});

test("期限の直前だけ受け入れ、期限と同時刻・期限後は拒否する", () => {
  const value = fixture();
  const boundary = Date.parse(expiresAt);
  assert.equal(evaluate(value, { now: new Date(boundary - 1) }).status, "accepted-exception");
  rejects(value, { now: new Date(boundary) });
  rejects(value, { now: new Date(boundary + 1) });
});

for (const invalid of ["not-a-date", "2026-12-01", "2026-12-01T24:00:00.000Z", "2026-12-01T15:00:00+00:00"]) {
  test(`期限が正規のUTC日時でない場合は拒否する: ${invalid}`, () => {
    const value = fixture();
    value.policy.expiresAt = invalid;
    rejects(value);
  });
}

test("判定時刻が無効な場合は期限判定を通過させない", () => {
  rejects(fixture(), { now: new Date("invalid") });
});

test("例外が期限切れでも脆弱性のない監査結果は成功する", () => {
  const value = fixture();
  value.report.vulnerabilities = {};
  value.report.metadata.vulnerabilities = counts();
  assert.equal(evaluate(value, { exitCode: 0, now: new Date("2026-12-10T00:00:00.000Z") }).status, "clean");
});

test("lowだけの結果は通常のhigh閾値を維持して例外なしで通過する", () => {
  const value = fixture();
  value.report.vulnerabilities.picomatch.severity = "low";
  value.report.vulnerabilities.picomatch.via[0].severity = "low";
  value.report.vulnerabilities["fixture-checker"].severity = "low";
  value.report.metadata.vulnerabilities = counts({ low: 2 });
  const result = evaluate(value, { exitCode: 0, now: new Date("2026-12-10T00:00:00.000Z") });
  assert.equal(result.status, "below-threshold");
  assert.deepEqual(result.counts, counts({ low: 2 }));
});

test("例外設定がなくても警告のない監査は通常判定で成功する", () => {
  const value = fixture();
  value.report.vulnerabilities = {};
  value.report.metadata.vulnerabilities = counts();
  assert.equal(evaluate(value, { policy: null, exitCode: 0 }).status, "clean");
});

test("例外設定がない場合もlowだけならhigh閾値を維持する", () => {
  const value = fixture();
  value.report.vulnerabilities.picomatch.severity = "low";
  value.report.vulnerabilities.picomatch.via[0].severity = "low";
  value.report.vulnerabilities["fixture-checker"].severity = "low";
  value.report.metadata.vulnerabilities = counts({ low: 2 });
  assert.equal(evaluate(value, { policy: null, exitCode: 0 }).status, "below-threshold");
});

for (const severity of ["high", "critical"]) {
  test(`例外設定がなければ${severity}は必ず拒否する`, () => {
    const value = fixture();
    for (const finding of Object.values(value.report.vulnerabilities)) finding.severity = severity;
    value.report.vulnerabilities.picomatch.via[0].severity = severity;
    value.report.metadata.vulnerabilities = counts({ [severity]: 2 });
    rejects(value, { policy: null });
  });
}

test("未指定の例外設定を削除済みのnullとみなさない", () => {
  const value = fixture();
  value.report.vulnerabilities = {};
  value.report.metadata.vulnerabilities = counts();
  rejects(value, { policy: undefined, exitCode: 0 });
});

test("監査の終了コード1を脆弱性JSONとともに受け取り、内容を判定へ渡す", () => {
  const value = fixture();
  assert.deepEqual(parseAuditOutput({ stdout: JSON.stringify(value.report), exitCode: 1 }), value.report);
});

for (const output of ["", "not-json", '{"auditReportVersion":2', JSON.stringify({ error: { code: "ENOAUDIT", summary: "監査APIを利用できない" } })]) {
  test(`監査結果でない出力を成功として扱わない: ${output.slice(0, 24)}`, () => {
    assert.throws(() => parseAuditOutput({ stdout: output, exitCode: 1 }), isPolicyError);
  });
}

for (const result of [
  { exitCode: 2 }, { exitCode: null }, { exitCode: 1, signal: "SIGTERM" },
  { exitCode: 1, error: new Error("検査用のタイムアウト") },
]) {
  test(`監査コマンド自体の異常を例外化しない: ${result.exitCode}/${result.signal ?? (result.error ? "error" : "none")}`, () => {
    assert.throws(() => parseAuditOutput({ stdout: JSON.stringify(fixture().report), ...result }), isPolicyError);
  });
}

test("未対応の監査JSON形式は黙って受け入れない", () => {
  const value = fixture();
  value.report.auditReportVersion = 3;
  assert.throws(() => parseAuditOutput({ stdout: JSON.stringify(value.report), exitCode: 1 }), isPolicyError);
});

for (const context of ["exception", "below-threshold"]) {
  for (const severity of ["low", "moderate"]) {
    for (const rootSeverity of ["high", "critical"]) {
      test(`${context}の${severity}表示に${rootSeverity}の原因を隠す重大度の不整合を拒否する`, () => {
        const value = fixture();
        const root = value.report.vulnerabilities.picomatch.via[0];
        if (context === "below-threshold") value.report.vulnerabilities = {};
        value.report.vulnerabilities["other-checker"] = {
          name: "other-checker", severity, isDirect: false,
          via: [{ ...root, source: 1247711, name: "other-checker", dependency: "other-checker", severity: rootSeverity, url: "https://github.com/advisories/GHSA-2345-6789-cfgh" }],
          effects: [], range: "*", nodes: ["node_modules/other-checker"], fixAvailable: false,
        };
        value.report.metadata.vulnerabilities = counts({ high: context === "exception" ? 2 : 0, [severity]: 1 });
        value.exitCode = context === "exception" ? 1 : 0;
        // 集計値だけを信用すると、単独の低い表示へ重大な勧告を隠せてしまう。
        assert.throws(() => evaluate(value), (error) => isPolicyError(error) && error.code === "AUDIT_SEVERITY_INVALID");
      });
    }
  }
}

async function runCliFixture({ stdout, exitCode = 0, signal = null }) {
  const temporaryRoot = resolve(tmpdir());
  const directory = await mkdtemp(join(temporaryRoot, "mame-audit-cli-"));
  const sentinel = "SYNTHETIC_AUDIT_STDERR_MUST_NOT_ESCAPE";
  try {
    const npm = join(directory, "fixture-npm.mjs");
    const summaryPath = join(directory, "summary.md");
    const argumentsPath = join(directory, "arguments.json");
    await writeFile(npm, `import { writeFile } from "node:fs/promises";
await writeFile(process.env.AUDIT_FIXTURE_ARGUMENTS, JSON.stringify(process.argv.slice(2)));
process.stderr.write(process.env.AUDIT_FIXTURE_SENTINEL);
if (process.env.AUDIT_FIXTURE_SIGNAL) process.kill(process.pid, process.env.AUDIT_FIXTURE_SIGNAL);
else {
  process.stdout.write(process.env.AUDIT_FIXTURE_STDOUT);
  process.exitCode = Number(process.env.AUDIT_FIXTURE_EXIT);
}
`, "utf8");
    const env = {
      ...process.env, npm_execpath: npm, GITHUB_STEP_SUMMARY: summaryPath,
      AUDIT_FIXTURE_ARGUMENTS: argumentsPath, AUDIT_FIXTURE_SENTINEL: sentinel,
      AUDIT_FIXTURE_STDOUT: stdout.replaceAll("TEST_SENTINEL", sentinel),
      AUDIT_FIXTURE_EXIT: String(exitCode), AUDIT_FIXTURE_SIGNAL: signal ?? "",
    };
    // 実行中のCIの要約やannotationへ、合成監査の結果を書き込まない。
    delete env.GITHUB_ACTIONS;
    const cli = fileURLToPath(new URL("../../scripts/check-dependency-audit.mjs", import.meta.url));
    const result = spawnSync(process.execPath, [cli], { env, encoding: "utf8", timeout: 10_000, maxBuffer: 1024 * 1024, windowsHide: true });
    assert.equal(result.error, undefined);
    const summary = await readFile(summaryPath, "utf8");
    const args = JSON.parse(await readFile(argumentsPath, "utf8"));
    assert.deepEqual(args, ["audit", "--audit-level=high", "--json", "--include=dev", "--include=optional", "--include=peer"]);
    for (const output of [result.stdout, result.stderr, summary]) assert.equal(output.includes(sentinel), false);
    return { status: result.status, stdout: result.stdout, stderr: result.stderr, summary };
  } finally {
    // 自分で作成した一時領域だけを削除し、環境変数由来の別領域へ削除範囲を広げない。
    const absolute = resolve(directory);
    const inside = relative(temporaryRoot, absolute);
    assert.equal(isAbsolute(directory) && inside !== "" && inside !== ".." && !inside.startsWith(`..${sep}`) && !isAbsolute(inside), true);
    await rm(absolute, { recursive: true, force: true });
  }
}

test("CLIは全依存を監査し、警告なしなら現在日時によらず例外なしで成功する", async () => {
  const clean = { auditReportVersion: 2, vulnerabilities: {}, metadata: { vulnerabilities: counts() } };
  const result = await runCliFixture({ stdout: JSON.stringify(clean) });
  assert.equal(result.status, 0);
  assert.equal(result.stdout.includes("期限付き例外は適用していません"), true);
  assert.equal(result.summary.includes("期限付き例外は適用していません"), true);
});

for (const output of [
  JSON.stringify({ error: { code: "ENOAUDIT", summary: "TEST_SENTINEL" } }),
  "not-json:TEST_SENTINEL",
]) {
  test(`CLIは${output.startsWith("{") ? "JSONの監査エラー" : "不正JSON"}とstderrの詳細を出力へ漏らさない`, async () => {
    const result = await runCliFixture({ stdout: output, exitCode: 1 });
    assert.equal(result.status, 1);
    assert.equal(result.stdout, "");
    assert.equal(result.stderr.includes("AUDIT_"), true);
    assert.equal(result.summary.includes("AUDIT_"), true);
  });
}

for (const failure of [{ exitCode: 2 }, { signal: "SIGTERM" }]) {
  test(`CLIは子npmの${failure.signal ? "signal終了" : "終了コード2"}を成功にしない`, async () => {
    const clean = { auditReportVersion: 2, vulnerabilities: {}, metadata: { vulnerabilities: counts() } };
    const result = await runCliFixture({ stdout: JSON.stringify(clean), ...failure });
    assert.equal(result.status, 1);
    assert.equal(result.stdout, "");
    assert.equal(result.stderr.includes("AUDIT_"), true);
  });
}
