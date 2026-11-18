import { createHash } from "node:crypto";

const levels = ["info", "low", "moderate", "high", "critical"];
const packageName = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/;
const object = value => value !== null && typeof value === "object" && !Array.isArray(value);
const own = (value, key) => Object.hasOwn(value, key);
const text = value => typeof value === "string" && value.length > 0;
const unique = values => new Set(values).size === values.length;

export class AuditPolicyError extends Error {
  constructor(code) {
    super(`依存監査の判定を停止しました（${code}）。`);
    this.name = "AuditPolicyError";
    this.code = code;
  }
}

function requireCondition(condition, code) {
  if (!condition) throw new AuditPolicyError(code);
}

function validateReport(report, exitCode) {
  requireCondition(object(report) && report.auditReportVersion === 2 && !own(report, "error") && object(report.vulnerabilities) && object(report.metadata?.vulnerabilities), "AUDIT_REPORT_INVALID");
  requireCondition(exitCode === 0 || exitCode === 1, "AUDIT_EXECUTION_FAILED");
  const entries = Object.entries(report.vulnerabilities);
  requireCondition(entries.length <= 1000, "AUDIT_REPORT_INVALID");
  const counts = Object.fromEntries(levels.map(level => [level, 0]));
  for (const [name, finding] of entries) {
    requireCondition(packageName.test(name) && object(finding) && finding.name === name && levels.includes(finding.severity) && typeof finding.isDirect === "boolean" && typeof finding.range === "string", "AUDIT_REPORT_INVALID");
    requireCondition(Array.isArray(finding.nodes) && finding.nodes.length > 0 && unique(finding.nodes) && finding.nodes.every(node => text(node) && !/[\\\s]/.test(node) && node.split("/").every(part => part && part !== "." && part !== "..")), "AUDIT_REPORT_INVALID");
    requireCondition(Array.isArray(finding.effects) && finding.effects.every(name => typeof name === "string" && packageName.test(name)), "AUDIT_REPORT_INVALID");
    requireCondition(Array.isArray(finding.via) && finding.via.length > 0 && finding.via.length <= 1000, "AUDIT_GRAPH_INVALID");
    for (const via of finding.via) {
      if (typeof via === "string") requireCondition(own(report.vulnerabilities, via), "AUDIT_GRAPH_INVALID");
      else requireCondition(object(via) && Number.isSafeInteger(via.source) && via.source > 0 && text(via.name) && text(via.dependency) && levels.includes(via.severity) && text(via.url) && typeof via.range === "string", "AUDIT_REPORT_INVALID");
    }
    counts[finding.severity] += 1;
  }
  counts.total = entries.length;
  for (const key of [...levels, "total"]) requireCondition(report.metadata.vulnerabilities[key] === counts[key], "AUDIT_COUNTS_INVALID");
  requireCondition(exitCode === (counts.high + counts.critical > 0 ? 1 : 0), "AUDIT_EXIT_MISMATCH");

  // 一つでも既知の原因があれば許可するのではなく、全原因をたどる。循環・欠損は異常として止める。
  const roots = new Map();
  const active = new Set();
  function visit(name) {
    if (roots.has(name)) return roots.get(name);
    requireCondition(!active.has(name), "AUDIT_GRAPH_INVALID");
    active.add(name);
    const result = report.vulnerabilities[name].via.flatMap(via => typeof via === "string" ? visit(via) : [via]);
    active.delete(name);
    requireCondition(result.length > 0 && result.length <= 10000, "AUDIT_GRAPH_INVALID");
    roots.set(name, result);
    return result;
  }
  for (const [name, finding] of entries) {
    const causes = visit(name);
    // 集計をlowに偽装してhigh/criticalの根を隠す不整合も、例外判定より前に拒否する。
    const maximum = Math.max(...causes.map(cause => levels.indexOf(cause.severity)));
    requireCondition(levels.indexOf(finding.severity) === maximum, "AUDIT_SEVERITY_INVALID");
  }
  return { counts, roots };
}

export function parseAuditOutput({ stdout, exitCode, signal = null, error = null }) {
  requireCondition(!error && !signal && (exitCode === 0 || exitCode === 1), "AUDIT_EXECUTION_FAILED");
  requireCondition(typeof stdout === "string" && Buffer.byteLength(stdout) <= 4 * 1024 * 1024, "AUDIT_RESPONSE_INVALID");
  let report;
  try { report = JSON.parse(stdout); }
  catch { throw new AuditPolicyError("AUDIT_RESPONSE_INVALID"); }
  validateReport(report, exitCode);
  return report;
}

function validatePolicy(policy) {
  requireCondition(object(policy) && policy.schemaVersion === 1 && object(policy.advisory) && object(policy.affected) && text(policy.owner) && text(policy.reason) && text(policy.residualRisk), "EXCEPTION_INVALID");
  const advisory = policy.advisory;
  requireCondition(/^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$/.test(advisory.id) && advisory.url === `https://github.com/advisories/${advisory.id}` && packageName.test(advisory.name) && advisory.severity === "high" && Number.isSafeInteger(advisory.source) && advisory.source > 0 && text(advisory.range), "EXCEPTION_INVALID");
  requireCondition(typeof policy.lockfileSha256 === "string" && /^[a-f0-9]{64}$/.test(policy.lockfileSha256), "EXCEPTION_INVALID");
  const expires = Date.parse(policy.expiresAt);
  requireCondition(Number.isFinite(expires) && new Date(expires).toISOString() === policy.expiresAt, "EXCEPTION_INVALID");
  const entries = Object.entries(policy.affected);
  requireCondition(entries.length > 0 && entries.length <= 1000 && own(policy.affected, advisory.name), "EXCEPTION_INVALID");
  for (const [name, scope] of entries) {
    requireCondition(packageName.test(name) && object(scope) && object(scope.nodes) && Object.keys(scope.nodes).length > 0 && Object.entries(scope.nodes).every(([node, version]) => text(node) && text(version)), "EXCEPTION_INVALID");
    requireCondition(Array.isArray(scope.via) && scope.via.length > 0 && unique(scope.via) && scope.via.every(via => via === advisory.url || own(policy.affected, via)), "EXCEPTION_INVALID");
  }
  return expires;
}

export function evaluateAudit({ report, exitCode, lockfile, policy, now = new Date() }) {
  const { counts, roots } = validateReport(report, exitCode);
  requireCondition(now instanceof Date && Number.isFinite(now.getTime()), "EXCEPTION_INVALID");
  // 修正版の導入後は設定を削除できるが、設定がない状態でhighを受け入れることはない。
  if (policy === null) {
    requireCondition(counts.high + counts.critical === 0, "NEW_HIGH_FINDING");
    return { status: counts.total === 0 ? "clean" : "below-threshold", counts, exceptedPackages: [] };
  }
  const expires = validatePolicy(policy);
  // 問題が消えた監査は、古い例外を適用せずに成功させる。低・中の警告は従来のhigh閾値に従う。
  if (counts.high + counts.critical === 0) return { status: counts.total === 0 ? "clean" : "below-threshold", counts, exceptedPackages: [] };
  requireCondition(counts.critical === 0, "NEW_HIGH_FINDING");
  requireCondition(now.getTime() < expires, "EXCEPTION_EXPIRED");
  requireCondition(typeof lockfile === "string" || Buffer.isBuffer(lockfile), "LOCKFILE_CHANGED");
  requireCondition(createHash("sha256").update(lockfile).digest("hex") === policy.lockfileSha256, "LOCKFILE_CHANGED");
  let lock;
  try { lock = JSON.parse(lockfile.toString()); }
  catch { throw new AuditPolicyError("LOCKFILE_CHANGED"); }
  requireCondition(object(lock.packages), "LOCKFILE_CHANGED");
  const exceptedPackages = [];
  for (const [name, finding] of Object.entries(report.vulnerabilities)) {
    if (finding.severity !== "high") continue;
    requireCondition(own(policy.affected, name), "NEW_HIGH_FINDING");
    const scope = policy.affected[name];
    requireCondition(finding.nodes.every(node => own(scope.nodes, node) && own(lock.packages, node) && object(lock.packages[node]) && lock.packages[node].version === scope.nodes[node]), "EXCEPTION_SCOPE_CHANGED");
    for (const via of finding.via) {
      requireCondition(scope.via.includes(typeof via === "string" ? via : via.url), "EXCEPTION_SCOPE_CHANGED");
      // 例外の経路へ別の低・中の問題が混在しても、同じ原因の波及として扱わない。
      if (typeof via === "string") requireCondition(report.vulnerabilities[via].severity === "high", "EXCEPTION_SCOPE_CHANGED");
      else requireCondition(name === policy.advisory.name, "ADVISORY_CHANGED");
    }
    for (const root of roots.get(name)) {
      requireCondition(root.source === policy.advisory.source && root.name === policy.advisory.name && root.dependency === policy.advisory.name && root.url === policy.advisory.url && root.severity === policy.advisory.severity && root.range === policy.advisory.range, "ADVISORY_CHANGED");
    }
    exceptedPackages.push(name);
  }
  return { status: "accepted-exception", counts, advisory: policy.advisory.id, expiresAt: policy.expiresAt, exceptedPackages: exceptedPackages.sort() };
}
