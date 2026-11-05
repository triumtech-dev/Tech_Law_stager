#!/usr/bin/env node

// ../../../../../Users/User/AppData/Local/Temp/claude/8f433162ca0cb8b3/4a05b86d-fc4a-4091-891f-4e28333938c1/scratchpad/pub/src/cli.ts
var import_promises = require("node:readline/promises");
var import_node_path5 = require("node:path");

// ../../../../../Users/User/AppData/Local/Temp/claude/8f433162ca0cb8b3/4a05b86d-fc4a-4091-891f-4e28333938c1/scratchpad/pub/src/hook.ts
var import_node_fs4 = require("node:fs");
var import_node_path4 = require("node:path");

// ../../../../../Users/User/AppData/Local/Temp/claude/8f433162ca0cb8b3/4a05b86d-fc4a-4091-891f-4e28333938c1/scratchpad/pub/src/core/client/seal.ts
var import_node_crypto = require("node:crypto");
var ENVELOPE_VERSION = 1;
var IV_BYTES = 12;
var KEY_BYTES = 32;
function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const entries = Object.entries(value).filter(([, v]) => v !== void 0).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0);
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}
function hashFindings(findings) {
  return (0, import_node_crypto.createHash)("sha256").update(canonicalJson(findings), "utf8").digest("hex");
}
function computeTreeDigest(files) {
  const lines = files.map((f) => `${f.path}\0${(0, import_node_crypto.createHash)("sha256").update(f.text, "utf8").digest("hex")}`).sort();
  return (0, import_node_crypto.createHash)("sha256").update(lines.join("\n"), "utf8").digest("hex");
}
function attestationHash(attestation) {
  return (0, import_node_crypto.createHash)("sha256").update(canonicalJson(attestation), "utf8").digest("hex");
}
function aadFor(lawyerId, nonce, findingsHash, attestation) {
  for (const part of [lawyerId, nonce, findingsHash]) {
    if (part.length === 0 || part.includes(":")) throw new Error("envelope: \u05E8\u05DB\u05D9\u05D1 \u05D4\u05E7\u05E9\u05E8 \u05E8\u05D9\u05E7 \u05D0\u05D5 \u05DB\u05D5\u05DC\u05DC \u05E0\u05E7\u05D5\u05D3\u05EA\u05D9\u05D9\u05DD");
  }
  return Buffer.from(`lawstager-envelope:v${ENVELOPE_VERSION}:${lawyerId}:${nonce}:${findingsHash}:${attestationHash(attestation)}`, "utf8");
}
function sealSubmission(submission, options) {
  const findingsHash = hashFindings(submission.findings);
  const key = (0, import_node_crypto.randomBytes)(KEY_BYTES);
  const iv = (0, import_node_crypto.randomBytes)(IV_BYTES);
  const cipher = (0, import_node_crypto.createCipheriv)("aes-256-gcm", key, iv);
  cipher.setAAD(aadFor(options.lawyerId, options.nonce, findingsHash, options.attestation));
  const ciphertext = Buffer.concat([cipher.update(canonicalJson(submission), "utf8"), cipher.final()]);
  const wrappedKey = (0, import_node_crypto.publicEncrypt)(
    { key: options.serverPublicKeyPem, padding: import_node_crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
    key
  );
  return {
    v: ENVELOPE_VERSION,
    lawyerId: options.lawyerId,
    nonce: options.nonce,
    findingsHash,
    attestation: options.attestation,
    wrappedKey: wrappedKey.toString("base64"),
    iv: iv.toString("base64"),
    ciphertext: ciphertext.toString("base64"),
    tag: cipher.getAuthTag().toString("base64")
  };
}

// ../../../../../Users/User/AppData/Local/Temp/claude/8f433162ca0cb8b3/4a05b86d-fc4a-4091-891f-4e28333938c1/scratchpad/pub/src/core/client/diff.ts
var import_node_crypto2 = require("node:crypto");
var BASELINE_SCHEMA_VERSION = 1;
var SILENT_PROCESS_TYPES = ["accessibility", "security"];
function baselineOf(findings) {
  const entries = findings.processes.map((p) => ({ kind: p.kind, processType: p.processType })).sort((a, b) => a.kind < b.kind ? -1 : a.kind > b.kind ? 1 : 0);
  return { schemaVersion: BASELINE_SCHEMA_VERSION, entries };
}
function hashBaseline(baseline) {
  return (0, import_node_crypto2.createHash)("sha256").update(canonicalJson(baseline), "utf8").digest("hex");
}
function isValidBaseline(value) {
  const v = value;
  return v !== null && typeof v === "object" && v.schemaVersion === BASELINE_SCHEMA_VERSION && Array.isArray(v.entries) && v.entries.length <= 1e3 && v.entries.every((e) => typeof e?.kind === "string" && e.kind.length <= 200 && typeof e.processType === "string");
}
var signal = (e) => !SILENT_PROCESS_TYPES.includes(e.processType);
function diffAgainstBaseline(baseline, current) {
  const before = new Map(baseline.entries.filter(signal).map((e) => [e.kind, e]));
  const after = new Map(baselineOf(current).entries.filter(signal).map((e) => [e.kind, e]));
  const added = [...after.keys()].filter((k) => !before.has(k)).sort();
  const removed = [...before.keys()].filter((k) => !after.has(k)).sort();
  if (added.length === 0 && removed.length === 0) return { significant: false };
  return { significant: true, added, removed, baselineHash: hashBaseline(baseline) };
}

// ../../../../../Users/User/AppData/Local/Temp/claude/8f433162ca0cb8b3/4a05b86d-fc4a-4091-891f-4e28333938c1/scratchpad/pub/src/scan.ts
var import_node_fs2 = require("node:fs");
var import_node_path2 = require("node:path");

// ../../../../../Users/User/AppData/Local/Temp/claude/8f433162ca0cb8b3/4a05b86d-fc4a-4091-891f-4e28333938c1/scratchpad/pub/src/core/constants.ts
var MAX_FILE_BYTES = 1e6;
var MAX_FILES_READ_INVENTED = 5e4;
var EVIDENCE_MAX = 200;
var MAX_FINDINGS_PER_KIND = 25;
var MAX_HOST_FINDINGS = 200;
var MINIFIED_AVG_LINE = 400;

// ../../../../../Users/User/AppData/Local/Temp/claude/8f433162ca0cb8b3/4a05b86d-fc4a-4091-891f-4e28333938c1/scratchpad/pub/src/core/analyzer/secrets.ts
var REDACTED = "[REDACTED]";
var PATTERNS = [
  // גוף ה-PEM הוא base64, רווחים ו-`\n` מוברח בלבד. ⛔ לא `[\s\S]*?…|$`: כותרת PEM במחרוזת רגילה הסתירה את כל שאר הקובץ.
  { id: "private_key", pattern: /-----BEGIN (?:[A-Z0-9]{1,20} ){0,4}PRIVATE KEY(?: BLOCK)?-----(?:[A-Za-z0-9+/= \t\r\n]|\\n|\\r){0,10000}(?:-----END (?:[A-Z0-9]{1,20} ){0,4}PRIVATE KEY(?: BLOCK)?-----)?/g, group: 0 },
  { id: "aws_access_key", pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, group: 0 },
  { id: "aws_secret_key", pattern: /aws_?secret_?(?:access_?)?key["']?\s{0,5}(?:[:=]|\s)\s{0,5}["']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])/gi, group: 1 },
  { id: "google_api_key", pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g, group: 0 },
  { id: "google_oauth_secret", pattern: /\bGOCSPX-[A-Za-z0-9_-]{20,200}/g, group: 0 },
  { id: "github_token", pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{40,255})/g, group: 0 },
  { id: "npm_token", pattern: /\bnpm_[A-Za-z0-9]{36,100}|_authToken\s{0,3}=\s{0,3}(\S{8,500})/g, group: 0 },
  { id: "stripe_key", pattern: /\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9_-]{16,500}|\bwhsec_[A-Za-z0-9]{16,500}/g, group: 0 },
  { id: "ai_api_key", pattern: /\bsk-(?:proj-|ant-[a-z0-9]{1,20}-)?[A-Za-z0-9_-]{20,500}/g, group: 0 },
  { id: "slack_token", pattern: /\bxox[abprs]-[A-Za-z0-9-]{10,500}/g, group: 0 },
  { id: "webhook_url", pattern: /hooks\.slack\.com\/services\/[A-Za-z0-9/_-]{20,500}|discord(?:app)?\.com\/api\/webhooks\/[0-9]{1,30}\/[A-Za-z0-9_-]{20,500}/g, group: 0 },
  { id: "telegram_bot_token", pattern: /\b(?:bot)?[0-9]{6,12}:[A-Za-z0-9_-]{30,200}/g, group: 0 },
  { id: "jwt", pattern: /\beyJ[A-Za-z0-9_-]{8,300}\.eyJ[A-Za-z0-9_-]{8,4000}\.[A-Za-z0-9_-]{8,2000}/g, group: 0 },
  { id: "http_auth_header", pattern: /\b(?:Bearer|Basic|Token)\s{1,5}([A-Za-z0-9._~+/=-]{12,2000})/g, group: 1 },
  // סכמה אופציונלית (כתובת `//user:pass@host`). הסיסמה עד ה-`@` האחרון לפני המארח, באורך כלשהו עד סוף השורה.
  { id: "url_credentials", pattern: /(?:\b[a-z][a-z0-9+.-]{0,20}:)?\/\/[^\s:/'"`@]{1,200}:([^\s'"`]{1,2000})@[^\s@/'"`]{1,200}/gi, group: 1 },
  { id: "url_query_secret", pattern: /[?&\s"'](?:key|api_key|apikey|token|access_token|refresh_token|auth|secret|client_secret|sig|signature|password|pass|pwd)=([^&\s"'`#]{6,2000})/gi, group: 1 },
  {
    id: "named_secret",
    pattern: /\b[A-Za-z0-9_]{0,40}(?:password|passwd|passphrase|pass|pwd|secret|token|credentials?|api[_-]?key|apikey|private[_-]?key)[A-Za-z0-9_]{0,40}["']?\s{0,10}[:=]\s{0,10}["'`]((?:[^"'`\\\n]|\\.){8,500})["'`]/gi,
    group: 1
  },
  // `pw` כמפתח שלם (קצר מכדי להיכלל ב-named_secret בלי התאמות שווא).
  { id: "named_secret", pattern: /\b(?:pw|pwd)["']?\s{0,10}[:=]\s{0,10}["'`]((?:[^"'`\\\n]|\\.){4,500})["'`]/gi, group: 1 },
  // סיסמה לפי מיקום: `smtp.login('user', 'pw')`, `connect(...)`, וזוג `auth=('user', 'pw')` של requests (Gate A, סבב 3).
  { id: "positional_password", pattern: /\.(?:login|connect|auth(?:enticate)?)\(\s{0,5}['"][^'"\n]{1,200}['"]\s{0,5},\s{0,5}['"]([^'"\n]{4,500})['"]/g, group: 1 },
  { id: "positional_password", pattern: /\bauth\s{0,3}=\s{0,3}\(\s{0,3}['"][^'"\n]{1,200}['"]\s{0,3},\s{0,3}['"]([^'"\n]{4,500})['"]/g, group: 1 },
  // צורת קובצי תצורה (env, sh, ini, yaml): `NAME=value` בלי מרכאות.
  { id: "config_secret", pattern: /(?:^|[\s;])(?:export\s{1,3})?[A-Za-z0-9_.-]{0,40}(?:SECRET|PASSWORD|PASSWD|TOKEN|API_?KEY|PRIVATE_?KEY|PASS|PWD)[A-Za-z0-9_.-]{0,40}\s{0,3}[=:]\s{0,3}([^\s"'`$({][^\s"'`]{7,500})/gim, group: 1 }
];
var PLACEHOLDER = /^(?:x{4,}|\*{4,}|\.{4,}|changeme|change_me|your[_-](?:api[_-]?key|secret|password|token)(?:[_-]here)?|<[^>]*>|\$\{[^}]*\}|process\.env\.[A-Z0-9_]+|placeholder)$/i;
var TOKEN_CHAR = /[A-Za-z0-9_+/=~-]/;
var MAX_SPAN = 5e4;
function rawHits(text) {
  const hits = [];
  for (const { id, pattern, group } of PATTERNS) {
    const withIndices = new RegExp(pattern.source, pattern.flags.includes("d") ? pattern.flags : `${pattern.flags}d`);
    for (const m of text.matchAll(withIndices)) {
      const value = m[group];
      const span = m.indices?.[group];
      if (value === void 0 || value === "" || span === void 0) continue;
      let end = span[1];
      while (end < text.length && end - span[0] < MAX_SPAN && TOKEN_CHAR.test(text[end] ?? "")) end += 1;
      hits.push({ id, index: span[0], length: end - span[0], placeholder: id === "named_secret" && PLACEHOLDER.test(value) });
    }
  }
  return hits;
}
function findSecrets(text) {
  const sorted = rawHits(text).sort((a, b) => a.index - b.index || b.length - a.length);
  const merged = [];
  for (const hit of sorted) {
    const last = merged.at(-1);
    if (last !== void 0 && hit.index <= last.index + last.length) {
      const end = Math.max(last.index + last.length, hit.index + hit.length);
      merged[merged.length - 1] = { ...last, length: end - last.index, placeholder: last.placeholder && hit.placeholder };
    } else {
      merged.push(hit);
    }
  }
  return merged;
}
function maskSecrets(text, hits = findSecrets(text)) {
  if (hits.length === 0) return text;
  let out = "";
  let cursor = 0;
  for (const hit of hits) {
    const segment = text.slice(hit.index, hit.index + hit.length);
    out += text.slice(cursor, hit.index) + segment.split("\n").map((part) => part.replace(/\r$/, "") === "" ? part : REDACTED).join("\n");
    cursor = hit.index + hit.length;
  }
  return out + text.slice(cursor);
}
function redactSecrets(text) {
  return maskSecrets(text);
}

// ../../../../../Users/User/AppData/Local/Temp/claude/8f433162ca0cb8b3/4a05b86d-fc4a-4091-891f-4e28333938c1/scratchpad/pub/src/core/analyzer/evidence.ts
function makeLocator(text) {
  const starts = [0];
  for (let i = 0; i < text.length; i += 1) if (text.charCodeAt(i) === 10) starts.push(i + 1);
  return {
    lineAt(index) {
      let lo = 0;
      let hi = starts.length - 1;
      while (lo < hi) {
        const mid = lo + hi + 1 >> 1;
        if ((starts[mid] ?? 0) <= index) lo = mid;
        else hi = mid - 1;
      }
      return lo + 1;
    },
    lineStart(line) {
      return starts[line - 1] ?? text.length;
    },
    lineText(line) {
      const start = starts[line - 1] ?? text.length;
      const next = starts[line];
      return text.slice(start, next === void 0 ? text.length : next - 1).replace(/\r$/, "");
    }
  };
}
var URL_TAIL = /(\b[a-z][a-z0-9+.-]{0,20}:\/\/[^\s"'`?#]{1,300})[?#][^\s"'`]{0,2000}/gi;
var TOKEN_LIKE = /[A-Za-z0-9+/=_~-]{20,1000}/g;
function maskHighEntropy(text) {
  return text.replace(TOKEN_LIKE, (t) => /[0-9]/.test(t) && /[A-Za-z]/.test(t) ? REDACTED : t);
}
function evidenceFor(text) {
  const clean2 = maskHighEntropy(redactSecrets(text.slice(0, EVIDENCE_MAX * 3)).replace(URL_TAIL, "$1?\u2026")).trim().replace(/\s+/g, " ");
  return clean2.length <= EVIDENCE_MAX ? clean2 : `${clean2.slice(0, EVIDENCE_MAX - 1)}\u2026`;
}
function evidenceAt(lineText, column) {
  const start = Math.max(0, column - Math.floor(EVIDENCE_MAX / 2));
  const end = Math.min(lineText.length, start + EVIDENCE_MAX * 2);
  let window = lineText.slice(start, end);
  if (start > 0) window = `\u2026${window.replace(/^\S{0,1000}\s?/, "")}`;
  if (end < lineText.length) window = `${window.replace(/\s?\S{0,1000}$/, "")}\u2026`;
  return evidenceFor(window);
}
function isCommentLine(lineText) {
  return /^\s*(?:\/\/|\/\*|\*|#(?!!)|<!--)/.test(lineText);
}

// ../../../../../Users/User/AppData/Local/Temp/claude/8f433162ca0cb8b3/4a05b86d-fc4a-4091-891f-4e28333938c1/scratchpad/pub/src/core/analyzer/types.ts
var PROCESS_TYPES = [
  "personal_data",
  "cookies_storage",
  "third_party",
  "payments",
  "subscription",
  "distance_sale",
  "user_content",
  "marketing",
  "notifications",
  "account",
  "minors",
  "dark_pattern",
  "accessibility",
  "security"
];
var SKIP_REASONS = ["dependency_dir", "build_dir", "not_text", "binary", "minified", "too_large", "test", "over_limit"];

// ../../../../../Users/User/AppData/Local/Temp/claude/8f433162ca0cb8b3/4a05b86d-fc4a-4091-891f-4e28333938c1/scratchpad/pub/src/core/analyzer/files.ts
var TEXT_EXTENSIONS = /* @__PURE__ */ new Set([
  "js",
  "jsx",
  "mjs",
  "cjs",
  "ts",
  "tsx",
  "mts",
  "cts",
  "vue",
  "svelte",
  "astro",
  "html",
  "htm",
  "php",
  "py",
  "rb",
  "go",
  "java",
  "kt",
  "swift",
  "dart",
  "cs",
  "json",
  "yaml",
  "yml",
  "toml",
  "xml",
  "txt",
  "md",
  "env",
  "rules",
  "css",
  "scss",
  "sass",
  "less",
  // קבצים שנושאים סודות לעיתים קרובות: נקראים כדי שהסוד יזוהה ויוסתר
  "pem",
  "key",
  "ini",
  "properties",
  "tf",
  "tfvars",
  "sh",
  "cfg",
  "conf"
]);
var TEXT_NAMES = /* @__PURE__ */ new Set(["dockerfile", "gemfile", "requirements.txt", "pipfile", "procfile", ".env", ".npmrc", ".pypirc", ".netrc"]);
var encoder = new TextEncoder();
function byteLength(text) {
  return text.length > MAX_FILE_BYTES ? text.length : encoder.encode(text).length;
}
var DEPENDENCY_DIRS = /* @__PURE__ */ new Set(["node_modules", "vendor", "bower_components", ".venv", "venv", "__pycache__", "pods", ".git"]);
var BUILD_DIRS = /* @__PURE__ */ new Set(["dist", "build", "out", ".next", ".nuxt", ".output", "coverage", ".firebase", ".turbo", ".cache", "lib-cov"]);
function segments(path) {
  return path.split("/").filter((s) => s !== "");
}
function extensionOf(path) {
  const name = segments(path).at(-1) ?? "";
  const dot = name.lastIndexOf(".");
  return dot <= 0 ? "" : name.slice(dot + 1).toLowerCase();
}
function isTextFile(path) {
  const name = (segments(path).at(-1) ?? "").toLowerCase();
  if (TEXT_NAMES.has(name) || name.startsWith(".env.")) return true;
  return TEXT_EXTENSIONS.has(extensionOf(path));
}
function isTestPath(path) {
  const lower = path.toLowerCase();
  return /(^|\/)(__tests__|__mocks__|test|tests|spec|e2e|cypress|fixtures?)\//.test(lower) || /\.(test|spec|stories)\.[a-z]+$/.test(lower);
}
function isMinified(path, text) {
  if (/\.min\.(js|css)$/i.test(path)) return true;
  const lines = text.split("\n").length;
  return text.length > 5e3 && text.length / lines > MINIFIED_AVG_LINE;
}
function skipReason(file) {
  const segs = segments(file.path).slice(0, -1).map((s) => s.toLowerCase());
  if (segs.some((s) => DEPENDENCY_DIRS.has(s))) return "dependency_dir";
  if (segs.some((s) => BUILD_DIRS.has(s))) return "build_dir";
  if (!isTextFile(file.path)) return "not_text";
  if (byteLength(file.text) > MAX_FILE_BYTES) return "too_large";
  if (file.text.includes("\0")) return "binary";
  if (isTestPath(file.path)) return "test";
  if (isMinified(file.path, file.text)) return "minified";
  return null;
}
function selectFiles(input) {
  const skipped = Object.fromEntries(SKIP_REASONS.map((r) => [r, 0]));
  const byExtension = {};
  const files = [];
  const secretsOnly = [];
  let bytesRead = 0;
  const sorted = [...input].sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  for (const file of sorted) {
    const reason = skipReason(file);
    if (reason !== null) {
      skipped[reason] += 1;
      if (reason === "test" && secretsOnly.length < MAX_FILES_READ_INVENTED) secretsOnly.push(file);
      continue;
    }
    if (files.length >= MAX_FILES_READ_INVENTED) {
      skipped.over_limit += 1;
      continue;
    }
    files.push(file);
    bytesRead += byteLength(file.text);
    const ext = extensionOf(file.path) || "other";
    byExtension[ext] = (byExtension[ext] ?? 0) + 1;
  }
  return { files, secretsOnly, coverage: { filesRead: files.length, bytesRead, skipped, byExtension } };
}

// ../../../../../Users/User/AppData/Local/Temp/claude/8f433162ca0cb8b3/4a05b86d-fc4a-4091-891f-4e28333938c1/scratchpad/pub/src/core/analyzer/rules.ts
var TAG_BODY = "[^>]{0,600}>?";
var UI_EXTENSIONS = ["js", "jsx", "ts", "tsx", "mjs", "vue", "svelte", "astro", "html", "htm", "php"];
var CODE_EXTENSIONS = [...UI_EXTENSIONS, "cjs", "mts", "cts", "py", "rb", "go", "java", "kt", "swift", "dart", "cs"];
function assertGlobal(rule) {
  if (!rule.pattern.flags.includes("g")) throw new Error(`rule ${rule.kind} pattern must be global`);
}
function runRules(file, rules) {
  const ext = extensionOf(file.path);
  const locator = makeLocator(file.text);
  const out = [];
  for (const rule of rules) {
    assertGlobal(rule);
    if (rule.extensions !== void 0 && !rule.extensions.includes(ext)) continue;
    const seenLines = /* @__PURE__ */ new Set();
    rule.pattern.lastIndex = 0;
    for (const m of file.text.matchAll(rule.pattern)) {
      if (m.index === void 0) continue;
      if (rule.accept !== void 0 && !rule.accept(m[0])) continue;
      const line = locator.lineAt(m.index);
      if (seenLines.has(line)) continue;
      seenLines.add(line);
      const text = locator.lineText(line);
      if (isCommentLine(text)) continue;
      const evidence = evidenceAt(text, m.index - locator.lineStart(line));
      out.push({ kind: rule.kind, processType: rule.processType, path: file.path, line, evidence, confidence: rule.confidence });
    }
  }
  return out;
}

// ../../../../../Users/User/AppData/Local/Temp/claude/8f433162ca0cb8b3/4a05b86d-fc4a-4091-891f-4e28333938c1/scratchpad/pub/src/core/analyzer/network.ts
var URL_IN_STRING = /["'`(]\s*(https?:)?\/\/([a-z0-9-]+(?:\.[a-z0-9-]+)+)(?::\d+)?[/"'`?#)]/gi;
var IGNORED = /(?:^|\.)(?:w3\.org|schema\.org|example\.(?:com|org|net)|localhost|xmlns\.com|purl\.org|ogp\.me|json-schema\.org|mozilla\.org|developer\.mozilla\.org|reactjs\.org|react\.dev|nextjs\.org|typescriptlang\.org|npmjs\.com|github\.com|githubusercontent\.com|stackoverflow\.com|wikipedia\.org)$|^(?:127\.0\.0\.1|0\.0\.0\.0)$/i;
var CLASSES = [
  { test: /(?:^|\.)(?:stripe\.com|paypal\.com|paypalobjects\.com|braintreegateway\.com)$|cardcom|payplus|tranzila|meshulam|grow-il|hyp\.co\.il|isracard|pelecard|icredit/i, category: "payments", processType: "payments" },
  { test: /(?:^|\.)(?:fonts\.googleapis\.com|fonts\.gstatic\.com|use\.typekit\.net)$/i, category: "fonts", processType: "third_party" },
  { test: /(?:^|\.)(?:cdn\.jsdelivr\.net|unpkg\.com|cdnjs\.cloudflare\.com|code\.jquery\.com)$/i, category: "cdn", processType: "third_party" },
  { test: /(?:^|\.)(?:youtube\.com|youtube-nocookie\.com|vimeo\.com|player\.vimeo\.com)$/i, category: "video_embed", processType: "third_party" },
  { test: /(?:^|\.)(?:maps\.googleapis\.com|maps\.google\.com|api\.mapbox\.com|tile\.openstreetmap\.org)$/i, category: "maps", processType: "third_party" },
  { test: /(?:^|\.)(?:recaptcha\.net|challenges\.cloudflare\.com|hcaptcha\.com|google\.com)$/i, category: "captcha_or_google", processType: "third_party" },
  { test: /(?:^|\.)(?:api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|aiplatform\.googleapis\.com)$/i, category: "ai_api", processType: "third_party" },
  { test: /(?:^|\.)(?:firebaseio\.com|firestore\.googleapis\.com|firebasestorage\.googleapis\.com|supabase\.co|amazonaws\.com|cloudinary\.com)$/i, category: "storage_backend", processType: "third_party" }
];
function maskHostLabels(host) {
  return host.split(".").map((label) => label.length >= 12 && /[0-9]/.test(label) && /[a-z]/i.test(label) ? "*" : label).join(".");
}
function classifyHost(host) {
  const hit = CLASSES.find((c) => c.test.test(host));
  return hit === void 0 ? { category: "unknown", processType: "third_party" } : { category: hit.category, processType: hit.processType };
}
function hostFindings(file) {
  const ext = extensionOf(file.path);
  if (!CODE_EXTENSIONS.includes(ext) && ext !== "json") return [];
  const locator = makeLocator(file.text);
  const seen = /* @__PURE__ */ new Set();
  const out = [];
  URL_IN_STRING.lastIndex = 0;
  for (const m of file.text.matchAll(URL_IN_STRING)) {
    const host = (m[2] ?? "").toLowerCase();
    if (host === "" || IGNORED.test(host) || seen.has(host) || m.index === void 0) continue;
    const line = locator.lineAt(m.index);
    if (isCommentLine(locator.lineText(line))) continue;
    seen.add(host);
    const { category, processType } = classifyHost(host);
    const shown = maskHostLabels(host);
    out.push({ kind: `host:${category}:${shown}`, processType, path: file.path, line, evidence: evidenceFor(shown), confidence: category === "unknown" ? "low" : "medium" });
  }
  return out;
}

// ../../../../../Users/User/AppData/Local/Temp/claude/8f433162ca0cb8b3/4a05b86d-fc4a-4091-891f-4e28333938c1/scratchpad/pub/src/core/analyzer/rules-a11y.ts
var MARKUP = ["jsx", "tsx", "vue", "svelte", "astro", "html", "htm", "php"];
var STYLES = [...UI_EXTENSIONS, "css", "scss", "sass", "less"];
var tag = (names) => new RegExp(`<(?:${names})\\b${TAG_BODY}`, "g");
var A11Y_RULES = [
  { kind: "img_without_alt", processType: "accessibility", pattern: tag("img|Image"), accept: (t) => !/\balt\s{0,5}=/.test(t), confidence: "high", extensions: MARKUP },
  {
    kind: "click_on_non_button",
    processType: "accessibility",
    pattern: tag("div|span|li|img"),
    accept: (t) => /\b(?:onClick|@click|v-on:click|onclick)\s{0,5}=/.test(t) && !/\b(?:role|tabIndex|tabindex|onKeyDown|onKeyUp|onKeyPress|@keydown)\s{0,5}=/.test(t),
    confidence: "medium",
    extensions: MARKUP
  },
  { kind: "negative_tabindex", processType: "accessibility", pattern: /\btab[Ii]ndex\s{0,5}=\s{0,5}["'{]\s{0,5}-1\b/g, confidence: "low", extensions: MARKUP },
  { kind: "outline_removed", processType: "accessibility", pattern: /\boutline\s{0,5}:\s{0,5}(?:none|0)\b|\boutline-none\b/g, confidence: "low", extensions: STYLES },
  { kind: "autoplay_media", processType: "accessibility", pattern: tag("video|audio"), accept: (t) => /\bautoplay\b/i.test(t), confidence: "medium", extensions: MARKUP },
  { kind: "zoom_disabled", processType: "accessibility", pattern: /user-scalable\s{0,3}=\s{0,3}(?:no|0)|maximum-scale\s{0,3}=\s{0,3}1(?:\.0)?\b/g, confidence: "high", extensions: MARKUP },
  { kind: "accessibility_statement_link", processType: "accessibility", pattern: /href\s{0,5}=\s{0,5}["'{][^"'}\n]{0,200}(?:accessibility|נגישות)[^"'}\n]{0,200}["'}]/gi, confidence: "medium", extensions: MARKUP }
];
var HTML_ROOT = /<html\b([^>]{0,600})>?/gi;

// ../../../../../Users/User/AppData/Local/Temp/claude/8f433162ca0cb8b3/4a05b86d-fc4a-4091-891f-4e28333938c1/scratchpad/pub/src/core/analyzer/rules-commerce.ts
var UI = UI_EXTENSIONS;
var CODE = CODE_EXTENSIONS;
function isHiddenDecline(tag2) {
  if (!/ביטול|לא\s{1,3}תודה|דחייה|\bcancel\b|\bdecline\b|no\s{1,3}thanks/i.test(tag2)) return false;
  return /opacity\s{0,3}:\s{0,3}0?\.[0-3]|font-?size\s{0,3}:\s{0,3}(?:[0-9]|1[01])px|text-\[(?:[0-9]|1[01])px\]/i.test(tag2);
}
var COMMERCE_RULES = [
  { kind: "checkout_flow", processType: "payments", pattern: /\b(?:checkout|createPaymentIntent|paymentIntents\.create|createOrder|placeOrder)\b|תשלום\s+מאובטח|(?<![֐-׿])לתשלום/gi, confidence: "medium", extensions: CODE },
  { kind: "recurring_billing", processType: "subscription", pattern: /\b(?:subscriptions\.create|recurring|auto[_-]?renew|autoRenew|billing_cycle|interval\s*:\s*["'](?:month|year)["'])|הוראת\s+קבע|חידוש\s+אוטומטי|מנוי\s+חודשי/gi, confidence: "medium", extensions: CODE },
  { kind: "trial_period", processType: "subscription", pattern: /\b(?:trial_period_days|trialEnd|free_?trial|trial_end)\b|תקופת\s+ניסיון/gi, confidence: "medium", extensions: CODE },
  { kind: "cancel_flow", processType: "subscription", pattern: /\b(?:cancelSubscription|subscriptions\.(?:cancel|del)|cancel_at_period_end)\b|ביטול\s+(?:מנוי|עסקה|הזמנה)/gi, confidence: "medium", extensions: CODE },
  { kind: "refund_flow", processType: "distance_sale", pattern: /\b(?:refunds\.create|createRefund|refund)\s*\(|החזר\s+כספי|מדיניות\s+(?:החזרות|ביטולים)/gi, confidence: "medium", extensions: CODE },
  { kind: "shipping", processType: "distance_sale", pattern: /\b(?:shipping_?address|shippingAddress|shippingMethod|delivery_?date|deliveryDate)\b|דמי\s+משלוח|מועד\s+(?:אספקה|משלוח)/gi, confidence: "medium", extensions: CODE },
  { kind: "price_display", processType: "distance_sale", pattern: /(?:₪|ש["״]ח|\bILS\b)[ \t]{0,3}\{|\{[^}\n]{0,80}\}[ \t]{0,3}(?:₪|ש["״]ח)|\bIntl\.NumberFormat\([^)]{0,200}currency\s*:\s*["']ILS["']/g, confidence: "low", extensions: UI },
  { kind: "vat_handling", processType: "distance_sale", pattern: /\b(?:vat|VAT_RATE|vatRate|tax_rate)\b|מע["״]מ/g, confidence: "low", extensions: CODE }
];
var CONTENT_ACCOUNT_RULES = [
  { kind: "user_upload_storage", processType: "user_content", pattern: /\b(?:uploadBytes|uploadBytesResumable|putObject|PutObjectCommand|multer\s*\(|upload\.single|cloudinary\.uploader\.upload)\b/g, confidence: "high", extensions: CODE },
  { kind: "user_generated_post", processType: "user_content", pattern: /\b(?:createPost|addComment|postComment|submitReview|createReview|publishPost)\b/g, confidence: "medium", extensions: CODE },
  { kind: "content_report", processType: "user_content", pattern: /\b(?:reportContent|reportAbuse|flagContent|report_abuse)\b|דיווח\s+על\s+(?:תוכן|הפרה)/gi, confidence: "medium", extensions: CODE },
  { kind: "originality_declaration", processType: "user_content", pattern: /\b(?:ownsRights|originalContent|rightsDeclaration|copyrightConfirm)\b|(?:מצהיר|מאשר)[^<>{}\n]{0,30}(?:זכויות|מקורי)/gi, confidence: "medium", extensions: UI },
  { kind: "signup", processType: "account", pattern: /\b(?:createUserWithEmailAndPassword|signUp|signup|register(?:User)?|auth\.admin\.createUser)\s*\(/g, confidence: "high", extensions: CODE },
  { kind: "social_login", processType: "third_party", pattern: /\b(?:GoogleAuthProvider|FacebookAuthProvider|OAuthProvider|signInWithPopup|signInWithRedirect)\b|\bprovider\s*:\s*["'](?:google|facebook|github|apple)["']/g, confidence: "high", extensions: CODE },
  { kind: "account_deletion", processType: "account", pattern: /\b(?:deleteUser|deleteAccount|delete_account|auth\.admin\.deleteUser)\s*\(|מחיקת\s+(?:חשבון|משתמש)/gi, confidence: "high", extensions: CODE },
  { kind: "data_export", processType: "account", pattern: /\b(?:exportUserData|downloadMyData|export_data|dataExport)\b|ייצוא\s+(?:המידע|נתונים)/gi, confidence: "medium", extensions: CODE },
  { kind: "age_gate", processType: "minors", pattern: /\b(?:ageVerification|verifyAge|isAdult|minAge|min_age|age\s*[<>]=?\s*1[368])\b|מעל\s+גיל\s+1[368]|הסכמת\s+(?:הורה|הורים)|קטינים?/g, confidence: "medium", extensions: CODE }
];
var MESSAGING_RULES = [
  { kind: "email_send", processType: "marketing", pattern: /\b(?:sendMail|transporter\.sendMail|sgMail\.send|resend\.emails\.send|ses\.sendEmail|SendEmailCommand|mailchimp\.)/g, confidence: "medium", extensions: CODE },
  { kind: "sms_send", processType: "marketing", pattern: /\b(?:twilio|messages\.create\s{0,5}\(\s{0,5}\{[^}]{0,300}\bto\b|sendSms|send_sms|inforu|019sms)/gi, confidence: "medium", extensions: CODE },
  { kind: "unsubscribe", processType: "marketing", pattern: /\bunsubscribe\b|List-Unsubscribe|הסרה\s+מ(?:רשימת|הדיוור)|להסרה/gi, confidence: "medium", extensions: CODE },
  { kind: "push_permission", processType: "notifications", pattern: /\bNotification\.requestPermission\s*\(|\bgetToken\s*\(\s*messaging|\bpushManager\.subscribe\s*\(|\bOneSignal\b/g, confidence: "high", extensions: UI },
  { kind: "whatsapp_link", processType: "marketing", pattern: /\b(?:wa\.me|api\.whatsapp\.com|graph\.facebook\.com\/v\d+\.\d+\/\d+\/messages)\b/g, confidence: "medium", extensions: CODE }
];
var DARK_PATTERN_RULES = [
  { kind: "countdown_pressure", processType: "dark_pattern", pattern: /\b(?:countdown|CountdownTimer|timeLeft|expiresIn)\b|(?:נשארו|נותרו)[ \t]{1,5}(?:רק[ \t]{1,5})?(?:\{[^}\n]{0,40}\}|\d{1,6})?[ \t]{0,5}(?:דקות|שעות|יחידות|מקומות)|ההצעה[ \t]{1,5}(?:תפוג|נגמרת)/gi, confidence: "low", extensions: UI },
  { kind: "confirmshaming", processType: "dark_pattern", pattern: /(?:לא\s+תודה,?\s+אני\s+(?:לא\s+)?(?:רוצה|אוהב|צריך))|no\s+thanks,?\s+i\s+(?:don'?t|prefer)/gi, confidence: "medium", extensions: UI },
  { kind: "hidden_decline", processType: "dark_pattern", pattern: /<(?:button|a)\b[^>]{0,600}>?[^<]{0,200}/gi, accept: isHiddenDecline, confidence: "low", extensions: UI }
];

// ../../../../../Users/User/AppData/Local/Temp/claude/8f433162ca0cb8b3/4a05b86d-fc4a-4091-891f-4e28333938c1/scratchpad/pub/src/core/analyzer/rules-privacy.ts
var UI2 = UI_EXTENSIONS;
var CODE2 = CODE_EXTENSIONS;
var COOKIE_STORAGE_RULES = [
  { kind: "cookie_write_client", processType: "cookies_storage", pattern: /document\.cookie\s*=[^=]/g, confidence: "high", extensions: UI2 },
  { kind: "cookie_write_server", processType: "cookies_storage", pattern: /\bSet-Cookie\b|\bres\.cookie\s*\(|\bcookies\(\)\.set\s*\(|\bsetcookie\s*\(|\bset_cookie\s*\(/gi, confidence: "high", extensions: CODE2 },
  { kind: "cookie_library", processType: "cookies_storage", pattern: /\b(?:Cookies|cookies)\.set\s*\(|\bsetCookie\s*\(|\bnookies\.set\s*\(/g, confidence: "medium", extensions: CODE2 },
  { kind: "local_storage", processType: "cookies_storage", pattern: /\b(?:localStorage|sessionStorage)\.setItem\s*\(|\b(?:localStorage|sessionStorage)\[[^\]]+\]\s*=[^=]/g, confidence: "high", extensions: UI2 },
  { kind: "indexed_db", processType: "cookies_storage", pattern: /\bindexedDB\.open\s*\(/g, confidence: "medium", extensions: UI2 },
  { kind: "device_fingerprint", processType: "cookies_storage", pattern: /\bfingerprintjs\b|\bFingerprintJS\b|\bcanvas\.toDataURL\s*\(/g, confidence: "low", extensions: UI2 }
];
var FIELD_TAG = new RegExp(`<(?:input|textarea|select|Input|TextField)\\b${TAG_BODY}`, "g");
var field = (names) => {
  const attr = new RegExp(`\\b(?:name|id|autoComplete|autocomplete|type)\\s{0,5}=\\s{0,5}["'{]\\s{0,5}["']?(?:${names})\\b`);
  return { pattern: FIELD_TAG, accept: (t) => attr.test(t) };
};
function isPrechecked(tag2) {
  if (!/type\s{0,5}=\s{0,5}["'{]\s{0,5}["']?checkbox|<Checkbox\b/.test(tag2)) return false;
  if (/\bdefaultChecked\b(?!\s{0,5}=\s{0,5}\{\s{0,5}false\s{0,5}\})/.test(tag2)) return true;
  return /\bchecked\b(?!\s{0,5}=)|\bchecked\s{0,5}=\s{0,5}(?:\{\s{0,5}true\s{0,5}\}|["']?checked["']?|["']true["'])/.test(tag2);
}
var PERSONAL_DATA_RULES = [
  { kind: "field_email", processType: "personal_data", ...field("email|e-mail|mail"), confidence: "high", extensions: UI2 },
  { kind: "field_phone", processType: "personal_data", ...field("tel|phone|mobile|telephone|cellphone"), confidence: "high", extensions: UI2 },
  { kind: "field_id_number", processType: "personal_data", ...field("id_?number|idNumber|teudat|tz|national_?id|ssn|passport"), confidence: "high", extensions: UI2 },
  { kind: "field_address", processType: "personal_data", ...field("address|street|city|zip|postal|street-address|address-line1"), confidence: "high", extensions: UI2 },
  { kind: "field_birth_date", processType: "personal_data", ...field("birth|dob|bday|birthday|birthdate"), confidence: "high", extensions: UI2 },
  { kind: "field_name", processType: "personal_data", ...field("name|fullName|full_name|firstName|first_name|lastName|last_name|given-name|family-name"), confidence: "medium", extensions: UI2 },
  { kind: "field_card", processType: "payments", ...field("cc-number|cardNumber|card_number|cc-csc|cvv|cvc"), confidence: "high", extensions: UI2 },
  { kind: "field_health", processType: "personal_data", ...field("health|medical|diagnosis|allerg|medication|disability"), confidence: "medium", extensions: UI2 },
  { kind: "field_file_upload", processType: "user_content", ...field("file"), confidence: "high", extensions: UI2 },
  { kind: "geolocation", processType: "personal_data", pattern: /navigator\.geolocation\.(?:getCurrentPosition|watchPosition)\s*\(/g, confidence: "high", extensions: UI2 },
  { kind: "camera_microphone", processType: "personal_data", pattern: /navigator\.mediaDevices\.getUserMedia\s*\(/g, confidence: "high", extensions: UI2 },
  { kind: "contacts_access", processType: "personal_data", pattern: /navigator\.contacts\.select\s*\(/g, confidence: "high", extensions: UI2 }
];
var CONSENT_RULES = [
  {
    kind: "checkbox_prechecked",
    processType: "dark_pattern",
    pattern: new RegExp(`<(?:input|Checkbox|Input)\\b${TAG_BODY}`, "g"),
    accept: isPrechecked,
    confidence: "medium",
    extensions: UI2
  },
  { kind: "marketing_consent_field", processType: "marketing", pattern: /\b(?:newsletter|marketing|promotions?|subscribe|optIn|opt_in|acceptMarketing)\b|דיוור|ניוזלטר|עדכונים\s+ומבצעים/gi, confidence: "low", extensions: UI2 },
  { kind: "terms_acceptance", processType: "distance_sale", pattern: /\b(?:acceptTerms|agreeTerms|termsAccepted|tosAccepted|terms_accepted|agree_to_terms)\b|(?:אני\s+)?(?:מסכימ|מאשר)[^<>{}\n]{0,30}(?:תנאי\s+השימוש|התקנון)/gi, confidence: "medium", extensions: UI2 },
  { kind: "privacy_link", processType: "personal_data", pattern: /href\s{0,5}=\s{0,5}["'{][^"'}\n]{0,200}(?:privacy|פרטיות)[^"'}\n]{0,200}["'}]/gi, confidence: "medium", extensions: UI2 },
  { kind: "cookie_banner", processType: "cookies_storage", pattern: /\b(?:CookieConsent|cookieconsent|CookieBanner|cookie-banner|cookiebot|onetrust|klaro|iubenda|usercentrics|complianz)\b|(?:באנר|הודעת)\s+עוגיות/gi, confidence: "medium", extensions: UI2 },
  { kind: "consent_mode", processType: "cookies_storage", pattern: /gtag\s*\(\s*["']consent["']/g, confidence: "high", extensions: UI2 }
];

// ../../../../../Users/User/AppData/Local/Temp/claude/8f433162ca0cb8b3/4a05b86d-fc4a-4091-891f-4e28333938c1/scratchpad/pub/src/core/analyzer/trackers.ts
var TRACKERS = [
  { id: "google-tag-manager", signature: /googletagmanager\.com\/(?:gtm\.js|ns\.html)|["'=]GTM-[A-Z0-9]{4,}["'&]/g },
  { id: "google-analytics", signature: /googletagmanager\.com\/gtag\/js|google-analytics\.com\/(?:analytics|ga)\.js|\bgtag\s*\(\s*["']config["']|["'=]G-[A-Z0-9]{6,}["'&]|["'=]UA-\d{4,}-\d+["'&]|\bfirebase\/analytics\b|\bgetAnalytics\s*\(/g },
  { id: "meta-pixel", signature: /connect\.facebook\.net\/[^"']*\/fbevents\.js|\bfbq\s*\(\s*["']init["']|react-facebook-pixel/gi },
  { id: "hotjar", signature: /static\.hotjar\.com|\bhj\s*\(\s*["']|@hotjar\/browser/gi },
  { id: "microsoft-clarity", signature: /clarity\.ms\/tag|\bclarity\s*\(\s*["']|@microsoft\/clarity/gi },
  { id: "cloudflare-web-analytics", signature: /static\.cloudflareinsights\.com\/beacon/gi },
  { id: "tiktok-pixel", signature: /analytics\.tiktok\.com|\bttq\.load\s*\(/gi },
  { id: "linkedin-insight", signature: /snap\.licdn\.com|_linkedin_partner_id/gi },
  { id: "taboola-outbrain", signature: /cdn\.taboola\.com|widgets\.outbrain\.com/gi },
  { id: "mixpanel", signature: /\bmixpanel\.init\s*\(|mixpanel-browser/gi },
  { id: "amplitude", signature: /@amplitude\/analytics-browser|\bamplitude\.init\s*\(/gi },
  { id: "posthog", signature: /\bposthog\.init\s*\(|posthog-js/gi },
  { id: "segment", signature: /cdn\.segment\.com|@segment\/analytics-next/gi },
  { id: "vercel-analytics", signature: /@vercel\/analytics/gi },
  { id: "session-replay", signature: /logrocket|@fullstory\/browser|\bLogRocket\.init\s*\(/gi }
];
var TRACKER_RULES = TRACKERS.map(({ id, signature }) => ({
  kind: `tracker:${id}`,
  processType: "third_party",
  pattern: signature,
  confidence: "high",
  extensions: [...CODE_EXTENSIONS, "json"]
}));

// ../../../../../Users/User/AppData/Local/Temp/claude/8f433162ca0cb8b3/4a05b86d-fc4a-4091-891f-4e28333938c1/scratchpad/pub/src/core/analyzer/vendors.ts
var VENDORS = [
  // תשלום
  { pkg: "stripe", vendor: "stripe", processType: "payments" },
  { pkg: "@stripe/", vendor: "stripe", processType: "payments" },
  { pkg: "@paypal/", vendor: "paypal", processType: "payments" },
  { pkg: "braintree", vendor: "braintree", processType: "payments" },
  { pkg: "braintree-web", vendor: "braintree", processType: "payments" },
  // התחברות וזהות
  { pkg: "next-auth", vendor: "next-auth", processType: "account" },
  { pkg: "@auth0/", vendor: "auth0", processType: "account" },
  { pkg: "@clerk/", vendor: "clerk", processType: "account" },
  { pkg: "@supabase/supabase-js", vendor: "supabase", processType: "account" },
  { pkg: "firebase", vendor: "firebase", processType: "third_party" },
  { pkg: "firebase-admin", vendor: "firebase", processType: "third_party" },
  { pkg: "passport", vendor: "passport", processType: "account" },
  // ניטור תקלות והקלטת סשן
  { pkg: "@sentry/", vendor: "sentry", processType: "third_party" },
  { pkg: "sentry-sdk", vendor: "sentry", processType: "third_party" },
  { pkg: "logrocket", vendor: "logrocket", processType: "third_party" },
  { pkg: "@fullstory/", vendor: "fullstory", processType: "third_party" },
  // אנליטיקה
  { pkg: "react-ga", vendor: "google-analytics", processType: "third_party" },
  { pkg: "react-ga4", vendor: "google-analytics", processType: "third_party" },
  { pkg: "mixpanel-browser", vendor: "mixpanel", processType: "third_party" },
  { pkg: "mixpanel", vendor: "mixpanel", processType: "third_party" },
  { pkg: "@amplitude/", vendor: "amplitude", processType: "third_party" },
  { pkg: "posthog-js", vendor: "posthog", processType: "third_party" },
  { pkg: "@segment/", vendor: "segment", processType: "third_party" },
  { pkg: "@vercel/analytics", vendor: "vercel-analytics", processType: "third_party" },
  { pkg: "@microsoft/clarity", vendor: "microsoft-clarity", processType: "third_party" },
  { pkg: "@hotjar/browser", vendor: "hotjar", processType: "third_party" },
  { pkg: "react-facebook-pixel", vendor: "meta-pixel", processType: "third_party" },
  // עוגיות והסכמה
  { pkg: "js-cookie", vendor: "js-cookie", processType: "cookies_storage" },
  { pkg: "universal-cookie", vendor: "universal-cookie", processType: "cookies_storage" },
  { pkg: "react-cookie", vendor: "react-cookie", processType: "cookies_storage" },
  { pkg: "cookies-next", vendor: "cookies-next", processType: "cookies_storage" },
  { pkg: "nookies", vendor: "nookies", processType: "cookies_storage" },
  { pkg: "cookie-parser", vendor: "cookie-parser", processType: "cookies_storage" },
  { pkg: "react-cookie-consent", vendor: "react-cookie-consent", processType: "cookies_storage" },
  { pkg: "vanilla-cookieconsent", vendor: "cookieconsent", processType: "cookies_storage" },
  // דיוור, SMS והתראות
  { pkg: "nodemailer", vendor: "nodemailer", processType: "marketing" },
  { pkg: "@sendgrid/mail", vendor: "sendgrid", processType: "marketing" },
  { pkg: "sendgrid", vendor: "sendgrid", processType: "marketing" },
  { pkg: "@mailchimp/", vendor: "mailchimp", processType: "marketing" },
  { pkg: "resend", vendor: "resend", processType: "marketing" },
  { pkg: "twilio", vendor: "twilio", processType: "marketing" },
  { pkg: "web-push", vendor: "web-push", processType: "notifications" },
  { pkg: "react-onesignal", vendor: "onesignal", processType: "notifications" },
  { pkg: "expo-notifications", vendor: "expo-notifications", processType: "notifications" },
  // העלאת תוכן ואחסון
  { pkg: "multer", vendor: "multer", processType: "user_content" },
  { pkg: "react-dropzone", vendor: "react-dropzone", processType: "user_content" },
  { pkg: "@aws-sdk/client-s3", vendor: "aws-s3", processType: "user_content" },
  { pkg: "cloudinary", vendor: "cloudinary", processType: "user_content" },
  { pkg: "uploadthing", vendor: "uploadthing", processType: "user_content" },
  // מפות וצ'אט
  { pkg: "@react-google-maps/api", vendor: "google-maps", processType: "third_party" },
  { pkg: "mapbox-gl", vendor: "mapbox", processType: "third_party" },
  { pkg: "@intercom/messenger-js-sdk", vendor: "intercom", processType: "third_party" },
  { pkg: "crisp-sdk-web", vendor: "crisp", processType: "third_party" },
  { pkg: "@tawk.to/tawk-messenger-react", vendor: "tawk", processType: "third_party" },
  // שירותי AI (מידע של משתמשים שעשוי לעבור לספק מודל)
  { pkg: "openai", vendor: "openai", processType: "third_party" },
  { pkg: "@anthropic-ai/sdk", vendor: "anthropic", processType: "third_party" },
  { pkg: "anthropic", vendor: "anthropic", processType: "third_party" },
  { pkg: "@google/genai", vendor: "google-genai", processType: "third_party" },
  { pkg: "@google/generative-ai", vendor: "google-genai", processType: "third_party" },
  { pkg: "@google-cloud/vertexai", vendor: "google-vertex", processType: "third_party" }
];
function vendorFor(pkg) {
  const name = pkg.trim().toLowerCase();
  return VENDORS.find((v) => v.pkg.endsWith("/") ? name.startsWith(v.pkg) : name === v.pkg);
}
function fileName(path) {
  return (path.split("/").at(-1) ?? "").toLowerCase();
}
function dependenciesOf(file) {
  const name = fileName(file.path);
  const locator = makeLocator(file.text);
  const out = [];
  if (name === "package.json") {
    let parsed;
    try {
      parsed = JSON.parse(file.text);
    } catch {
      return [];
    }
    if (typeof parsed !== "object" || parsed === null) return [];
    const record = parsed;
    for (const section of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
      const deps = record[section];
      if (typeof deps !== "object" || deps === null) continue;
      for (const dep of Object.keys(deps)) {
        const at = file.text.indexOf(`"${dep}"`);
        out.push({ name: dep, line: at < 0 ? 1 : locator.lineAt(at) });
      }
    }
    return out;
  }
  if (name === "requirements.txt" || name.endsWith("-requirements.txt")) {
    file.text.split("\n").forEach((raw, i) => {
      const dep = /^\s*([A-Za-z0-9_.-]+)/.exec(raw.replace(/#.*/, ""))?.[1];
      if (dep !== void 0) out.push({ name: dep, line: i + 1 });
    });
  }
  return out;
}
function vendorFindings(file) {
  const out = [];
  const seen = /* @__PURE__ */ new Set();
  for (const dep of dependenciesOf(file)) {
    const entry = vendorFor(dep.name);
    if (entry === void 0 || seen.has(entry.vendor)) continue;
    seen.add(entry.vendor);
    out.push({
      kind: `vendor:${entry.vendor}`,
      processType: entry.processType,
      path: file.path,
      line: dep.line,
      evidence: evidenceFor(dep.name),
      confidence: "high"
    });
  }
  return out;
}

// ../../../../../Users/User/AppData/Local/Temp/claude/8f433162ca0cb8b3/4a05b86d-fc4a-4091-891f-4e28333938c1/scratchpad/pub/src/core/analyzer/analyze.ts
var ALL_RULES = [
  ...COOKIE_STORAGE_RULES,
  ...PERSONAL_DATA_RULES,
  ...CONSENT_RULES,
  ...COMMERCE_RULES,
  ...CONTENT_ACCOUNT_RULES,
  ...MESSAGING_RULES,
  ...DARK_PATTERN_RULES,
  ...A11Y_RULES,
  ...TRACKER_RULES
];
function maskFile(file) {
  const hits = findSecrets(file.text);
  if (hits.length === 0) return { masked: file, secrets: [] };
  const masked = { path: file.path, text: maskSecrets(file.text, hits) };
  const locator = makeLocator(file.text);
  const secrets = hits.filter((hit) => !hit.placeholder).map((hit) => ({ kind: `secret:${hit.id}`, processType: "security", path: file.path, line: locator.lineAt(hit.index), evidence: SECRET_EVIDENCE, confidence: "high" }));
  return { masked, secrets };
}
var SECRET_EVIDENCE = "[REDACTED]: \u05E0\u05DE\u05E6\u05D0 \u05E2\u05E8\u05DA \u05E1\u05D5\u05D3\u05D9 \u05D1\u05E9\u05D5\u05E8\u05D4 \u05D4\u05D6\u05D5. \u05D4\u05E2\u05E8\u05DA \u05D0\u05D9\u05E0\u05D5 \u05E0\u05E9\u05DE\u05E8";
function htmlRootFindings(file) {
  if (!["html", "htm", "tsx", "jsx", "php", "astro", "vue"].includes(extensionOf(file.path))) return [];
  const locator = makeLocator(file.text);
  const out = [];
  for (const m of file.text.matchAll(HTML_ROOT)) {
    if (m.index === void 0) continue;
    const attrs = m[1] ?? "";
    const line = locator.lineAt(m.index);
    const evidence = evidenceAt(locator.lineText(line), m.index - locator.lineStart(line));
    if (!/\blang\s*=/i.test(attrs)) out.push({ kind: "html_without_lang", processType: "accessibility", path: file.path, line, evidence, confidence: "high" });
    if (!/\bdir\s*=/i.test(attrs)) out.push({ kind: "html_without_dir", processType: "accessibility", path: file.path, line, evidence, confidence: "medium" });
  }
  return out;
}
function byLocation(a, b) {
  if (a.path !== b.path) return a.path < b.path ? -1 : 1;
  if (a.line !== b.line) return a.line - b.line;
  return a.kind < b.kind ? -1 : a.kind > b.kind ? 1 : 0;
}
function analyzeRepo(input) {
  const { files, secretsOnly, coverage } = selectFiles(input);
  const all = [];
  for (const file of secretsOnly) all.push(...maskFile(file).secrets);
  for (const file of files) {
    const { masked, secrets } = maskFile(file);
    all.push(...secrets, ...vendorFindings(file), ...hostFindings(masked), ...htmlRootFindings(masked), ...runRules(masked, ALL_RULES));
  }
  all.sort(byLocation);
  const totals = {};
  const findings = [];
  let hosts = 0;
  for (const finding of all) {
    const count = (totals[finding.kind] ?? 0) + 1;
    totals[finding.kind] = count;
    if (count > MAX_FINDINGS_PER_KIND) continue;
    if (finding.kind.startsWith("host:")) {
      hosts += 1;
      if (hosts > MAX_HOST_FINDINGS) continue;
    }
    findings.push(finding);
  }
  return { findings, totals, coverage };
}

// ../../../../../Users/User/AppData/Local/Temp/claude/8f433162ca0cb8b3/4a05b86d-fc4a-4091-891f-4e28333938c1/scratchpad/pub/src/core/client-findings.ts
var CLIENT_FINDINGS_SCHEMA_VERSION = 1;
var REFERENCES_PER_KIND_INVENTED = 5;
var CONFIDENCE_RANK = { low: 0, medium: 1, high: 2 };
function byLocation2(a, b) {
  return a.path === b.path ? a.line - b.line : a.path < b.path ? -1 : 1;
}
function buildClientFindings(result, analyzerVersion) {
  const groups = /* @__PURE__ */ new Map();
  for (const finding of result.findings) {
    const list = groups.get(finding.kind);
    if (list) list.push(finding);
    else groups.set(finding.kind, [finding]);
  }
  const processes = [...groups.entries()].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([kind, list]) => {
    const sorted = [...list].sort(byLocation2);
    const confidence = sorted.reduce(
      (best, f) => CONFIDENCE_RANK[f.confidence] > CONFIDENCE_RANK[best] ? f.confidence : best,
      "low"
    );
    return {
      kind,
      processType: sorted[0]?.processType ?? "security",
      confidence,
      count: Math.max(result.totals[kind] ?? 0, sorted.length),
      references: sorted.slice(0, REFERENCES_PER_KIND_INVENTED).map((f) => ({ path: f.path, line: f.line }))
    };
  });
  const { skipped } = result.coverage;
  return {
    schemaVersion: CLIENT_FINDINGS_SCHEMA_VERSION,
    analyzerVersion,
    processes,
    coverage: result.coverage,
    partialCoverage: skipped.too_large > 0 || skipped.over_limit > 0
  };
}

// ../../../../../Users/User/AppData/Local/Temp/claude/8f433162ca0cb8b3/4a05b86d-fc4a-4091-891f-4e28333938c1/scratchpad/pub/src/core/client/process-labels.ts
var EXACT = {
  accessibility_statement_link: "\u05E7\u05D9\u05E9\u05D5\u05E8 \u05DC\u05D4\u05E6\u05D4\u05E8\u05EA \u05E0\u05D2\u05D9\u05E9\u05D5\u05EA",
  account_deletion: "\u05DE\u05D7\u05D9\u05E7\u05EA \u05D7\u05E9\u05D1\u05D5\u05DF \u05DE\u05E9\u05EA\u05DE\u05E9",
  age_gate: "\u05D1\u05D3\u05D9\u05E7\u05EA \u05D2\u05D9\u05DC \u05D0\u05D5 \u05D4\u05E1\u05DB\u05DE\u05EA \u05D4\u05D5\u05E8\u05D4",
  autoplay_media: "\u05DE\u05D3\u05D9\u05D4 \u05E9\u05DE\u05EA\u05D7\u05D9\u05DC\u05D4 \u05DC\u05E0\u05D2\u05DF \u05DE\u05E2\u05E6\u05DE\u05D4",
  camera_microphone: "\u05D2\u05D9\u05E9\u05D4 \u05DC\u05DE\u05E6\u05DC\u05DE\u05D4 \u05D0\u05D5 \u05DC\u05DE\u05D9\u05E7\u05E8\u05D5\u05E4\u05D5\u05DF",
  cancel_flow: "\u05EA\u05D4\u05DC\u05D9\u05DA \u05D1\u05D9\u05D8\u05D5\u05DC (\u05DE\u05E0\u05D5\u05D9 \u05D0\u05D5 \u05D4\u05D6\u05DE\u05E0\u05D4)",
  checkbox_prechecked: "\u05EA\u05D9\u05D1\u05EA \u05D4\u05E1\u05DB\u05DE\u05D4 \u05E9\u05DE\u05E1\u05D5\u05DE\u05E0\u05EA \u05DE\u05E8\u05D0\u05E9",
  checkout_flow: "\u05EA\u05D4\u05DC\u05D9\u05DA \u05EA\u05E9\u05DC\u05D5\u05DD \u05D0\u05D5 \u05E7\u05D5\u05E4\u05D4",
  click_on_non_button: "\u05E8\u05DB\u05D9\u05D1 \u05E9\u05E0\u05DC\u05D7\u05E5 \u05D1\u05E2\u05DB\u05D1\u05E8 \u05D1\u05DC\u05D9 \u05EA\u05DE\u05D9\u05DB\u05D4 \u05D1\u05DE\u05E7\u05DC\u05D3\u05EA",
  confirmshaming: "\u05E0\u05D9\u05E1\u05D5\u05D7 \u05E9\u05DE\u05DC\u05D7\u05D9\u05E5 \u05DE\u05E9\u05EA\u05DE\u05E9 \u05E9\u05D3\u05D5\u05D7\u05D4 \u05D4\u05E6\u05E2\u05D4",
  consent_mode: "\u05D4\u05D2\u05D3\u05E8\u05EA \u05D4\u05E1\u05DB\u05DE\u05D4 \u05DC\u05E2\u05D5\u05D2\u05D9\u05D5\u05EA \u05D5\u05DC\u05DE\u05D3\u05D9\u05D3\u05D4",
  contacts_access: "\u05D2\u05D9\u05E9\u05D4 \u05DC\u05D0\u05E0\u05E9\u05D9 \u05D4\u05E7\u05E9\u05E8 \u05E9\u05DC \u05D4\u05DE\u05E9\u05EA\u05DE\u05E9",
  content_report: "\u05D3\u05D9\u05D5\u05D5\u05D7 \u05E2\u05DC \u05EA\u05D5\u05DB\u05DF \u05D0\u05D5 \u05E2\u05DC \u05D4\u05E4\u05E8\u05D4",
  cookie_banner: "\u05D1\u05D0\u05E0\u05E8 \u05E2\u05D5\u05D2\u05D9\u05D5\u05EA",
  cookie_library: "\u05E1\u05E4\u05E8\u05D9\u05D9\u05D4 \u05DC\u05E0\u05D9\u05D4\u05D5\u05DC \u05E2\u05D5\u05D2\u05D9\u05D5\u05EA",
  cookie_write_client: "\u05DB\u05EA\u05D9\u05D1\u05EA \u05E2\u05D5\u05D2\u05D9\u05D4 \u05DE\u05D3\u05E4\u05D3\u05E4\u05DF \u05D4\u05DE\u05E9\u05EA\u05DE\u05E9",
  cookie_write_server: "\u05DB\u05EA\u05D9\u05D1\u05EA \u05E2\u05D5\u05D2\u05D9\u05D4 \u05DE\u05D4\u05E9\u05E8\u05EA",
  countdown_pressure: "\u05D8\u05D9\u05D9\u05DE\u05E8 \u05D0\u05D5 \u05E1\u05E4\u05D9\u05E8\u05D4 \u05DC\u05D0\u05D7\u05D5\u05E8 \u05E9\u05D9\u05D5\u05E6\u05E8\u05D9\u05DD \u05DC\u05D7\u05E5",
  data_export: "\u05D9\u05D9\u05E6\u05D5\u05D0 \u05DE\u05D9\u05D3\u05E2 \u05D0\u05D9\u05E9\u05D9 \u05DC\u05DE\u05E9\u05EA\u05DE\u05E9",
  device_fingerprint: "\u05D6\u05D9\u05D4\u05D5\u05D9 \u05D4\u05DE\u05DB\u05E9\u05D9\u05E8 \u05DC\u05E4\u05D9 \u05DE\u05D0\u05E4\u05D9\u05D9\u05E0\u05D9\u05D5",
  email_send: "\u05E9\u05DC\u05D9\u05D7\u05EA \u05DE\u05D9\u05D9\u05DC\u05D9\u05DD",
  field_address: "\u05D0\u05D9\u05E1\u05D5\u05E3 \u05DB\u05EA\u05D5\u05D1\u05EA \u05DE\u05D2\u05D5\u05E8\u05D9\u05DD",
  field_birth_date: "\u05D0\u05D9\u05E1\u05D5\u05E3 \u05EA\u05D0\u05E8\u05D9\u05DA \u05DC\u05D9\u05D3\u05D4",
  field_card: "\u05D0\u05D9\u05E1\u05D5\u05E3 \u05E4\u05E8\u05D8\u05D9 \u05DB\u05E8\u05D8\u05D9\u05E1 \u05D0\u05E9\u05E8\u05D0\u05D9",
  field_email: "\u05D0\u05D9\u05E1\u05D5\u05E3 \u05DB\u05EA\u05D5\u05D1\u05EA \u05DE\u05D9\u05D9\u05DC",
  field_file_upload: "\u05D4\u05E2\u05DC\u05D0\u05EA \u05E7\u05D1\u05E6\u05D9\u05DD \u05E2\u05DC \u05D9\u05D3\u05D9 \u05DE\u05E9\u05EA\u05DE\u05E9\u05D9\u05DD",
  field_health: "\u05D0\u05D9\u05E1\u05D5\u05E3 \u05DE\u05D9\u05D3\u05E2 \u05D1\u05E8\u05D9\u05D0\u05D5\u05EA\u05D9",
  field_id_number: "\u05D0\u05D9\u05E1\u05D5\u05E3 \u05DE\u05E1\u05E4\u05E8 \u05D6\u05D4\u05D5\u05EA",
  field_name: "\u05D0\u05D9\u05E1\u05D5\u05E3 \u05E9\u05DD",
  field_phone: "\u05D0\u05D9\u05E1\u05D5\u05E3 \u05DE\u05E1\u05E4\u05E8 \u05D8\u05DC\u05E4\u05D5\u05DF",
  geolocation: "\u05E9\u05D9\u05DE\u05D5\u05E9 \u05D1\u05DE\u05D9\u05E7\u05D5\u05DD \u05D4\u05DE\u05E9\u05EA\u05DE\u05E9",
  hidden_decline: "\u05DB\u05E4\u05EA\u05D5\u05E8 \u05D3\u05D7\u05D9\u05D9\u05D4 \u05E9\u05DE\u05D5\u05E1\u05EA\u05E8 \u05D0\u05D5 \u05DE\u05D5\u05D7\u05DC\u05E9",
  html_without_dir: "\u05D3\u05E3 \u05D1\u05DC\u05D9 \u05D4\u05D2\u05D3\u05E8\u05EA \u05DB\u05D9\u05D5\u05D5\u05DF \u05DB\u05EA\u05D9\u05D1\u05D4",
  html_without_lang: "\u05D3\u05E3 \u05D1\u05DC\u05D9 \u05D4\u05D2\u05D3\u05E8\u05EA \u05E9\u05E4\u05D4",
  img_without_alt: "\u05EA\u05DE\u05D5\u05E0\u05D4 \u05D1\u05DC\u05D9 \u05D8\u05E7\u05E1\u05D8 \u05D7\u05DC\u05D5\u05E4\u05D9",
  indexed_db: "\u05E9\u05DE\u05D9\u05E8\u05EA \u05DE\u05D9\u05D3\u05E2 \u05D1\u05DE\u05E1\u05D3 \u05E0\u05EA\u05D5\u05E0\u05D9\u05DD \u05D1\u05D3\u05E4\u05D3\u05E4\u05DF",
  local_storage: "\u05E9\u05DE\u05D9\u05E8\u05EA \u05DE\u05D9\u05D3\u05E2 \u05D1\u05D0\u05D7\u05E1\u05D5\u05DF \u05D4\u05DE\u05E7\u05D5\u05DE\u05D9 \u05E9\u05DC \u05D4\u05D3\u05E4\u05D3\u05E4\u05DF",
  marketing_consent_field: "\u05D4\u05E1\u05DB\u05DE\u05D4 \u05DC\u05E7\u05D1\u05DC\u05EA \u05D3\u05D9\u05D5\u05D5\u05E8 \u05E9\u05D9\u05D5\u05D5\u05E7\u05D9",
  negative_tabindex: "\u05E8\u05DB\u05D9\u05D1 \u05E9\u05D4\u05D5\u05E6\u05D0 \u05DE\u05E1\u05D3\u05E8 \u05D4\u05E0\u05D9\u05D5\u05D5\u05D8 \u05D1\u05DE\u05E7\u05DC\u05D3\u05EA",
  originality_declaration: "\u05D4\u05E6\u05D4\u05E8\u05EA \u05DE\u05E7\u05D5\u05E8\u05D9\u05D5\u05EA \u05E2\u05DC \u05EA\u05D5\u05DB\u05DF \u05E9\u05DE\u05D5\u05E2\u05DC\u05D4",
  outline_removed: "\u05D4\u05E1\u05E8\u05EA \u05E1\u05D9\u05DE\u05D5\u05DF \u05D4\u05DE\u05D9\u05E7\u05D5\u05D3 \u05D1\u05DE\u05E7\u05DC\u05D3\u05EA",
  price_display: "\u05D4\u05E6\u05D2\u05EA \u05DE\u05D7\u05D9\u05E8",
  privacy_link: "\u05E7\u05D9\u05E9\u05D5\u05E8 \u05DC\u05DE\u05D3\u05D9\u05E0\u05D9\u05D5\u05EA \u05E4\u05E8\u05D8\u05D9\u05D5\u05EA",
  push_permission: "\u05D1\u05E7\u05E9\u05EA \u05D4\u05E8\u05E9\u05D0\u05D4 \u05DC\u05D4\u05EA\u05E8\u05D0\u05D5\u05EA",
  recurring_billing: "\u05D7\u05D9\u05D5\u05D1 \u05D7\u05D5\u05D6\u05E8 \u05D0\u05D5 \u05DE\u05E0\u05D5\u05D9 \u05DE\u05EA\u05D7\u05D3\u05E9",
  refund_flow: "\u05EA\u05D4\u05DC\u05D9\u05DA \u05D4\u05D7\u05D6\u05E8 \u05DB\u05E1\u05E4\u05D9",
  shipping: "\u05DE\u05E9\u05DC\u05D5\u05D7 \u05DE\u05D5\u05E6\u05E8\u05D9\u05DD",
  signup: "\u05D4\u05E8\u05E9\u05DE\u05EA \u05DE\u05E9\u05EA\u05DE\u05E9\u05D9\u05DD",
  sms_send: "\u05E9\u05DC\u05D9\u05D7\u05EA \u05D4\u05D5\u05D3\u05E2\u05D5\u05EA SMS",
  social_login: "\u05D4\u05EA\u05D7\u05D1\u05E8\u05D5\u05EA \u05D3\u05E8\u05DA \u05E8\u05E9\u05EA \u05D7\u05D1\u05E8\u05EA\u05D9\u05EA",
  terms_acceptance: "\u05D0\u05D9\u05E9\u05D5\u05E8 \u05EA\u05E0\u05D0\u05D9 \u05E9\u05D9\u05DE\u05D5\u05E9",
  trial_period: "\u05EA\u05E7\u05D5\u05E4\u05EA \u05E0\u05D9\u05E1\u05D9\u05D5\u05DF",
  unsubscribe: "\u05D4\u05E1\u05E8\u05D4 \u05DE\u05E8\u05E9\u05D9\u05DE\u05EA \u05D3\u05D9\u05D5\u05D5\u05E8",
  user_generated_post: "\u05E4\u05E8\u05E1\u05D5\u05DD \u05EA\u05D5\u05DB\u05DF \u05E2\u05DC \u05D9\u05D3\u05D9 \u05DE\u05E9\u05EA\u05DE\u05E9\u05D9\u05DD",
  user_upload_storage: "\u05D0\u05D7\u05E1\u05D5\u05DF \u05E7\u05D1\u05E6\u05D9\u05DD \u05E9\u05DE\u05E9\u05EA\u05DE\u05E9\u05D9\u05DD \u05D4\u05E2\u05DC\u05D5",
  vat_handling: '\u05D8\u05D9\u05E4\u05D5\u05DC \u05D1\u05DE\u05E2"\u05DE',
  whatsapp_link: "\u05E7\u05D9\u05E9\u05D5\u05E8 \u05DC\u05D5\u05D5\u05D0\u05D8\u05E1\u05D0\u05E4",
  zoom_disabled: "\u05D7\u05E1\u05D9\u05DE\u05EA \u05D4\u05D2\u05D3\u05DC\u05D4 \u05D1\u05DE\u05DB\u05E9\u05D9\u05E8\u05D9\u05DD \u05E0\u05D9\u05D9\u05D3\u05D9\u05DD"
};
var SECRET_LABEL = "\u05E2\u05E8\u05DA \u05E1\u05D5\u05D3\u05D9 (\u05DE\u05E4\u05EA\u05D7 \u05D0\u05D5 \u05E1\u05D9\u05E1\u05DE\u05D4) \u05E9\u05E0\u05DE\u05E6\u05D0 \u05D1\u05E7\u05D5\u05D3. \u05D4\u05E2\u05E8\u05DA \u05E2\u05E6\u05DE\u05D5 \u05D0\u05D9\u05E0\u05D5 \u05E0\u05E9\u05DC\u05D7";
function describeKind(kind) {
  const exact = EXACT[kind];
  if (exact) return exact;
  const [prefix, ...rest] = kind.split(":");
  const tail = rest.join(":");
  switch (prefix) {
    case "tracker":
      return `\u05D8\u05E8\u05E7\u05E8 \u05D0\u05D5 \u05E4\u05D9\u05E7\u05E1\u05DC \u05DE\u05D3\u05D9\u05D3\u05D4: ${tail}`;
    case "vendor":
      return `\u05E1\u05E4\u05E7 \u05D0\u05D5 \u05E1\u05E4\u05E8\u05D9\u05D9\u05D4 \u05D7\u05D9\u05E6\u05D5\u05E0\u05D9\u05EA: ${tail}`;
    case "host": {
      const [category, ...host] = rest;
      return `\u05E4\u05E0\u05D9\u05D9\u05D4 \u05DC\u05E9\u05E8\u05EA \u05D7\u05D9\u05E6\u05D5\u05E0\u05D9 (${category ?? "\u05DC\u05D0 \u05DE\u05E1\u05D5\u05D5\u05D2"}): ${host.join(":")}`;
    }
    case "secret":
      return SECRET_LABEL;
    default:
      return `\u05DE\u05DE\u05E6\u05D0 \u05DE\u05E1\u05D5\u05D2 ${kind}`;
  }
}

// ../../../../../Users/User/AppData/Local/Temp/claude/8f433162ca0cb8b3/4a05b86d-fc4a-4091-891f-4e28333938c1/scratchpad/pub/src/core/client/preview.ts
var PREVIEW_DISCLAIMER = "\u05D6\u05D5 \u05EA\u05E6\u05D5\u05D2\u05D4 \u05DC\u05E7\u05E8\u05D9\u05D0\u05D4 \u05D1\u05DC\u05D1\u05D3. \u05D0\u05D9\u05DF \u05DC\u05D4 \u05EA\u05D5\u05E7\u05E3 \u05DE\u05D5\u05DC \u05D4\u05E9\u05E8\u05EA, \u05D5\u05D4\u05D3\u05D5\u05D7 \u05DE\u05D1\u05D5\u05E1\u05E1 \u05E8\u05E7 \u05E2\u05DC \u05D4\u05E7\u05D5\u05D1\u05E5 \u05D4\u05D0\u05D8\u05D5\u05DD \u05E9\u05D9\u05D9\u05E9\u05DC\u05D7.";
function reviewItems(findings) {
  return findings.processes.map((p) => ({
    kind: p.kind,
    description: describeKind(p.kind),
    count: p.count,
    locations: p.references.map((r) => `${r.path}:${r.line}`)
  }));
}
function renderPreview(findings) {
  const items = reviewItems(findings);
  const lines = ["\u05E1\u05D9\u05DB\u05D5\u05DD \u05D4\u05E1\u05E8\u05D9\u05E7\u05D4 (\u05DC\u05E7\u05E8\u05D9\u05D0\u05D4 \u05D1\u05DC\u05D1\u05D3)", "", PREVIEW_DISCLAIMER, ""];
  if (items.length === 0) lines.push("\u05DC\u05D0 \u05D6\u05D5\u05D4\u05D5 \u05EA\u05D4\u05DC\u05D9\u05DB\u05D9\u05DD \u05D1\u05E7\u05D5\u05D3.");
  items.forEach((item, index) => {
    lines.push(`${index + 1}. ${item.description} (\u05E0\u05DE\u05E6\u05D0 ${item.count} \u05E4\u05E2\u05DE\u05D9\u05DD)`);
    for (const location of item.locations) lines.push(`   ${location}`);
  });
  const { coverage } = findings;
  lines.push("", `\u05DB\u05D9\u05E1\u05D5\u05D9: \u05E0\u05E7\u05E8\u05D0\u05D5 ${coverage.filesRead} \u05E7\u05D1\u05E6\u05D9\u05DD.`);
  if (findings.partialCoverage) lines.push("\u05D4\u05DB\u05D9\u05E1\u05D5\u05D9 \u05D7\u05DC\u05E7\u05D9: \u05D7\u05DC\u05E7 \u05DE\u05D4\u05E7\u05D1\u05E6\u05D9\u05DD \u05D3\u05D5\u05DC\u05D2\u05D5 \u05D1\u05D2\u05DC\u05DC \u05D2\u05D5\u05D3\u05DC \u05D0\u05D5 \u05EA\u05E7\u05E8\u05D4, \u05D5\u05D4\u05D3\u05D5\u05D7 \u05D9\u05E1\u05D5\u05DE\u05DF \u05DB\u05DA.");
  return lines.join("\n");
}

// ../../../../../Users/User/AppData/Local/Temp/claude/8f433162ca0cb8b3/4a05b86d-fc4a-4091-891f-4e28333938c1/scratchpad/pub/src/walk.ts
var import_node_fs = require("node:fs");
var import_node_path = require("node:path");
var SKIP_DIRS = /* @__PURE__ */ new Set(["node_modules", ".git", ".next", "dist", "build", "out", "vendor", ".venv", "__pycache__"]);
var OUTPUT_DIR = ".lawstager";
function readProjectFiles(root) {
  const out = [];
  const visit = (dir) => {
    for (const entry of (0, import_node_fs.readdirSync)(dir, { withFileTypes: true })) {
      if (out.length >= MAX_FILES_READ_INVENTED) return;
      if (entry.isSymbolicLink()) continue;
      const full = (0, import_node_path.join)(dir, entry.name);
      if (entry.isDirectory()) {
        const skipOutput = dir === root && entry.name === OUTPUT_DIR;
        if (!SKIP_DIRS.has(entry.name) && !skipOutput) visit(full);
        continue;
      }
      if (!entry.isFile()) continue;
      try {
        if ((0, import_node_fs.statSync)(full).size > MAX_FILE_BYTES) continue;
        const text = (0, import_node_fs.readFileSync)(full, "utf8");
        if (text.includes("\0")) continue;
        out.push({ path: (0, import_node_path.relative)(root, full).split(import_node_path.sep).join("/"), text });
      } catch {
      }
    }
  };
  visit(root);
  return out;
}

// ../../../../../Users/User/AppData/Local/Temp/claude/8f433162ca0cb8b3/4a05b86d-fc4a-4091-891f-4e28333938c1/scratchpad/pub/src/scan.ts
var ANALYZER_VERSION = "0.1.0";
var OUT_DIR_NAME = ".lawstager";
var FINDINGS_FILE = "lawstager-findings.json";
var PREVIEW_FILE = "lawstager-preview.txt";
var STATE_FILE = "scan-state.json";
function runScan(root, options = {}) {
  const files = options.files ?? readProjectFiles(root);
  const findings = buildClientFindings(analyzeRepo(files), ANALYZER_VERSION);
  const preview = renderPreview(findings);
  const state = {
    analyzerVersion: ANALYZER_VERSION,
    treeDigest: computeTreeDigest(files),
    findingsHash: hashFindings(findings),
    scannedAtMs: (options.now ?? Date.now)()
  };
  const outDir = options.outDir ?? (0, import_node_path2.join)(root, OUT_DIR_NAME);
  (0, import_node_fs2.mkdirSync)(outDir, { recursive: true });
  (0, import_node_fs2.writeFileSync)((0, import_node_path2.join)(outDir, ".gitignore"), "*\n", "utf8");
  (0, import_node_fs2.writeFileSync)((0, import_node_path2.join)(outDir, FINDINGS_FILE), `${JSON.stringify(findings, null, 2)}
`, "utf8");
  (0, import_node_fs2.writeFileSync)((0, import_node_path2.join)(outDir, PREVIEW_FILE), `${preview}
`, "utf8");
  (0, import_node_fs2.writeFileSync)((0, import_node_path2.join)(outDir, STATE_FILE), `${JSON.stringify(state, null, 2)}
`, "utf8");
  return { findings, state, preview, outDir };
}

// ../../../../../Users/User/AppData/Local/Temp/claude/8f433162ca0cb8b3/4a05b86d-fc4a-4091-891f-4e28333938c1/scratchpad/pub/src/send.ts
var import_node_crypto3 = require("node:crypto");
var import_node_fs3 = require("node:fs");
var import_node_path3 = require("node:path");

// ../../../../../Users/User/AppData/Local/Temp/claude/8f433162ca0cb8b3/4a05b86d-fc4a-4091-891f-4e28333938c1/scratchpad/pub/src/core/client/consent.ts
var CLIENT_SCAN_CONSENT_VERSION = "2026-11-05.1-DRAFT";
var CLIENT_SCAN_CONSENT_PARAGRAPHS = [
  "\u05D4\u05D7\u05D1\u05D9\u05DC\u05D4 \u05E1\u05E8\u05E7\u05D4 \u05D0\u05EA \u05D4\u05E7\u05D5\u05D3 \u05D1\u05DE\u05D7\u05E9\u05D1 \u05E9\u05DC\u05DA. \u05D4\u05E7\u05D5\u05D3 \u05E2\u05E6\u05DE\u05D5 \u05DC\u05D0 \u05E0\u05E9\u05DC\u05D7 \u05D5\u05DC\u05D0 \u05D9\u05D9\u05E9\u05DC\u05D7.",
  "\u05D9\u05D9\u05E9\u05DC\u05D7\u05D5: \u05EA\u05D9\u05D0\u05D5\u05E8 \u05D4\u05EA\u05D4\u05DC\u05D9\u05DB\u05D9\u05DD \u05E9\u05E0\u05DE\u05E6\u05D0\u05D5 (\u05DC\u05DE\u05E9\u05DC \u05D0\u05D9\u05D6\u05D4 \u05DE\u05D9\u05D3\u05E2 \u05E0\u05D0\u05E1\u05E3 \u05D5\u05DC\u05D0\u05DF \u05D4\u05D5\u05D0 \u05E2\u05D5\u05D1\u05E8), \u05E9\u05DE\u05D5\u05EA \u05E1\u05E4\u05E7\u05D9\u05DD \u05D5\u05D3\u05D5\u05DE\u05D9\u05D9\u05E0\u05D9\u05DD, \u05D5\u05D4\u05E4\u05E0\u05D9\u05D5\u05EA \u05DC\u05E7\u05D5\u05D1\u05E5 \u05D5\u05DC\u05E9\u05D5\u05E8\u05D4, \u05D1\u05DC\u05D9 \u05E7\u05D8\u05E2\u05D9 \u05E7\u05D5\u05D3. \u05DC\u05E4\u05E0\u05D9 \u05D4\u05E9\u05DC\u05D9\u05D7\u05D4 \u05D4\u05D5\u05E1\u05E8\u05D5 \u05DE\u05E4\u05EA\u05D7\u05D5\u05EA, \u05E1\u05D9\u05E1\u05DE\u05D0\u05D5\u05EA \u05D5\u05D8\u05D5\u05E7\u05E0\u05D9\u05DD \u05E9\u05D6\u05D5\u05D4\u05D5. \u05D4\u05D4\u05E1\u05E8\u05D4 \u05DE\u05E6\u05DE\u05E6\u05DE\u05EA \u05E1\u05D9\u05DB\u05D5\u05DF \u05D5\u05D0\u05D9\u05E0\u05D4 \u05DE\u05D1\u05D8\u05D9\u05D7\u05D4 \u05E9\u05DC\u05D0 \u05D9\u05D9\u05E9\u05DC\u05D7 \u05DE\u05D9\u05D3\u05E2 \u05DE\u05D6\u05D4\u05D4. \u05D9\u05D9\u05E9\u05DC\u05D7\u05D5 \u05D2\u05DD \u05D4\u05E4\u05E8\u05D8\u05D9\u05DD \u05E9\u05DE\u05D9\u05DC\u05D0\u05EA (\u05E9\u05DD \u05D4\u05DE\u05E2\u05E8\u05DB\u05EA, \u05DB\u05EA\u05D5\u05D1\u05EA \u05D4\u05D0\u05EA\u05E8 \u05D5\u05E4\u05E8\u05D8\u05D9 \u05D4\u05E7\u05E9\u05E8 \u05E9\u05DC\u05DA), \u05D4\u05D0\u05D9\u05E9\u05D5\u05E8\u05D9\u05DD \u05D5\u05D4\u05D4\u05E1\u05EA\u05D9\u05D9\u05D2\u05D5\u05D9\u05D5\u05EA \u05E9\u05E1\u05D9\u05DE\u05E0\u05EA \u05D5\u05D4\u05D4\u05E2\u05E8\u05D5\u05EA \u05E9\u05DB\u05EA\u05D1\u05EA.",
  "\u05D4\u05E7\u05D5\u05D1\u05E5 \u05DE\u05D5\u05E6\u05E4\u05DF \u05D5\u05E0\u05E4\u05EA\u05D7 \u05E8\u05E7 \u05D1\u05E9\u05E8\u05EA \u05E9\u05DC\u05E0\u05D5. \u05E2\u05D5\u05E8\u05DA \u05D4\u05D3\u05D9\u05DF \u05E8\u05D5\u05D0\u05D4 \u05E8\u05E7 \u05D0\u05EA \u05E4\u05E8\u05D8\u05D9 \u05D4\u05E7\u05E9\u05E8 \u05E9\u05DC\u05DA \u05E2\u05D3 \u05E9\u05D4\u05D5\u05D0 \u05DE\u05E1\u05DB\u05DD \u05D0\u05D9\u05EA\u05DA \u05D0\u05EA \u05D4\u05E2\u05E1\u05E7\u05D4 \u05D5\u05E4\u05D5\u05EA\u05D7 \u05D0\u05EA \u05D4\u05DE\u05DE\u05E6\u05D0\u05D9\u05DD. \u05D4\u05DE\u05DE\u05E6\u05D0\u05D9\u05DD \u05DE\u05E2\u05D5\u05D1\u05D3\u05D9\u05DD \u05D1\u05DE\u05D5\u05D3\u05DC \u05D1\u05D9\u05E0\u05D4 \u05DE\u05DC\u05D0\u05DB\u05D5\u05EA\u05D9\u05EA \u05D1-Vertex AI \u05E9\u05DC Google \u05D1\u05D0\u05D9\u05E8\u05D5\u05E4\u05D4. \u05D4\u05DD \u05E0\u05E9\u05DE\u05E8\u05D9\u05DD \u05DB\u05DC \u05E2\u05D5\u05D3 \u05D4\u05EA\u05D9\u05E7 \u05E9\u05DC \u05E2\u05D5\u05E8\u05DA \u05D4\u05D3\u05D9\u05DF \u05E4\u05E2\u05D9\u05DC \u05D5\u05E2\u05D3 30 \u05D9\u05D5\u05DD \u05D0\u05D7\u05E8\u05D9 \u05E1\u05D2\u05D9\u05E8\u05EA\u05D5. \u05E7\u05D5\u05D1\u05E5 \u05E9\u05E2\u05D5\u05E8\u05DA \u05D3\u05D9\u05DF \u05DC\u05D0 \u05E4\u05EA\u05D7 \u05E0\u05DE\u05D7\u05E7 \u05D0\u05D7\u05E8\u05D9 30 \u05D9\u05D5\u05DD.",
  "\u05D4\u05DE\u05E1\u05DE\u05DB\u05D9\u05DD \u05E9\u05D9\u05D5\u05E4\u05E7\u05D5 \u05D4\u05DD \u05D8\u05D9\u05D5\u05D8\u05D4 \u05E9\u05E2\u05D5\u05E8\u05DA \u05D4\u05D3\u05D9\u05DF \u05E2\u05D5\u05E8\u05DA \u05D5\u05DE\u05D0\u05E9\u05E8. \u05D4\u05DD \u05EA\u05D5\u05E6\u05E8 \u05E9\u05DC \u05D1\u05D9\u05E0\u05D4 \u05DE\u05DC\u05D0\u05DB\u05D5\u05EA\u05D9\u05EA, \u05D5\u05D0\u05D9\u05E0\u05DD \u05D9\u05D9\u05E2\u05D5\u05E5 \u05DE\u05E9\u05E4\u05D8\u05D9 \u05E2\u05D3 \u05E9\u05E2\u05D5\u05E8\u05DA \u05D4\u05D3\u05D9\u05DF \u05D0\u05D9\u05E9\u05E8 \u05D0\u05D5\u05EA\u05DD."
];
var HOOK_CONSENT_VERSION = "2026-11-05.1-HOOK-DRAFT";
var HOOK_CONSENT_CHECKBOX = "\u05D0\u05E0\u05D9 \u05DE\u05E1\u05DB\u05D9\u05DD \u05E9\u05D1\u05DB\u05DC \u05E4\u05E2\u05DD \u05E9\u05D4\u05E7\u05D5\u05D3 \u05D9\u05E9\u05EA\u05E0\u05D4 \u05D1\u05D0\u05D5\u05E4\u05DF \u05E9\u05DE\u05E9\u05E4\u05D9\u05E2 \u05E2\u05DC \u05D4\u05DE\u05E1\u05DE\u05DB\u05D9\u05DD \u05D4\u05DE\u05E9\u05E4\u05D8\u05D9\u05D9\u05DD, \u05D9\u05D9\u05D5\u05D5\u05E6\u05E8 \u05D5\u05D9\u05D9\u05E9\u05DC\u05D7 \u05D0\u05D5\u05D8\u05D5\u05DE\u05D8\u05D9\u05EA \u05D3\u05D5\u05D7 \u05E9\u05D9\u05E0\u05D5\u05D9\u05D9\u05DD (\u05D1\u05DC\u05D9 \u05E7\u05D5\u05D3) \u05D1\u05E0\u05D5\u05E1\u05D7 \u05D4\u05D4\u05E1\u05DB\u05DE\u05D4 \u05E9\u05DC\u05DE\u05E2\u05DC\u05D4. \u05D4\u05D4\u05D5\u05E7 \u05D0\u05D9\u05E0\u05D5 \u05DE\u05E2\u05D3\u05DB\u05DF \u05E9\u05D5\u05DD \u05DE\u05E1\u05DE\u05DA \u05D1\u05D0\u05EA\u05E8 \u05E9\u05DC\u05D9, \u05D5\u05D0\u05D5\u05DB\u05DC \u05DC\u05D4\u05E1\u05D9\u05E8 \u05D0\u05D5\u05EA\u05D5 \u05D1\u05DB\u05DC \u05E2\u05EA.";
var CLIENT_SCAN_CONSENT_CHECKBOX = "\u05E2\u05D1\u05E8\u05EA\u05D9 \u05E2\u05DC \u05D4\u05EA\u05D4\u05DC\u05D9\u05DB\u05D9\u05DD \u05E9\u05DE\u05D5\u05E6\u05D2\u05D9\u05DD, \u05D0\u05D9\u05E9\u05E8\u05EA\u05D9 \u05D0\u05EA \u05D0\u05DC\u05D4 \u05E9\u05E0\u05DB\u05D5\u05E0\u05D9\u05DD \u05D5\u05E1\u05D9\u05DE\u05E0\u05EA\u05D9 \u05D0\u05EA \u05D0\u05DC\u05D4 \u05E9\u05DC\u05D0. \u05D0\u05E0\u05D9 \u05DE\u05D5\u05E8\u05E9\u05D4 \u05DC\u05D1\u05E7\u05E9 \u05E1\u05E8\u05D9\u05E7\u05D4 \u05D5\u05E9\u05DC\u05D9\u05D7\u05D4 \u05D1\u05E9\u05DD \u05D4\u05D2\u05D5\u05E3 \u05E9\u05DE\u05E4\u05E2\u05D9\u05DC \u05D0\u05EA \u05D4\u05DE\u05E2\u05E8\u05DB\u05EA, \u05D5\u05DE\u05E1\u05DB\u05D9\u05DD \u05DC\u05E2\u05D9\u05D1\u05D5\u05D3 \u05DB\u05DE\u05EA\u05D5\u05D0\u05E8 \u05DB\u05D0\u05DF.";

// ../../../../../Users/User/AppData/Local/Temp/claude/8f433162ca0cb8b3/4a05b86d-fc4a-4091-891f-4e28333938c1/scratchpad/pub/src/core/client/protocol.ts
var POOL_LAWYER_ID = "pool";
var LAWSTAGER_ENDPOINT_INVENTED = "https://europe-west1-israelaw.cloudfunctions.net";
var BEGIN_FUNCTION = "beginClientScan";
var SUBMIT_FUNCTION = "submitClientScan";

// ../../../../../Users/User/AppData/Local/Temp/claude/8f433162ca0cb8b3/4a05b86d-fc4a-4091-891f-4e28333938c1/scratchpad/pub/src/core/client/findings-validate.ts
var MAX_PROCESSES_INVENTED = 600;
var KIND_PATTERN = /^[A-Za-z0-9_:.*\-]{1,200}$/;
var EXT_PATTERN = /^[A-Za-z0-9_+\-]{0,16}$/;
var MAX_PATH = 300;
var MAX_INT = 1e9;
function isObj(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function exactKeys(value, keys) {
  const own = Object.keys(value);
  return own.length === keys.length && keys.every((k) => own.includes(k));
}
function isInt(value, min = 0) {
  return typeof value === "number" && Number.isInteger(value) && value >= min && value <= MAX_INT;
}
function safePath(value) {
  if (typeof value !== "string" || value.length === 0 || value.length > MAX_PATH) return false;
  for (let i = 0; i < value.length; i += 1) {
    const c = value.charCodeAt(i);
    if (c < 32 || c === 127) return false;
  }
  return !value.startsWith("/") && !value.includes("..");
}
function validCoverage(value) {
  if (!isObj(value) || !exactKeys(value, ["filesRead", "bytesRead", "skipped", "byExtension"])) return false;
  if (!isInt(value.filesRead) || !isInt(value.bytesRead)) return false;
  const skipped = value.skipped;
  if (!isObj(skipped) || !exactKeys(skipped, SKIP_REASONS) || !SKIP_REASONS.every((r) => isInt(skipped[r]))) return false;
  const ext = value.byExtension;
  if (!isObj(ext) || Object.keys(ext).length > 200) return false;
  return Object.entries(ext).every(([k, v]) => EXT_PATTERN.test(k) && isInt(v));
}
function validProcess(value) {
  if (!isObj(value) || !exactKeys(value, ["kind", "processType", "confidence", "count", "references"])) return false;
  if (typeof value.kind !== "string" || !KIND_PATTERN.test(value.kind)) return false;
  if (!PROCESS_TYPES.includes(value.processType)) return false;
  if (value.confidence !== "high" && value.confidence !== "medium" && value.confidence !== "low") return false;
  if (!isInt(value.count)) return false;
  const refs = value.references;
  if (!Array.isArray(refs) || refs.length > REFERENCES_PER_KIND_INVENTED) return false;
  return refs.every((r) => isObj(r) && exactKeys(r, ["path", "line"]) && safePath(r.path) && isInt(r.line, 1));
}
function isValidChangeReport(value) {
  if (!isObj(value) || !exactKeys(value, ["added", "removed", "baselineHash"])) return false;
  if (typeof value.baselineHash !== "string" || !/^[0-9a-f]{64}$/.test(value.baselineHash)) return false;
  const okList = (l) => Array.isArray(l) && l.length <= MAX_PROCESSES_INVENTED && l.every((k) => typeof k === "string" && KIND_PATTERN.test(k));
  return okList(value.added) && okList(value.removed);
}
function isValidFindingsFile(value) {
  if (!isObj(value) || !exactKeys(value, ["schemaVersion", "analyzerVersion", "processes", "coverage", "partialCoverage"])) return false;
  if (value.schemaVersion !== CLIENT_FINDINGS_SCHEMA_VERSION) return false;
  if (typeof value.analyzerVersion !== "string" || !/^[0-9A-Za-z.\-]{1,32}$/.test(value.analyzerVersion)) return false;
  if (typeof value.partialCoverage !== "boolean") return false;
  const processes = value.processes;
  if (!Array.isArray(processes) || processes.length > MAX_PROCESSES_INVENTED || !processes.every(validProcess)) return false;
  return validCoverage(value.coverage);
}

// ../../../../../Users/User/AppData/Local/Temp/claude/8f433162ca0cb8b3/4a05b86d-fc4a-4091-891f-4e28333938c1/scratchpad/pub/src/core/client/submission.ts
var DISAGREE_NOTE_MAX_INVENTED = 500;
var DECLARATION_MAX_INVENTED = 4e3;
var FIELD_MAX_INVENTED = 200;
var EMAIL = /^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,190}\.[A-Za-z]{2,}$/;
var PHONE = /^[0-9+\-\s()]{7,20}$/;
function clean(value) {
  return (value ?? "").replace(/\r\n/g, "\n").trim();
}
function validUrl(raw) {
  try {
    const url = new URL(raw);
    return url.protocol === "https:" || url.protocol === "http:";
  } catch {
    return false;
  }
}
function buildSubmission(input) {
  const errors = [];
  if (!isValidFindingsFile(input.findings)) return { ok: false, errors: ["\u05E7\u05D5\u05D1\u05E5 \u05D4\u05DE\u05DE\u05E6\u05D0\u05D9\u05DD \u05D0\u05D9\u05E0\u05D5 \u05EA\u05E7\u05D9\u05DF"] };
  const { details } = input;
  const name = clean(details.systemName);
  const url = clean(details.siteUrl);
  const contactName = clean(details.contactName);
  const email = clean(details.contactEmail);
  const phone = clean(details.contactPhone);
  if (!name) errors.push("\u05D7\u05E1\u05E8 \u05E9\u05DD \u05D4\u05DE\u05E2\u05E8\u05DB\u05EA");
  if (!validUrl(url)) errors.push("\u05DB\u05EA\u05D5\u05D1\u05EA \u05D4\u05D0\u05EA\u05E8 \u05D0\u05D9\u05E0\u05D4 \u05EA\u05E7\u05D9\u05E0\u05D4 (\u05E0\u05D3\u05E8\u05E9\u05EA \u05DB\u05EA\u05D5\u05D1\u05EA \u05E9\u05DE\u05EA\u05D7\u05D9\u05DC\u05D4 \u05D1-https://)");
  if (!contactName) errors.push("\u05D7\u05E1\u05E8 \u05E9\u05DD \u05D0\u05D9\u05E9 \u05D4\u05E7\u05E9\u05E8");
  if (!EMAIL.test(email)) errors.push("\u05DB\u05EA\u05D5\u05D1\u05EA \u05D4\u05DE\u05D9\u05D9\u05DC \u05D0\u05D9\u05E0\u05D4 \u05EA\u05E7\u05D9\u05E0\u05D4");
  if (phone && !PHONE.test(phone)) errors.push("\u05DE\u05E1\u05E4\u05E8 \u05D4\u05D8\u05DC\u05E4\u05D5\u05DF \u05D0\u05D9\u05E0\u05D5 \u05EA\u05E7\u05D9\u05DF");
  for (const value of [name, url, contactName, email, phone]) {
    if (value.length > FIELD_MAX_INVENTED) errors.push("\u05D0\u05D7\u05D3 \u05D4\u05E9\u05D3\u05D5\u05EA \u05D0\u05E8\u05D5\u05DA \u05DE\u05D3\u05D9");
  }
  const known = new Set(input.findings.processes.map((p) => p.kind));
  const seen = /* @__PURE__ */ new Set();
  const reviews = [];
  for (const review of input.reviews) {
    if (!known.has(review.kind)) {
      errors.push("\u05D0\u05D9\u05E9\u05D5\u05E8 \u05DC\u05EA\u05D4\u05DC\u05D9\u05DA \u05E9\u05DC\u05D0 \u05E0\u05DE\u05E6\u05D0 \u05D1\u05E7\u05D5\u05D1\u05E5 \u05D4\u05DE\u05DE\u05E6\u05D0\u05D9\u05DD");
      continue;
    }
    if (seen.has(review.kind)) {
      errors.push("\u05D0\u05D5\u05EA\u05D5 \u05EA\u05D4\u05DC\u05D9\u05DA \u05E1\u05D5\u05DE\u05DF \u05E4\u05E2\u05DE\u05D9\u05D9\u05DD");
      continue;
    }
    seen.add(review.kind);
    const note = clean(review.note);
    if (review.verdict === "disagree" && !note) errors.push('\u05EA\u05D4\u05DC\u05D9\u05DA \u05E9\u05E1\u05D5\u05DE\u05DF "\u05DC\u05D0 \u05DE\u05E1\u05DB\u05D9\u05DD" \u05D3\u05D5\u05E8\u05E9 \u05D4\u05E1\u05D1\u05E8 \u05E7\u05E6\u05E8');
    if (note.length > DISAGREE_NOTE_MAX_INVENTED) errors.push("\u05D4\u05E1\u05D1\u05E8 \u05D0\u05E8\u05D5\u05DA \u05DE\u05D3\u05D9");
    reviews.push(review.verdict === "disagree" ? { kind: review.kind, verdict: "disagree", note } : { kind: review.kind, verdict: "agree" });
  }
  if (input.hook === void 0 && seen.size !== known.size) errors.push("\u05DC\u05D0 \u05DB\u05DC \u05D4\u05EA\u05D4\u05DC\u05D9\u05DB\u05D9\u05DD \u05E1\u05D5\u05DE\u05E0\u05D5: \u05D7\u05D5\u05D1\u05D4 \u05DC\u05D0\u05E9\u05E8 \u05D0\u05D5 \u05DC\u05D7\u05DC\u05D5\u05E7 \u05E2\u05DC \u05DB\u05DC \u05D0\u05D7\u05D3");
  if (input.hook !== void 0) {
    const h = input.hook;
    const consistent = isValidChangeReport(h) && h.added.length + h.removed.length > 0 && h.added.every((k) => known.has(k)) && h.removed.every((k) => !known.has(k)) && new Set(h.added).size === h.added.length;
    if (!consistent) errors.push("\u05D3\u05D5\u05D7 \u05D4\u05E9\u05D9\u05E0\u05D5\u05D9\u05D9\u05DD \u05D0\u05D9\u05E0\u05D5 \u05EA\u05E7\u05D9\u05DF");
  }
  const declarationText = clean(input.declarationText);
  if (declarationText.length > DECLARATION_MAX_INVENTED) errors.push("\u05D4\u05D4\u05E6\u05D4\u05E8\u05D4 \u05D4\u05D7\u05D5\u05E4\u05E9\u05D9\u05EA \u05D0\u05E8\u05D5\u05DB\u05D4 \u05DE\u05D3\u05D9");
  if (!input.consentGiven) errors.push("\u05D7\u05D5\u05D1\u05D4 \u05DC\u05E1\u05DE\u05DF \u05D4\u05E1\u05DB\u05DE\u05D4 \u05DE\u05D3\u05E2\u05EA \u05DC\u05E4\u05E0\u05D9 \u05E9\u05DC\u05D9\u05D7\u05D4");
  if (errors.length > 0) return { ok: false, errors };
  return {
    ok: true,
    submission: {
      findings: input.findings,
      reviews,
      declaration: { text: declarationText, status: "unverified" },
      details: { systemName: name, siteUrl: url, contactName, contactEmail: email, ...phone ? { contactPhone: phone } : {} },
      consentVersion: CLIENT_SCAN_CONSENT_VERSION,
      runMode: input.runMode,
      ...input.hook ? { hook: { added: input.hook.added, removed: input.hook.removed, baselineHash: input.hook.baselineHash }, hookConsentVersion: HOOK_CONSENT_VERSION } : {}
    }
  };
}

// ../../../../../Users/User/AppData/Local/Temp/claude/8f433162ca0cb8b3/4a05b86d-fc4a-4091-891f-4e28333938c1/scratchpad/pub/src/send.ts
var ANSWERS_FILE = "lawstager-answers.json";
var BASELINE_FILE = "lawstager-baseline.json";
function readJson(path) {
  if (!(0, import_node_fs3.existsSync)(path)) throw new Error(`\u05D4\u05E7\u05D5\u05D1\u05E5 ${path} \u05DC\u05D0 \u05E0\u05DE\u05E6\u05D0. \u05D4\u05E8\u05E5 \u05E7\u05D5\u05D3\u05DD \u05D0\u05EA \u05E9\u05DC\u05D1 \u05D4\u05E1\u05E8\u05D9\u05E7\u05D4 (scan)`);
  return parseJsonSafe((0, import_node_fs3.readFileSync)(path, "utf8"), "\u05E7\u05D5\u05D1\u05E5 JSON \u05D0\u05D9\u05E0\u05D5 \u05EA\u05E7\u05D9\u05DF");
}
function parseJsonSafe(text, message) {
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(message);
  }
}
var YES = /* @__PURE__ */ new Set(["\u05DB\u05DF", "y", "yes", "Y"]);
async function collectAnswers(findings, hash, prompter) {
  prompter.say('\u05E2\u05D1\u05D5\u05E8 \u05E2\u05DC \u05D4\u05EA\u05D4\u05DC\u05D9\u05DB\u05D9\u05DD \u05E9\u05E0\u05DE\u05E6\u05D0\u05D5. \u05DC\u05DB\u05DC \u05D0\u05D7\u05D3: "\u05DB\u05DF" \u05D0\u05DD \u05D6\u05D4 \u05DE\u05D4 \u05E9\u05D4\u05DE\u05E2\u05E8\u05DB\u05EA \u05E2\u05D5\u05E9\u05D4, \u05D0\u05D5 "\u05DC\u05D0" \u05D0\u05DD \u05D0\u05D9\u05E0\u05DA \u05DE\u05E1\u05DB\u05D9\u05DD \u05D0\u05D5 \u05D0\u05D9\u05E0\u05DA \u05D1\u05D8\u05D5\u05D7.');
  const reviews = [];
  for (const item of reviewItems(findings)) {
    prompter.say(`
${item.description} (\u05E0\u05DE\u05E6\u05D0 ${item.count} \u05E4\u05E2\u05DE\u05D9\u05DD)`);
    const answer = (await prompter.ask("\u05E0\u05DB\u05D5\u05DF? (\u05DB\u05DF/\u05DC\u05D0): ")).trim();
    if (YES.has(answer)) reviews.push({ kind: item.kind, verdict: "agree" });
    else reviews.push({ kind: item.kind, verdict: "disagree", note: await prompter.ask("\u05D4\u05E1\u05D1\u05E8 \u05E7\u05E6\u05E8: ") });
  }
  prompter.say("\n\u05E4\u05E8\u05D8\u05D9 \u05D4\u05DE\u05E2\u05E8\u05DB\u05EA \u05D5\u05D0\u05D9\u05E9 \u05D4\u05E7\u05E9\u05E8, \u05DB\u05D3\u05D9 \u05E9\u05E2\u05D5\u05E8\u05DA \u05D4\u05D3\u05D9\u05DF \u05D9\u05D3\u05E2 \u05E2\u05DD \u05DE\u05D9 \u05DC\u05D4\u05EA\u05DB\u05EA\u05D1:");
  const details = {
    systemName: await prompter.ask("\u05E9\u05DD \u05D4\u05DE\u05E2\u05E8\u05DB\u05EA: "),
    siteUrl: await prompter.ask("\u05DB\u05EA\u05D5\u05D1\u05EA \u05D4\u05D0\u05EA\u05E8 (https://...): "),
    contactName: await prompter.ask("\u05E9\u05DD \u05D0\u05D9\u05E9 \u05D4\u05E7\u05E9\u05E8: "),
    contactEmail: await prompter.ask("\u05DE\u05D9\u05D9\u05DC: "),
    contactPhone: await prompter.ask("\u05D8\u05DC\u05E4\u05D5\u05DF (\u05D0\u05E4\u05E9\u05E8 \u05DC\u05D4\u05E9\u05D0\u05D9\u05E8 \u05E8\u05D9\u05E7): ")
  };
  prompter.say('\n\u05DE\u05DC\u05DC \u05D7\u05D5\u05E4\u05E9\u05D9 (\u05DC\u05D0 \u05D7\u05D5\u05D1\u05D4): \u05EA\u05D4\u05DC\u05D9\u05DB\u05D9\u05DD \u05E2\u05EA\u05D9\u05D3\u05D9\u05D9\u05DD \u05E9\u05E2\u05D5\u05D3 \u05DC\u05D0 \u05D1\u05E7\u05D5\u05D3, \u05D0\u05D5 \u05E4\u05E8\u05D8\u05D9\u05DD \u05DE\u05E9\u05E4\u05D8\u05D9\u05D9\u05DD \u05DE\u05D3\u05D5\u05D9\u05E7\u05D9\u05DD (\u05E9\u05DD \u05D4\u05EA\u05D0\u05D2\u05D9\u05D3 \u05DB\u05E4\u05D9 \u05E9\u05D4\u05D5\u05D0 \u05E8\u05E9\u05D5\u05DD, \u05DB\u05EA\u05D5\u05D1\u05EA, \u05DE\u05E1\u05E4\u05E8 \u05E8\u05D9\u05E9\u05D5\u05DD). \u05D4\u05D8\u05E7\u05E1\u05D8 \u05D9\u05E1\u05D5\u05DE\u05DF "\u05D4\u05E6\u05D4\u05E8\u05EA \u05DC\u05E7\u05D5\u05D7, \u05DC\u05D0 \u05D0\u05D5\u05DE\u05EA".');
  const declarationText = await prompter.ask("\u05D4\u05E6\u05D4\u05E8\u05D4: ");
  prompter.say(`
${CLIENT_SCAN_CONSENT_PARAGRAPHS.join("\n\n")}`);
  const consent = await prompter.ask(`${CLIENT_SCAN_CONSENT_CHECKBOX}
\u05DE\u05E1\u05DB\u05D9\u05DD? (\u05DB\u05DF/\u05DC\u05D0): `);
  const given = YES.has(consent.trim());
  let hookConsentGiven = false;
  if (given) {
    prompter.say("\n\u05D0\u05D5\u05E4\u05E6\u05D9\u05D5\u05E0\u05DC\u05D9: \u05D4\u05D5\u05E7 \u05E9\u05D1\u05D5\u05D3\u05E7 \u05D1\u05DB\u05DC \u05E9\u05D9\u05E0\u05D5\u05D9 \u05D1\u05E7\u05D5\u05D3 \u05D0\u05DD \u05D4\u05E9\u05EA\u05E0\u05D4 \u05DE\u05E9\u05D4\u05D5 \u05DE\u05E9\u05E4\u05D8\u05D9, \u05D5\u05E9\u05D5\u05DC\u05D7 \u05D3\u05D5\u05D7 \u05E9\u05D9\u05E0\u05D5\u05D9\u05D9\u05DD \u05E8\u05E7 \u05D0\u05DD \u05DB\u05DF.");
    hookConsentGiven = YES.has((await prompter.ask(`${HOOK_CONSENT_CHECKBOX}
\u05DE\u05E1\u05DB\u05D9\u05DD? (\u05DB\u05DF/\u05DC\u05D0): `)).trim());
  }
  return { findingsHash: hash, details, reviews, declarationText, consentGiven: given, hookConsentGiven };
}
async function callFunction(fetchFn, endpoint, name, data) {
  const response = await fetchFn(`${endpoint}/${name}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ data })
  });
  if (!response.ok) throw new Error(`\u05D4\u05E9\u05E8\u05EA \u05D3\u05D7\u05D4 \u05D0\u05EA \u05D4\u05D1\u05E7\u05E9\u05D4 (${response.status})`);
  const body = await response.json();
  if (!body.result) throw new Error("\u05EA\u05E9\u05D5\u05D1\u05EA \u05D4\u05E9\u05E8\u05EA \u05D0\u05D9\u05E0\u05D4 \u05EA\u05E7\u05D9\u05E0\u05D4");
  return body.result;
}
async function runSend(options) {
  const dir = options.outDir ?? (0, import_node_path3.join)(options.root, OUT_DIR_NAME);
  const findings = readJson((0, import_node_path3.join)(dir, FINDINGS_FILE));
  const state = readJson((0, import_node_path3.join)(dir, STATE_FILE));
  const hash = hashFindings(findings);
  if (hash !== state.findingsHash) throw new Error("\u05E7\u05D5\u05D1\u05E5 \u05D4\u05DE\u05DE\u05E6\u05D0\u05D9\u05DD \u05E9\u05D5\u05E0\u05D4 \u05D0\u05D7\u05E8\u05D9 \u05D4\u05E1\u05E8\u05D9\u05E7\u05D4. \u05D4\u05E8\u05E5 \u05E1\u05E8\u05D9\u05E7\u05D4 \u05DE\u05D7\u05D3\u05E9");
  const answersPath = (0, import_node_path3.join)(dir, ANSWERS_FILE);
  let answers;
  if (options.prompter) {
    answers = await collectAnswers(findings, hash, options.prompter);
    (0, import_node_fs3.writeFileSync)(answersPath, `${JSON.stringify(answers, null, 2)}
`, "utf8");
  } else {
    answers = options.answersJson !== void 0 ? parseJsonSafe(options.answersJson, "\u05E7\u05D5\u05D1\u05E5 \u05D4\u05EA\u05E9\u05D5\u05D1\u05D5\u05EA \u05D0\u05D9\u05E0\u05D5 JSON \u05EA\u05E7\u05D9\u05DF") : readJson(answersPath);
    if (answers.findingsHash !== hash) throw new Error("\u05D4\u05DE\u05DE\u05E6\u05D0\u05D9\u05DD \u05D4\u05E9\u05EA\u05E0\u05D5 \u05DE\u05D0\u05D6 \u05E9\u05D0\u05D9\u05E9\u05E8\u05EA \u05D0\u05D5\u05EA\u05DD. \u05D4\u05E8\u05E5 \u05E9\u05D5\u05D1 \u05D0\u05EA \u05D4\u05E9\u05DC\u05D9\u05D7\u05D4 \u05D4\u05D0\u05D9\u05E0\u05D8\u05E8\u05D0\u05E7\u05D8\u05D9\u05D1\u05D9\u05EA");
  }
  const result = await transmit(
    { findings, reviews: answers.reviews, declarationText: answers.declarationText, details: answers.details, consentGiven: answers.consentGiven, runMode: options.runMode },
    state,
    options
  );
  (0, import_node_fs3.writeFileSync)((0, import_node_path3.join)(dir, BASELINE_FILE), `${JSON.stringify(baselineOf(findings), null, 2)}
`, "utf8");
  return result;
}
async function transmit(input, state, options) {
  const built = buildSubmission(input);
  if (!built.ok) throw new Error(built.errors.join("\n"));
  const endpoint = options.endpoint ?? LAWSTAGER_ENDPOINT_INVENTED;
  const lawyerId = options.lawyerId ?? POOL_LAWYER_ID;
  const begin = await callFunction(options.fetchFn, endpoint, BEGIN_FUNCTION, {
    lawyerId,
    ...options.getOidcToken ? { oidcToken: await options.getOidcToken("lawstager") } : {}
  });
  if (begin.consentVersion !== built.submission.consentVersion) throw new Error("\u05E0\u05D5\u05E1\u05D7 \u05D4\u05D4\u05E1\u05DB\u05DE\u05D4 \u05D1\u05D7\u05D1\u05D9\u05DC\u05D4 \u05D0\u05D9\u05E0\u05D5 \u05D4\u05E0\u05D5\u05E1\u05D7 \u05E9\u05D4\u05E9\u05E8\u05EA \u05D3\u05D5\u05E8\u05E9. \u05E2\u05D3\u05DB\u05DF \u05D0\u05EA \u05D4\u05D7\u05D1\u05D9\u05DC\u05D4");
  const envelope = sealSubmission(built.submission, {
    serverPublicKeyPem: begin.serverPublicKeyPem,
    lawyerId,
    nonce: begin.nonce,
    attestation: {
      analyzerVersion: state.analyzerVersion,
      runMode: options.runMode,
      treeDigest: state.treeDigest,
      ...options.commit ? { commit: options.commit } : {},
      ...options.runId ? { runId: options.runId } : {}
    }
  });
  return callFunction(options.fetchFn, endpoint, SUBMIT_FUNCTION, {
    envelope,
    requestId: (0, import_node_crypto3.randomUUID)(),
    ...options.getOidcToken ? { oidcToken: await options.getOidcToken(`lawstager:${begin.nonce}`) } : {}
  });
}

// ../../../../../Users/User/AppData/Local/Temp/claude/8f433162ca0cb8b3/4a05b86d-fc4a-4091-891f-4e28333938c1/scratchpad/pub/src/hook.ts
async function runHook(options) {
  if (!(0, import_node_fs4.existsSync)(options.baselinePath)) throw new Error("\u05D0\u05D9\u05DF \u05E7\u05D5\u05D1\u05E5 \u05D1\u05E1\u05D9\u05E1. \u05D4\u05E8\u05E5 \u05E7\u05D5\u05D3\u05DD send \u05D9\u05D3\u05E0\u05D9, \u05D5\u05D4\u05DB\u05E0\u05E1 \u05D0\u05EA lawstager-baseline.json \u05DC\u05E8\u05D9\u05E4\u05D5");
  const baseline = parseJsonSafe((0, import_node_fs4.readFileSync)(options.baselinePath, "utf8"), "\u05E7\u05D5\u05D1\u05E5 \u05D4\u05D1\u05E1\u05D9\u05E1 \u05D0\u05D9\u05E0\u05D5 JSON \u05EA\u05E7\u05D9\u05DF");
  if (!isValidBaseline(baseline)) throw new Error("\u05E7\u05D5\u05D1\u05E5 \u05D4\u05D1\u05E1\u05D9\u05E1 \u05D0\u05D9\u05E0\u05D5 \u05EA\u05E7\u05D9\u05DF");
  const scan = runScan(options.root, { outDir: options.outDir, ...options.files ? { files: options.files } : {} });
  const diff = diffAgainstBaseline(baseline, scan.findings);
  if (!diff.significant) return { sent: false, reason: "no-legal-change" };
  const raw = options.answersJson ?? ((0, import_node_fs4.existsSync)((0, import_node_path4.join)(options.outDir, ANSWERS_FILE)) ? (0, import_node_fs4.readFileSync)((0, import_node_path4.join)(options.outDir, ANSWERS_FILE), "utf8") : void 0);
  if (raw === void 0) throw new Error("\u05D0\u05D9\u05DF \u05E7\u05D5\u05D1\u05E5 \u05EA\u05E9\u05D5\u05D1\u05D5\u05EA. \u05E9\u05DC\u05D9\u05D7\u05D4 \u05D9\u05D3\u05E0\u05D9\u05EA \u05E8\u05D0\u05E9\u05D5\u05E0\u05D4 \u05E0\u05D3\u05E8\u05E9\u05EA \u05DC\u05E4\u05E0\u05D9 \u05E9\u05D4\u05D4\u05D5\u05E7 \u05D9\u05DB\u05D5\u05DC \u05DC\u05E9\u05DC\u05D5\u05D7");
  const answers = parseJsonSafe(raw, "\u05E7\u05D5\u05D1\u05E5 \u05D4\u05EA\u05E9\u05D5\u05D1\u05D5\u05EA \u05D0\u05D9\u05E0\u05D5 JSON \u05EA\u05E7\u05D9\u05DF");
  if (answers.consentGiven !== true || answers.hookConsentGiven !== true) throw new Error("\u05DC\u05D0 \u05E0\u05D9\u05EA\u05E0\u05D4 \u05D4\u05E1\u05DB\u05DE\u05D4 \u05DC\u05D4\u05D5\u05E7. \u05DC\u05D0 \u05E0\u05E9\u05DC\u05D7 \u05D3\u05D1\u05E8");
  const result = await transmit(
    {
      findings: scan.findings,
      reviews: [],
      declarationText: answers.declarationText,
      details: answers.details,
      consentGiven: true,
      runMode: options.runMode,
      hook: { added: diff.added, removed: diff.removed, baselineHash: diff.baselineHash }
    },
    scan.state,
    options
  );
  return { sent: true, scanId: result.scanId, added: diff.added, removed: diff.removed };
}

// ../../../../../Users/User/AppData/Local/Temp/claude/8f433162ca0cb8b3/4a05b86d-fc4a-4091-891f-4e28333938c1/scratchpad/pub/src/cli.ts
function flag(args, name) {
  const index = args.indexOf(`--${name}`);
  return index >= 0 ? args[index + 1] : void 0;
}
function terminalPrompter() {
  const rl = (0, import_promises.createInterface)({ input: process.stdin, output: process.stdout });
  return { say: (text) => console.log(text), ask: (question) => rl.question(question), close: () => rl.close() };
}
async function fetchOidcToken(audience) {
  const url = process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
  const bearer = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  if (!url || !bearer) throw new Error("\u05D0\u05D9\u05DF \u05D0\u05E1\u05D9\u05DE\u05D5\u05DF OIDC: --ci \u05E8\u05E5 \u05E8\u05E7 \u05DE\u05EA\u05D5\u05DA GitHub Actions \u05E2\u05DD \u05D4\u05E8\u05E9\u05D0\u05EA id-token");
  const response = await fetch(`${url}&audience=${encodeURIComponent(audience)}`, { headers: { authorization: `Bearer ${bearer}` } });
  if (!response.ok) throw new Error("\u05E7\u05D1\u05DC\u05EA \u05D0\u05E1\u05D9\u05DE\u05D5\u05DF OIDC \u05E0\u05DB\u05E9\u05DC\u05D4");
  const body = await response.json();
  if (!body.value) throw new Error("\u05D0\u05E1\u05D9\u05DE\u05D5\u05DF OIDC \u05D7\u05E1\u05E8 \u05D1\u05EA\u05E9\u05D5\u05D1\u05D4");
  return body.value;
}
async function main(args) {
  const [command, maybeDir] = args;
  const root = (0, import_node_path5.resolve)(maybeDir && !maybeDir.startsWith("--") ? maybeDir : ".");
  if (command === "scan") {
    const out = runScan(root, { outDir: flag(args, "out") });
    console.log(out.preview);
    console.log(`
\u05D4\u05E7\u05D1\u05E6\u05D9\u05DD \u05E0\u05DB\u05EA\u05D1\u05D5 \u05DC-${out.outDir}. \u05E7\u05E8\u05D0 \u05D0\u05D5\u05EA\u05DD, \u05D5\u05D0\u05D6 \u05D4\u05E8\u05E5: send`);
    return 0;
  }
  if (command === "send") {
    const ci = args.includes("--ci");
    const answersEnv = flag(args, "answers-env");
    if (ci && !answersEnv) throw new Error("--ci \u05D3\u05D5\u05E8\u05E9 --answers-env: \u05D4\u05EA\u05E9\u05D5\u05D1\u05D5\u05EA \u05E2\u05D5\u05D1\u05E8\u05D5\u05EA \u05DB\u05E1\u05D5\u05D3, \u05DC\u05D0 \u05DB\u05E7\u05D5\u05D1\u05E5 \u05D1\u05E8\u05D9\u05E4\u05D5");
    const prompter = ci ? void 0 : terminalPrompter();
    try {
      const result = await runSend({
        root,
        lawyerId: flag(args, "lawyer"),
        endpoint: flag(args, "endpoint"),
        runMode: ci ? "github-actions" : "local",
        fetchFn: fetch,
        prompter,
        outDir: flag(args, "out"),
        answersJson: answersEnv ? process.env[answersEnv] : void 0,
        getOidcToken: ci ? fetchOidcToken : void 0,
        commit: ci ? process.env.GITHUB_SHA : void 0,
        runId: ci ? process.env.GITHUB_RUN_ID : void 0
      });
      console.log(`\u05E0\u05E9\u05DC\u05D7. \u05DE\u05E1\u05E4\u05E8 \u05D4\u05E1\u05E8\u05D9\u05E7\u05D4: ${result.scanId}`);
      if (!ci) {
        console.log(`\u05D4\u05EA\u05E9\u05D5\u05D1\u05D5\u05EA \u05E0\u05E9\u05DE\u05E8\u05D5 \u05D1-${OUT_DIR_NAME}/${ANSWERS_FILE} \u05D5\u05D0\u05D9\u05E0\u05DF \u05E0\u05DB\u05E0\u05E1\u05D5\u05EA \u05DC-git. \u05DC\u05DE\u05E1\u05DC\u05D5\u05DC \u05D4\u05DE\u05D0\u05D5\u05DE\u05EA: \u05D4\u05E2\u05EA\u05E7 \u05D0\u05EA \u05EA\u05D5\u05DB\u05DF \u05D4\u05E7\u05D5\u05D1\u05E5 \u05DC\u05E1\u05D5\u05D3 LAWSTAGER_ANSWERS \u05D1-GitHub. \u05D0\u05DC \u05EA\u05D5\u05E1\u05D9\u05E3 \u05D0\u05D5\u05EA\u05D5 \u05DC\u05E8\u05D9\u05E4\u05D5: \u05D9\u05E9 \u05D1\u05D5 \u05E4\u05E8\u05D8\u05D9 \u05E7\u05E9\u05E8.`);
      }
      return 0;
    } finally {
      prompter?.close();
    }
  }
  if (command === "hook") {
    const ci = args.includes("--ci");
    const answersEnv = flag(args, "answers-env");
    const out = flag(args, "out") ?? process.env.RUNNER_TEMP;
    if (!out) throw new Error("\u05D4\u05D5\u05E7 \u05D3\u05D5\u05E8\u05E9 --out (\u05EA\u05D9\u05E7\u05D9\u05D9\u05EA \u05E4\u05DC\u05D8 \u05D6\u05DE\u05E0\u05D9\u05EA \u05DE\u05D7\u05D5\u05E5 \u05DC\u05E8\u05D9\u05E4\u05D5)");
    const outcome = await runHook({
      root,
      lawyerId: flag(args, "lawyer"),
      endpoint: flag(args, "endpoint"),
      runMode: ci ? "github-actions" : "local",
      fetchFn: fetch,
      outDir: (0, import_node_path5.resolve)(out, "lawstager-hook"),
      baselinePath: (0, import_node_path5.resolve)(root, flag(args, "baseline") ?? "lawstager-baseline.json"),
      answersJson: answersEnv ? process.env[answersEnv] : void 0,
      getOidcToken: ci ? fetchOidcToken : void 0,
      commit: ci ? process.env.GITHUB_SHA : void 0,
      runId: ci ? process.env.GITHUB_RUN_ID : void 0
    });
    console.log(outcome.sent ? `\u05E0\u05E9\u05DC\u05D7 \u05D3\u05D5\u05D7 \u05E9\u05D9\u05E0\u05D5\u05D9\u05D9\u05DD. \u05DE\u05E1\u05E4\u05E8 \u05D4\u05E1\u05E8\u05D9\u05E7\u05D4: ${outcome.scanId}. \u05E2\u05D3\u05DB\u05DF \u05D0\u05EA lawstager-baseline.json \u05D0\u05D7\u05E8\u05D9 \u05E9\u05E2\u05D5\u05E8\u05DA \u05D4\u05D3\u05D9\u05DF \u05D0\u05D9\u05E9\u05E8.` : "\u05D0\u05D9\u05DF \u05E9\u05D9\u05E0\u05D5\u05D9 \u05DE\u05E9\u05E4\u05D8\u05D9. \u05DC\u05D0 \u05E0\u05E9\u05DC\u05D7 \u05D3\u05D1\u05E8.");
    return 0;
  }
  console.log("\u05E9\u05D9\u05DE\u05D5\u05E9: scan [\u05EA\u05D9\u05E7\u05D9\u05D9\u05D4] | send [\u05EA\u05D9\u05E7\u05D9\u05D9\u05D4] [--lawyer \u05DE\u05D6\u05D4\u05D4] [--ci] | hook [\u05EA\u05D9\u05E7\u05D9\u05D9\u05D4] --out \u05EA\u05D9\u05E7\u05D9\u05D9\u05D4 [--baseline \u05E7\u05D5\u05D1\u05E5] [--ci --answers-env \u05E9\u05DD]");
  return 1;
}
main(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (error) => {
    console.error(error instanceof Error ? error.message : "\u05E9\u05D2\u05D9\u05D0\u05D4 \u05DC\u05D0 \u05E6\u05E4\u05D5\u05D9\u05D4");
    process.exit(1);
  }
);
