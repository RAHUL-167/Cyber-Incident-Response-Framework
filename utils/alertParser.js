const fs = require("fs");
const path = require("path");

function safeReadFile(filePath) {
  try {
    return fs.readFileSync(filePath, "utf8");
  } catch {
    return "";
  }
}

function parseTimestampMaybe(s) {
  if (!s) return null;
  const trimmed = String(s).trim();

  // Common formats in this repo:
  // 1) "2025-07-23 12:34:56"
  // 2) "2025-07-23 12:34:56.123456"
  // 3) "2025-07-23T12:34:56"
  // 4) Python datetime default: "2026-02-03 12:34:56.123456"
  // Normalize " " -> "T" if it looks like a date-time.
  let isoLike = trimmed;
  if (/^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}/.test(isoLike)) {
    isoLike = isoLike.replace(" ", "T");
  }

  const d = new Date(isoLike);
  // NaN check
  if (Number.isNaN(d.getTime())) return null;
  return d;
}

function inferSeverity(lineLower) {
  if (lineLower.includes("critical")) return "CRITICAL";
  if (lineLower.includes("high")) return "HIGH";
  if (lineLower.includes("medium")) return "MEDIUM";
  if (lineLower.includes("low")) return "LOW";

  // Heuristic inference by common high-risk keywords
  const criticalHints = ["sql injection", "xss", "command injection", "malware", "ransomware", "syn flood"];
  if (criticalHints.some((h) => lineLower.includes(h))) return "CRITICAL";
  const highHints = ["privilege escalation", "brute force", "port scan", "data exfiltration", "dns tunneling"];
  if (highHints.some((h) => lineLower.includes(h))) return "HIGH";
  const mediumHints = ["suspicious", "anomaly", "unauthorized", "policy change"];
  if (mediumHints.some((h) => lineLower.includes(h))) return "MEDIUM";
  return "UNKNOWN";
}

function parseRuleName(line) {
  // New format: [ts] [SEV] Rule Name triggered - details: ...
  let m = line.match(/\]\s+\[(?:CRITICAL|HIGH|MEDIUM|LOW)\]\s+(.+?)\s+triggered/i);
  if (m) return m[1].trim();

  // Older format: [ts] Rule Name triggered: ...
  m = line.match(/\]\s+(.+?)\s+triggered[:\s]/i);
  if (m) return m[1].trim();

  // Fallback: try to capture "triggered" prefix
  m = line.match(/^\s*(.+?)\s+triggered/i);
  if (m) return m[1].trim();

  return "Unknown Rule";
}

function parseDescription(line) {
  const idxTriggered = line.toLowerCase().indexOf("triggered");
  if (idxTriggered >= 0) {
    const after = line.slice(idxTriggered + "triggered".length);
    // common separators: ":" or " - "
    const colonIdx = after.indexOf(":");
    if (colonIdx >= 0) return after.slice(colonIdx + 1).trim();
    const dashIdx = after.indexOf(" - ");
    if (dashIdx >= 0) return after.slice(dashIdx + 3).trim();
    return after.trim().replace(/^[:\-]+/, "").trim();
  }

  // Otherwise: return the line minus leading timestamp/severity blocks
  return line.replace(/^\s*(\[[^\]]+\]\s*){1,3}/, "").trim();
}

function parseAlertLine(rawLine, sourceFile) {
  const line = String(rawLine || "").trim();
  if (!line) return null;

  const bracketTokens = [...line.matchAll(/\[([^\]]+)\]/g)].map((m) => m[1]);
  const lineLower = line.toLowerCase();

  const tsCandidate = bracketTokens.length > 0 ? bracketTokens[0] : null;
  const ts = parseTimestampMaybe(tsCandidate);

  const sevToken = bracketTokens.find((t) => /^(CRITICAL|HIGH|MEDIUM|LOW)$/i.test(String(t).trim()));
  const severity = sevToken ? String(sevToken).trim().toUpperCase() : inferSeverity(lineLower);

  const rule = parseRuleName(line);
  const description = parseDescription(line);

  return {
    timestamp: ts ? ts.toISOString() : null,
    tsEpoch: ts ? ts.getTime() : null,
    severity,
    rule,
    description,
    raw: line,
    sourceFile,
  };
}

function readAllAlertLogs(alertsDir) {
  let files = [];
  try {
    files = fs
      .readdirSync(alertsDir, { withFileTypes: true })
      .filter((d) => d.isFile())
      .map((d) => d.name)
      .filter((name) => name.toLowerCase().endsWith(".log"))
      .map((name) => path.join(alertsDir, name));
  } catch {
    return [];
  }

  const alerts = [];
  for (const filePath of files) {
    const text = safeReadFile(filePath);
    if (!text) continue;
    const sourceFile = path.basename(filePath);
    const lines = text.split(/\r?\n/);
    for (const line of lines) {
      const parsed = parseAlertLine(line, sourceFile);
      if (parsed) alerts.push(parsed);
    }
  }

  // Sort newest first when timestamps exist; otherwise stable-ish by file name
  alerts.sort((a, b) => {
    const at = a.tsEpoch ?? -1;
    const bt = b.tsEpoch ?? -1;
    if (at !== bt) return bt - at;
    if (a.sourceFile !== b.sourceFile) return String(b.sourceFile).localeCompare(String(a.sourceFile));
    return String(b.raw).localeCompare(String(a.raw));
  });

  return alerts;
}

module.exports = {
  readAllAlertLogs,
  parseAlertLine,
};


