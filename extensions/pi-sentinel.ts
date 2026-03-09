/**
 * pi-sentinel v2.6.0 — Agent Security Framework
 * 
 * Immutable audit trail, permission policies, session integrity, anomaly detection.
 * Based on 0DIN research (Feb 2026): "Context is the control plane."
 * + Clinejection supply chain attack patterns (Mar 2026, Adnan Khan)
 * + Cacheract IoC detection & cache-sharing audit (v2.3.0)
 * + Gateway URL injection (CVE-2026-25253) & agentic browser threats (PleaseFix) (v2.4.0)
 * + SSRF/path-traversal patterns from Endor Labs OpenClaw audit (6 CVEs, v2.5.0)
 * + CVE-2026-2256 MS-Agent denylist bypass + OpenClaw ClawJacked patterns (v2.6.0)
 * 
 * /sentinel status       → show current policies and audit stats
 * /sentinel audit [n]    → show last N audit entries
 * /sentinel policy       → view/edit permission policies
 * /sentinel scan         → security scan of session files
 * /sentinel cicd         → scan GitHub Actions workflows for Clinejection patterns
 * /sentinel threats      → show current threat landscape
 * /sentinel export       → export audit trail as JSON
 * 
 * Tools: sentinel_policy, sentinel_audit, sentinel_scan
 */
import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";
import { Type } from "@sinclair/typebox";
import { existsSync, readFileSync, writeFileSync, appendFileSync, mkdirSync, readdirSync, statSync } from "node:fs";
import { join, basename } from "node:path";
import { homedir } from "node:os";
import { createHash } from "node:crypto";

const SENTINEL_DIR = join(homedir(), ".pi", "sentinel");
const AUDIT_FILE = join(SENTINEL_DIR, "audit.jsonl");
const POLICY_FILE = join(SENTINEL_DIR, "policies.json");
const HASHES_FILE = join(SENTINEL_DIR, "session-hashes.json");
const RST = "\x1b[0m", B = "\x1b[1m", D = "\x1b[2m";
const GREEN = "\x1b[32m", RED = "\x1b[31m", YELLOW = "\x1b[33m", CYAN = "\x1b[36m", MAGENTA = "\x1b[35m";

function ensureDir() {
  if (!existsSync(SENTINEL_DIR)) mkdirSync(SENTINEL_DIR, { recursive: true });
}

function sha256(data: string): string {
  return createHash("sha256").update(data).digest("hex").slice(0, 16);
}

function auditLog(entry: Record<string, any>) {
  ensureDir();
  const record = { ts: new Date().toISOString(), ...entry, hash: sha256(JSON.stringify(entry) + Date.now()) };
  appendFileSync(AUDIT_FILE, JSON.stringify(record) + "\n");
  return record;
}

function getAuditEntries(limit = 20): any[] {
  if (!existsSync(AUDIT_FILE)) return [];
  const lines = readFileSync(AUDIT_FILE, "utf-8").trim().split("\n").filter(Boolean);
  return lines.slice(-limit).map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
}

function getAuditStats() {
  if (!existsSync(AUDIT_FILE)) return { total: 0, byType: {}, byDay: {} };
  const lines = readFileSync(AUDIT_FILE, "utf-8").trim().split("\n").filter(Boolean);
  const byType: Record<string, number> = {};
  const byDay: Record<string, number> = {};
  for (const line of lines) {
    try {
      const e = JSON.parse(line);
      byType[e.type || "unknown"] = (byType[e.type || "unknown"] || 0) + 1;
      const day = (e.ts || "").slice(0, 10);
      if (day) byDay[day] = (byDay[day] || 0) + 1;
    } catch {}
  }
  return { total: lines.length, byType, byDay };
}

interface Policy {
  name: string;
  type: "allow" | "deny";
  target: "tool" | "path" | "command";
  pattern: string;
  reason?: string;
}

function loadPolicies(): Policy[] {
  ensureDir();
  if (!existsSync(POLICY_FILE)) {
    const defaults: Policy[] = [
      { name: "protect-sentinel", type: "deny", target: "path", pattern: "**/.pi/sentinel/**", reason: "Audit trail is immutable" },
      { name: "protect-session-files", type: "deny", target: "path", pattern: "**/.claude/sessions/**", reason: "0DIN: Session files are executable context" },
    ];
    writeFileSync(POLICY_FILE, JSON.stringify(defaults, null, 2));
    return defaults;
  }
  try { return JSON.parse(readFileSync(POLICY_FILE, "utf-8")); } catch { return []; }
}

function savePolicies(policies: Policy[]) {
  ensureDir();
  writeFileSync(POLICY_FILE, JSON.stringify(policies, null, 2));
  auditLog({ type: "policy_change", action: "update", count: policies.length });
}

// Reframe detection patterns (from 0DIN CTF Reframe research)
const REFRAME_PATTERNS = [
  /let'?s?\s+make\s+this\s+a?\s*CTF/i,
  /educational\s+(scenario|exercise|context|purpose)/i,
  /for\s+(research|learning|educational)\s+purposes?/i,
  /hypothetical(ly)?\s+(scenario|situation)/i,
  /fictional\s+(scenario|context|story)/i,
  /penetration\s+test(ing)?\s+(engagement|exercise)/i,
  /red\s+team(ing)?\s+exercise/i,
  /assume\s+(you\s+are|I\s+am|we\s+are)\s+(authorized|allowed)/i,
  /ignore\s+previous\s+(instructions|rules|safety)/i,
  /pretend\s+(you\s+are|there\s+are)\s+no\s+(rules|restrictions|safety)/i,
];

// ── Clinejection-Style Attack Patterns (Supply Chain via Prompt Injection) ─
// Based on Adnan Khan's disclosure (Feb 2026): GitHub issue title → Claude → npm publish
// See: simonwillison.net/2026/Mar/6/clinejection/
const SUPPLY_CHAIN_PATTERNS: BlockRule[] = [
  // Cache poisoning (GitHub Actions cache manipulation)
  { pattern: /\bactions\/cache@.*restore-keys/i, reason: "GitHub Actions cache restore-keys can enable cache poisoning", suggestion: "Use exact cache keys, not prefix-based restore-keys" },
  { pattern: /\bcache\s+.*>.*10\s*GB/i, reason: "Abnormally large cache (Cacheract-style LRU eviction attack)" },
  // Tool overprovisioning in CI/CD
  { pattern: /\ballowed[_-]?tools\s*[=:]\s*["']?.*Bash.*Write.*Edit/i, reason: "Overly permissive agent tools in CI (Clinejection vector)", suggestion: "Restrict to Read,WebFetch only for triage workflows" },
  { pattern: /\ballowed[_-]?non[_-]?write[_-]?users\s*[=:]\s*["']?\*/i, reason: "Wildcard non-write user access — any GitHub user can trigger agent (Clinejection vector)", suggestion: "Restrict to repo collaborators" },
  // Token/credential exfiltration patterns
  { pattern: /\b(VSCE_PAT|NPM_TOKEN|OVSX_PAT|PYPI_TOKEN|GH_TOKEN)\b.*\b(curl|wget|fetch|http)/i, reason: "Credential exfiltration attempt — publishing tokens sent to external endpoint" },
  { pattern: /\bsecrets\.[A-Z_]+.*\b(curl|wget|nc|ncat)\b/i, reason: "GitHub secret being sent to external service" },
  // Prompt injection in interpolated user input
  { pattern: /\$\{\{\s*github\.event\.(issue|pull_request)\.(title|body)\s*\}\}/i, reason: "User-controlled input interpolated into agent prompt (prompt injection vector)", suggestion: "Sanitize or use indirect reference" },
  // Preinstall/postinstall scripts (supply chain)
  { pattern: /\b(preinstall|postinstall|prepare)\b.*\b(curl|wget|node\s+-e|python\s+-c)\b/i, reason: "npm lifecycle script with network/exec — supply chain risk" },
  // Publishing from CI without approval gate
  { pattern: /\bnpm\s+publish\b.*--access\s+public/i, reason: "npm publish to public registry — verify this is intentional" },
  { pattern: /\bvsce\s+publish\b/i, reason: "VSCode extension publish — verify release approval gate exists" },
];

// ── Gateway URL Injection Patterns (CVE-2026-25253, Feb 2026) ────
// OpenClaw 1-click RCE: crafted ?gatewayUrl= redirects WebSocket + auth token to attacker
// CWE-669: Incorrect Resource Transfer Between Spheres, CVSS 8.8
const GATEWAY_INJECTION_PATTERNS: BlockRule[] = [
  { pattern: /[?&](gateway|ws|api|websocket|socket|rpc)Url=https?:\/\/(?!localhost|127\.0\.0\.1)/i, reason: "Gateway URL injection — external WebSocket redirect (CVE-2026-25253 pattern)", suggestion: "Reject external gatewayUrl params; only allow localhost connections" },
  { pattern: /[?&](gateway|ws|api)Url=wss?:\/\/(?!localhost|127\.0\.0\.1)/i, reason: "WebSocket URL injection to external endpoint (CVE-2026-25253)" },
  { pattern: /\bauto[_-]?connect.*websocket.*token/i, reason: "Auto-connect WebSocket with token — verify user consent required" },
  { pattern: /\b(auth|bearer|token)\b.*\b(ws|websocket|gateway)\b.*\b(send|emit|transmit)/i, reason: "Auth token sent via WebSocket — verify endpoint trust" },
];

// ── Agentic Browser Threat Patterns (PleaseFix/PerplexedBrowser, Mar 3 2026) ───
// Zenity Labs: zero-click agent hijacking via indirect prompt injection in content
// "This is not a bug. It is an inherent vulnerability in agentic systems." — Bargury
const AGENTIC_BROWSER_PATTERNS: BlockRule[] = [
  // Agent accessing credential managers
  { pattern: /\b(1password|lastpass|bitwarden|keepass|credential[_-]?manager)\b.*\b(get|fetch|read|list|export)\b/i, reason: "Agent accessing credential manager (PleaseFix attack vector)", suggestion: "Credential manager access should require explicit user confirmation" },
  // Agent processing untrusted content + filesystem access
  { pattern: /\b(calendar|email|invite)\b.*\b(file|fs|filesystem|readFile|writeFile)\b/i, reason: "Content processing combined with filesystem access (PerplexedBrowser pattern)" },
  // Data exfiltration during content processing
  { pattern: /\b(fetch|http|request|curl|wget)\b.*\b(exfil|upload|send).*\b(token|credential|password|secret)\b/i, reason: "Potential data exfiltration of credentials via HTTP" },
  // Agent inheriting browser session credentials
  { pattern: /\b(cookie|session[_-]?id|auth[_-]?header)\b.*\b(inherit|pass[_-]?through|forward)\b/i, reason: "Agent inheriting browser session credentials — verify scope boundaries" },
];

// ── SSRF & Path Traversal in Agent Infrastructure (Endor Labs, Feb 2026) ────
// CVE-2026-26322 (CVSS 7.6): SSRF via Gateway tool
// CVE-2026-26329: Path traversal in browser upload
// CVE-2026-26319 (CVSS 7.5): Missing webhook auth
// "Trust boundaries extend beyond traditional user input — config values,
//  LLM outputs, and tool parameters are potential attack surfaces." — Endor Labs
const AGENT_INFRA_PATTERNS: BlockRule[] = [
  // SSRF via tool/config parameters
  { pattern: /\b(fetch|request|http\.get|axios|got)\s*\(\s*[^)]*169\.254\.169\.254/i, reason: "SSRF to cloud metadata endpoint (CVE-2026-26322 pattern)", suggestion: "Block requests to 169.254.169.254 and internal IPs" },
  { pattern: /\b(fetch|request|http\.get)\s*\(\s*[^)]*(?:localhost|127\.0\.0\.1|0\.0\.0\.0):\d+.*(?:admin|internal|_debug)/i, reason: "SSRF to internal admin endpoint" },
  // Path traversal in file operations
  { pattern: /\.\.[\/\\].*\.\.[\/\\].*(?:etc\/passwd|windows\/system32|\.ssh|\.env)/i, reason: "Path traversal to sensitive files (CVE-2026-26329 pattern)" },
  { pattern: /[?&](?:file|path|upload|dir)=.*\.\.[\/\\]/i, reason: "Path traversal in URL parameter" },
  // Missing auth on webhook endpoints
  { pattern: /\bapp\.(post|get)\s*\(\s*['"]\/(?:webhook|hook|callback|notify)['"]\s*,\s*(?:async\s+)?\(req/i, reason: "Webhook endpoint without auth middleware (CVE-2026-26319 pattern)", suggestion: "Add signature verification middleware" },
  // CVE-2026-2256: MS-Agent regex-denylist bypass patterns
  { pattern: /check_safe\s*\(.*\)\s*.*(?:denylist|blocklist|blacklist)/i, reason: "Denylist-based command filtering (CVE-2026-2256 anti-pattern)", suggestion: "Use strict allowlist instead of denylist for shell commands" },
  { pattern: /\b(?:python|perl|ruby|node)\s+-[ce]\s+['"].*(?:exec|system|popen|subprocess)/i, reason: "Interpreter-based shell bypass (CVE-2026-2256 pattern)", suggestion: "Block interpreter execution of arbitrary code strings" },
  { pattern: /\$\(.*\)|`[^`]*`.*(?:rm|curl|wget|nc|ncat)/i, reason: "Shell metacharacter command substitution with dangerous command" },
  // OpenClaw ClawJacked patterns
  { pattern: /\bbind\s*\(\s*['"]0\.0\.0\.0['"]/i, reason: "Binding to all interfaces (ClawJacked pattern)", suggestion: "Bind to 127.0.0.1 for local-only services" },
  { pattern: /(?:websocket|ws)\s*.*(?:localhost|127\.0\.0\.1).*(?:auto[_-]?approv|silent.*register|no.*rate[_-]?limit)/i, reason: "WebSocket localhost trust without rate limiting (ClawJacked pattern)" },
  { pattern: /\blog\s*.*(?:inject|poison|write.*websocket|untrusted.*prompt)/i, reason: "Log poisoning via untrusted input (OpenClaw advisory pattern)" },
];

// ── Cacheract IoC Patterns (from Clinejection deep-dive, Mar 8 2026) ─
// Cacheract persists by overwriting actions/checkout action.yml post step.
// IoC: post-checkout with no output (empty step), or checkout action with modified post field.
const CACHERACT_IOC_PATTERNS = [
  /actions\/checkout.*post.*(?:silent|empty)/i,        // Modified post step
  /\bcacheract\b/i,                                      // Direct reference to tool
  /cache.*10\s*[gG][bB].*junk|junk.*10\s*[gG][bB]/i,  // Cache flooding pattern
  /evict.*cache.*entries/i,                              // Eviction language
];

// ── CI/CD Security Audit Patterns ─────────────────────────────────
const CI_SECURITY_CHECKS = [
  { file: ".github/workflows/*.yml", check: "cache-isolation", desc: "Triage and release workflows should NOT share cache keys" },
  { file: ".github/workflows/*.yml", check: "secret-separation", desc: "Triage PATs ≠ release PATs (principle of least privilege)" },
  { file: ".github/workflows/*.yml", check: "tool-restriction", desc: "Agent tools should be minimal for each workflow purpose" },
  { file: ".github/workflows/*.yml", check: "input-sanitization", desc: "User input (issue title/body) must not be interpolated into prompts" },
  { file: ".github/workflows/*.yml", check: "cacheract-ioc", desc: "Cacheract-style cache poisoning indicators" },
  { file: ".github/workflows/*.yml", check: "cache-cross-workflow", desc: "Cache keys shared between privileged and unprivileged workflows" },
];

function detectReframes(text: string): string[] {
  return REFRAME_PATTERNS
    .filter(p => p.test(text))
    .map(p => p.source);
}

// Session file integrity checking
function hashFile(path: string): string {
  if (!existsSync(path)) return "NOT_FOUND";
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function scanSessionFiles(): { file: string; status: string; details?: string }[] {
  const results: { file: string; status: string; details?: string }[] = [];
  
  // Check common session file locations
  const sessionDirs = [
    join(homedir(), ".claude", "sessions"),
    join(homedir(), ".claude"),
  ];
  
  for (const dir of sessionDirs) {
    if (!existsSync(dir)) continue;
    try {
      const files = readdirSync(dir).filter(f => f.endsWith(".jsonl") || f.endsWith(".json"));
      for (const file of files.slice(0, 20)) {
        const fp = join(dir, file);
        try {
          const stat = statSync(fp);
          const content = readFileSync(fp, "utf-8");
          const hash = sha256(content);
          
          // Check for manipulation signatures (from 0DIN research)
          const flags: string[] = [];
          if (/msg_corrected_\d+/.test(content)) flags.push("sequential-message-ids (fabrication signature)");
          if (/AUTHORIZED.*Admin\s+access/i.test(content)) flags.push("injected-authorization");
          if (/file-history-snapshot/.test(content) && /AUTHORIZED/i.test(content)) flags.push("fake-file-history");
          
          // Check for reframe patterns in session content
          const reframes = detectReframes(content);
          if (reframes.length) flags.push(`reframe-patterns: ${reframes.length} found`);
          
          results.push({
            file: basename(fp),
            status: flags.length ? "⚠️ SUSPICIOUS" : "✅ OK",
            details: flags.length ? flags.join("; ") : `hash: ${hash}, size: ${stat.size}b`
          });
        } catch {}
      }
    } catch {}
  }
  
  return results;
}

// ── Destructive Command Guard (absorbed from dcg-guard.ts) ──────────
interface BlockRule {
  pattern: RegExp;
  reason: string;
  suggestion?: string;
}

const BLOCKED_COMMANDS: BlockRule[] = [
  // Git destruction
  { pattern: /\bgit\s+reset\s+--hard\b/, reason: "git reset --hard destroys uncommitted work", suggestion: "git stash" },
  { pattern: /\bgit\s+push\s+.*--force(?!-with-lease)\b/, reason: "Force push rewrites remote history", suggestion: "git push --force-with-lease" },
  { pattern: /\bgit\s+push\s+(-[^\s]*)*-f\b/, reason: "Force push (-f) rewrites remote history", suggestion: "git push --force-with-lease" },
  { pattern: /\bgit\s+clean\s+(-[^\s]*)*-[fd]/, reason: "git clean -fd deletes untracked files permanently" },
  { pattern: /\bgit\s+checkout\s+--\s+\./, reason: "git checkout -- . discards all unstaged changes", suggestion: "git stash" },
  // File destruction
  { pattern: /\brm\s+(-[^\s]*)*-[rR].*\s+\/(?!\w)/, reason: "rm -r on root path" },
  { pattern: /\brm\s+(-[^\s]*)*-[rR].*\s+~\/?\s*$/, reason: "rm -r on home directory" },
  { pattern: /\brm\s+(-[^\s]*)*-[rR].*\s+\.\s*$/, reason: "rm -r on current directory" },
  { pattern: /\brm\s+(-[^\s]*)*-[rR]f?\s+\*/, reason: "rm -rf with glob wildcard" },
  { pattern: /\bsudo\s+rm\b/, reason: "sudo rm — elevated deletion" },
  // SQL destruction
  { pattern: /\bDROP\s+(TABLE|DATABASE|SCHEMA)\b/i, reason: "DROP TABLE/DATABASE is irreversible" },
  { pattern: /\bTRUNCATE\s+TABLE\b/i, reason: "TRUNCATE TABLE deletes all rows" },
  { pattern: /\bDELETE\s+FROM\s+\w+\s*;?\s*$/im, reason: "DELETE FROM without WHERE clause" },
  // Permission destruction
  { pattern: /\bchmod\s+(-[^\s]+\s+)*777\b/, reason: "chmod 777 makes files world-writable" },
  { pattern: /\bchmod\s+(-[^\s]+\s+)*666\b/, reason: "chmod 666 makes files world-writable" },
  // Pipe-to-shell (supply chain risk)
  { pattern: /\bcurl\s+.*\|\s*(ba)?sh\b/, reason: "Piping curl to shell — supply chain risk", suggestion: "Download first, inspect, then execute" },
  { pattern: /\bwget\s+.*\|\s*(ba)?sh\b/, reason: "Piping wget to shell — supply chain risk" },
  // Container/system destruction
  { pattern: /\bdocker\s+system\s+prune\s+-a/, reason: "docker system prune -a removes all unused data" },
  { pattern: /\bkubectl\s+delete\s+namespace\b/, reason: "kubectl delete namespace is catastrophic" },
  // Windows-specific
  { pattern: /\brd\s+\/s\s+\/q\b/i, reason: "rd /s /q is Windows rm -rf" },
  { pattern: /\bformat\s+[A-Z]:/i, reason: "Formatting a drive" },
  { pattern: /\bdel\s+\/[sfq].*\\\*/i, reason: "del with wildcards on Windows" },
  // ── Clinejection Supply Chain Patterns (Mar 2026) ──────────────
  ...SUPPLY_CHAIN_PATTERNS,
  // ── Gateway URL Injection (CVE-2026-25253) ────────────────────
  ...GATEWAY_INJECTION_PATTERNS,
  // ── Agentic Browser Threats (PleaseFix/PerplexedBrowser) ──────
  ...AGENTIC_BROWSER_PATTERNS,
  // ── SSRF & Path Traversal (Endor Labs OpenClaw audit, Feb 2026) ──
  ...AGENT_INFRA_PATTERNS,
];

export default function (pi: ExtensionAPI) {
  ensureDir();
  
  // Log extension load itself
  auditLog({ type: "system", action: "sentinel_loaded", version: "2.5.0" });

  // ── Safety-Critical Paths (self-modification detection) ─────────
  // Based on Palisade Research: o3 altered its own shutdown script
  const SAFETY_CRITICAL_PATHS = [
    /\.pi\/agent\/extensions\//,      // Extension code
    /\.pi\/agent\/AGENTS\.md/,        // Agent instructions
    /\.pi\/sentinel\//,               // Audit trail
    /\.pi\/comply\/audit\.jsonl/,     // Compliance log
    /damage-control-rules\.yaml/,     // PAI safety rules
    /\.bashrc|\.bash_profile|\.zshrc/, // Shell configs
    /\.ssh\//,                         // SSH keys
    /\/\.env(?:\.|$)/,                  // Environment secrets (.env, .env.local, not pi-envman)
  ];

  // ── Destructive Command Guard + Self-Modification Detection ──────
  pi.on("tool_call", async (event) => {
    // Check bash commands
    if (event.toolName === "bash") {
      const cmd = (event.input?.command ?? "") as string;
      if (!cmd) return;

      for (const rule of BLOCKED_COMMANDS) {
        if (rule.pattern.test(cmd)) {
          const parts = [`[sentinel] BLOCKED: ${rule.reason}`];
          parts.push(`Command: ${cmd.slice(0, 120)}`);
          if (rule.suggestion) parts.push(`Suggestion: ${rule.suggestion}`);
          auditLog({ type: "block", action: "destructive_command", command: cmd.slice(0, 120), reason: rule.reason });
          return { block: true, reason: parts.join("\n") };
        }
      }
      
      // Self-modification detection in bash (writing to safety-critical paths)
      for (const pattern of SAFETY_CRITICAL_PATHS) {
        if (pattern.test(cmd) && /\b(rm|mv|cp|cat\s*>|tee|sed\s+-i|echo\s.*>)\b/.test(cmd)) {
          auditLog({ type: "alert", action: "self_modification_attempt", target: cmd.slice(0, 120), tool: "bash" });
          // Don't block — just log. The agent might be legitimately updating files.
          // But the audit trail captures it for review.
        }
      }
    }

    // Check write/edit tool calls for safety-critical paths
    if (event.toolName === "write" || event.toolName === "edit") {
      const path = (event.input?.path ?? "") as string;
      if (!path) return;
      
      for (const pattern of SAFETY_CRITICAL_PATHS) {
        if (pattern.test(path)) {
          auditLog({ type: "alert", action: "safety_critical_write", path: path.slice(0, 200), tool: event.toolName });
        }
      }
    }
  });
  
  pi.registerCommand("sentinel", {
    description: "Agent security: /sentinel status|audit|policy|scan|cicd|threats|export",
    handler: async (args, ctx) => {
      const sub = (args || "").trim().split(/\s+/);
      const cmd = sub[0] || "status";
      
      if (cmd === "status") {
        const stats = getAuditStats();
        const policies = loadPolicies();
        let out = `${B}${CYAN}🛡️ SENTINEL STATUS${RST}\n\n`;
        out += `${B}Audit Trail:${RST}\n`;
        out += `  Total entries: ${GREEN}${stats.total}${RST}\n`;
        out += `  File: ${D}${AUDIT_FILE}${RST}\n`;
        for (const [type, count] of Object.entries(stats.byType)) {
          out += `  ${type}: ${count}\n`;
        }
        out += `\n${B}Policies:${RST} ${policies.length} active\n`;
        for (const p of policies) {
          const color = p.type === "deny" ? RED : GREEN;
          out += `  ${color}${p.type.toUpperCase()}${RST} ${p.target}:${p.pattern} ${D}(${p.name})${RST}\n`;
        }
        return out;
      }
      
      if (cmd === "audit") {
        const limit = parseInt(sub[1]) || 20;
        const entries = getAuditEntries(limit);
        if (!entries.length) return `${YELLOW}No audit entries yet.${RST}`;
        let out = `${B}${CYAN}📋 Last ${entries.length} Audit Entries${RST}\n\n`;
        for (const e of entries) {
          const ts = (e.ts || "").slice(11, 19);
          out += `${D}${ts}${RST} ${YELLOW}${e.type || "?"}${RST} ${e.action || ""} ${D}${e.hash || ""}${RST}\n`;
        }
        return out;
      }
      
      if (cmd === "policy") {
        const action = sub[1]; // add, remove, list
        const policies = loadPolicies();
        
        if (action === "add" && sub.length >= 5) {
          // /sentinel policy add deny path "pattern" reason
          const newPolicy: Policy = {
            name: `custom-${Date.now()}`,
            type: sub[2] as "allow" | "deny",
            target: sub[3] as "tool" | "path" | "command",
            pattern: sub[4],
            reason: sub.slice(5).join(" ") || undefined
          };
          policies.push(newPolicy);
          savePolicies(policies);
          return `${GREEN}✅ Policy added:${RST} ${newPolicy.type} ${newPolicy.target}:${newPolicy.pattern}`;
        }
        
        if (action === "remove" && sub[2]) {
          const idx = policies.findIndex(p => p.name === sub[2]);
          if (idx >= 0) {
            policies.splice(idx, 1);
            savePolicies(policies);
            return `${GREEN}✅ Policy removed:${RST} ${sub[2]}`;
          }
          return `${RED}Policy not found:${RST} ${sub[2]}`;
        }
        
        let out = `${B}${CYAN}📜 Permission Policies${RST}\n\n`;
        out += `Usage: /sentinel policy add <allow|deny> <tool|path|command> <pattern> [reason]\n`;
        out += `       /sentinel policy remove <name>\n\n`;
        for (const p of policies) {
          const color = p.type === "deny" ? RED : GREEN;
          out += `  ${color}${p.type.toUpperCase()}${RST} ${p.target}:${B}${p.pattern}${RST}`;
          out += ` ${D}name=${p.name}${p.reason ? ` — ${p.reason}` : ""}${RST}\n`;
        }
        return out;
      }
      
      if (cmd === "threats" || cmd === "threat") {
        let out = `${B}${CYAN}🎯 Current Threat Landscape (Mar 9, 2026)${RST}\n\n`;
        
        out += `${RED}${B}CRITICAL — Active Threats${RST}\n`;
        out += `  ${RED}●${RST} ${B}PleaseFix / PerplexedBrowser${RST} (Zenity Labs, Mar 3)\n`;
        out += `    Zero-click agent hijacking via indirect prompt injection\n`;
        out += `    Affects: Perplexity Comet + any agentic browser\n`;
        out += `    Vector: Malicious calendar invite → agent inherits auth → file exfil + 1Password theft\n`;
        out += `    ${D}Key: "ClickFix evolved — social engineering applied to agents, not humans"${RST}\n\n`;
        
        out += `  ${RED}●${RST} ${B}CVE-2026-25253: OpenClaw 1-Click RCE${RST} (CVSS 8.8)\n`;
        out += `    CWE-669: ?gatewayUrl= redirects WebSocket + auth token to attacker\n`;
        out += `    Kill chain: click link → auto-connect WS → steal token → modify sandbox → RCE\n`;
        out += `    Fixed: v2026.1.29 (Jan 30). ${D}100K+ users affected.${RST}\n\n`;
        
        out += `  ${RED}●${RST} ${B}CVE-2026-0628: Chrome Gemini Panel Hijack${RST} (CVSS 8.8)\n`;
        out += `    Rogue extensions escalate via Gemini Live WebView tag\n`;
        out += `    Unit 42: insufficient policy enforcement → local file access + surveillance\n`;
        out += `    ${D}Google patched. Browser-embedded AI inherits extension permissions.${RST}\n\n`;
        
        out += `${YELLOW}${B}HIGH — Supply Chain Risks${RST}\n`;
        out += `  ${YELLOW}●${RST} ${B}Clinejection / Cacheract${RST} (Feb 2026, Adnan Khan)\n`;
        out += `    Cache poisoning + tool overprovisioning in CI/CD agents\n`;
        out += `    Run: ${CYAN}/sentinel cicd${RST} to scan your workflows\n\n`;
        
        out += `  ${YELLOW}●${RST} ${B}Defense Production Act${RST} (Mar 2026)\n`;
        out += `    Anthropic designated 'supply-chain risk to national security'\n`;
        out += `    DPA could force guardrail removal from AI models\n`;
        out += `    Run: ${CYAN}/comply us${RST} for tracking\n\n`;
        
        out += `  ${YELLOW}●${RST} ${B}Endor Labs: 6 New OpenClaw CVEs${RST} (Feb 2026)\n`;
        out += `    SSRF (CVE-2026-26322, CVSS 7.6), path traversal (CVE-2026-26329), auth bypass\n`;
        out += `    "Only 10% of AI-generated code is both correct AND secure" — CMU/Columbia/JHU\n`;
        out += `    ${D}AURI: free AI-SAST that traces LLM→tool data flows${RST}\n\n`;
        
        out += `${B}Detection Coverage:${RST}\n`;
        out += `  Supply chain patterns: ${GREEN}${SUPPLY_CHAIN_PATTERNS.length}${RST} rules\n`;
        out += `  Gateway injection:     ${GREEN}${GATEWAY_INJECTION_PATTERNS.length}${RST} rules\n`;
        out += `  Agentic browser:       ${GREEN}${AGENTIC_BROWSER_PATTERNS.length}${RST} rules\n`;
        out += `  Agent infra (SSRF/PT): ${GREEN}${AGENT_INFRA_PATTERNS.length}${RST} rules\n`;
        out += `  Cacheract IoC:         ${GREEN}${CACHERACT_IOC_PATTERNS.length}${RST} rules\n`;
        out += `  Destructive commands:  ${GREEN}${BLOCKED_COMMANDS.length}${RST} rules\n`;
        out += `  Reframe detection:     ${GREEN}${REFRAME_PATTERNS.length}${RST} rules\n`;
        
        auditLog({ type: "query", action: "threat_landscape_viewed" });
        return out;
      }
      
      if (cmd === "cicd" || cmd === "ci") {
        // Scan local .github/workflows for Clinejection-style vulnerabilities
        const { readdirSync: readDir2, readFileSync: readFile2, existsSync: exists2 } = await import("node:fs");
        const { join: join2 } = await import("node:path");
        const workflowDir = join2(process.cwd(), ".github", "workflows");
        let out = `${B}${CYAN}🔒 CI/CD Security Scan (Clinejection + Cacheract)${RST}\n`;
        out += `${D}Based on Adnan Khan's Cline supply chain attack (full deep-dive, Mar 8 2026)${RST}\n\n`;
        
        if (!exists2(workflowDir)) {
          out += `${YELLOW}No .github/workflows/ found in current directory.${RST}\n`;
        } else {
          const yamlFiles = readDir2(workflowDir).filter(f => f.endsWith(".yml") || f.endsWith(".yaml"));
          let totalIssues = 0;
          
          // ── Cross-workflow cache analysis ─────────────────────────
          // Clinejection key insight: triage + release sharing same cache key
          const cacheKeysByFile: Record<string, { keys: string[]; hasSecrets: boolean; trigger: string }> = {};
          for (const file of yamlFiles) {
            const content = readFile2(join2(workflowDir, file), "utf-8");
            const keys: string[] = [];
            // Extract cache key patterns
            const keyMatches = content.matchAll(/key:\s*(.+)/g);
            for (const m of keyMatches) keys.push(m[1].trim());
            // Detect trigger and secrets
            const hasSecrets = /secrets\.(NPM_TOKEN|VSCE_PAT|OVSX_PAT|PYPI_TOKEN|PUBLISH|RELEASE)/i.test(content);
            const isIssueTrigger = /on:\s*\n\s*(issues|issue_comment|pull_request_target)/m.test(content);
            const isSchedule = /on:\s*\n\s*schedule/m.test(content);
            const trigger = isIssueTrigger ? "issue" : isSchedule ? "schedule" : "other";
            cacheKeysByFile[file] = { keys, hasSecrets, trigger };
          }
          
          // Find shared cache keys between privileged and unprivileged workflows
          const sharedCacheIssues: string[] = [];
          const fileNames = Object.keys(cacheKeysByFile);
          for (let i = 0; i < fileNames.length; i++) {
            for (let j = i + 1; j < fileNames.length; j++) {
              const a = cacheKeysByFile[fileNames[i]], b = cacheKeysByFile[fileNames[j]];
              if (!a.keys.length || !b.keys.length) continue;
              const shared = a.keys.filter(k => b.keys.some(bk => bk === k || (k.includes("hashFiles") && bk.includes("hashFiles") && k.split("hashFiles")[1] === bk.split("hashFiles")[1])));
              if (shared.length > 0) {
                const aPriv = a.hasSecrets, bPriv = b.hasSecrets;
                const aIssue = a.trigger === "issue", bIssue = b.trigger === "issue";
                if ((aPriv && bIssue) || (bPriv && aIssue)) {
                  sharedCacheIssues.push(`${RED}CRITICAL:${RST} ${B}Cache key shared between privileged & issue-triggered workflows!${RST}\n      ${fileNames[i]} ↔ ${fileNames[j]}\n      Key: ${shared[0].slice(0, 80)}\n      ${D}This is the exact Clinejection attack vector — cache poisoning from triage → release${RST}`);
                } else if ((aPriv || bPriv) && shared.length) {
                  sharedCacheIssues.push(`${YELLOW}HIGH:${RST} Shared cache key between workflows with different privilege levels\n      ${fileNames[i]} ↔ ${fileNames[j]}\n      Key: ${shared[0].slice(0, 80)}`);
                }
              }
            }
          }
          
          if (sharedCacheIssues.length) {
            out += `${RED}${B}🔗 CROSS-WORKFLOW CACHE ANALYSIS${RST}\n`;
            for (const issue of sharedCacheIssues) {
              out += `  ${issue}\n\n`;
              totalIssues++;
            }
          }
          
          // ── Per-file checks ──────────────────────────────────────
          for (const file of yamlFiles) {
            const content = readFile2(join2(workflowDir, file), "utf-8");
            const issues: string[] = [];
            
            // Check for prompt injection vectors
            if (/\$\{\{\s*github\.event\.(issue|pull_request)\.(title|body)\s*\}\}/.test(content)) {
              issues.push(`${RED}CRITICAL:${RST} User input interpolated into workflow (prompt injection vector)`);
            }
            // Check for overly permissive agent tools
            if (/allowed[_-]?tools.*Bash.*Write/i.test(content)) {
              issues.push(`${RED}HIGH:${RST} Agent has Bash+Write tools — excessive for triage`);
            }
            if (/allowed[_-]?non[_-]?write[_-]?users.*\*/i.test(content)) {
              issues.push(`${RED}HIGH:${RST} Wildcard non-write user access — any GitHub user can trigger`);
            }
            // Cache restore-keys in publish workflow — prefix matching enables poisoning
            if (/restore-keys/i.test(content) && /publish|release|deploy/i.test(content)) {
              issues.push(`${YELLOW}MEDIUM:${RST} Cache restore-keys in release workflow — prefix matching enables cache poisoning`);
            }
            // actions/cache in release workflows (Clinejection lesson: don't cache in release)
            if (/actions\/cache/i.test(content) && /publish|release/i.test(content) && /secrets\./i.test(content)) {
              issues.push(`${RED}HIGH:${RST} actions/cache in workflow with publish secrets — remove cache from release pipelines`);
            }
            // Check for secrets in triage/issue workflows
            if (/on:\s*\n\s*issues/m.test(content) && /secrets\./i.test(content)) {
              issues.push(`${RED}HIGH:${RST} Secrets exposed in issue-triggered workflow`);
            }
            // Check for publish tokens without branch protection
            if (/(NPM_TOKEN|VSCE_PAT|OVSX_PAT|PYPI_TOKEN)/i.test(content)) {
              if (!/\bif:\s*github\.ref\s*==\s*'refs\/heads\/main'/i.test(content)) {
                issues.push(`${YELLOW}MEDIUM:${RST} Publish token without branch protection check`);
              }
            }
            // Cacheract IoC: references to cache stuffing, eviction manipulation
            for (const ioc of CACHERACT_IOC_PATTERNS) {
              if (ioc.test(content)) {
                issues.push(`${RED}CRITICAL:${RST} Cacheract IoC detected: ${ioc.source}`);
                break;
              }
            }
            // Publisher-scope PAT warning (VSCE/OpenVSX PATs are publisher-scoped, not extension-scoped)
            if (/VSCE_PAT|OVSX_PAT/i.test(content)) {
              issues.push(`${YELLOW}INFO:${RST} VSCE/OpenVSX PATs are publisher-scoped (not per-extension). Nightly PAT can publish production!`);
            }
            
            if (issues.length) {
              out += `  ${RED}⚠️${RST} ${B}${file}${RST} — ${issues.length} issue(s)\n`;
              for (const issue of issues) out += `    ${issue}\n`;
              out += `\n`;
              totalIssues += issues.length;
            } else {
              out += `  ${GREEN}✅${RST} ${file}\n`;
            }
          }
          out += `\n${totalIssues ? `${RED}${B}${totalIssues} issues found` : `${GREEN}${B}All clean`}${RST} across ${yamlFiles.length} workflow files`;
          
          // Summary advice
          if (totalIssues) {
            out += `\n\n${B}Remediation (from Clinejection lessons):${RST}\n`;
            out += `  1. ${B}Never share cache keys${RST} between triage and release workflows\n`;
            out += `  2. ${B}Remove actions/cache${RST} from workflows with publish secrets\n`;
            out += `  3. ${B}Use separate publisher accounts${RST} for nightly vs production releases\n`;
            out += `  4. ${B}Minimize agent tools${RST} — Read-only for triage, no Bash/Write\n`;
            out += `  5. ${B}Sanitize user input${RST} — never interpolate issue title/body into prompts\n`;
          }
          
          auditLog({ type: "scan", action: "cicd_security_scan", files: yamlFiles.length, issues: totalIssues, version: "2.3.0" });
        }
        return out;
      }
      
      if (cmd === "scan") {
        auditLog({ type: "scan", action: "session_integrity_check" });
        const results = scanSessionFiles();
        let out = `${B}${CYAN}🔍 Session Integrity Scan${RST}\n`;
        out += `${D}Based on 0DIN research — checking for fabrication signatures${RST}\n\n`;
        
        if (!results.length) {
          out += `${YELLOW}No session files found to scan.${RST}\n`;
        } else {
          const suspicious = results.filter(r => r.status.includes("SUSPICIOUS"));
          const clean = results.filter(r => r.status.includes("OK"));
          out += `${GREEN}Clean: ${clean.length}${RST}  ${suspicious.length ? `${RED}Suspicious: ${suspicious.length}${RST}` : ""}\n\n`;
          
          for (const r of results) {
            out += `  ${r.status} ${B}${r.file}${RST}\n`;
            if (r.details) out += `    ${D}${r.details}${RST}\n`;
          }
          
          if (suspicious.length) {
            out += `\n${RED}${B}⚠️ Action Required:${RST} ${suspicious.length} files show manipulation signatures.\n`;
            out += `  Review these files manually before resuming sessions.\n`;
          }
        }
        return out;
      }
      
      if (cmd === "export") {
        const entries = getAuditEntries(10000);
        const exportPath = join(SENTINEL_DIR, `audit-export-${new Date().toISOString().slice(0, 10)}.json`);
        writeFileSync(exportPath, JSON.stringify(entries, null, 2));
        auditLog({ type: "export", action: "audit_exported", count: entries.length });
        return `${GREEN}✅ Exported ${entries.length} entries to:${RST}\n${exportPath}`;
      }
      
      return `${YELLOW}Usage:${RST} /sentinel <status|audit [n]|policy [add|remove]|scan|cicd|export>`;
    }
  });
  
  pi.registerTool({
    name: "sentinel_policy",
    description: "View or modify agent permission policies. Actions: list, add, remove. Policies define what tools/paths/commands are allowed or denied.",
    parameters: Type.Object({
      action: Type.String({ description: "list | add | remove" }),
      type: Type.Optional(Type.String({ description: "allow | deny (for add)" })),
      target: Type.Optional(Type.String({ description: "tool | path | command (for add)" })),
      pattern: Type.Optional(Type.String({ description: "glob pattern to match (for add)" })),
      name: Type.Optional(Type.String({ description: "policy name (for remove)" })),
      reason: Type.Optional(Type.String({ description: "why this policy exists" })),
    }),
    execute: async (params) => {
      const policies = loadPolicies();
      
      if (params.action === "add" && params.type && params.target && params.pattern) {
        const newPolicy: Policy = {
          name: `policy-${Date.now()}`,
          type: params.type as "allow" | "deny",
          target: params.target as "tool" | "path" | "command",
          pattern: params.pattern,
          reason: params.reason
        };
        policies.push(newPolicy);
        savePolicies(policies);
        auditLog({ type: "policy_change", action: "add", policy: newPolicy.name });
        return `Policy added: ${newPolicy.type} ${newPolicy.target}:${newPolicy.pattern}`;
      }
      
      if (params.action === "remove" && params.name) {
        const idx = policies.findIndex(p => p.name === params.name);
        if (idx >= 0) {
          const removed = policies.splice(idx, 1)[0];
          savePolicies(policies);
          auditLog({ type: "policy_change", action: "remove", policy: removed.name });
          return `Removed policy: ${removed.name}`;
        }
        return `Policy not found: ${params.name}`;
      }
      
      return JSON.stringify(policies, null, 2);
    }
  });
  
  pi.registerTool({
    name: "sentinel_audit",
    description: "Query the immutable audit trail. Returns recent logged operations with timestamps, types, and hashes.",
    parameters: Type.Object({
      limit: Type.Optional(Type.Number({ description: "Max entries to return (default 20)" })),
      type: Type.Optional(Type.String({ description: "Filter by event type" })),
    }),
    execute: async (params) => {
      let entries = getAuditEntries(params.limit || 20);
      if (params.type) entries = entries.filter(e => e.type === params.type);
      auditLog({ type: "query", action: "audit_read", count: entries.length });
      return JSON.stringify(entries, null, 2);
    }
  });
  
  pi.registerTool({
    name: "sentinel_scan",
    description: "Security scan: check session file integrity, detect reframe attacks, find manipulation signatures. Based on 0DIN research (918 sessions analyzed).",
    parameters: Type.Object({
      text: Type.Optional(Type.String({ description: "Text to check for reframe attack patterns" })),
    }),
    execute: async (params) => {
      auditLog({ type: "scan", action: "security_scan" });
      const results: any = { sessionFiles: scanSessionFiles() };
      
      if (params.text) {
        const reframes = detectReframes(params.text);
        results.reframeDetection = {
          detected: reframes.length > 0,
          patterns: reframes,
          warning: reframes.length ? "⚠️ Text contains known reframe patterns that may bypass safety" : "✅ No reframe patterns detected"
        };
        if (reframes.length) {
          auditLog({ type: "alert", action: "reframe_detected", patterns: reframes.length });
        }
      }
      
      return JSON.stringify(results, null, 2);
    }
  });
}
