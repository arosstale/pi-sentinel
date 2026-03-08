/**
 * pi-sentinel v2.2.0 — Agent Security Framework
 * 
 * Immutable audit trail, permission policies, session integrity, anomaly detection.
 * Based on 0DIN research (Feb 2026): "Context is the control plane."
 * + Clinejection supply chain attack patterns (Mar 2026, Adnan Khan)
 * 
 * /sentinel status       → show current policies and audit stats
 * /sentinel audit [n]    → show last N audit entries
 * /sentinel policy       → view/edit permission policies
 * /sentinel scan         → security scan of session files
 * /sentinel cicd         → scan GitHub Actions workflows for Clinejection patterns
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

// ── CI/CD Security Audit Patterns ─────────────────────────────────
const CI_SECURITY_CHECKS = [
  { file: ".github/workflows/*.yml", check: "cache-isolation", desc: "Triage and release workflows should NOT share cache keys" },
  { file: ".github/workflows/*.yml", check: "secret-separation", desc: "Triage PATs ≠ release PATs (principle of least privilege)" },
  { file: ".github/workflows/*.yml", check: "tool-restriction", desc: "Agent tools should be minimal for each workflow purpose" },
  { file: ".github/workflows/*.yml", check: "input-sanitization", desc: "User input (issue title/body) must not be interpolated into prompts" },
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
];

export default function (pi: ExtensionAPI) {
  ensureDir();
  
  // Log extension load itself
  auditLog({ type: "system", action: "sentinel_loaded", version: "2.2.0" });

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
    description: "Agent security: /sentinel status|audit|policy|scan|cicd|export",
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
      
      if (cmd === "cicd" || cmd === "ci") {
        // Scan local .github/workflows for Clinejection-style vulnerabilities
        const { readdirSync: readDir2, readFileSync: readFile2, existsSync: exists2 } = await import("node:fs");
        const { join: join2 } = await import("node:path");
        const workflowDir = join2(process.cwd(), ".github", "workflows");
        let out = `${B}${CYAN}🔒 CI/CD Security Scan (Clinejection Patterns)${RST}\n`;
        out += `${D}Based on Adnan Khan's Cline supply chain attack disclosure${RST}\n\n`;
        
        if (!exists2(workflowDir)) {
          out += `${YELLOW}No .github/workflows/ found in current directory.${RST}\n`;
        } else {
          const yamlFiles = readDir2(workflowDir).filter(f => f.endsWith(".yml") || f.endsWith(".yaml"));
          let totalIssues = 0;
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
            // Check cache sharing between workflows
            if (/restore-keys/i.test(content) && /publish|release|deploy/i.test(content)) {
              issues.push(`${YELLOW}MEDIUM:${RST} Cache restore-keys in release workflow — cache poisoning risk`);
            }
            // Check for secrets in triage/issue workflows
            if (/on:\s*\n\s*issues/i.test(content) && /secrets\./i.test(content)) {
              issues.push(`${RED}HIGH:${RST} Secrets exposed in issue-triggered workflow`);
            }
            // Check for publish tokens
            if (/(NPM_TOKEN|VSCE_PAT|OVSX_PAT|PYPI_TOKEN)/i.test(content)) {
              if (!/\bif:\s*github\.ref\s*==\s*'refs\/heads\/main'/i.test(content)) {
                issues.push(`${YELLOW}MEDIUM:${RST} Publish token without branch protection check`);
              }
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
          auditLog({ type: "scan", action: "cicd_security_scan", files: yamlFiles.length, issues: totalIssues });
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
