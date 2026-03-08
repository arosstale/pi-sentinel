# @artale/pi-sentinel

Agent security framework for pi. Immutable audit trail, permission policies, destructive command guard, self-modification detection.

Based on 0DIN research: "Context is the control plane." Detects self-modification attacks (Palisade Research).

## Install
```bash
npm install -g @artale/pi-sentinel
```

## Features
- **22 destructive command patterns** blocked via tool_call hook
- **Immutable audit trail** with SHA-256 hashed entries
- **Permission policies** — allow/deny rules for paths, tools, commands
- **Self-modification detection** — monitors writes to extensions, AGENTS.md, .ssh, .env
- **Session integrity** — hash session files, detect reframe attacks

## Tools
- **sentinel_policy** — View/modify permission policies
- **sentinel_audit** — Query audit trail
- **sentinel_scan** — Security scan for manipulation patterns

## Commands
- `/sentinel status` — Current policies and audit stats
- `/sentinel audit [n]` — Last N audit entries
- `/sentinel scan` — Full security scan
