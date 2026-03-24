import { Decision, FirewallDecision, ToolCallContext } from "../types/firewallTypes";
import * as fs from "fs";
import * as path from "path";

// ── Config loading ──────────────────────────────────────────────────────────

const CONFIG_DIR = path.resolve(__dirname, "../../config");

interface DenyRules {
  patterns: string[];
  paths: string[];
}

interface SecretRules {
  filenames: string[];
  directories: string[];
}

interface ReviewRules {
  patterns: string[];
}

interface ConfigRules {
  patterns: string[];
}

interface PolicyConfig {
  rules: {
    deny: DenyRules;
    secret: SecretRules;
    review: ReviewRules;
    config: ConfigRules;
  };
}

interface AllowlistConfig {
  allowlist: {
    domains: string[];
  };
}

function loadJSON<T>(filename: string): T {
  const filePath = path.join(CONFIG_DIR, filename);
  const raw = fs.readFileSync(filePath, "utf-8");
  return JSON.parse(raw) as T;
}

const policy: PolicyConfig = loadJSON<PolicyConfig>("firewall.policy.json");
const allowlist: AllowlistConfig = loadJSON<AllowlistConfig>("allowlist.domains.json");

// ── Helpers ─────────────────────────────────────────────────────────────────

/** Flatten all tool-call arguments into a single lowercase string for matching. */
function flattenArgs(args: Record<string, any>): string {
  return JSON.stringify(args).toLowerCase();
}

/** Build a FirewallDecision with boiler-plate fields filled in. */
function makeDecision(
  decision: Decision,
  category: string,
  reason: string,
  context: ToolCallContext
): FirewallDecision {
  return {
    decision,
    category,
    reason,
    toolName: context.toolName,
    toolCallId: context.toolCallId ?? context.metadata?.toolCallId ?? `call-${Date.now()}`,
    timestamp: new Date().toISOString(),
  };
}

// ── Check functions ─────────────────────────────────────────────────────────

/**
 * Check for destructive shell patterns (rm -rf, mkfs, dd, fork-bomb …).
 * Matches against the deny.patterns list from firewall.policy.json using tokenized boundaries.
 */
function checkDenyPatterns(flat: string, ctx: ToolCallContext): FirewallDecision | null {
  for (const pattern of policy.rules.deny.patterns) {
    const escaped = escapeRegExp(pattern.toLowerCase());
    const regex = new RegExp(`(?:^|[^a-z0-9])${escaped}(?:$|[^a-z0-9])`, "i");
    if (regex.test(flat)) {
      return makeDecision(
        Decision.DENY,
        "DANGEROUS_COMMAND",
        `Blocked: command matches deny-listed pattern "${pattern}".`,
        ctx
      );
    }
  }
  return null;
}

/**
 * Check whether the tool call targets a critical system path.
 * Matches against the deny.paths list from firewall.policy.json using tokenized boundaries.
 */
function checkDenyPaths(flat: string, ctx: ToolCallContext): FirewallDecision | null {
  for (const criticalPath of policy.rules.deny.paths) {
    const escaped = escapeRegExp(criticalPath.toLowerCase());
    // Safe boundaries to prevent matching "~" against "~~markdown~~"
    const regex = new RegExp(`(?:^|[\\s="'])${escaped}(?:$|[\\s="'/\\\\])`, "i");
    if (regex.test(flat)) {
      return makeDecision(
        Decision.DENY,
        "CRITICAL_PATH",
        `Blocked: action targets critical system path "${criticalPath}".`,
        ctx
      );
    }
  }
  return null;
}

function escapeRegExp(string: string): string {
  return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Check if the call tries to read / write a secret or credential file.
 * Matches filenames and directories from the secret rules using tokenized path boundaries.
 */
function checkSecretAccess(flat: string, ctx: ToolCallContext): FirewallDecision | null {
  for (const filename of policy.rules.secret.filenames) {
    const escaped = escapeRegExp(filename.toLowerCase());
    const regex = new RegExp(`(?:^|[/\\\\:,="']|\\s)${escaped}(?:$|[/\\\\:,="']|\\s)`, "i");
    if (regex.test(flat)) {
      return makeDecision(
        Decision.DENY,
        "SECRET_ACCESS",
        `Blocked: action references secret / credential file "${filename}".`,
        ctx
      );
    }
  }
  for (const dir of policy.rules.secret.directories) {
    const escaped = escapeRegExp(dir.toLowerCase());
    const regex = new RegExp(`(?:^|[/\\\\:,="']|\\s)${escaped}(?:$|[/\\\\:,="']|\\s)`, "i");
    if (regex.test(flat)) {
      return makeDecision(
        Decision.DENY,
        "SECRET_ACCESS",
        `Blocked: action targets sensitive directory "${dir}".`,
        ctx
      );
    }
  }
  return null;
}

/**
 * Check for risky production config updates.
 * Matches against the config.patterns list. Returns REVIEW.
 */
function checkConfigWrites(flat: string, ctx: ToolCallContext): FirewallDecision | null {
  for (const pattern of policy.rules.config.patterns) {
    const escaped = escapeRegExp(pattern.toLowerCase());
    const regex = new RegExp(`(?:^|[\\s="'])${escaped}(?:$|[\\s="'/\\\\])`, "i");
    if (regex.test(flat)) {
      return makeDecision(
        Decision.REVIEW,
        "CONFIG_WRITE_ESCALATION",
        `Flagged for review: potentially risky production config manipulation "${pattern}".`,
        ctx
      );
    }
  }
  return null;
}

/**
 * Check for review-level patterns (curl, wget, sudo, git push …).
 * Matches against the review.patterns list using tokenized boundaries to prevent false match on sub-words.
 */
function checkReviewPatterns(flat: string, ctx: ToolCallContext): FirewallDecision | null {
  for (const pattern of policy.rules.review.patterns) {
    const escaped = escapeRegExp(pattern.toLowerCase());
    const regex = new RegExp(`(?:^|[^a-z0-9])${escaped}(?:$|[^a-z0-9])`, "i");
    if (regex.test(flat)) {
      return makeDecision(
        Decision.REVIEW,
        "RISKY_OPERATION",
        `Flagged for review: command matches review-listed pattern "${pattern}".`,
        ctx
      );
    }
  }
  return null;
}

/**
 * Check outbound network calls against the domain allowlist.
 * Any URL whose host is NOT in allowlist.domains triggers REVIEW.
 */
function checkDomainAllowlist(flat: string, ctx: ToolCallContext): FirewallDecision | null {
  const urlPattern = /https?:\/\/[^\/\s"']+/gi;
  let match: RegExpExecArray | null;

  while ((match = urlPattern.exec(flat)) !== null) {
    try {
      const parsedUrl = new URL(match[0]);
      const host = parsedUrl.hostname.toLowerCase();
      
      const isAllowed = allowlist.allowlist.domains.some(
        (d) => host === d.toLowerCase() || host.endsWith("." + d.toLowerCase())
      );
      if (!isAllowed) {
        return makeDecision(
          Decision.REVIEW,
          "UNKNOWN_DOMAIN",
          `Flagged for review: outbound request to non-allowlisted domain "${host}".`,
          ctx
        );
      }
    } catch (e) {
      // Ignore invalid URLs that fail to parse
    }
  }
  return null;
}

// ── Public API ──────────────────────────────────────────────────────────────

/**
 * Evaluate a tool-call context against the loaded security policies.
 *
 * ORDER IS CRITICAL:
 * 1. deny patterns
 * 2. critical paths
 * 3. secret access
 * 4. review patterns
 * 5. domain allowlist
 * 6. default allow
 */
export async function evaluateSecurity(
  context: ToolCallContext
): Promise<FirewallDecision> {
  const flat = flattenArgs(context.arguments).concat(" ", context.toolName.toLowerCase());

  // 1. deny patterns
  const resultDenyPatterns = checkDenyPatterns(flat, context);
  if (resultDenyPatterns) return resultDenyPatterns;

  // 2. critical paths
  const resultDenyPaths = checkDenyPaths(flat, context);
  if (resultDenyPaths) return resultDenyPaths;

  // 3. secret access
  const resultSecretAccess = checkSecretAccess(flat, context);
  if (resultSecretAccess) return resultSecretAccess;

  // 4. config write escalation
  const resultConfigWrites = checkConfigWrites(flat, context);
  if (resultConfigWrites) return resultConfigWrites;

  // 5. review patterns
  const resultReviewPatterns = checkReviewPatterns(flat, context);
  if (resultReviewPatterns) return resultReviewPatterns;

  // 6. domain allowlist
  const resultDomainAllowlist = checkDomainAllowlist(flat, context);
  if (resultDomainAllowlist) return resultDomainAllowlist;

  // 7. default allow
  return makeDecision(
    Decision.ALLOW,
    "SAFE_DEFAULT",
    "Tool call passed all security checks.",
    context
  );
}
