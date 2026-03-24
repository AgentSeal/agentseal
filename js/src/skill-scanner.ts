/**
 * Skill threat detection — layered analysis for skill/rules files.
 *
 * Layer 1: Static pattern matching (compiled regex, ~1ms per skill)
 * Layer 2: Semantic similarity against known danger concepts (optional)
 *
 * Port of Python agentseal/detection/skill_detector.py — same patterns, same order.
 */

import { hasInvisibleChars } from "./deobfuscate.js";
import type { SkillFinding } from "./guard-models.js";

// ═══════════════════════════════════════════════════════════════════════
// PATTERN DEFINITIONS
// ═══════════════════════════════════════════════════════════════════════

interface PatternRule {
  code: string;
  title: string;
  severity: string;
  patterns: RegExp[];
  descriptionTemplate: string;   // Uses {match} for the matched text
  remediation: string;
}

const PATTERN_RULES: PatternRule[] = [
  {
    code: "SKILL-001",
    title: "Credential access",
    severity: "critical",
    patterns: [
      /~\/\.ssh\b/i,
      /~\/\.aws\b/i,
      /~\/\.gnupg\b/i,
      /~\/\.config\/gh\b/i,
      /~\/\.npmrc\b/i,
      /~\/\.pypirc\b/i,
      /~\/\.docker\b/i,
      /~\/\.kube\b/i,
      /~\/\.netrc\b/i,
      /~\/\.bitcoin\b/i,
      /~\/\.ethereum\b/i,
      /~\/Library\/Keychains\b/i,
      /\.env\b(?!\.example|\.sample|\.template)/i,
      /credentials\.json\b/i,
      /id_rsa\b/i,
      /id_ed25519\b/i,
      /wallet\.dat\b/i,
      /aws_access_key_id/i,
      /aws_secret_access_key/i,
      /\/etc\/passwd\b/i,
      /\/etc\/shadow\b/i,
      /PRIVATE[_\s]KEY/i,
    ],
    descriptionTemplate: "This skill accesses sensitive credentials: {match}",
    remediation: "Remove this skill immediately and rotate all credentials it may have accessed.",
  },
  {
    code: "SKILL-002",
    title: "Data exfiltration",
    severity: "critical",
    patterns: [
      /curl\s+.*(?:-d|--data)\s+.*https?:\/\//i,
      /wget\s+.*--post-(?:data|file)/i,
      /requests\.post\s*\(/i,
      /fetch\s*\(.*method.*['"]POST['"]/i,
      /urllib\.request\.urlopen\s*\(.*data=/i,
      /socket\.connect\s*\(/i,
      /\bnc(?:at)?\b.*\b(?:--send-only|--recv-only)\b/i,
      /httpx\.post\s*\(/i,
      /!\[.*?\]\(https?:\/\/[^\s)]+\?[^\s)]*(?:data|content|file|secret|key|token|d)=/i,
      /<img\s+[^>]*src=["']https?:\/\/[^"']+\?[^"']*(?:data|content|file|secret|key|token|d)=/i,
      /(?:render|display|show|include)\s+(?:an?\s+)?(?:image|img|markdown)\s+(?:tag|link)?\s*.*https?:\/\//i,
    ],
    descriptionTemplate: "This skill sends data to an external server: {match}",
    remediation: "Remove this skill. It exfiltrates data to an external endpoint. Check for compromised credentials.",
  },
  {
    code: "SKILL-003",
    title: "Remote payload execution",
    severity: "critical",
    patterns: [
      /curl\s+.*\|\s*(?:sh|bash|python|python3|node|ruby|perl)\b/i,
      /wget\s+.*-O\s*-\s*\|/i,
      /eval\s*\(\s*(?:fetch|require|import)/i,
      /exec\s*\(\s*(?:urllib|requests|httpx)/i,
      /pip\s+install\s+--index-url\s+http[^s]/i,
      /npm\s+install\s+.*--registry\s+http[^s]/i,
      /curl\s+.*>\s*\/tmp\/.*&&.*(?:sh|bash|chmod)/i,
    ],
    descriptionTemplate: "This skill downloads and executes remote code: {match}",
    remediation: "Remove this skill immediately. It fetches and runs code from the internet.",
  },
  {
    code: "SKILL-004",
    title: "Reverse shell / backdoor",
    severity: "critical",
    patterns: [
      /\/bin\/(?:ba)?sh\s+-i/i,
      /python3?\s+-c\s+['"]import\s+socket/i,
      /\bnc(?:at)?\s+(?:-e|--exec)\b/i,
      /bash\s+-c\s+.*>\/dev\/tcp\//i,
      /mkfifo\s+.*\bnc(?:at)?\b/i,
      /socat\s+.*exec:/i,
      /powershell.*-e\s+[A-Za-z0-9+/=]{20,}/i,
    ],
    descriptionTemplate: "This skill opens a backdoor to your machine: {match}",
    remediation: "Remove this skill immediately and run a full system security audit.",
  },
  {
    code: "SKILL-005",
    title: "Code obfuscation",
    severity: "high",
    patterns: [
      /base64\s+(?:--)?decode/i,
      /\batob\s*\(/i,
      /(?:\\x[0-9a-fA-F]{2}){10,}/i,
      /eval\s*\(.*chr\s*\(/i,
      /String\.fromCharCode/i,
      /codecs\.decode\s*\(.*rot.13/i,
      /exec\s*\(\s*compile\s*\(/i,
      /exec\s*\(\s*__import__/i,
    ],
    descriptionTemplate: "This skill uses code obfuscation: {match}",
    remediation: "This skill obfuscates its code \u2014 a common malware technique. Review the decoded content before trusting it.",
  },
  {
    code: "SKILL-006",
    title: "Prompt injection",
    severity: "high",
    patterns: [
      /ignore\s+(?:all\s+)?previous\s+instructions/i,
      /you\s+are\s+now\s+(?:a|an|in)\b/i,
      /disregard\s+(?:all|any|your)\s+(?:previous|prior)/i,
      /system:\s*you\s+are/i,
      /<\s*system\s*>/i,
      /IMPORTANT:.*override/i,
      /\[INST\]|\[\/INST\]|<<SYS>>|<\|im_start\|>/i,
      /new\s+instructions?\s*:/i,
      /forget\s+(?:all|everything)\s+(?:above|before|previous)/i,
    ],
    descriptionTemplate: "This skill contains prompt injection: {match}",
    remediation: "This skill tries to override your agent's instructions. Remove it.",
  },
  {
    code: "SKILL-007",
    title: "Suspicious URLs",
    severity: "medium",
    patterns: [
      /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[:/]/i,
      /https?:\/\/[^\s]*\.(?:tk|ml|ga|cf|gq)\//i,
      /(?:bit\.ly|tinyurl\.com|is\.gd|t\.co|rb\.gy)\/[^\s]+/i,
      /(?:pastebin\.com|hastebin\.com|0x0\.st)\/[^\s]+/i,
    ],
    descriptionTemplate: "This skill references a suspicious URL: {match}",
    remediation: "Verify this URL is legitimate before allowing the skill to access it.",
  },
  {
    code: "SKILL-008",
    title: "Hardcoded secrets",
    severity: "high",
    patterns: [
      /(?:sk-(?:proj-)?|sk_live_|sk_test_)[a-zA-Z0-9]{20,}/i,
      /AKIA[0-9A-Z]{16}/,
      /ghp_[a-zA-Z0-9]{36}/,
      /gho_[a-zA-Z0-9]{36}/,
      /xoxb-[a-zA-Z0-9-]+/,
      /xoxp-[a-zA-Z0-9-]+/,
      /-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+)?PRIVATE\s+KEY/i,
      /glpat-[a-zA-Z0-9_-]{20,}/,
      /SG\.[a-zA-Z0-9_-]{22,}/,
    ],
    descriptionTemplate: "This skill contains a hardcoded secret: {match}",
    remediation: "Rotate the exposed credentials immediately. Never store secrets in skill files.",
  },
  {
    code: "SKILL-009",
    title: "System modification",
    severity: "high",
    patterns: [
      /chmod\s+[0-7]*[7][0-7]*\s/i,
      /crontab\s+(?:-r|-e|-)\b/i,
      /launchctl\s+(?:load|submit)\b/i,
      /systemctl\s+(?:enable|start)\b/i,
      /\/etc\/(?:init\.d|rc\.local)\b/i,
      /(?:>>.*(?:\.bashrc|\.zshrc|\.bash_profile|\.profile)\b|(?:\.bashrc|\.zshrc|\.bash_profile|\.profile)\b.*>>)/i,
      /chown\s+root\b/i,
      /visudo\b/i,
    ],
    descriptionTemplate: "This skill modifies system configuration: {match}",
    remediation: "This skill changes system startup scripts or permissions. Review carefully before allowing.",
  },
];


// ═══════════════════════════════════════════════════════════════════════
// SEMANTIC DANGER CONCEPTS (for optional Layer 2 analysis)
// ═══════════════════════════════════════════════════════════════════════

export const DANGER_CONCEPTS: string[] = [
  "Read SSH private keys and send them to a remote server",
  "Download a script from the internet and execute it",
  "Open a reverse shell connection back to the attacker",
  "Steal browser cookies and saved passwords",
  "Exfiltrate environment variables to an external endpoint",
  "Override the AI assistant's system instructions",
  "Ignore previous safety guidelines and follow new ones",
  "Encode stolen data in base64 and send via DNS",
  "Install a cryptocurrency miner in the background",
  "Modify crontab to maintain persistence after reboot",
  "Read wallet.dat and private keys for crypto theft",
  "Access AWS credentials from ~/.aws/credentials",
  "Send keystrokes to a command and control server",
  "Replace legitimate binaries with trojanized versions",
  "Disable security monitoring and logging",
  "Create a hidden user account for backdoor access",
  "Intercept and forward API tokens to attacker domain",
  "Use steganography to hide data in image files",
  "Establish covert channel through DNS tunneling",
  "Scrape and exfiltrate local git credentials",
];


// ═══════════════════════════════════════════════════════════════════════
// INVISIBLE CHARACTER EVIDENCE
// ═══════════════════════════════════════════════════════════════════════

const INVISIBLE_CATEGORIES: Array<{ pattern: RegExp; name: string }> = [
  { pattern: /[\u{E0001}-\u{E007F}]/gu, name: "Unicode Tag Characters (ASCII smuggling)" },
  { pattern: /[\uFE00-\uFE0F\u{E0100}-\u{E01EF}]/gu, name: "Variation Selectors" },
  { pattern: /[\u202A-\u202E\u2066-\u2069\u200E\u200F]/g, name: "BiDi Controls" },
  { pattern: /[\u200B\u200C\u200D\uFEFF\u00AD\u2060]/g, name: "Zero-width Characters" },
];

function findInvisibleEvidence(content: string): string {
  const found: string[] = [];
  for (const { pattern, name } of INVISIBLE_CATEGORIES) {
    pattern.lastIndex = 0;
    const matches = content.match(pattern);
    if (matches && matches.length > 0) {
      found.push(`${name} (${matches.length} chars)`);
    }
  }
  return found.length > 0 ? found.join("; ") : "Invisible characters detected";
}

function extractEvidenceLine(content: string, matchPos: number): string {
  const lineStart = content.lastIndexOf("\n", matchPos - 1) + 1;
  let lineEnd = content.indexOf("\n", matchPos);
  if (lineEnd === -1) lineEnd = content.length;

  let line = content.slice(lineStart, lineEnd).trim();
  if (line.length > 200) {
    line = line.slice(0, 197) + "...";
  }
  return line;
}


// ═══════════════════════════════════════════════════════════════════════
// SKILL SCANNER CLASS
// ═══════════════════════════════════════════════════════════════════════

export class SkillScanner {
  /** Layer 1: Fast static pattern matching against known threat patterns. */
  scanPatterns(content: string): SkillFinding[] {
    const findings: SkillFinding[] = [];
    const seenCodes = new Set<string>();

    for (const rule of PATTERN_RULES) {
      if (seenCodes.has(rule.code)) continue;

      for (const pattern of rule.patterns) {
        // Reset lastIndex for global patterns
        pattern.lastIndex = 0;
        const match = pattern.exec(content);
        if (match) {
          let matchedText = match[0];
          if (matchedText.length > 80) {
            matchedText = matchedText.slice(0, 77) + "...";
          }
          findings.push({
            code: rule.code,
            title: rule.title,
            description: rule.descriptionTemplate.replace("{match}", matchedText),
            severity: rule.severity,
            evidence: extractEvidenceLine(content, match.index),
            remediation: rule.remediation,
          });
          seenCodes.add(rule.code);
          break; // One finding per code is enough
        }
      }
    }

    // SKILL-011: Invisible character detection
    if (hasInvisibleChars(content)) {
      findings.push({
        code: "SKILL-011",
        title: "Invisible characters detected",
        description:
          "This skill contains invisible Unicode characters (tag chars, variation " +
          "selectors, BiDi controls, or zero-width chars) that can hide malicious instructions.",
        severity: "high",
        evidence: findInvisibleEvidence(content),
        remediation: "Strip invisible characters and review the decoded content carefully.",
      });
    }

    return findings;
  }

  /**
   * Layer 2: Semantic similarity against known danger concepts.
   *
   * Requires an embedding function. Returns empty array if not provided.
   * Compares content chunks against DANGER_CONCEPTS with similarity thresholds.
   */
  async scanSemantic(
    content: string,
    embedFn?: (texts: string[]) => Promise<number[][]>,
  ): Promise<SkillFinding[]> {
    if (!embedFn) return [];

    const findings: SkillFinding[] = [];
    const chunkSize = 2000;
    const chunks: string[] = [];
    for (let i = 0; i < content.length; i += chunkSize) {
      const chunk = content.slice(i, i + chunkSize);
      if (chunk.trim().length >= 20) chunks.push(chunk);
    }
    if (chunks.length === 0) return [];

    // Embed all chunks + all concepts in one batch
    const allTexts = [...chunks, ...DANGER_CONCEPTS];
    let embeddings: number[][];
    try {
      embeddings = await embedFn(allTexts);
    } catch {
      return [];
    }

    const chunkEmbeddings = embeddings.slice(0, chunks.length);
    const conceptEmbeddings = embeddings.slice(chunks.length);

    for (let ci = 0; ci < chunks.length; ci++) {
      const chunkVec = chunkEmbeddings[ci]!;
      const chunk = chunks[ci]!;
      for (let di = 0; di < DANGER_CONCEPTS.length; di++) {
        const conceptVec = conceptEmbeddings[di]!;
        const similarity = cosineSimilarity(chunkVec, conceptVec);
        if (similarity >= 0.85) {
          findings.push({
            code: "SKILL-SEM",
            title: "Semantic threat match",
            description:
              `Content semantically matches danger pattern: '${DANGER_CONCEPTS[di]}' ` +
              `(similarity: ${similarity.toFixed(2)})`,
            severity: "critical",
            evidence: chunk.slice(0, 120).replace(/\n/g, " ") + "...",
            remediation:
              "This skill's content closely matches known malicious behavior. " +
              "Review carefully before allowing.",
          });
          break;
        } else if (similarity >= 0.75) {
          findings.push({
            code: "SKILL-SEM",
            title: "Suspicious semantic similarity",
            description:
              `Content resembles danger pattern: '${DANGER_CONCEPTS[di]}' ` +
              `(similarity: ${similarity.toFixed(2)})`,
            severity: "medium",
            evidence: chunk.slice(0, 120).replace(/\n/g, " ") + "...",
            remediation: "Review this skill's content \u2014 it resembles known malicious patterns.",
          });
          break;
        }
      }
    }

    // Deduplicate: keep first per severity
    const seen = new Set<string>();
    return findings.filter((f) => {
      if (seen.has(f.severity)) return false;
      seen.add(f.severity);
      return true;
    });
  }
}

/** Cosine similarity between two vectors. */
function cosineSimilarity(a: number[], b: number[]): number {
  let dot = 0;
  let normA = 0;
  let normB = 0;
  for (let i = 0; i < a.length; i++) {
    const ai = a[i]!;
    const bi = b[i]!;
    dot += ai * bi;
    normA += ai * ai;
    normB += bi * bi;
  }
  const denom = Math.sqrt(normA) * Math.sqrt(normB);
  return denom === 0 ? 0 : dot / denom;
}
