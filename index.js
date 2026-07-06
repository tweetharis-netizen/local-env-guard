#!/usr/bin/env node
import { readdir, readFile, lstat } from 'node:fs/promises';
import path from 'node:path';
import chalk from 'chalk';

const rootDir = path.resolve(process.cwd());
const DEFAULT_IGNORED_NAMES = new Set(['.git', 'node_modules', '.hg', '.svn', '.DS_Store']);
const SENSITIVE_FILE_NAMES = [
  '.env', '.env.local', '.env.development', '.env.production', '.env.test',
  '.npmrc', '.ssh', '.aws', '.secrets'
];
const SENSITIVE_PATTERNS = [
  /\b(?:sk|pk|api[_-]?key|access[_-]?token|auth[_-]?token|secret|password|token)\b/i,
  /\b(?:sk|ai)_[A-Za-z0-9_-]{8,}\b/,
  /\bgh[pousr]_[A-Za-z0-9]{8,}\b/,
  /\b(?:AIza|AKIA)[A-Za-z0-9_-]{10,}\b/
];
const PROVIDER_SIGNATURES = [
  { provider: 'Stripe', category: 'Critical Provider Key', patterns: [/sk_live_[0-9a-zA-Z]{24}/, /sk_test_[0-9a-zA-Z]{24}/] },
  { provider: 'Slack Webhook', category: 'Critical Provider Key', patterns: [/https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9]+\/B[a-zA-Z0-9]+\/[a-zA-Z0-9]+/] },
  { provider: 'AWS', category: 'Critical Provider Key', patterns: [/\bAKIA[0-9A-Z]{16}\b/, /\b(?:ASIA|AGPA|AIDA|AROA|AIPA)[0-9A-Z]{16}\b/] }
];
const FALSE_POSITIVE_EXTENSIONS = new Set(['.css', '.scss', '.min.js']);
const CHUNK_SIZE = 4096;
const ENTROPY_THRESHOLD = 4.5;

function escapeRegex(value) { return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
function normalizePattern(pattern) { return pattern.replace(/\\/g, '/').replace(/\/+$/, ''); }

function parseGitignore(content) {
  const rules = [];
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    let negated = false, pattern = line;
    if (pattern.startsWith('!')) { negated = true; pattern = pattern.slice(1); }
    let directoryOnly = false;
    if (pattern.endsWith('/')) { directoryOnly = true; pattern = pattern.slice(0, -1); }
    if (pattern.startsWith('/')) { pattern = pattern.slice(1); }
    rules.push({ negated, directoryOnly, pattern: normalizePattern(pattern) });
  }
  return rules;
}

async function loadGitignoreRules(root) {
  try { return parseGitignore(await readFile(path.join(root, '.gitignore'), 'utf8')); } catch { return []; }
}

function matchesGitignoreRule(relativePath, rules) {
  const normalizedPath = normalizePattern(relativePath);
  const segments = normalizedPath.split('/').filter(Boolean);
  const baseName = segments.at(-1) || '';
  for (const rule of rules) {
    if (rule.negated) continue;
    const candidate = rule.pattern;
    if (!candidate) continue;
    if (!candidate.includes('/')) {
      const wildcard = candidate.includes('*') || candidate.includes('?') || candidate.includes('[');
      if (wildcard) {
        const regex = new RegExp(`^${candidate.replace(/\*\*/g, '.*').replace(/\*/g, '[^/]*').replace(/\?/g, '[^/]')}$`);
        if (regex.test(baseName) || segments.some((segment) => regex.test(segment))) return true;
      } else if (segments.some((segment) => segment === candidate || segment.endsWith(`/${candidate}`))) {
        return true;
      }
      continue;
    }
    const regex = new RegExp(`^${escapeRegex(candidate).replace(/\\*\\*/g, '.*').replace(/\\*/g, '[^/]*')}$`);
    if (regex.test(normalizedPath) || (rule.directoryOnly && normalizedPath.startsWith(`${candidate}/`))) return true;
  }
  return false;
}

function isIgnoredByDefault(relativePath) {
  return relativePath.split(path.sep).filter(Boolean).some((seg) => DEFAULT_IGNORED_NAMES.has(seg));
}

function isWithinRoot(candidatePath) {
  const resolved = path.resolve(candidatePath);
  return resolved === rootDir || resolved.startsWith(`${rootDir}${path.sep}`);
}

function shannonEntropy(value) {
  const counts = new Map();
  for (const char of value) { counts.set(char, (counts.get(char) || 0) + 1); }
  let entropy = 0, length = value.length;
  for (const count of counts.values()) { const p = count / length; entropy -= p * Math.log2(p); }
  return entropy;
}

function looksSensitive(fileName) {
  const lower = fileName.toLowerCase();
  return SENSITIVE_FILE_NAMES.some((name) => lower === name || lower.startsWith(`${name}.`) || lower.endsWith(name));
}

function shouldSkipFile(fileName) {
  return Array.from(FALSE_POSITIVE_EXTENSIONS).some((ext) => fileName.toLowerCase().endsWith(ext));
}

function classifyFinding(candidate, fileName) {
  for (const signature of PROVIDER_SIGNATURES) {
    if (signature.patterns.some((pattern) => pattern.test(candidate))) {
      return { category: signature.category, provider: signature.provider, bucket: 'critical' };
    }
  }
  if (looksSensitive(fileName)) {
    return { category: 'Critical Provider Key', provider: 'Sensitive File', bucket: 'critical' };
  }
  return { category: 'Generic High-Entropy Token', provider: 'Generic', bucket: 'warning' };
}

function chunkBuffer(buffer, size = CHUNK_SIZE) {
  const chunks = [];
  for (let offset = 0; offset < buffer.length; offset += size) {
    chunks.push(buffer.subarray(offset, Math.min(offset + size, buffer.length)).toString('utf8'));
  }
  return chunks;
}

function lineNumberAtIndex(text, index) {
  let line = 1;
  for (let cursor = 0; cursor < index; cursor += 1) { if (text[cursor] === '\n') line += 1; }
  return line;
}

function collectHighEntropyCandidates(text, fileName) {
  const findings = [];
  const chunked = chunkBuffer(Buffer.from(text, 'utf8'));
  let combined = '', startIndex = 0;

  for (const chunk of chunked) {
    combined += chunk;
    const quotedValues = combined.matchAll(/(["'])([\s\S]{12,}?)\1/g);
    for (const match of quotedValues) {
      const candidate = match[2].trim();
      if (!candidate || candidate.includes(' ') || candidate.includes('\n')) continue;
      const entropy = shannonEntropy(candidate);
      if (candidate.length >= 20 && entropy > ENTROPY_THRESHOLD && /[A-Za-z]/.test(candidate) && (/\d/.test(candidate) || /[^A-Za-z0-9]/.test(candidate))) {
        const matchIndex = combined.indexOf(candidate, startIndex);
        const classification = classifyFinding(candidate, fileName);
        findings.push({
          line: lineNumberAtIndex(text, matchIndex),
          snippet: candidate.slice(0, 80),
          entropy: entropy.toFixed(2),
          reason: classification.category,
          provider: classification.provider,
          bucket: classification.bucket
        });
      }
    }

    const rawTokens = combined.matchAll(/[A-Za-z0-9_./:=+\-]{20,}/g);
    for (const match of rawTokens) {
      const candidate = match[0];
      if (candidate.includes('/') || candidate.includes('.') || candidate.includes('://')) continue;
      const entropy = shannonEntropy(candidate);
      if (entropy > ENTROPY_THRESHOLD && /[A-Za-z]/.test(candidate) && (/\d/.test(candidate) || /[^A-Za-z0-9]/.test(candidate))) {
        const matchIndex = combined.indexOf(candidate, startIndex);
        const classification = classifyFinding(candidate, fileName);
        findings.push({
          line: lineNumberAtIndex(text, matchIndex),
          snippet: candidate.slice(0, 80),
          entropy: entropy.toFixed(2),
          reason: classification.category,
          provider: classification.provider,
          bucket: classification.bucket
        });
      }
    }
    startIndex = combined.length;
  }
  return findings;
}

function findLeakInText(content, fileName) {
  const findings = [];
  const normalizeSnippet = (snippet) => snippet.replace(/\s+/g, ' ').trim();
  const text = content;
  const chunked = chunkBuffer(Buffer.from(text, 'utf8'));
  let offset = 0;

  for (const chunk of chunked) {
    for (const pattern of SENSITIVE_PATTERNS) {
      for (const match of chunk.matchAll(pattern)) {
        const classification = classifyFinding(match[0], fileName);
        findings.push({
          line: lineNumberAtIndex(text, offset + match.index),
          snippet: normalizeSnippet(match[0].slice(0, 100)),
          entropy: null,
          reason: classification.category,
          provider: classification.provider,
          bucket: classification.bucket
        });
      }
    }
    if (looksSensitive(fileName)) {
      const trimmed = chunk.trim();
      if (trimmed.length > 0) {
        findings.push({
          line: lineNumberAtIndex(text, offset),
          snippet: normalizeSnippet(trimmed.slice(0, 100)),
          entropy: null,
          reason: 'Critical Provider Key',
          provider: 'Sensitive File',
          bucket: 'critical'
        });
      }
    }
    offset += chunk.length;
  }

  for (const item of collectHighEntropyCandidates(text, fileName)) { findings.push(item); }
  return findings;
}

async function scanDirectory(dirPath, root, gitignoreRules, findings, scannedCount) {
  const entries = await readdir(dirPath, { withFileTypes: true });
  const sortedEntries = entries.sort((left, right) => left.name.localeCompare(right.name));
  for (const entry of sortedEntries) {
    const fullPath = path.join(dirPath, entry.name);
    const relativePath = path.relative(root, fullPath).split(path.sep).join('/');
    if (!isWithinRoot(fullPath) || isIgnoredByDefault(relativePath) || matchesGitignoreRule(relativePath, gitignoreRules)) continue;
    if (entry.isDirectory()) {
      scannedCount.value += 1;
      await scanDirectory(fullPath, root, gitignoreRules, findings, scannedCount);
      continue;
    }
    if (entry.isFile()) {
      if (shouldSkipFile(entry.name)) continue;
      scannedCount.value += 1;
      try {
        const stats = await lstat(fullPath);
        if (!stats.isFile() || stats.isSymbolicLink()) continue;
        if (stats.size > 5 * 1024 * 1024) { console.log(chalk.gray(`[Skipped >5MB Asset] -> ${relativePath}`)); continue; }
        const content = await readFile(fullPath, 'utf8');
        const matches = findLeakInText(content, entry.name);
        for (const m of matches) {
          findings.push({ file: relativePath, line: m.line, snippet: m.snippet, entropy: m.entropy, reason: m.reason, provider: m.provider, bucket: m.bucket });
        }
      } catch {}
    }
  }
}

function renderDashboard(findings, scannedCount) {
  const width = 74;
  const pad = (val, size) => String(val).padEnd(size).slice(0, size);
  const border = '┌' + '─'.repeat(width - 2) + '┐';
  const divider = '├' + '─'.repeat(width - 2) + '┤';
  const footer = '└' + '─'.repeat(width - 2) + '┘';

  console.log(chalk.bold.hex('#b794f6')(border));
  console.log(chalk.bold.hex('#b794f6')(`│ ${pad('❖ Prism Labs // Local Env Guard', width - 4)} │`));
  console.log(chalk.bold.hex('#b794f6')(divider));
  console.log(chalk.hex('#d8b4fe')(`│ ${pad(`Scanned ${scannedCount.value} files and folders`, width - 4)} │`));
  console.log(chalk.hex('#d8b4fe')(`│ ${pad(findings.length === 0 ? 'Status: Clean' : `Status: ${findings.length} findings`, width - 4)} │`));

  if (findings.length === 0) {
    console.log(chalk.greenBright(`│ ${pad('✓ No obvious secrets detected.', width - 4)} │`));
    console.log(chalk.bold.hex('#b794f6')(footer));
    return;
  }

  const critical = findings.filter((f) => f.bucket === 'critical');
  const warnings = findings.filter((f) => f.bucket === 'warning');

  console.log(chalk.bold.hex('#b794f6')(divider));
  console.log(chalk.hex('#d8b4fe')(`│ ${pad('🚨 CRITICAL PROVIDER KEYS', width - 4)} │`));
  if (critical.length === 0) {
    console.log(chalk.hex('#d8b4fe')(`│ ${pad('None flagged', width - 4)} │`));
  } else {
    for (const f of critical) { console.log(chalk.magenta(`│ ${pad(`${f.file}:${f.line} • ${f.provider || f.reason}`, width - 4)} │`)); }
  }

  console.log(chalk.bold.hex('#b794f6')(divider));
  console.log(chalk.hex('#d8b4fe')(`│ ${pad('⚠️ HIGH-ENTROPY WARNINGS', width - 4)} │`));
  if (warnings.length === 0) {
    console.log(chalk.hex('#d8b4fe')(`│ ${pad('None flagged', width - 4)} │`));
  } else {
    for (const f of warnings) { console.log(chalk.magenta(`│ ${pad(`${f.file}:${f.line} • Entropy ${f.entropy || 'n/a'}`, width - 4)} │`)); }
  }
  console.log(chalk.bold.hex('#b794f6')(footer));
}

async function main() {
  const gitignoreRules = await loadGitignoreRules(rootDir);
  const findings = [];
  const scannedCount = { value: 0 };
  await scanDirectory(rootDir, rootDir, gitignoreRules, findings, scannedCount);
  renderDashboard(findings, scannedCount);
}

main().catch((err) => { console.error(chalk.redBright(`✖ Scan failed: ${err.message}`)); process.exit(1); });
