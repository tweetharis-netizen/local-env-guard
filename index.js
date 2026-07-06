import { readdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import chalk from 'chalk';

const rootDir = process.cwd();
const DEFAULT_IGNORED_NAMES = new Set(['.git', 'node_modules', '.hg', '.svn', '.DS_Store']);
const SENSITIVE_FILE_NAMES = [
  '.env',
  '.env.local',
  '.env.development',
  '.env.production',
  '.env.test',
  '.npmrc',
  '.ssh',
  '.aws',
  '.secrets'
];
const SENSITIVE_PATTERNS = [
  /\b(?:sk|pk|api[_-]?key|access[_-]?token|auth[_-]?token|secret|password)\b/i,
  /\b(?:sk|ai)_[A-Za-z0-9_-]{8,}\b/,
  /\bgh[pousr]_[A-Za-z0-9]{8,}\b/,
  /\b(?:AIza|AKIA)[A-Za-z0-9_-]{10,}\b/
];

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function normalizePattern(pattern) {
  return pattern.replace(/\\/g, '/').replace(/\/+$/, '');
}

function gitignoreToRegex(pattern, { directoryOnly = false } = {}) {
  const normalized = normalizePattern(pattern)
    .replace(/^\//, '')
    .replace(/\*\*/g, '__DOUBLE_STAR__')
    .replace(/\*/g, '[^/]*')
    .replace(/__DOUBLE_STAR__/g, '.*');

  const body = directoryOnly ? `${escapeRegex(normalized)}` : `${escapeRegex(normalized)}`;
  return new RegExp(`^${body}$`);
}

function parseGitignore(content) {
  const rules = [];

  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;

    let negated = false;
    let pattern = line;

    if (pattern.startsWith('!')) {
      negated = true;
      pattern = pattern.slice(1);
    }

    let directoryOnly = false;
    if (pattern.endsWith('/')) {
      directoryOnly = true;
      pattern = pattern.slice(0, -1);
    }

    if (pattern.startsWith('/')) {
      pattern = pattern.slice(1);
    }

    rules.push({
      original: line,
      negated,
      directoryOnly,
      pattern: normalizePattern(pattern)
    });
  }

  return rules;
}

async function loadGitignoreRules(root) {
  const gitignorePath = path.join(root, '.gitignore');
  try {
    const content = await readFile(gitignorePath, 'utf8');
    return parseGitignore(content);
  } catch {
    return [];
  }
}

function matchesGitignoreRule(relativePath, rules) {
  const normalizedPath = normalizePattern(relativePath);
  const segments = normalizedPath.split('/').filter(Boolean);
  const baseName = segments.at(-1) || '';

  for (const rule of rules) {
    if (rule.negated) continue;
    const candidate = rule.pattern;

    if (!candidate.includes('/')) {
      const wildcard = candidate.includes('*') || candidate.includes('?') || candidate.includes('[');
      if (wildcard) {
        const regex = new RegExp(`^${candidate.replace(/\*\*/g, '.*').replace(/\*/g, '[^/]*').replace(/\?/g, '[^/]')}$`);
        if (regex.test(baseName) || segments.some((segment) => regex.test(segment))) {
          return true;
        }
      } else if (segments.some((segment) => segment === candidate || segment.endsWith(`/${candidate}`))) {
        return true;
      }

      continue;
    }

    const regex = gitignoreToRegex(candidate, { directoryOnly: rule.directoryOnly });
    const target = rule.directoryOnly ? normalizedPath : normalizedPath;

    if (regex.test(target) || (rule.directoryOnly && normalizedPath.startsWith(`${candidate}/`))) {
      return true;
    }
  }

  return false;
}

function isIgnoredByDefault(relativePath) {
  const segments = relativePath.split(path.sep).filter(Boolean);
  return segments.some((segment) => DEFAULT_IGNORED_NAMES.has(segment));
}

function looksSensitive(fileName) {
  const lowerName = fileName.toLowerCase();
  return SENSITIVE_FILE_NAMES.some((name) => lowerName === name || lowerName.startsWith(`${name}.`) || lowerName.endsWith(name));
}

function findLeakInText(content, fileName) {
  const lines = content.split(/\r?\n/);
  const matches = [];

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    const isFileNameSensitive = looksSensitive(fileName);

    if (isFileNameSensitive && line.trim()) {
      matches.push({ lineNumber: index + 1, snippet: line.trim() });
      continue;
    }

    const matchedPattern = SENSITIVE_PATTERNS.some((pattern) => pattern.test(line));
    if (matchedPattern) {
      matches.push({ lineNumber: index + 1, snippet: line.trim() });
    }
  }

  return matches;
}

async function scanDirectory(dirPath, root, gitignoreRules, findings, scannedCount) {
  const entries = await readdir(dirPath, { withFileTypes: true });
  const sortedEntries = entries.sort((left, right) => left.name.localeCompare(right.name));

  for (const entry of sortedEntries) {
    const fullPath = path.join(dirPath, entry.name);
    const relativePath = path.relative(root, fullPath).split(path.sep).join('/');

    if (isIgnoredByDefault(relativePath) || matchesGitignoreRule(relativePath, gitignoreRules)) {
      continue;
    }

    if (entry.isDirectory()) {
      scannedCount.value += 1;
      await scanDirectory(fullPath, root, gitignoreRules, findings, scannedCount);
      continue;
    }

    if (entry.isFile()) {
      scannedCount.value += 1;

      try {
        const stats = await stat(fullPath);
        if (!stats.isFile()) continue;

        const content = await readFile(fullPath, 'utf8');
        const matches = findLeakInText(content, entry.name);

        if (matches.length > 0) {
          for (const match of matches) {
            findings.push({ file: relativePath, line: match.lineNumber, snippet: match.snippet });
          }
        }
      } catch {
        // Skip unreadable files gracefully.
      }
    }
  }

  return { findings, scannedCount };
}

async function main() {
  const gitignoreRules = await loadGitignoreRules(rootDir);
  const findings = [];
  const scannedCount = { value: 0 };

  await scanDirectory(rootDir, rootDir, gitignoreRules, findings, scannedCount);

  console.log(chalk.bold.hex('#b794f6')('\n❖ Prism Labs // Local Env Guard\n'));
  console.log(chalk.hex('#d8b4fe')(`Scanned ${chalk.bold(scannedCount.value)} files and folders.`));

  if (findings.length === 0) {
    console.log(chalk.greenBright('✓ No obvious secrets detected. The local environment looks clean.'));
    return;
  }

  console.log(chalk.redBright(`✖ Found ${findings.length} potential leak${findings.length === 1 ? '' : 's'}.`));
  for (const finding of findings) {
    console.log(`  ${chalk.magenta('•')} ${chalk.cyan(finding.file)}:${chalk.yellow(finding.line)} ${chalk.gray(`— ${finding.snippet}`)}`);
  }
}

main().catch((error) => {
  console.error(chalk.redBright(`✖ Scan failed: ${error.message}`));
  process.exit(1);
});
