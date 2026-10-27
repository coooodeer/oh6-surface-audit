'use strict';

/**
 * tools/oh6-r1-source-version.js —— R1-A 起点：固定源码版本标识。
 *
 * 只读：对 OpenHarmony/base、OpenHarmony/foundation 的每个 bundle 组件定位其所属 git
 * 子仓（repo 管理），记录 HEAD、分支与 tracked dirty 状态（diff-index --quiet，不扫描
 * untracked）。多仓库分别记版本，不编造整树单一 commit；同时记录审计工具仓状态与首层
 * 基线 JSON 的 sha256。输出 out/autonomy/inventory/r1-source-version.json。
 *
 * 用法：node tools/oh6-r1-source-version.js
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');

const TOOL_DIR = path.resolve(__dirname, '..');
const WORKSPACE = path.resolve(TOOL_DIR, '..');
const SRC_ROOT = path.join(WORKSPACE, 'OpenHarmony');
const OUT = path.join(TOOL_DIR, 'out', 'autonomy', 'inventory', 'r1-source-version.json');
const ROOTS = ['base', 'foundation'];
const BASELINE_JSON = path.join(TOOL_DIR, 'out', 'autonomy', 'inventory', 'full-scope-baseline.json');

function git(dir, args) {
  const r = spawnSync('git', ['-C', dir, ...args], { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
  return { code: r.status, out: r.status === 0 ? r.stdout.trim() : null, err: r.stderr ? r.stderr.trim() : null };
}

function listBundleDirs() {
  const dirs = [];
  const stack = ROOTS.map((root) => path.join(SRC_ROOT, root));
  while (stack.length) {
    const dir = stack.pop();
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (_) { continue; }
    if (entries.some((entry) => entry.isFile() && entry.name === 'bundle.json')) dirs.push(dir);
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      if (entry.name === '.git' || entry.name === 'node_modules' || entry.name === 'out') continue;
      stack.push(path.join(dir, entry.name));
    }
  }
  return dirs;
}

function repoRootOf(abs) {
  let dir = abs;
  for (;;) {
    if (fs.existsSync(path.join(dir, '.git'))) return dir;
    const parent = path.dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

function relFromSrc(abs) {
  return path.relative(SRC_ROOT, abs).split(path.sep).join('/');
}

function sha256File(abs) {
  try {
    return crypto.createHash('sha256').update(fs.readFileSync(abs)).digest('hex');
  } catch (_) { return null; }
}

function main() {
  const started = new Date().toISOString();
  const bundleDirs = listBundleDirs();

  const repos = new Map();
  const components = [];
  for (const dir of bundleDirs.sort()) {
    const repoDir = repoRootOf(dir);
    const rel = relFromSrc(dir);
    if (!repoDir) {
      components.push({ component: rel, repo: null, state: 'no-git-ancestor' });
      continue;
    }
    const repoRel = relFromSrc(repoDir);
    if (!repos.has(repoDir)) {
      const head = git(repoDir, ['rev-parse', 'HEAD']);
      const branch = git(repoDir, ['rev-parse', '--abbrev-ref', 'HEAD']);
      // 原始口径：diff-index --quiet，含 NTFS 丢 exec 位（100755→100644）与 autocrlf 的
      // CRLF checkout 噪声，在 Windows 上几乎必然报 dirty。
      const rawDirty = git(repoDir, ['diff-index', '--quiet', 'HEAD']);
      // 内容口径：忽略 filemode 与行尾 CR 后的真实内容差异，仅捕获实际编辑/回填。
      const contentDirty = git(repoDir, ['-c', 'core.filemode=false',
        'diff', '--ignore-cr-at-eol', '--quiet', 'HEAD']);
      // 未跟踪口径：ls-files --others（不哈希内容）；这些文件在工作区磁盘上，
      // 会被文件系统清点扫到，必须显式记账而不是只看 tracked。
      const untrackedOut = git(repoDir, ['ls-files', '--others', '--exclude-standard']);
      const untrackedPaths = untrackedOut.out ? untrackedOut.out.split('\n').filter(Boolean) : [];
      repos.set(repoDir, {
        repo: repoRel,
        head: head.out ? head.out.slice(0, 40) : null,
        branch: branch.out || null,
        dirtyTrackedRaw: head.out ? rawDirty.code === 1 : null,
        dirtyContent: head.out ? contentDirty.code === 1 : null,
        untrackedCount: head.out ? untrackedPaths.length : null,
        untrackedSample: untrackedPaths.slice(0, 30),
        state: head.out ? (contentDirty.code === 1 ? 'content-dirty'
          : contentDirty.code === 0 ? 'content-clean' : 'dirty-unknown') : 'git-error'
      });
    }
    components.push({ component: rel, repo: repoRel });
  }

  const repoRows = [...repos.values()].sort((a, b) => (a.repo < b.repo ? -1 : 1));
  const dirtyRepos = repoRows.filter((row) => row.dirtyContent === true);
  const rawDirtyRepos = repoRows.filter((row) => row.dirtyTrackedRaw === true);

  // ---- 未跟踪文件 × 生产清单交叉：untracked 是否进入本次生产清单 ----
  // r1-files.jsonl 存在时逐仓匹配（不重哈希全树，只对照清单路径）；不存在时记 pending。
  const filesJsonl = path.join(TOOL_DIR, 'out', 'autonomy', 'inventory', 'r1-files.jsonl');
  const productionPaths = new Set();
  let inventoryAvailable = false;
  if (fs.existsSync(filesJsonl)) {
    inventoryAvailable = true;
    const content = fs.readFileSync(filesJsonl, 'utf8');
    for (const line of content.split('\n')) {
      if (!line) continue;
      try {
        const rec = JSON.parse(line);
        if (rec.r === 'production-code') productionPaths.add(rec.p);
      } catch (_) { /* 跳过坏行 */ }
    }
  }
  const untrackedCross = [];
  let untrackedTotal = 0;
  let untrackedInProductionTotal = 0;
  for (const row of repoRows) {
    if (row.untrackedCount === null || row.untrackedCount === 0) {
      untrackedCross.push({ repo: row.repo, untracked: 0, inProduction: 0, paths: [] });
      continue;
    }
    untrackedTotal += row.untrackedCount;
    const out = git(path.join(SRC_ROOT, row.repo), ['ls-files', '--others', '--exclude-standard']);
    const all = out.out ? out.out.split('\n').filter(Boolean) : [];
    const inProduction = [];
    for (const relPath of all) {
      const fullPath = `${row.repo}/${relPath}`;
      if (productionPaths.has(fullPath)) inProduction.push(fullPath);
    }
    untrackedInProductionTotal += inProduction.length;
    untrackedCross.push({ repo: row.repo, untracked: row.untrackedCount,
      inProduction: inProduction.length, paths: inProduction.slice(0, 20),
      truncated: inProduction.length > 20 });
  }

  const auditRepo = {};
  {
    const head = git(TOOL_DIR, ['rev-parse', 'HEAD']);
    const status = git(TOOL_DIR, ['status', '--porcelain']);
    auditRepo.repo = 'oh6-surface-audit';
    auditRepo.head = head.out ? head.out.slice(0, 40) : null;
    auditRepo.branch = (git(TOOL_DIR, ['rev-parse', '--abbrev-ref', 'HEAD']) || {}).out || null;
    auditRepo.dirtyEntries = status.out ? status.out.split('\n').filter(Boolean).length : null;
  }

  const result = {
    inventoryVersion: 'r1-source-version-v2',
    recordedAt: started,
    environment: {
      platform: process.platform,
      osRelease: require('node:os').release(),
      node: process.version
    },
    sourceRoot: 'OpenHarmony',
    roots: ROOTS,
    baselineJson: {
      path: path.relative(TOOL_DIR, BASELINE_JSON).split(path.sep).join('/'),
      sha256: sha256File(BASELINE_JSON)
    },
    summary: {
      bundleComponents: components.length,
      gitRepos: repoRows.length,
      componentsWithoutGitAncestor: components.filter((row) => !row.repo).length,
      dirtyTrackedReposRaw: rawDirtyRepos.length,
      dirtyContentRepos: dirtyRepos.length,
      dirtyRepoList: dirtyRepos.map((row) => row.repo),
      untrackedCheck: {
        inventoryAvailable,
        reposWithUntracked: repoRows.filter((row) => (row.untrackedCount || 0) > 0).length,
        untrackedTotal,
        untrackedInProductionRepos: untrackedCross.filter((row) => row.inProduction > 0).length,
        untrackedInProductionTotal,
        note: 'untracked = git ls-files --others --exclude-standard（不含被 ignore 的文件）；'
          + 'inProduction = 该未跟踪文件出现在 r1-files.jsonl 的 production-code 角色。'
      }
    },
    untrackedCross,
    repos: repoRows,
    components,
    auditRepo,
    notes: [
      'repo 管理的多仓工作区：每个 bundle 组件归属其最近的含 .git 祖先；没有整树单一 commit。',
      'dirtyTrackedRaw 为 diff-index --quiet 原始口径，在 Windows 上被 NTFS 丢 exec 位与 '
        + 'autocrlf 的 CRLF checkout 噪声支配，几乎必然 dirty，不作为改动证据。',
      'dirtyContent 为 -c core.filemode=false + diff --ignore-cr-at-eol --quiet HEAD 的内容口径，'
        + '只捕获真实内容编辑；dirty 判定以该列为准。',
      'untracked 检查用 git ls-files --others --exclude-standard（不哈希内容）；'
        + '未跟踪文件在工作区磁盘上、会被文件系统清点扫到，因此逐仓登记并交叉生产清单。',
      '本文件为一次性 R1-A 记录，不是逐文件内容哈希；需要绑定证据的文件在相应产物中单独固定。'
    ]
  };

  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, `${JSON.stringify(result, null, 2)}\n`, 'utf8');
  process.stdout.write(`${JSON.stringify({
    ok: true, out: path.relative(TOOL_DIR, OUT).split(path.sep).join('/'),
    components: components.length, repos: repoRows.length,
    dirtyTrackedReposRaw: rawDirtyRepos.length, dirtyContentRepos: dirtyRepos.length,
    dirtyRepoList: dirtyRepos.map((row) => row.repo),
    untrackedTotal, untrackedInProductionTotal,
    untrackedInProductionRepos: untrackedCross.filter((row) => row.inProduction > 0)
      .map((row) => `${row.repo}(${row.inProduction})`),
    baselineSha256: result.baselineJson.sha256 ? `${result.baselineJson.sha256.slice(0, 16)}…` : null
  })}\n`);
  return 0;
}

module.exports = { main, git, listBundleDirs, repoRootOf };

if (require.main === module) {
  try { process.exitCode = main(); }
  catch (e) { process.stderr.write(`${JSON.stringify({ ok: false, error: e.message })}\n`); process.exitCode = 1; }
}
