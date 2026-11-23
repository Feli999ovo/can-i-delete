'use strict';
// Deterministic v1.3.1 + v0.7 UI & geometry/wording checks (no real files, no Windows setting changes).
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.resolve(__dirname, '..');
const html = fs.readFileSync(path.join(root, 'ui', 'index.html'), 'utf8');
const css = fs.readFileSync(path.join(root, 'ui', 'styles.css'), 'utf8');
const script = fs.readFileSync(path.join(root, 'ui', 'app.js'), 'utf8');
new vm.Script(script);

// 1. Prohibited words check across ui/index.html & ui/app.js
for (const bad of ['释放', '可清理', '不需要清理', '放心删', '暂存区']) {
  assert(!html.includes(bad), `ui/index.html must not contain prohibited term: ${bad}`);
  assert(!script.includes(bad), `ui/app.js must not contain prohibited term: ${bad}`);
}
assert(script.includes('删除后不进回收站，无法恢复。'), 'confirmation panel must state irreversible non-recycle deletion');

// 2. Units & byte integer rule (§3.6, A8)
const ctx = vm.createContext({});
vm.runInContext(script.slice(script.indexOf('var nativeTextScale ='), script.indexOf('function esc(')), ctx);
assert.equal(ctx.fs(38 / 1073741824), '38 B');
assert.equal(ctx.fs(26 / 1073741824), '26 B');
assert.equal(ctx.fs(0), '0 B');
assert.equal(ctx.num3(ctx.inUnit(26 / 1073741824, 'B'), 'B'), '26');
assert.equal(ctx.fs(4.1 * 1024 / 1073741824), '4.1 KB');
assert.equal(ctx.num3(0.02, 'KB'), '<0.1');

// 3. Linear pillar height formula & min 28px (§3.1, A1)
assert(!script.includes('Math.log1p'), 'logarithmic bar scaling must be removed');
assert(script.includes('v / maxT * MAXH'), 'pillar height must be linear v / maxT * MAXH');
assert(script.includes('S.cleaning && S.cleanMaxT > 0'), 'scale must lock to pre-clean maximum during clean execution');

// 4. Text scaling < 120px hides distribution before < 72px list mode (§3.9, §14.14)
assert(script.includes('if (max < 120) { hidden = true; max = chart.clientHeight - labelHeight(true) - 12; }'), 'must hide .ds when max bar height < 120px');

// 5. v0.7 Quick scan dual-entry + dynamic backend-driven clean panel + single-file recycle + v0.9.0-preview.2 clean button labels
assert(script.includes('id="cleanBtn">清理</button>'), 'main clean button must be 清理 without ellipsis or size');
for (const staleEllipsis of ['清理…', '选择位置…', '添加文件夹…', '>移入回收站…<', '"移入回收站…"', '「移入回收站…」']) {
  assert(!html.includes(staleEllipsis), `ui/index.html must not contain idle ellipsis: ${staleEllipsis}`);
  assert(!script.includes(staleEllipsis), `ui/app.js must not contain idle ellipsis: ${staleEllipsis}`);
}
assert(script.includes('var text = o[k] === 0 ? "—" : fs(o[k]);'), 'pillar .ds .d must render real unit-suffixed sizes via fs(o[k])');
assert(!script.includes('覆盖不完整') && !script.includes('目录条目') && !script.includes('存在覆盖跳过或局部分析失败'), 'skipline and caption must use plain human language without alarming incomplete jargon');
assert(script.includes('id="quickScanBtn">快速扫描常见缓存</button>'), 'first screen must expose 快速扫描常见缓存 button');
assert(script.includes('常见缓存位置（快速）'), 'picker drawer must include 常见缓存位置（快速） top radio');
assert(script.includes('action: "startQuickScan"'), 'quick scan must send startQuickScan');
assert(!html.includes('id="proto"'), 'prototype control bar #proto must be removed');
assert(html.includes('id="viewLargeFiles"') && html.includes('id="largeFilesPanel"'), 'Large Files tab and panel must exist');
assert(script.includes('case "largeFilesPage":') && script.includes('case "fileTechResult":') && script.includes('case "recycleSingleResult":'), 'bridge handlers for largeFilesPage, fileTechResult, recycleSingleResult must exist');
assert(script.includes('f.j !== "keep"') && script.includes('data-a="recycle"') && script.includes('将这个文件移入系统回收站？'), 'single-file recycle button and confirmation dialog must exist and exclude keep');
assert(script.includes('"先选择至少一组"') && script.includes('"永久删除 " + fmtCount(cnt) + " 个文件"'), 'danger button must state file count or disabled prompt');
assert(css.includes('.pcheck') && css.includes('.scrim.dialog-dim') && css.includes('.ghost.cleaning'), 'porcelain checkbox, dimmed backdrop, and dashed ghost styles must exist');

// 6. Directory view (§08B, A6, A7, A10, B6)
assert(!html.includes('▱') && !script.includes('▱'), 'directory folder icon must not use ▱');
assert(script.includes('fi-dir') && script.includes('dir-bars'), 'directory view must use porcelain folder icon and byte-distribution bars');
assert(html.includes('重新汇总'), 'directory resummarize action must be renamed 重新汇总 inside menu');
assert(css.includes('::-webkit-scrollbar-button') && /display:\s*none/.test(css), 'porcelain scrollbar must hide Windows arrow buttons');

// 7. Coverage directory count note (B5)
assert(script.includes('含起始目录'), 'coverage directory count must clarify inclusion of root directory');

console.log('PASS all v1.3.1 + v0.7 modular specification checks');
