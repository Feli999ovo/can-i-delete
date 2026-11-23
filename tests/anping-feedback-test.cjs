'use strict';
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');

const appJs = fs.readFileSync(path.join(__dirname, '../ui/app.js'), 'utf8');
new vm.Script(appJs);

const ctx = vm.createContext({
  esc: s => String(s || '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]))
});
for (const [start, end] of [
  ['function completionReady(', 'function soundState('],
  ['function purposeHTML(', 'function fileInfo(']
]) {
  const a = appJs.indexOf(start);
  const b = appJs.indexOf(end, a);
  assert(a >= 0 && b > a, 'missing section: ' + start);
  vm.runInContext(appJs.slice(a, b), ctx);
}

const done = { action: 'scanComplete', completed: true, incomplete: true, evidenceIncomplete: 3 };
assert(ctx.completionReady(done));
for (const m of [
  { ...done, completed: false },
  { ...done, action: 'scanPaused' },
  { ...done, stopped: true },
  { ...done, limited: true },
  { ...done, error: 'failure' }
]) {
  assert(!ctx.completionReady(m));
}

assert.equal(ctx.purposeHTML(null), '');
const p = {
  title: '<script>',
  use: '修复、更新和卸载',
  owner: '尚未核实具体所属软件',
  advice: '不建议手动删除',
  basis: '目录用途，不是归属验证',
  source: 'KB 2667628',
  url: 'https://learn.microsoft.com/'
};
const before = JSON.stringify(p);
const out = ctx.purposeHTML(p);
assert(out.includes('&lt;script&gt;') && !out.includes('<script>'));
for (const text of ['修复、更新和卸载', '尚未核实具体所属软件', '不建议手动删除', 'KB 2667628', '不改变现有判断']) {
  assert(out.includes(text));
}
assert.equal(JSON.stringify(p), before);

console.log('PASS completion lifecycle separated from coverage; pause/stop/error refused; purpose escaped, attributed, display-only');
