'use strict';
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');

const root = path.resolve(__dirname, '..');
const appJs = fs.readFileSync(path.join(root, 'ui/app.js'), 'utf8');
const css = fs.readFileSync(path.join(root, 'ui/styles.css'), 'utf8');

function body(start, end) {
  const a = appJs.indexOf(start);
  const b = appJs.indexOf(end, a);
  assert(a >= 0 && b > a, 'missing section: ' + start);
  return appJs.slice(a, b);
}

const ctx = {
  esc: s => String(s).replace(/</g, '&lt;'),
  fmtCount: n => String(n),
  fs: n => n + ' GB',
  drawerText: s => s
};
vm.createContext(ctx);
vm.runInContext(body('function reviewFolderTitle(', 'function drawReviewGroups('), ctx);

assert.equal(ctx.reviewFolderTitle('E:\\isolated\\cache'), 'cache · 待核实');
assert.equal(ctx.reviewFolderTitle(''), '来源未知 · 待核实');
const group = ctx.renderReviewGroup({ folder: 'E:\\isolated\\cache', count: 125, bytes: 4096, reason: '未核实', incomplete: 0 }, 0);
assert(group.indexOf('先保留') < group.indexOf('复核原因'));
assert(group.includes('review-path'));
assert(!group.match(/<b>[^<]*E:/));

const posted = [];
const d = { g: null, filter: 'all', sort: 'size', waitSnapshot: true };
const drawerCtx = {
  $: () => ({ inert: false, setAttribute() {} }),
  drawer: { querySelector: () => null },
  syncDrawerTabs() {},
  dState: d,
  filesRequest: 0,
  CATS: [],
  nativeDetail: () => true,
  focusToken: () => '',
  drawRender() {},
  window: { chrome: { webview: { postMessage: s => posted.push(JSON.parse(s)) } } }
};
vm.createContext(drawerCtx);
vm.runInContext(body('function loadDrawerPage(', 'function openDrawer('), drawerCtx);
d.snapshot = 2;
d.snapshotCats = [];
drawerCtx.loadDrawerPage(0);
assert.equal(posted.length, 1);
assert.equal(posted[0].snapshot, 2);
assert.equal(posted[0].categories.length, 12);

assert(appJs.includes('openDrawer(null, true)'));
assert(appJs.includes('dState.snapshotCats = (msg.categories || [])'));
assert(/\.coverage-block\s+\.rows\s*\{[^}]*max-height:\s*none/s.test(css));
assert(appJs.includes('这份快照还没有已分析文件'));

console.log('RESULT OK review hierarchy, empty snapshot categories, protocol consumption and single-scroll assertions');
