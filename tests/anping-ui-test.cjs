'use strict';
// Run production functions from ui/app.js in a deterministic DOM stand-in.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.resolve(__dirname, '..');

function createHarness(scriptPath) {
  const script = fs.readFileSync(scriptPath || path.join(root, 'ui', 'app.js'), 'utf8');
  new vm.Script(script);

  class Element {
    constructor(id = '') {
      this.id = id;
      this.style = { setProperty() {}, width: '', height: '', transform: '', margin: '', opacity: '', left: '', top: '' };
      this.dataset = {};
      this.innerHTML = '';
      this.textContent = '';
      this.hidden = false;
      this.inert = false;
      this.disabled = false;
      this.checked = false;
      this.value = '';
      this.scrollTop = 0;
      this.scrollHeight = 120;
      this.offsetWidth = 960;
      this.offsetHeight = 640;
      this.clientWidth = 960;
      this.clientHeight = 360;
      this.attrs = {};
      this._classes = new Set();
      this.classList = {
        add: (...cs) => cs.forEach(c => this._classes.add(c)),
        remove: (...cs) => cs.forEach(c => this._classes.delete(c)),
        toggle: (c, force) => {
          const on = force === undefined ? !this._classes.has(c) : !!force;
          if (on) this._classes.add(c); else this._classes.delete(c);
          return on;
        },
        contains: c => this._classes.has(c)
      };
    }
    get className() { return Array.from(this._classes).join(' '); }
    set className(v) { this._classes = new Set(String(v || '').split(/\s+/).filter(Boolean)); }
    querySelector(selector) {
      if (selector === '.seg-ctl') return null;
      this.queries = this.queries || {};
      return this.queries[selector] || (this.queries[selector] = new Element(selector));
    }
    querySelectorAll(selector) {
      if (selector === '.seg') return [new Element(), new Element(), new Element()];
      if (selector === '.ds .d') return [new Element(), new Element(), new Element()];
      return [];
    }
    appendChild() {}
    replaceChild() {}
    replaceChildren() {}
    replaceWith() {}
    prepend() {}
    before() {}
    contains() { return false; }
    closest() { return null; }
    matches() { return false; }
    addEventListener(type, fn) { this.listeners = this.listeners || {}; this.listeners[type] = fn; }
    focus() {}
    click() { if (typeof this.onclick === 'function') this.onclick({ stopPropagation() {}, preventDefault() {}, currentTarget: this }); }
    setAttribute(k, v) { this.attrs[k] = String(v); }
    getAttribute(k) { return this.attrs[k] || null; }
    removeAttribute(k) { delete this.attrs[k]; }
    getBoundingClientRect() { return { left: 0, top: 0, width: 100, height: 100 }; }
    getClientRects() { return [{ width: 10, height: 10 }]; }
  }

  const nodes = {}, sent = [], listeners = {}, timeouts = [];
  const get = id => nodes[id] || (nodes[id] = new Element(id));
  const webview = {
    postMessage: json => sent.push(JSON.parse(json)),
    addEventListener: (name, callback) => { listeners[name] = callback; }
  };
  const docListeners = {};
  const documentStub = {
    body: new Element('body'),
    documentElement: new Element('html'),
    activeElement: get('soundBtn'),
    readyState: 'complete',
    getElementById: get,
    createElement: () => new Element(),
    createTextNode: text => ({ textContent: text }),
    querySelector: sel => get('qs:' + sel),
    querySelectorAll: () => [],
    addEventListener: (name, callback) => { docListeners[name] = callback; }
  };
  const windowStub = {
    innerWidth: 960,
    innerHeight: 640,
    chrome: { webview },
    matchMedia: () => ({ matches: false, addEventListener() {} }),
    addEventListener: (name, callback) => { listeners['window:' + name] = callback; }
  };
  const localStorageStub = {
    _map: new Map(),
    getItem(k) { return this._map.has(k) ? this._map.get(k) : null; },
    setItem(k, v) { this._map.set(k, String(v)); }
  };

  const context = vm.createContext({
    console: { log() {}, error() {} },
    document: documentStub,
    window: windowStub,
    navigator: {},
    localStorage: localStorageStub,
    performance: { now: () => 0 },
    requestAnimationFrame: () => 1,
    setTimeout: callback => { timeouts.push(callback); return timeouts.length; },
    clearTimeout: () => {}
  });
  windowStub.window = windowStub;

  vm.runInContext(fs.readFileSync(path.join(root, 'ui', 'anping-audio.js'), 'utf8'), context);
  context.AnPingAudio = windowStub.AnPingAudio;
  vm.runInContext(script, context);

  const origToast = context.toast;
  context.toast = text => { context.lastToast = text; origToast(text); };

  function receive(data) { listeners.message({ data }); }
  function category(files = []) {
    return { id: 'tmp', name: '真实分类', total: 1, ok: 0, review: 1, keep: 0, count: files.length, files };
  }

  return { context, windowStub, documentStub, localStorageStub, get, sent, listeners, docListeners, timeouts, receive, category };
}

module.exports = { createHarness };

if (require.main === module) {
const { context, windowStub, get, sent, docListeners, receive, category } = createHarness(process.argv[2]);
function check(name, body) { body(); console.log('PASS ' + name); }

check('native boot clears mock categories, omits __auditEval backdoor, hides idle view-tabs, and upgrades home screen on initState', () => {
  assert.equal(context.CATS.length, 0);
  assert.equal(typeof windowStub.__auditEval, 'undefined');
  assert.equal(context.S.state, 'first');
  // Fallback before initState (driveTotalBytes === 0)
  assert.equal(get('num').textContent, '尚未扫描');
  assert.equal(get('unit').textContent, '');
  assert(get('viewTabs').classList.contains('tabs-idle'), 'viewTabs must have tabs-idle before scan');
  assert(!get('controls').innerHTML.includes('id="firstChatScanBtn"'), 'firstChatScanBtn hidden when chatFolderCount===0');
  assert(get('controls').innerHTML.includes('id="quickScanBtn"'));
  get('quickScanBtn').onclick();
  assert.deepEqual(sent.at(-1), { action: 'startQuickScan' });

  // Receive real initState with live drive capacity & chatFolderCount
  receive({
    action: 'initState',
    appName: '按平',
    isReadOnly: true,
    defaultDrive: 'C:\\',
    driveLabel: 'C:',
    driveFreeBytes: Math.round(65.9 * 1073741824),
    driveTotalBytes: 476 * 1073741824,
    chatFolderCount: 2,
    isAdmin: false,
    hasAdminTargets: true
  });
  assert.equal(get('num').textContent, '65.9');
  assert.equal(get('unit').textContent, 'GB');
  assert(get('caption').textContent.includes('C: 系统盘当前可用 · 共 476 GB · 选择扫描方式查看空间去向'));
  assert(get('viewTabs').classList.contains('tabs-idle'), 'viewTabs remains tabs-idle on home screen');
  assert(get('controls').innerHTML.includes('id="firstChatScanBtn">微信 / QQ 专向扫描</button>'));
  get('firstChatScanBtn').onclick();
  assert.deepEqual(sent.at(-1), { action: 'startChatScan' });
});

check('picker defaults to quick scan and supports switching to drive scan', () => {
  get('pick').onclick();
  assert.equal(sent.at(-1).action, 'getDrives');
  receive({ action: 'drivesList', drives: [{ path: 'X:\\', title: 'X: 测试盘', desc: '测试', selected: true }] });
  assert(get('sheet').innerHTML.includes('常见缓存位置（快速）'));
  assert(get('sheet').innerHTML.includes('X: 测试盘'));
  // Default selection is quick scan
  get('pkGo').onclick();
  assert.deepEqual(sent.at(-1), { action: 'startQuickScan' });

  // Reopen picker & add folder selects drive mode
  get('pick').onclick();
  receive({ action: 'folderAdded', folder: { path: 'E:\\SandboxDir', title: 'SandboxDir', desc: 'E:\\SandboxDir', selected: true } });
  get('pkGo').onclick();
  assert.deepEqual(sent.at(-1), { action: 'startScan', targets: ['E:\\SandboxDir'] });
});

check('late drive response does not reopen a dismissed sheet', () => {
  const before = get('sheet').innerHTML;
  receive({ action: 'drivesList', drives: [] });
  assert.equal(get('sheet').innerHTML, before);
  assert.equal(context.overlay, null);
});

check('new scan resets prior state; same-category progress reuses springs', () => {
  context.S.moved.tmp = 9; context.S.failed.tmp = 4; context.S.selected.tmp = false;
  context.S.capOverride = '旧提示';
  receive({ action: 'scanStarted', scanSessionId: 10, target: 'X:\\' });
  assert.equal(Object.keys(context.S.moved).length, 0);
  assert.equal(context.S.capOverride, null);
  receive({ action: 'scanProgress', scanSessionId: 10, categories: [category()] });
  const spring = context.slots[0].h, count = context.springs.length;
  for (let i = 0; i < 50; i++) receive({ action: 'scanProgress', scanSessionId: 10, categories: [category()], analyzed: i });
  assert.equal(context.slots[0].h, spring);
  assert.equal(context.springs.length, count);
  assert.equal(context.S.found.tmp, 1);
});

check('stopping remains visibly pending; completion clears it', () => {
  receive({ action: 'scanStopping', scanSessionId: 10 });
  assert.equal(get('stopScan').disabled, true);
  receive({ action: 'scanProgress', scanSessionId: 10, categories: [] });
  assert(get('caption').textContent.includes('正在停止'));
  receive({ action: 'scanComplete', scanSessionId: 10, categories: [], stopped: true });
  assert.equal(context.S.state, 'stopped');
  assert.equal(context.S.stopping, false);
});

check('empty second scan has no stale categories; failure is not success', () => {
  receive({ action: 'scanStarted', scanSessionId: 11, target: 'X:\\' });
  receive({ action: 'scanComplete', scanSessionId: 11, categories: [] });
  assert.equal(context.S.state, 'empty');
  receive({ action: 'scanComplete', scanSessionId: 11, categories: [], error: '真实读取失败' });
  assert.equal(context.S.state, 'failed');
  assert.equal(context.S.scanError, '真实读取失败');
  context.startScan();
  assert.deepEqual(sent.at(-1), { action: 'startScan', targets: ['X:\\'] });
});

check('dynamic cleanSummary renders backend metadata and enforces separate confirm', () => {
  receive({ action: 'scanStarted', scanSessionId: 12, target: '常见缓存位置（2 处）', quick: true });
  receive({ action: 'scanComplete', scanSessionId: 12, completed: true, categories: [{ id: 'pkg', name: '开发包管理器缓存', total: 0.2, ok: 0.2, review: 0, keep: 0, count: 3, files: [] }] });
  context.openClean();
  const sumReq = sent.at(-1);
  assert.equal(sumReq.action, 'cleanSummary');
  get('dialog').classList.add('show');
  receive({
    action: 'cleanSummary',
    request: sumReq.request,
    scanSessionId: 12,
    groups: [
      { rule: 'TMP-PKGCACHE', title: '开发包管理器缓存 · npm / pip / NuGet / Yarn / pnpm', cost: '按需重下', requiresConfirm: false, confirmLabel: '', count: 2, bytes: 2048, locations: ['E:\\Yarn\\Cache'] },
      { rule: 'TMP-CRASHDUMP', title: '系统转储与诊断日志 · 崩溃转储', cost: '不可重新生成', requiresConfirm: true, confirmLabel: '我确认不再需要这份崩溃报告', count: 1, bytes: 4096, locations: ['E:\\CrashDumps'] }
    ]
  });
  assert(get('dialog').innerHTML.includes('开发包管理器缓存 · npm / pip / NuGet / Yarn / pnpm'));
  assert(get('dialog').innerHTML.includes('我确认不再需要这份崩溃报告'));
  context.closeDialogModal();
});

check('detail drawer renders 移入回收站 for review/ok files, hides it for keep files, and completes recycle loop', () => {
  const reviewFile = { id: 101, catId: 'tmp', n: 'big_archive.zip', p: 'X:\\dl\\', s: 0.5, j: 'review', r: '未知文件', why: '未核实', mt: '2026-11-22 10:00', x: { bytes: 536870912 } };
  const keepFile = { id: 102, catId: 'user', n: '6cb1dd.msi', p: 'C:\\Windows\\Installer\\', s: 0.1, j: 'keep', r: 'MSI 缓存', why: '系统维护缓存', mt: '2026-11-22 10:00', x: { bytes: 104857600 } };

  context.openDirectoryFile(keepFile, '‹ 返回大文件');
  assert(!get('drawer').innerHTML.includes('data-a="recycle"'), 'keep file must NOT render recycle button');

  context.openDirectoryFile(reviewFile, '‹ 返回大文件');
  assert(get('drawer').innerHTML.includes('data-a="recycle">移入回收站</button>'), 'review file must render 移入回收站 button without ellipsis');
  assert(!get('drawer').innerHTML.includes('移入回收站…'), 'idle recycle button must not have trailing ellipsis');
  assert.equal(sent.at(-1).action, 'fileTech');

  context.openRecycleConfirm(reviewFile);
  assert(get('dialog').innerHTML.includes('将这个文件移入系统回收站？'));
  assert(get('dialog').innerHTML.includes('id="rGo">移入回收站</button>'));
  get('rGo').onclick();
  assert.equal(get('rGo').textContent, '正在移入回收站…');
  const recReq = sent.at(-1);
  assert.equal(recReq.action, 'recycleSingleFile');
  assert.equal(recReq.id, 101);

  receive({ action: 'recycleSingleResult', request: recReq.request, id: 101, success: true, name: 'big_archive.zip', bytes: 536870912, categories: [] });
  assert(context.lastToast.includes('已移入系统回收站：big_archive.zip'));
});

check('delegated copy action uses ID and waits for host acknowledgement', () => {
  const files = [1, 2].map(id => ({ id, catId: 'tmp', n: 'same.bin', p: `X:\\d${id}\\`, s: 0, j: 'review', r: '规则', why: '<script>bad</script>', mt: '未知', x: { sizeComplete: false } }));
  receive({ action: 'scanComplete', scanSessionId: 12, categories: [category(files)] });
  context.dState = { g: null, filter: 'all', sort: 'size', open: {}, page: { files, offset: 0, limit: 100, total: 2, counts: { all: 2, ok: 0, review: 2, keep: 0 } } };
  context.drawerOpen = true;
  context.drawRender();
  assert(!get('drawer').innerHTML.includes('<script>bad'));
  assert(get('drawer').innerHTML.includes('≥ 0 B'));

  const row = { dataset: { k: 'id|2' } };
  const button = { dataset: { a: 'copy' }, closest: () => row };
  let intercepted = false, prevented = false;
  docListeners.click({ target: { closest: () => button }, stopPropagation() { intercepted = true; }, preventDefault() { prevented = true; } });
  assert(intercepted && prevented);
  assert.deepEqual(sent.at(-1), { action: 'copyPath', id: 2 });
  const copy = get('drawer').querySelector('[data-k="id|2"] [data-a="copy"]');
  receive({ action: 'fileActionResult', op: 'copy', id: 2, success: true });
  assert.equal(copy.textContent, '已复制完整路径');
});

check('pause, continuation and paged drawer reject stale replies', () => {
  receive({ action: 'scanPaused', scanSessionId: 12, categories: [category()], canContinue: true, limited: true, fileCount: 17, coverage: { Root: 'X:\\', DirectoriesStarted: 5, DirectoriesCompleted: 3, PendingDirectories: 2, PendingPaths: ['X:\\left'], SkippedPaths: ['X:\\link · not followed'] } });
  assert.equal(context.S.state, 'paused');
  assert(context.S.canContinue);
  context.openSkipped();
  assert(get('sheet').innerHTML.includes('left') && get('sheet').innerHTML.includes('待处理'));
  receive({ action: 'scanContinued', scanSessionId: 12 });
  assert.equal(context.S.state, 'scanning');

  receive({ action: 'scanComplete', scanSessionId: 12, categories: [{ ...category([]), count: 603 }], fileCount: 603 });
  context.drawerOpen = true;
  context.dState = { g: null, filter: 'all', sort: 'name', open: {} };
  context.loadDrawerPage(0);
  const req = sent.at(-1);
  assert.equal(req.action, 'filesPage');
  const page = { action: 'filesPage', request: req.request, offset: 0, limit: 100, total: 603, counts: { all: 603, ok: 0, review: 603, keep: 0 }, files: [] };
  receive(page);
  assert(get('drawer').innerHTML.includes('1–100 / 603'));
  context.loadDrawerPage(600);
  const next = sent.at(-1);
  receive({ ...page, request: req.request });
  assert.equal(context.dState.page, null);
  receive({ ...page, request: next.request, offset: 600, files: [{ id: 601, catId: 'tmp', n: 'tail.bin', p: 'X:\\', s: 0.01, j: 'review', r: '规则', why: '依据', mt: '未知', x: {} }] });
  assert.equal(context.dState.page.offset, 600);
  assert(get('drawer').innerHTML.includes('601–603 / 603'));
});

check('lockedCacheBytes hints and dual-mode largeFiles (excludeCacheShards + two-line summary)', () => {
  receive({ action: 'scanStarted', scanSessionId: 20, target: '常见缓存位置（2 处）', quick: true });
  receive({
    action: 'scanComplete',
    scanSessionId: 20,
    completed: true,
    lockedCacheBytes: 52428800,
    fileCount: 40,
    categories: [{ id: 'br', name: '浏览器缓存', total: 0.25, ok: 0.2, review: 0, keep: 0.05, count: 40, files: [] }]
  });
  assert(get('summary').innerHTML.includes('id="lockedCacheNote"'), 'main summary must render #lockedCacheNote when lockedCacheBytes > 0');
  assert(get('summary').innerHTML.includes('关闭对应程序后重扫可一并清理'));

  context.openClean();
  const cReq = sent.at(-1);
  get('dialog').classList.add('show');
  receive({
    action: 'cleanSummary',
    request: cReq.request,
    scanSessionId: 20,
    lockedCacheBytes: 52428800,
    groups: [{ rule: 'TMP-BROWSERCACHE', title: '浏览器缓存 · Edge / Chrome', cost: '自动重下', requiresConfirm: false, confirmLabel: '', count: 36, bytes: 209715200, locations: ['E:\\Chrome\\Cache_Data'] }]
  });
  assert(get('dialog').innerHTML.includes('id="cleanLockedTip"'), 'clean dialog must render #cleanLockedTip when lockedCacheBytes > 0');
  context.closeDialogModal();

  // Switch to largeFiles view -> defaults to excludeCacheShards: true
  context.switchMainView('largeFiles');
  const lfReq1 = sent.at(-1);
  assert.equal(lfReq1.action, 'largeFiles');
  assert.equal(lfReq1.excludeCacheShards, true);

  // Empty independent large files when only caches were scanned -> warm guidance + #lfShowCacheBtn
  receive({
    action: 'largeFilesPage',
    request: lfReq1.request,
    scanSessionId: 20,
    excludeCacheShards: true,
    independentCount: 0,
    allFileCount: 40,
    totalFiles: 0,
    totalBytes: 0,
    files: []
  });
  assert(get('largeFilesRows').innerHTML.includes('id="lfShowCacheBtn"'));

  // Toggle to include cache shards -> sends excludeCacheShards: false and renders two-line subtitle with summary
  context.setLargeFilesMode(false);
  const lfReq2 = sent.at(-1);
  assert.equal(lfReq2.action, 'largeFiles');
  assert.equal(lfReq2.excludeCacheShards, false);
  receive({
    action: 'largeFilesPage',
    request: lfReq2.request,
    scanSessionId: 20,
    excludeCacheShards: false,
    independentCount: 0,
    allFileCount: 40,
    totalFiles: 40,
    totalBytes: 52428800,
    files: [{
      id: 901,
      catId: 'br',
      n: 'data_2',
      p: 'E:\\Chrome\\Cache_Data\\',
      s: 0.05,
      j: 'keep',
      r: '浏览器缓存',
      why: '正被某个程序占用中',
      mt: '2026-11-23 04:00',
      x: { detail: { type: 'Chrome 缓存（正在使用）', summary: '正被运行中的 Chrome 占用 · 关闭后重扫可清', risk: '影响很小', riskText: '它是可再生的缓存，但所属软件正在运行并占用它。', confidence: '已确认', steps: ['先关闭 Google Chrome 浏览器，再点「重新扫描」即可一并清理。'], evidence: [] } }
    }]
  });
  assert(get('largeFilesRows').innerHTML.includes('Chrome 缓存（正在使用） · 正被运行中的 Chrome 占用 · 关闭后重扫可清'));
  context.switchMainView('categories');
});

check('v0.9.0 drive space, UAC elevation, chat picker, merged drawer subcats, and chat largeFiles mode', () => {
  context.openPicker();
  receive({
    action: 'drivesList',
    drives: [{ path: 'C:\\', title: 'C: 系统盘', desc: '可用 80.0 GB / 共 500.0 GB', selected: true }],
    chatFolders: [
      { appName: '微信', kind: 'wechat', path: 'D:\\WeChat Files' },
      { appName: 'QQ', kind: 'qq', path: 'D:\\Tencent Files' }
    ]
  });
  assert(get('sheet').innerHTML.includes('id="pickChatScan"'), 'picker must render #pickChatScan when chatFolders present');
  assert(get('sheet').innerHTML.includes('微信 / QQ 存储专向扫描'));
  context.closeSheet();

  context.startChatScan();
  assert.equal(sent.at(-1).action, 'startChatScan');

  receive({
    action: 'scanStarted',
    scanSessionId: 30,
    target: '微信 / QQ 存储空间（2 处）',
    quick: false,
    chat: true,
    driveLabel: 'D:',
    driveFreeBytes: 128 * 1073741824,
    driveTotalBytes: 512 * 1073741824,
    isAdmin: false,
    hasAdminTargets: true
  });
  receive({
    action: 'scanComplete',
    scanSessionId: 30,
    endKind: 'ended',
    completed: true,
    stopped: false,
    limited: false,
    analyzed: 60,
    delivered: 60,
    fileCount: 60,
    directoryCount: 8,
    lockedCacheBytes: 0,
    driveLabel: 'D:',
    driveFreeBytes: 128 * 1073741824,
    driveTotalBytes: 512 * 1073741824,
    isAdmin: false,
    hasAdminTargets: true,
    coverage: { Root: '微信 / QQ 存储空间（2 处）', DirectoriesStarted: 8, DirectoriesCompleted: 8 },
    categories: [
      { id: 'wx', name: '微信 / 办公聊天缓存', ok: 0.4, review: 0, keep: 0, total: 0.4, count: 20, files: [] },
      { id: 'br', name: '浏览器缓存', ok: 0.3, review: 0, keep: 0, total: 0.3, count: 10, files: [] },
      { id: 'app', name: '桌面软件缓存', ok: 0.25, review: 0, keep: 0, total: 0.25, count: 10, files: [] },
      { id: 'winupd', name: 'Windows 更新缓存', ok: 0.2, review: 0, keep: 0, total: 0.2, count: 5, files: [] },
      { id: 'systmp', name: '系统与软件临时文件', ok: 0.1, review: 0, keep: 0, total: 0.1, count: 8, files: [] },
      { id: 'pkg', name: '开发包管理器缓存', ok: 0.05, review: 0, keep: 0, total: 0.05, count: 7, files: [] }
    ]
  });

  assert(get('caption').textContent.includes('D: 可用 128 GB / 共 512 GB'), 'caption must render drive space suffix');
  assert(get('summary').innerHTML.includes('id="elevateBtn"'), 'non-admin with hasAdminTargets must render #elevateBtn');
  assert.equal(get('adminBadge').hidden, true);

  context.requestRelaunchAdmin('quick');
  assert.equal(sent.at(-1).action, 'relaunchAdmin');
  receive({ action: 'relaunchAdminResult', ok: false, cancelled: true, error: '' });
  assert(get('toast').textContent.includes('已取消管理员授权'));

  // Open 5th merged bar ('other') -> renders #drawerSubcats pills
  const mergedGroup = context.GROUPS[4];
  assert.equal(mergedGroup.group, true);
  context.openDrawer(mergedGroup);
  const subReq = sent.at(-1);
  assert.equal(subReq.action, 'filesPage');
  receive({
    action: 'filesPage',
    request: subReq.request,
    snapshot: 0,
    offset: 0,
    limit: 100,
    total: 0,
    logicalBytes: 0,
    counts: { all: 0, ok: 0, review: 0, keep: 0 },
    files: []
  });
  assert(get('drawer').innerHTML.includes('id="drawerSubcats"'), 'merged group drawer must render #drawerSubcats');
  context.closeDrawer();

  // Large files 'chat' filter mode
  context.switchMainView('largeFiles');
  context.setLargeFilesMode('chat');
  const lfChatReq = sent.at(-1);
  assert.equal(lfChatReq.action, 'largeFiles');
  assert.equal(lfChatReq.filterMode, 'chat');
  receive({
    action: 'largeFilesPage',
    request: lfChatReq.request,
    scanSessionId: 30,
    filterMode: 'chat',
    excludeCacheShards: true,
    independentCount: 3,
    chatFileCount: 2,
    chatFileBytes: 104857600,
    allFileCount: 60,
    totalFiles: 2,
    totalBytes: 104857600,
    files: [{
      id: 950,
      catId: 'user',
      n: '年度审计报告终版.pdf',
      p: 'D:\\WeChat Files\\wxid_demo\\FileStorage\\File\\2026-11\\',
      s: 0.035,
      j: 'review',
      r: '个人文档',
      why: '文档类型',
      mt: '2026-11-23 10:00',
      x: { detail: { type: '微信聊天接收文件', summary: '微信聊天接收文件 · 无用可移入回收站', risk: '可能丢失你的内容', riskText: '若发送方已过期未另存，删除后可能无法重新下载。', confidence: '很可能', steps: ['确认无需保留可移入回收站'], evidence: [] } }
    }]
  });
  assert(get('largeFilesRows').innerHTML.includes('微信聊天接收文件 · 无用可移入回收站'));
  assert(!get('largeFilesRows').innerHTML.includes('微信聊天接收文件 · 微信聊天接收文件'), 'subtitle must not duplicate detail.type prefix');
  assert(get('lfModeChat').innerHTML.includes('lf-badge'));
  context.switchMainView('categories');

  // v0.9.0-preview.2: routine permission/reparse skip uses calm human language (no warn red text) & pillar .ds shows units
  receive({
    action: 'scanComplete',
    scanSessionId: 30,
    endKind: 'ended',
    completed: true,
    stopped: false,
    limited: false,
    incomplete: true,
    analysisWarning: false,
    analyzed: 65,
    delivered: 65,
    fileCount: 65,
    directoryCount: 7,
    driveLabel: 'D:',
    driveFreeBytes: 128 * 1073741824,
    driveTotalBytes: 512 * 1073741824,
    coverage: { Root: 'D:\\', DirectoriesStarted: 8, DirectoriesCompleted: 8, ReparseSkipped: 1 },
    categories: [
      { id: 'br', name: '浏览器缓存', ok: 2.7, review: 205 / 1024, keep: 42 / 1048576, total: 2.7 + 205 / 1024 + 42 / 1048576, count: 65, files: [] }
    ]
  });
  assert(!get('caption').textContent.includes('不完整') && !get('caption').textContent.includes('存在覆盖跳过'), 'routine skip must not alarm user in #caption');
  assert(!get('skipline').classList.contains('warn') && !get('skipline').innerHTML.includes('⚠'), 'routine skip must not render red warn in #skipline');
  assert(get('skipline').innerHTML.includes('已检查 65 个文件 · 共扫描 8 个文件夹（含起始目录，已自动跳过无权限或系统保护位置）'));
  assert(get('skipline').innerHTML.includes('>查看跳过项</button>'));
  assert(get('controls').innerHTML.includes('id="cleanBtn">清理</button>'));
  const bar0Dist = context.slots[0].lab.querySelectorAll('.ds .d');
  // Note: querySelectorAll('.ds .d') returns fresh stand-in elements unless cached; verify fs() values directly via gv(GROUPS[0])
  const bar0Vals = context.gv(context.GROUPS[0]);
  assert.equal(context.fs(bar0Vals.ok), '2.7 GB');
  assert.equal(context.fs(bar0Vals.review), '205 MB');
  assert.equal(context.fs(bar0Vals.keep), '42.0 KB');
  void bar0Dist;
});

check('UI security hardening: esc(), confidenceHTML(), empty-state/sourceUrl, prototype-safe maps, CSS escaping, and bridge schema guards', () => {
  // UI-03: single-quote & null/undefined escaping, confidenceHTML escaping
  assert.equal(context.esc("'"), '&#39;');
  assert.equal(context.esc('<img src="x" onerror=\'1\'>'), '&lt;img src=&quot;x&quot; onerror=&#39;1&#39;&gt;');
  assert.equal(context.esc(null), '');
  assert.equal(context.esc(undefined), '');
  const conf = context.confidenceHTML('<img src=x onerror=1>');
  assert(!conf.includes('<img') && conf.includes('&lt;img src=x onerror=1&gt;'), 'confidenceHTML must escape label in both aria-label and span');
  assert(context.elevateRowHTML('a"b\'c').includes('a&quot;b&#39;c') || !context.canOfferElevate(), 'elevateRowHTML escapes id when offered');

  // UI-03: dState.filter === "all" empty list must NOT render literal "undefined"; d.source without d.sourceUrl must NOT render "undefined"
  context.dState = { g: null, filter: 'all', sort: 'size', open: Object.create(null), page: { files: [], offset: 0, limit: 100, total: 0, counts: { all: 0, ok: 0, review: 0, keep: 0 } } };
  context.drawerOpen = true;
  context.drawRender();
  assert(!get('drawer').innerHTML.includes('undefined'), 'empty drawer list with filter=all must not contain literal undefined');

  const noUrlFile = { id: 999, catId: 'tmp', n: 'note.dat', p: 'X:\\a\\', s: 0.001, j: 'review', r: 'R', why: 'W', mt: '2026-11-24', x: { detail: { type: '测试', confidence: '<script>1</script>', purpose: '用途', basis: '依据', risk: '低', riskText: '无', steps: ['保留'], evidence: [{ state: 'toString', text: '测试', strength: '弱' }], source: '仅来源无链接' } } };
  context.openDirectoryFile(noUrlFile, '‹ 返回');
  assert(!get('drawer').innerHTML.includes('undefined'), 'detail view with source and missing sourceUrl must not render literal undefined');
  assert(!get('drawer').innerHTML.includes('<script>1</script>'), 'detail view must escape confidenceHTML');
  assert(!get('drawer').innerHTML.includes('function toString'), 'evidence state lookup must not read Object.prototype');
  context.closeDrawer();

  // UI-06: dynamic querySelector escaping handles quotes/backslashes without throwing
  context.dState = { g: null, filter: 'all', sort: 'size', open: Object.create(null), detailKey: 'tmp|bad\\"name\n.txt', listScroll: 0 };
  context.backToList();
  assert(context.dState.focusToken.includes('\\\\\\"'), 'backToList focusToken must escape backslash and quote');

  // UI-07: prototype-key category ID must not produce NaN totals
  receive({ action: 'scanStarted', scanSessionId: 91, target: 'X:\\' });
  receive({ action: 'scanComplete', scanSessionId: 91, completed: true, categories: [{ id: 'toString', name: 'proto', total: 0.5, ok: 0.5, review: 0, keep: 0, count: 1, files: [] }] });
  const tot = context.totals();
  assert(Number.isFinite(tot.ok) && Math.abs(tot.ok - 0.5) < 1e-9, 'prototype-named category id must produce finite totals');

  // UI-07: malformed bridge messages & missing scanSessionId on scan* must be ignored safely
  const stateBefore = context.S.state;
  receive(null);
  receive([]);
  receive(42);
  receive({ action: 123 });
  receive({ action: 'scanComplete', categories: [] }); // missing scanSessionId -> ignored
  assert.equal(context.S.state, stateBefore, 'malformed or sessionless scanComplete must be ignored');
  assert.equal(typeof windowStub.NATIVE_DRIVES, 'undefined', 'NATIVE_DRIVES must not leak on window');
  assert.equal(typeof windowStub.NATIVE_CHAT_FOLDERS, 'undefined', 'NATIVE_CHAT_FOLDERS must not leak on window');
});

Promise.resolve(context.audio.play('toString')).then(res => {
  assert.equal(res, false, "audio.play('toString') must return false without throwing");
  console.log('PASS audio.play prototype key rejected without throwing');
  console.log('RESULT OK: modular UI regressions (DOM stand-in)');
}).catch(err => {
  console.error(err);
  process.exitCode = 1;
});
}
