"use strict";

/* ================= helpers ================= */
var CATS = [];
var $ = function(id) { return document.getElementById(id); };
var nativeTextScale = 1;
function textScale() { return nativeTextScale; }
function unitOf(gb) {
  var b = gb * 1073741824;
  return b < 1024 ? "B" : b < 1048576 ? "KB" : b < 1073741824 ? "MB" : b < 1099511627776 ? "GB" : "TB";
}
function inUnit(gb, u) {
  var div = u === "B" ? 1 : u === "KB" ? 1024 : u === "MB" ? 1048576 : u === "GB" ? 1073741824 : 1099511627776;
  return gb * 1073741824 / div;
}
function num3(n, u) {
  if (n === 0) return "0";
  if (u === "B") return String(Math.max(1, Math.round(n)));
  return n < 0.05 ? "<0.1" : n >= 100 ? String(Math.round(n)) : n.toFixed(1);
}
function fmt(gb) {
  var v = Math.max(0, gb), u = unitOf(v);
  return { n: num3(inUnit(v, u), u), u: u };
}
function fs(gb) { var f = fmt(gb); return f.n + " " + f.u; }
function sh(gb) { var f = fmt(gb); return f.u === "GB" ? f.n : f.n + " " + f.u; }
function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, function(c) {
    return c === "&" ? "&amp;" : c === "<" ? "&lt;" : c === ">" ? "&gt;" : c === '"' ? "&quot;" : "&#39;";
  });
}
function hasOwn(o, k) { return o != null && Object.prototype.hasOwnProperty.call(o, k); }
function safeInt(v) { var n = Number(v); return Number.isFinite(n) ? Math.trunc(n) : 0; }
function cssAttrVal(s) {
  return String(s == null ? "" : s).replace(/[\0-\x1f\x7f\\"]/g, function(ch) {
    return (ch === "\\" || ch === '"') ? ("\\" + ch) : ("\\" + ch.charCodeAt(0).toString(16) + " ");
  });
}
function cssEsc(s) {
  var str = String(s == null ? "" : s);
  if (typeof CSS !== "undefined" && CSS && typeof CSS.escape === "function") return CSS.escape(str);
  return str.replace(/(?:^\d)|[^A-Za-z0-9_-]/g, function(ch) {
    return "\\" + ch.charCodeAt(0).toString(16) + " ";
  });
}
function safeQuery(rootEl, sel) {
  if (!rootEl || !sel || typeof rootEl.querySelector !== "function") return null;
  try { return rootEl.querySelector(sel); } catch (_) { return null; }
}
function wbrPath(p) { return esc(p).replace(/\\/g, "\\<wbr>"); }
function midDir(p) {
  var parts = String(p == null ? "" : p).replace(/[\\/]$/, "").split(/[\\/]/);
  return parts.length <= 2 ? String(p == null ? "" : p) : parts[0] + "\\…\\" + parts[parts.length - 1] + "\\";
}
function midPath(p) {
  var s = String(p || "");
  return s.length <= 56 ? s : s.slice(0, 22) + "…" + s.slice(-30);
}
var G = Object.assign(Object.create(null), { ok: "●", review: "◐", keep: "○" });
var JL = Object.assign(Object.create(null), { ok: "符合清理规则", review: "需复核", keep: "建议保留" });
function judgeGlyph(j) { return hasOwn(G, j) ? G[j] : "○"; }
function judgeLabel(j) { return hasOwn(JL, j) ? JL[j] : "未知"; }

var motionQuery = typeof window !== "undefined" && window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)");
var contrastQuery = typeof window !== "undefined" && window.matchMedia && window.matchMedia("(forced-colors: active)");
var nativeReduce = false, nativeContrast = false, RM = !!(motionQuery && motionQuery.matches);
function syncSystemPreferences() {
  RM = nativeReduce || !!(motionQuery && motionQuery.matches);
  document.body.classList.toggle("reduceMotion", RM);
  document.body.classList.toggle("hc", nativeContrast || !!(contrastQuery && contrastQuery.matches));
  if (RM && springs) springs.forEach(function(s) { s.to(s.t, true); });
  kick();
}
if (motionQuery) motionQuery.addEventListener("change", syncSystemPreferences);
if (contrastQuery) contrastQuery.addEventListener("change", syncSystemPreferences);

/* ================= spring engine ================= */
var springs = [];
function Spring(x, onUpd, opt) {
  this.x = x; this.v = 0; this.t = x; this.u = onUpd;
  this.k = (opt && opt.k) || 170;
  this.d = (opt && opt.d) || 26;
  this.over = !!(opt && opt.over);
  springs.push(this);
  onUpd(x);
}
Spring.prototype.to = function(t, snap) {
  this.t = t;
  if (snap || RM) { this.x = t; this.v = 0; this.u(t); }
  kick();
};
var running = false, last = 0;
function kick() {
  if (!running) { running = true; last = performance.now(); requestAnimationFrame(tick); }
}
function tick(now) {
  var dt = Math.min(0.032, (now - last) / 1000);
  last = now;
  var active = false;
  springs.forEach(function(s) {
    if (s.x === s.t && s.v === 0) return;
    var k = s.k, d = RM ? 2 * Math.sqrt(k) * 1.05 : (s.over ? s.d * 0.72 : s.d);
    if (RM) k *= 2;
    var steps = 2, h = dt / steps;
    for (var i = 0; i < steps; i++) {
      var a = -k * (s.x - s.t) - d * s.v;
      s.v += a * h;
      s.x += s.v * h;
    }
    if (Math.abs(s.x - s.t) < 0.05 && Math.abs(s.v) < 0.05) { s.x = s.t; s.v = 0; }
    else active = true;
    s.u(s.x);
  });
  if (active) requestAnimationFrame(tick);
  else running = false;
}

/* ================= state ================= */
var S = {
  state: "first",
  mode: "readonly",
  found: Object.create(null),
  moved: Object.create(null),
  failed: Object.create(null),
  selected: Object.create(null),
  legendSeen: false,
  stopped: false,
  phase: "idle",
  zoom: 1,
  scanRoot: "",
  lastScanMode: "targets",
  skipped: [],
  checked: 0,
  lockedCacheBytes: 0,
  driveLabel: "",
  driveFreeBytes: 0,
  driveTotalBytes: 0,
  chatFolderCount: 0,
  isAdmin: false,
  hasAdminTargets: false,
  elevating: false,
  recyclingRequest: null,
  recyclingId: null,
  recyclingName: ""
};
function applyDriveInfo(msg) {
  if (!msg) return;
  if (typeof msg.driveTotalBytes === "number" && msg.driveTotalBytes > 0) {
    S.driveLabel = typeof msg.driveLabel === "string" ? msg.driveLabel.trim() : "";
    S.driveFreeBytes = typeof msg.driveFreeBytes === "number" ? Math.max(0, msg.driveFreeBytes) : 0;
    S.driveTotalBytes = msg.driveTotalBytes;
  }
}
function driveSpaceText() {
  if (!(S.driveTotalBytes > 0)) return "";
  var lbl = String(S.driveLabel || "").replace(/[\\\/]+$/, "").trim();
  return (lbl ? lbl + " " : "") + "可用 " + fs((S.driveFreeBytes || 0) / 1073741824) + " / 共 " + fs(S.driveTotalBytes / 1073741824);
}
function driveSpaceSuffix() {
  var t = driveSpaceText();
  return t ? " · " + t : "";
}
function syncAdminBadge() {
  var b = $("adminBadge");
  if (b) b.hidden = !S.isAdmin;
}
function applyAdminState(msg) {
  if (!msg) return;
  if (typeof msg.isAdmin === "boolean") S.isAdmin = msg.isAdmin;
  if (typeof msg.hasAdminTargets === "boolean") S.hasAdminTargets = msg.hasAdminTargets;
  syncAdminBadge();
}
function canOfferElevate() {
  return !S.isAdmin && !!S.hasAdminTargets && !S.cleaning;
}
function elevateRowHTML(id) {
  if (!canOfferElevate()) return "";
  return '<button class="tlink elevate-link" type="button" id="' + esc(id || "elevateBtn") + '">以管理员身份重开（可多扫系统更新与系统 Temp）</button>';
}
function requestRelaunchAdmin(mode) {
  if (S.elevating || S.cleaning) return;
  var m = mode || "quick";
  if (nativeDetail()) {
    S.elevating = true;
    window.chrome.webview.postMessage(JSON.stringify({ action: "relaunchAdmin", mode: m }));
  } else {
    toast("请在桌面程序中使用管理员模式重开");
  }
}
function rootLabel() {
  var r = S.scanRoot || "C: 系统盘";
  if (r.length <= 44) return r;
  return r.slice(0, 18) + "…" + r.slice(-22);
}
function fmtCount(n) { return (n || 0).toLocaleString("en-US"); }
function resetData(full) {
  CATS.forEach(function(c) {
    S.found[c.id] = full ? 1 : 0;
    S.moved[c.id] = 0;
    S.failed[c.id] = 0;
    S.selected[c.id] = c.ok > 0;
  });
  S.phase = "idle";
}
resetData(false);

/* ================= slots ================= */
var chart = $("chart"), MAXH = 300, slots = [];
function groups() {
  var sorted = CATS.slice().sort(function(a, b) { return b.total - a.total; }).filter(function(c) { return c.total > 0; });
  if (sorted.length <= 5) {
    return sorted.map(function(c) { return { id: c.id, name: c.name, cats: [c], group: false }; });
  }
  var rest = sorted.slice(4);
  return sorted.slice(0, 4).map(function(c) {
    return { id: c.id, name: c.name, cats: [c], group: false };
  }).concat([{ id: "other", name: "其他 " + rest.length + " 类", cats: rest, group: true }]);
}
var GROUPS = groups();
function gv(g) {
  var o = { ok: 0, review: 0, keep: 0, orig: 0, okOrig: 0 };
  g.cats.forEach(function(c) {
    var f = hasOwn(S.found, c.id) ? (Number(S.found[c.id]) || 0) : 0;
    var moved = hasOwn(S.moved, c.id) ? (Number(S.moved[c.id]) || 0) : 0;
    var delGb = (S.cleaning && S.cleanByCat && hasOwn(S.cleanByCat, c.id)) ? (Number(S.cleanByCat[c.id]) || 0) / 1073741824 : 0;
    var okRem = c.ok * f - moved - delGb;
    o.ok += Math.max(0, okRem);
    o.review += c.review * f;
    o.keep += c.keep * f;
    o.orig += c.total * f;
    o.okOrig += c.ok * f;
  });
  o.total = o.ok + o.review + o.keep;
  return o;
}
function gSelected(g) { return g.cats.some(function(c) { return c.ok > 0 && hasOwn(S.selected, c.id) && !!S.selected[c.id]; }); }
function gSelectable(g) { return g.cats.some(function(c) { return c.ok > 0; }); }

function buildSlots() {
  slots.forEach(function(sl) {
    [sl.h, sl.lift, sl.shift].concat(sl.mix).forEach(function(s) {
      var i = springs.indexOf(s);
      if (i >= 0) springs.splice(i, 1);
    });
  });
  chart.innerHTML = "";
  slots = [];
  for (var i = 0; i < 5; i++) {
    var g = GROUPS[i];
    var el = document.createElement("div");
    el.className = "slot";
    // pi-lens-ignore: no-inner-html-js
    el.innerHTML = '<div class="bw"><div class="ghost"></div><button class="block" type="button"><div class="segs"><div class="seg ok"></div><div class="seg review"></div><div class="seg keep"></div></div>' +
      (g && g.group ? '<div class="grooves"></div>' : '') +
      '</button></div><div class="label"><div class="nm"></div><div class="sz"><span class="n"></span><span class="u"></span></div><div class="ds">' +
      ["ok", "review", "keep"].map(function(k) { return '<span class="d"><span class="g">' + G[k] + '</span><span class="v"></span></span>'; }).join("") +
      '</div><div class="fb"></div></div>';
    chart.appendChild(el);
    var sl = {
      el: el, g: g, i: i,
      block: el.querySelector(".block"),
      ghost: el.querySelector(".ghost"),
      segs: el.querySelectorAll(".seg"),
      bw: el.querySelector(".bw"),
      lab: el.querySelector(".label")
    };
    (function(sl) {
      sl.h = new Spring(0, function(x) {
        sl.block.style.height = Math.max(0, x) + "px";
        sl.block.style.setProperty("--ao", Math.min(1, x / 60));
        sl.block.style.visibility = x < 1 ? "hidden" : "visible";
      }, { over: true });
      sl.shift = new Spring(0, function(x) { sl.el.style.transform = "translateX(" + x + "px)"; }, { k: 170, d: 26 });
      sl.mix = [];
      function paintMix() {
        var values = sl.mix.map(function(s) { return Math.max(0, s.x); });
        var sum = values.reduce(function(a, b) { return a + b; }, 0) || 1;
        values.forEach(function(v, idx) { sl.segs[idx].style.height = (v / sum * 100) + "%"; });
      }
      for (var j = 0; j < 3; j++) sl.mix.push(new Spring(j === 0 ? 100 : 0, paintMix, { k: 170, d: 26 }));
      sl.lift = new Spring(0, function(x) { sl.block.style.transform = "translateY(" + (-x) + "px)"; }, { k: 300, d: 30 });
      sl.block.addEventListener("click", function() { onBar(sl); });
      sl.block.addEventListener("pointerenter", function(e) { if (sl.block.disabled) return; sl.lift.to(2); showTip(sl, e); });
      sl.block.addEventListener("pointerleave", function() { sl.lift.to(0); hideTip(); });
      sl.block.addEventListener("keydown", function(e) {
        if (e.key === "ArrowRight" || e.key === "ArrowLeft") {
          e.preventDefault();
          var vis = slots.filter(function(s) { return s.g && !s.block.disabled; });
          var idx = vis.indexOf(sl) + (e.key === "ArrowRight" ? 1 : -1);
          if (vis[idx]) vis[idx].block.focus({ preventScroll: true });
        }
      });
    })(sl);
    slots.push(sl);
  }
}
buildSlots();

var SHORT_NAMES = Object.assign(Object.create(null), {
  pkg: "开发包管理器缓存",
  br: "浏览器缓存",
  app: "桌面软件缓存",
  thumb: "缩略图与图标缓存",
  shader: "图形与着色器缓存",
  systmp: "系统与软件临时文件",
  dump: "系统转储与诊断日志",
  user: "受保护系统/用户数据",
  tmp: "其他未识别文件",
  wx: "聊天软件缓存",
  winupd: "系统更新缓存",
  upd: "应用程序更新残留",
  dl: "未完成下载残留",
  draft: "办公草稿与自动保存",
  log: "安装与系统更新日志"
});
function shortName(g) {
  if (g.group) return g.name;
  return (g.cats[0] && g.cats[0].short) || (hasOwn(SHORT_NAMES, g.id) ? SHORT_NAMES[g.id] : "") || g.name;
}
function labelHeight(hidden) {
  return 16 + 32 * textScale() + 4 + 20 * textScale() + (hidden ? 0 : 4 + 48 * textScale());
}
function layoutMax() {
  var ww = $("win").clientWidth, n = GROUPS.length || 5, ts = textScale(), avail = Math.max(0, chart.clientWidth);
  var C = ww >= 840 ? 124 : ww >= 600 ? 104 : Math.floor((avail - 32) / 5);
  var W = ww >= 840 ? 92 : ww >= 600 ? 76 : Math.min(72, C - 8);
  var gmin = ww >= 840 ? 16 : ww >= 600 ? 12 : 8;
  var gmax = ww >= 840 ? 40 : ww >= 600 ? 24 : 8;
  var gap = Math.max(gmin, Math.min(gmax, Math.floor((avail - n * C) / Math.max(1, n - 1))));
  var list = C < 64 * ts || 5 * 64 * ts > avail || n * C + (n - 1) * gmin > avail;
  var max = chart.clientHeight - labelHeight(false) - 12, hidden = false;
  if (max < 120) { hidden = true; max = chart.clientHeight - labelHeight(true) - 12; }
  if (max < 72) list = true;
  chart.classList.toggle("nods", hidden);
  chart.classList.toggle("listmode", list);
  $("main").classList.toggle("list-layout", list);
  $("barlist").classList.toggle("show", list && (S.state === "done" || S.state === "stopped" || S.state === "paused" || S.state === "scanning"));
  var lh = list ? 28 : labelHeight(hidden);
  chart.style.setProperty("--labelh", lh + "px");
  chart.style.setProperty("--colw", C + "px");
  chart.style.setProperty("--barw", Math.max(1, Math.min(W, C - 8)) + "px");
  chart.style.setProperty("--gut", gap + "px");
  MAXH = list ? 72 : Math.max(0, Math.min(300, chart.clientHeight - lh - 12));
  chart.style.setProperty("--barspace", Math.max(0, chart.clientHeight - lh) + "px");
}

function renderBars(snap) {
  var st = S.state, maxT = (S.cleaning && S.cleanMaxT > 0) ? S.cleanMaxT : 0;
  if (!maxT) {
    GROUPS.forEach(function(g) {
      var full = g.cats.reduce(function(a, c) { return a + c.total; }, 0);
      maxT = Math.max(maxT, full);
    });
  }
  slots.forEach(function(sl) {
    var g = sl.g, el = sl.el;
    if (!g) {
      var placeholder = st === "first" || (st === "picking" && !S.hasResult) || (st === "scanning" && CATS.length === 0);
      el.className = placeholder ? "slot slotEmpty" : "slot hide";
      sl.ghost.classList.remove("cleaning");
      sl.block.disabled = true;
      sl.ghost.style.height = ([150, 110, 80, 60, 46][sl.i] * MAXH / 300) + "px";
      sl.ghost.style.opacity = placeholder ? 0.7 : 0;
      return;
    }
    var show = (st === "scanning" || st === "done" || st === "stopped" || st === "paused");
    var o = gv(g);
    el.className = "slot" + (st === "first" || st === "empty" || st === "failed" || (st === "picking" && !S.hasResult) ? " slotEmpty" : "");
    var target = 0;
    // v1.3.1 §3.1 线性比例，最小 28 px 兜底；删除执行期间比例尺锁定为删除前的最大值。
    function barH(v) { return v <= 0 || maxT <= 0 ? 0 : Math.max(Math.min(28, MAXH), v / maxT * MAXH); }
    if (show && o.total > 0) target = barH(o.total);
    sl.h.to(target, snap || false);

    /* segments */
    var tot = o.total || 1;
    var keepPct = o.keep / tot * 100, revPct = o.review / tot * 100, okPct = Math.max(0, 100 - keepPct - revPct);
    keepPct = +keepPct.toFixed(3); revPct = +revPct.toFixed(3); okPct = +okPct.toFixed(3);
    [okPct, revPct, keepPct].forEach(function(v, i) { sl.mix[i].to(v, snap); });
    sl.segs[2].classList.toggle("tiny", keepPct * target / 100 < 22);

    /* ghost (dashed outline during clean execution, recessed dent on initial surface) */
    var cleanSink = !!(S.cleaning && o.orig > 0 && o.total < o.orig - 1e-9);
    var ghostOn = cleanSink || (o.orig > 0 && !S.cleaning && o.total < o.orig - 0.001) || st === "first" || (st === "picking" && !S.hasResult);
    sl.ghost.classList.toggle("cleaning", cleanSink);
    var gh = (st === "first" || (st === "picking" && !S.hasResult)) ? [150, 110, 80, 60, 46][sl.i] * MAXH / 300 : barH(o.orig);
    sl.ghost.style.height = gh + "px";
    sl.ghost.style.opacity = ghostOn ? (st === "first" || st === "picking" ? 0.7 : 1) : 0;
    sl.ghost.style.transition = "opacity .3s";

    /* labels */
    var lab = sl.lab, fm = fmt(o.total), u = fm.u;
    lab.querySelector(".nm").textContent = chart.classList.contains("listmode") ? String(sl.i + 1) : shortName(g);
    lab.querySelector(".nm").title = g.group ? g.cats.map(function(c) { return c.name; }).join("、") : g.name;
    var szText = fs(o.total);
    var size = lab.querySelector(".sz"), number = size.querySelector(".n"), unit = size.querySelector(".u");
    if (number.textContent !== fm.n) number.textContent = fm.n;
    if (unit.textContent !== fm.u) unit.textContent = fm.u;
    var distribution = lab.querySelectorAll(".ds .d");
    ["ok", "review", "keep"].forEach(function(k, i) {
      var row = distribution[i], value = row.querySelector(".v");
      var text = o[k] === 0 ? "—" : fs(o[k]);
      row.classList.toggle("z", o[k] === 0);
      if (value.textContent !== text) value.textContent = text;
    });
    sl.block.disabled = !(st === "done" || st === "stopped" || st === "paused") || !!S.cleaning;
    sl.block.setAttribute("aria-label", g.name + "，" + szText +
      (o.ok > 0 ? "，符合清理规则 " + fs(o.ok) : "") +
      (o.review > 0 ? "，需复核 " + fs(o.review) : "") +
      (o.keep > 0 ? "，建议保留 " + fs(o.keep) : "") +
      "，按 Enter 查看文件");
  });

  var list = $("barlist");
  list.replaceChildren();
  if (chart.classList.contains("listmode")) {
    GROUPS.forEach(function(g, i) {
      var v = gv(g), b = document.createElement("button");
      b.className = "bline";
      b.type = "button";
      b.dataset.bar = String(i);
      [
        ["", String(i + 1)],
        ["bn", shortName(g)],
        ["bv", fs(v.total)],
        ["bd", ["ok", "review", "keep"].map(function(k) { return G[k] + " " + (v[k] === 0 ? "—" : fs(v[k])); }).join(" · ")]
      ].forEach(function(part) {
        var span = document.createElement("span");
        span.className = part[0];
        span.textContent = part[1];
        b.appendChild(span);
      });
      b.onclick = function() { onBar(slots[i]); };
      list.appendChild(b);
    });
  }
}

/* ================= readout & main render ================= */
var numSp = new Spring(0, function(x) {
  if (S.numMode === "gb") {
    var f = fmt(Math.max(0, x));
    $("num").textContent = f.n;
    $("unit").textContent = f.u;
  }
}, { k: 120, d: 22 });
function setNum(gb, snap) {
  S.numMode = "gb";
  $("num").classList.remove("txt");
  numSp.to(gb, snap);
  if (snap) { var f = fmt(gb); $("num").textContent = f.n; $("unit").textContent = f.u; }
}
function setText(n, u) {
  S.numMode = "text";
  $("num").classList.toggle("txt", /[^\d.—]/.test(n));
  numSp.to(0, true);
  $("num").textContent = n;
  $("unit").textContent = u || "";
}
function totals() {
  var o = { ok: 0, review: 0, keep: 0, all: 0 };
  CATS.forEach(function(c) {
    var f = hasOwn(S.found, c.id) ? (Number(S.found[c.id]) || 0) : 0;
    var moved = hasOwn(S.moved, c.id) ? (Number(S.moved[c.id]) || 0) : 0;
    o.ok += Math.max(0, c.ok * f - moved);
    o.review += c.review * f;
    o.keep += c.keep * f;
  });
  o.all = o.ok + o.review + o.keep;
  return o;
}
function lockedCacheHintHTML() {
  if (!(S.lockedCacheBytes > 0)) return "";
  return '<div class="locked-note" id="lockedCacheNote">另有 <b>' + esc(fs(S.lockedCacheBytes / 1073741824)) + "</b> 缓存正被运行中的程序（如浏览器）占用，关闭对应程序后重扫可一并清理</div>";
}
function summaryRest(t) {
  return '<span class="k"><span class="g">◐</span><b>' + esc(fs(t.review)) + '</b> 需复核</span>' +
    '<span class="k"><span class="g">○</span><b>' + esc(fs(t.keep)) + '</b> 建议保留</span>' +
    '<button class="tlink" id="legendBtn" type="button">怎么看这些柱子？</button>' +
    elevateRowHTML("elevateBtn") +
    lockedCacheHintHTML();
}
function renderCleanBand(b) {
  var chk = '<span class="check draw"><svg width="11" height="11" viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"><path d="M2 6.4l2.6 2.6L10 3.4"/></svg></span>';
  var btn = ' · <button class="tlink" type="button" id="cleanDetailBtn">查看明细</button>';
  var deleted = Math.max(0, safeInt(b.deleted));
  var attempted = Math.max(0, safeInt(b.attempted));
  var notExecuted = Math.max(0, safeInt(b.notExecuted));
  var unknown = Math.max(0, safeInt(b.unknown));
  var sz = esc(fs((Number(b.freedBytes) || 0) / 1073741824));
  if (b.stopped) {
    var rest = notExecuted + " 个未处理，保持原样" + (Array.isArray(b.otherParts) && b.otherParts.length ? "；" + b.otherParts.join(" · ") : "");
    return '<div class="result-band" role="status"><div class="rb-lines"><div class="rb-main">已停止。已永久删除 ' + deleted + " 个文件，共 " + sz + "（文件大小合计）；其余 " + esc(rest) + btn + "</div></div></div>";
  }
  if (deleted === 0) {
    return '<div class="result-band" role="status"><div class="rb-lines"><div class="rb-main">没有删除任何文件：' + esc(b.subText || "文件正在使用或状态已变化") + btn + "</div></div></div>";
  }
  if (deleted < attempted || unknown > 0) {
    return '<div class="result-band" role="status">' + chk + '<div class="rb-lines"><div class="rb-main"><b>已永久删除 ' + deleted + " 个文件，共 " + sz + '</b>（文件大小合计）</div><div class="rb-sub">' + esc(b.subText) + btn + "</div></div></div>";
  }
  return '<div class="result-band" role="status">' + chk + '<div class="rb-lines"><div class="rb-main"><b>已永久删除 ' + deleted + " 个文件，共 " + sz + "</b>（文件大小合计）</div></div></div>";
}

function render(snap) {
  var st = S.state, t = totals();
  var vt = $("viewTabs") || document.querySelector(".view-tabs");
  if (vt) vt.classList.toggle("tabs-idle", !S.hasResult && st !== "scanning");
  $("suffix").textContent = "";
  var cap = "", sum = "", skip = "", ctl = "";
  $("track").className = "track";
  $("trackFill").style.width = "0";
  $("ptext").textContent = "";

  if (st === "first" || (st === "picking" && !S.hasResult)) {
    $("num").style.fontSize = "";
    if (S.driveTotalBytes > 0) {
      setNum((S.driveFreeBytes || 0) / 1073741824, true);
      var firstDrive = String(S.driveLabel || "C:").replace(/[\\\/]+$/, "").trim() || "C:";
      cap = firstDrive + " 系统盘当前可用 · 共 " + fs(S.driveTotalBytes / 1073741824) + " · 选择扫描方式查看空间去向";
    } else {
      setText("尚未扫描", "");
      cap = "选择一个位置，按平会告诉你空间去了哪里。";
    }
    var firstElevate = canOfferElevate()
      ? '<button class="tlink elevate-link" type="button" id="elevateBtn">以管理员身份重开（可多扫系统更新与系统 Temp）</button>'
      : "";
    var firstChatBtn = S.chatFolderCount > 0
      ? '<button class="tlink" type="button" id="firstChatScanBtn">微信 / QQ 专向扫描</button>'
      : "";
    ctl = '<span class="note' + (firstElevate ? " note-stack" : "") + '"><span>只读扫描；快扫覆盖浏览器、聊天与桌面软件、着色器、包管理器及过期临时文件。</span>' + firstElevate + "</span>" +
      firstChatBtn +
      '<button class="pill porcelain" type="button" id="pick">选择位置</button>' +
      '<button class="pill" type="button" id="quickScanBtn">快速扫描常见缓存</button>';
  } else if (st === "scanning") {
    setNum(t.all);
    cap = "正在分析 " + rootLabel() + "…" + driveSpaceSuffix();
    sum = lockedCacheHintHTML();
    $("track").className = "track show indet";
    ctl = '<button class="tlink" type="button" id="snapshotFiles">查看已分析文件</button>' +
      '<span class="note">结果会随扫描实时出现，未完成前不代表最终结果。</span>' +
      '<button class="pill light" type="button" id="stopScan">停止扫描</button>';
  } else if (st === "empty") {
    setText("0", "B");
    cap = "没有发现符合规则或需要关注的文件。";
    sum = lockedCacheHintHTML() + elevateRowHTML("elevateBtn");
    ctl = '<span class="note">这里没有符合清理规则的文件。扫描位置：' + esc(rootLabel()) + esc(driveSpaceSuffix()) + " · 已检查 " + fmtCount(S.checked) + ' 个文件</span>' +
      '<button class="pill" type="button" id="pick">重新扫描</button>';
  } else if (st === "failed") {
    setText("—", "");
    cap = "扫描异常结束 · " + (S.scanError || "只保留已有结果");
    ctl = '<button class="tlink" type="button" id="pick2">选择其他位置</button><button class="pill" type="button" id="retry">重试</button>';
  } else if (S.cleaning) {
    var prog = S.cleanProg || { done: 0, total: 0 };
    var det = S.cleanDetail || { deleted: 0, deletedBytes: 0, currentPath: "" };
    setNum((det.deletedBytes || 0) / 1073741824);
    cap = "已删除 · " + (det.deleted || 0) + " / " + (prog.total || 0) + " 个文件 · 剩余 " + Math.max(0, (prog.total || 0) - (prog.done || 0)) + " 个" + (S.cleanStopping ? " · 正在停止…" : "");
    sum = "<span>正在逐个删除并确认…</span>" + (det.currentPath ? '<span class="clean-curpath" title="' + esc(det.currentPath) + '">' + esc(midPath(det.currentPath)) + "</span>" : "");
    $("track").className = "track show";
    $("trackFill").style.width = (prog.total > 0 ? Math.min(100, prog.done / prog.total * 100) : 0) + "%";
    ctl = '<span class="note" role="status">' + (S.cleanStopping ? "正在停止（当前文件处理完后立即停止）…" : "停止后：已删除的文件无法恢复，未处理的文件保持原样。") + "</span>" +
      '<button class="pill" type="button" id="stopClean"' + (S.cleanStopping ? " disabled" : "") + ">" + (S.cleanStopping ? "正在停止…" : "停止") + "</button>";
  } else {
    var stopped = st === "stopped";
    setNum(t.ok, snap);
    var prefix = S.scanError ? "扫描异常 · " + S.scanError + " · 结果不完整 · " : (S.limited ? "预算暂停 · 可继续分析 · " : (stopped ? "扫描已停止 · 结果不完整 · " : ""));
    cap = prefix + "符合清理规则 · 共分析 " + fs(t.all) + " · " + rootLabel() + driveSpaceSuffix();
    sum = summaryRest(t);
    if (!stopped && S.skipped.length) {
      skip = "<span>" + S.skipped.length + ' 个位置无权限，已跳过</span><span>·</span><button class="tlink" id="skipBtn" type="button">查看跳过项</button>';
    }
    var band = S.cleanBand ? renderCleanBand(S.cleanBand) : "";
    ctl = st === "paused"
      ? '<span class="note">' + esc(S.budgetReason || "本轮预算") + '已达上限，结果不完整。</span><button class="tlink" type="button" id="stopScan">结束本次</button><button class="pill porcelain" type="button" id="allFiles">查看已分析文件</button><button class="pill" type="button" id="continueScan">继续分析</button>'
      : S.cleanLocked
        ? (band || '<span class="note warn">' + (S.freedNote ? esc(S.freedNote) + " · " : "") + '有文件结果无法确认，重新扫描核对后才能再清理。</span>') + '<button class="pill" type="button" id="rescan">重新扫描</button><button class="pill porcelain" type="button" id="allFiles">查看全部文件</button>'
        : t.ok > 0
          ? (band || '<span class="note">' + (S.freedNote ? esc(S.freedNote) : "只会删除「符合清理规则」的文件，其余文件不动。") + "</span>") + '<button class="tlink" type="button" id="rescan">重新扫描</button><button class="pill porcelain" type="button" id="allFiles">查看全部文件</button><button class="pill" type="button" id="cleanBtn">清理</button>'
          : (band || '<span class="note">' + (S.freedNote ? esc(S.freedNote) : "这里没有符合清理规则的文件。") + "</span>") + '<button class="tlink" type="button" id="rescan">重新扫描</button><button class="pill" type="button" id="allFiles">查看全部文件</button>';
  }

  if (!S.cleaning && S.coverage) {
    var scannedDirs = safeInt(S.coverage.DirectoriesStarted || S.directoryCount || 0);
    var dirNote = S.incomplete ? "（含起始目录，已自动跳过无权限或系统保护位置）" : "（含起始目录）";
    var warnPrefix = S.analysisWarning ? ("⚠ " + Math.max(1, safeInt(S.failedItems)) + " 项分析失败未计入 · ") : "";
    var skipLabel = (S.incomplete || S.analysisWarning) ? "查看跳过项" : "扫描范围";
    skip = '<span class="' + (S.analysisWarning ? "warn" : "") + '">' + warnPrefix +
      "已检查 " + esc(fmtCount(safeInt(S.fileCount))) + " 个文件 · 共扫描 " + esc(fmtCount(scannedDirs)) + " 个文件夹" + dirNote +
      '</span><span>·</span><button class="tlink' + (S.analysisWarning ? " warn" : "") + '" type="button" id="skipBtn">' + skipLabel + "</button>";
  }

  $("caption").textContent = S.capOverride || cap;
  // pi-lens-ignore: no-inner-html-js
  $("summary").innerHTML = sum;
  $("skipline").classList.remove("warn");
  // pi-lens-ignore: no-inner-html-js
  $("skipline").innerHTML = skip;
  // pi-lens-ignore: no-inner-html-js
  $("controls").innerHTML = ctl;
  if (S.suffix) $("suffix").textContent = S.suffix;

  bindControls();

  if (!S.cleaning && S.state === "paused" && !S.canContinue) {
    var cont = $("continueScan");
    if (cont) { cont.textContent = "重新选择位置"; cont.onclick = openPicker; }
    $("caption").textContent = "预算暂停 · " + (S.resumeBlocked || "当前不能继续旧游标") + " · " + rootLabel();
  }
  if (!S.cleaning && S.rejection) {
    $("skipline").textContent = "未启动：" + S.rejection + "（已有结果保留；可重新选择位置）";
  }
  if (!S.cleaning && (S.state === "done" || S.state === "empty")) {
    if (S.scanError || S.endKind === "failed") {
      $("caption").textContent = "扫描异常结束 · 已有结果不代表完整扫描";
    } else if (S.analysisWarning) {
      $("caption").textContent = S.state === "empty"
        ? "没有发现符合规则或需要关注的文件（部分文件读取失败，未计入结果）。"
        : ("符合清理规则 · 共分析 " + fs(t.all) + " · " + rootLabel() + driveSpaceSuffix() + "（部分文件读取失败，未计入结果）");
      $("skipline").classList.add("warn");
      if (!S.coverage) {
        var line = $("skipline");
        var lead = document.createElement("span");
        lead.textContent = "⚠ " + S.failedItems + " 项分析失败或未交付 · 未计入成功结果";
        line.prepend(lead);
      }
    }
  }
  if (S.stopping) {
    var stop = $("stopScan");
    if (stop) { stop.disabled = true; stop.textContent = "正在停止…"; }
  }

  if (chart && !chart.hidden && chart.clientHeight > 0) layoutMax();
  renderBars(snap);

  if (render.lastState !== S.state) {
    render.lastState = S.state;
    $("a11yStatus").textContent = $("caption").textContent;
  }

  if ($("directoryRefresh")) $("directoryRefresh").disabled = !!S.cleaning;
  if ($("directoryMoreBtn")) $("directoryMoreBtn").disabled = !!S.cleaning;
  if (S.view === "directories" && currentScanSession != null && !directoryState.loading && !S.cleaning) {
    var dp = directoryState.page;
    loadDirectory(dp ? dp.directoryId : 0, dp ? dp.pageOffset : 0);
  }
  updateModals();
}

/* ================= dynamic metadata-driven clean confirmation ================= */
// 真实清理：只发送意图，不发送任何路径；每组名称、后果说明、单独确认标记全部由后端 CacheRuleRegistry 下发驱动。
var cleanList = null, cleanSummaryRequest = 0;

function closeDialogModal() {
  var dlg = $("dialog");
  dlg.classList.remove("show", "clean-dlg", "recycle-dlg");
  dlg.removeAttribute("aria-describedby");
  updateModals();
}

function openClean() {
  if (S.cleaning || S.cleanLocked || S.recyclingRequest != null) return;
  cleanList = null;
  cleanSummaryRequest++;
  var dlg = $("dialog");
  dlg.classList.remove("recycle-dlg");
  dlg.classList.add("clean-dlg");
  dlg.removeAttribute("aria-describedby");
  // pi-lens-ignore: no-inner-html-js
  dlg.innerHTML = '<h2>永久删除这些文件？</h2><p class="clean-lead" role="status">正在读取已校验的文件…</p><div class="dfoot"><span id="cleanChosen"></span><button class="tlink clean-cancel" type="button" id="cCancel">取消</button></div>';
  $("cCancel").onclick = function() { cleanSummaryRequest++; closeDialogModal(); };
  dlg.classList.add("show");
  updateModals();
  $("cCancel").focus({ preventScroll: true });
  if (nativeDetail()) {
    window.chrome.webview.postMessage(JSON.stringify({
      action: "cleanSummary",
      request: cleanSummaryRequest,
      scanSessionId: currentScanSession
    }));
  }
}

function receiveCleanSummary(msg) {
  if (msg.request !== cleanSummaryRequest || msg.scanSessionId !== currentScanSession || !$("dialog").classList.contains("show")) return;
  if (msg.error) {
    closeDialogModal();
    toast(msg.error);
    return;
  }
  applyAdminState(msg);
  var rawGroups = Array.isArray(msg.groups) ? msg.groups : [];
  var lockedBytes = typeof msg.lockedCacheBytes === "number" ? Math.max(0, msg.lockedCacheBytes) : (S.lockedCacheBytes || 0);
  if (typeof msg.lockedCacheBytes === "number") S.lockedCacheBytes = lockedBytes;
  cleanList = {
    groups: rawGroups.filter(function(g) {
      return g && typeof g.rule === "string" && g.rule.length > 0 &&
        Number.isFinite(g.count) && g.count > 0 &&
        Number.isFinite(g.bytes) && Array.isArray(g.locations);
    }).map(function(g) {
      var reqConfirm = typeof g.requiresConfirm === "boolean" ? g.requiresConfirm : (g.rule === "TMP-CRASHDUMP");
      return {
        rule: g.rule,
        title: g.title || g.name || g.rule,
        cost: g.cost || "",
        requiresConfirm: reqConfirm,
        confirmLabel: g.confirmLabel || (g.rule === "TMP-CRASHDUMP" ? "我确认不再需要这份崩溃报告" : "我确认不再需要这些文件"),
        count: g.count,
        bytes: g.bytes,
        locations: g.locations
      };
    }),
    lockedCacheBytes: lockedBytes,
    session: msg.scanSessionId
  };
  drawCleanList();
}

function drawCleanList() {
  var dlg = $("dialog");
  dlg.classList.remove("recycle-dlg");
  dlg.classList.add("clean-dlg");
  dlg.setAttribute("aria-describedby", "cleanLead");

  // pi-lens-ignore: no-inner-html-js
  dlg.innerHTML = '<h2>永久删除这些文件？</h2>' +
    '<p class="clean-lead" id="cleanLead"><b>删除后不进回收站，无法恢复。</b>只列出内容已校验、符合清理规则的文件；需复核和建议保留的文件不会被删除。</p>' +
    (cleanList.lockedCacheBytes > 0
      ? '<div class="clean-locked-tip" id="cleanLockedTip">另有 <b>' + fs(cleanList.lockedCacheBytes / 1073741824) + "</b> 缓存因浏览器等程序正在运行而自动跳过，关闭对应程序后重新扫描即可一并清理。</div>"
      : "") +
    (canOfferElevate()
      ? '<div class="clean-elevate-tip"><button class="tlink elevate-link" type="button" id="cleanElevateBtn" data-elevate="elevateBtn">以管理员身份重开（可多扫系统更新与系统 Temp）</button></div>'
      : "") +
    '<div class="clean-list" role="region" aria-label="符合清理规则的分组列表">' +
    cleanList.groups.map(function(g) {
      var needSub = !!g.requiresConfirm;
      var id = "cleanRule_" + g.rule;
      var rowId = g.rule === "TMP-CRASHDUMP" ? "dumpConfirmRow" : ("confirmRow_" + g.rule);
      var subId = g.rule === "TMP-CRASHDUMP" ? "confirmDumps" : ("confirmRule_" + g.rule);
      return '<section class="clean-group">' +
        '<label class="clean-check-wrap" for="' + esc(id) + '">' +
        '<input class="sr-check" type="checkbox" id="' + esc(id) + '" data-clean-rule="' + esc(g.rule) + '" ' + (needSub ? "" : "checked") + '>' +
        '<span class="pcheck" aria-hidden="true"></span></label>' +
        '<div class="clean-group-body">' +
        '<label class="clean-head" for="' + esc(id) + '"><b>' + esc(g.title) + '</b><span>' + esc(fmtCount(safeInt(g.count))) + " 个文件 · " + esc(fs((Number(g.bytes) || 0) / 1073741824)) + "</span></label>" +
        (g.cost ? '<p class="clean-cost">' + esc(g.cost) + "</p>" : "") +
        (needSub ? '<label class="dump-confirm-row" id="' + esc(rowId) + '" data-confirm-row="' + esc(g.rule) + '" hidden><span class="clean-check-wrap"><input class="sr-check" type="checkbox" id="' + esc(subId) + '" data-confirm-for="' + esc(g.rule) + '"><span class="pcheck" aria-hidden="true"></span></span><span>' + esc(g.confirmLabel) + "</span></label>" : "") +
        '<details class="clean-locs"><summary>位置（' + safeInt(g.locations.length) + " 处）</summary>" +
        g.locations.map(function(p) { return '<p class="sel">' + esc(p) + "</p>"; }).join("") +
        "</details></div></section>";
    }).join("") +
    '</div><div class="dfoot"><span id="cleanChosen" role="status"></span><button class="tlink clean-cancel" type="button" id="cCancel">取消</button><button class="pill clean-danger" type="button" id="cGo">先选择至少一组</button></div>';

  function computeEffective() {
    var eff = [], confirmedRules = [], pendingConfirm = false;
    cleanList.groups.forEach(function(g) {
      var ruleSel = cssAttrVal(g.rule);
      var mainChk = safeQuery(dlg, '[data-clean-rule="' + ruleSel + '"]');
      var mainOn = !!(mainChk && mainChk.checked);
      if (g.requiresConfirm) {
        var row = safeQuery(dlg, '[data-confirm-row="' + ruleSel + '"]');
        var subChk = safeQuery(dlg, '[data-confirm-for="' + ruleSel + '"]');
        if (row) row.hidden = !mainOn;
        if (subChk) {
          subChk.disabled = !mainOn;
          if (!mainOn) subChk.checked = false;
        }
        var subOn = !!(subChk && subChk.checked);
        if (mainOn && !subOn) pendingConfirm = true;
        if (mainOn && subOn) {
          eff.push(g);
          confirmedRules.push(g.rule);
        }
      } else if (mainOn) {
        eff.push(g);
      }
    });
    return { eff: eff, confirmedRules: confirmedRules, pendingConfirm: pendingConfirm };
  }

  function update() {
    var st = computeEffective();
    var cnt = st.eff.reduce(function(n, g) { return n + g.count; }, 0);
    var bytes = st.eff.reduce(function(n, g) { return n + g.bytes; }, 0);
    $("cleanChosen").textContent = "已选 " + fmtCount(cnt) + " 个文件 · " + fs(bytes / 1073741824);
    $("cGo").disabled = !st.eff.length || st.pendingConfirm;
    $("cGo").textContent = !st.eff.length ? "先选择至少一组" : ("永久删除 " + fmtCount(cnt) + " 个文件");
  }

  dlg.querySelectorAll("input").forEach(function(inp) {
    inp.onchange = function() {
      update();
      if (inp.dataset && inp.dataset.cleanRule && inp.checked) {
        var confirmRow = safeQuery(dlg, '[data-confirm-row="' + cssAttrVal(inp.dataset.cleanRule) + '"]');
        if (confirmRow && !confirmRow.hidden && typeof confirmRow.scrollIntoView === "function") {
          confirmRow.scrollIntoView({ block: "nearest", behavior: RM ? "auto" : "smooth" });
        }
      }
    };
    inp.onkeydown = function(e) { if (e.key === "Enter") e.preventDefault(); };
  });
  update();

  $("cCancel").onclick = function() { cleanSummaryRequest++; closeDialogModal(); };
  var cleanElev = $("cleanElevateBtn") || dlg.querySelector("[data-elevate]");
  if (cleanElev) cleanElev.onclick = function() { requestRelaunchAdmin("quick"); };
  $("cGo").onkeydown = function(e) { if (e.key === "Enter") e.preventDefault(); };
  $("cGo").onclick = function() {
    if (this.disabled || !cleanList) return;
    var st = computeEffective();
    if (!st.eff.length || st.pendingConfirm) return;
    var rules = st.eff.map(function(g) { return g.rule; });
    S.cleanMaxT = 0;
    GROUPS.forEach(function(g) {
      var full = g.cats.reduce(function(a, c) { return a + c.total; }, 0);
      S.cleanMaxT = Math.max(S.cleanMaxT, full);
    });
    S.cleanByCat = Object.create(null);
    S.cleanDetail = { deleted: 0, deletedBytes: 0, currentPath: "" };
    closeDialogModal();
    S.cleaning = true;
    S.cleanStopping = false;
    S.cleanProg = {
      done: 0,
      total: st.eff.reduce(function(n, g) { return n + g.count; }, 0)
    };
    S.cleanRequest = ++filesRequest;
    render();
    window.chrome.webview.postMessage(JSON.stringify({
      action: "cleanEligible",
      request: S.cleanRequest,
      scanSessionId: cleanList.session,
      rules: rules,
      confirmDumps: st.confirmedRules.indexOf("TMP-CRASHDUMP") >= 0,
      confirmedRules: st.confirmedRules
    }));
  };
  updateModals();
  $("cCancel").focus({ preventScroll: true });
}

function showCleanProblems(msg, lead, title) {
  var dlg = $("dialog");
  dlg.classList.remove("clean-dlg", "recycle-dlg");
  dlg.removeAttribute("aria-describedby");
  var list = (msg && Array.isArray(msg.items) && msg.items.length) ? msg.items : ((msg && Array.isArray(msg.problems)) ? msg.problems : []);
  var rows = list.map(function(p) {
    var item = p && typeof p === "object" ? p : {};
    var tag = item.status === "DeletedVerified" ? "已删除" : (item.status === "NotExecutedDueToStop" ? "未处理" : "未删除");
    return "<li><b>[" + tag + "] " + esc(item.name) + "</b>：" + esc(item.detail) + "</li>";
  }).join("");
  // pi-lens-ignore: no-inner-html-js
  dlg.innerHTML = "<h2>" + esc(title || "清理明细") + "</h2>" +
    (title ? "" : "<p>" + esc(S.freedNote || "") + "</p>") +
    (lead ? "<p>" + esc(lead) + "</p>" : "") +
    (rows ? '<ul class="cleanProblems">' + rows + "</ul>" : "") +
    '<div class="foot"><button class="pill" type="button" id="cOk">知道了</button></div>';
  dlg.classList.add("show");
  updateModals();
  $("cOk").focus({ preventScroll: true });
  $("cOk").onclick = function() { closeDialogModal(); };
}

/* ================= controls & quick scan entry ================= */
function startQuickScan() {
  closeDrawer();
  if (overlay === "sheet") closeSheet();
  S.lastScanMode = "quick";
  if (nativeDetail()) {
    window.chrome.webview.postMessage(JSON.stringify({ action: "startQuickScan" }));
  } else {
    S.scanRoot = "常见缓存位置";
    startScan();
  }
}

function startChatScan() {
  closeDrawer();
  if (overlay === "sheet") closeSheet();
  S.lastScanMode = "chat";
  if (nativeDetail()) {
    window.chrome.webview.postMessage(JSON.stringify({ action: "startChatScan" }));
  } else {
    S.scanRoot = "微信 / QQ 存储空间";
    startScan();
  }
}

function bindControls() {
  var b;
  if ((b = $("quickScanBtn"))) b.onclick = startQuickScan;
  if ((b = $("firstChatScanBtn"))) b.onclick = startChatScan;
  if ((b = $("elevateBtn"))) b.onclick = function() { requestRelaunchAdmin("quick"); };
  if ((b = $("cleanBtn"))) b.onclick = openClean;
  if ((b = $("cleanDetailBtn"))) b.onclick = function() { if (S.cleanBand) showCleanProblems(S.cleanBand.raw, S.cleanBand.lead, "清理明细"); };
  if ((b = $("pick"))) b.onclick = openPicker;
  if ((b = $("pick2"))) b.onclick = openPicker;
  if ((b = $("retry"))) b.onclick = function() { startScan(); };
  if ((b = $("rescan"))) b.onclick = openPicker;
  if ((b = $("stopClean"))) b.onclick = function() {
    S.cleanStopping = true;
    render();
    if (nativeDetail()) window.chrome.webview.postMessage(JSON.stringify({ action: "stopClean" }));
  };
  if ((b = $("stopScan"))) b.onclick = function() { stopScan(); };
  if ((b = $("continueScan"))) b.onclick = function() {
    if (nativeDetail()) window.chrome.webview.postMessage(JSON.stringify({ action: "continueScan" }));
  };
  if ((b = $("snapshotFiles"))) b.onclick = function() {
    openDrawer(null, true);
    dState.request = ++filesRequest;
    if (nativeDetail()) window.chrome.webview.postMessage(JSON.stringify({ action: "snapshotStart", request: dState.request }));
  };
  if ((b = $("allFiles"))) b.onclick = function() { openDrawer(null); };
  if ((b = $("skipBtn"))) b.onclick = function() { openSkipped(); };
  if ((b = $("legendBtn"))) b.onclick = function(e) { showLegend(e.currentTarget); };
}

/* ================= tooltip / toast / legend ================= */
var tip = $("tip"), tipT;
function rel(el) {
  var w = $("win").getBoundingClientRect(), r = el.getBoundingClientRect(), s = w.width / $("win").offsetWidth;
  return { x: (r.left - w.left) / s, y: (r.top - w.top) / s, w: r.width / s, h: r.height / s };
}
function showTip(sl) {
  clearTimeout(tipT);
  tipT = setTimeout(function() {
    if (!sl.g) return;
    var o = gv(sl.g), u = unitOf(o.total);
    tip.textContent = sl.g.group ? sl.g.cats.map(function(c) { return c.name; }).join("、") : sl.g.name;
    tip.appendChild(document.createElement("br"));
    tip.appendChild(document.createTextNode(fs(o.total) + ["ok", "review", "keep"].map(function(k) {
      return o[k] > 0 ? " · " + G[k] + " " + num3(inUnit(o[k], u), u) : "";
    }).join("") + "（" + u + "）"));
    var r = rel(sl.block);
    tip.style.left = Math.max(8, r.x + r.w / 2 - 80) + "px";
    tip.style.top = Math.max(44, r.y - 56) + "px";
    tip.classList.add("show");
  }, 300);
}
function hideTip() { clearTimeout(tipT); tip.classList.remove("show"); }
var toastT;
function toast(t) {
  var el = $("toast");
  el.textContent = t;
  el.classList.add("show");
  clearTimeout(toastT);
  toastT = setTimeout(function() { el.classList.remove("show"); }, 2400);
}
var legend = $("legend");
function showLegend(anchor) {
  lastFocus = anchor || document.activeElement;
  var r = anchor ? rel(anchor) : { x: 34, y: 120, h: 0 };
  legend.style.left = Math.min(r.x, 560) + "px";
  legend.style.top = (r.y + r.h + 8) + "px";
  legend.classList.add("show");
  $("legendOk").focus({ preventScroll: true });
  S.legendSeen = true;
  updateModals();
}
$("legendOk").onclick = function() { legend.classList.remove("show"); updateModals(); };

/* ================= sheets & location picker ================= */
var sheet = $("sheet"), scrim = $("scrim");
var sheetSp = new Spring(104, function(x) { sheet.style.transform = "translateY(" + x + "%)"; }, { k: 200, d: 28 });
var lastFocus = null, overlay = null, pickerMode = "quick", REFRESH_PICKER = null;

function openSheet(html, onClose) {
  hideTip();
  lastFocus = document.activeElement;
  // pi-lens-ignore: no-inner-html-js
  sheet.innerHTML = '<div class="grip"></div>' + html;
  sheetSp.to(0);
  scrim.classList.add("show");
  overlay = "sheet";
  S.sheetClose = onClose;
  updateModals();
  setTimeout(function() {
    var f = sheet.querySelector('[role="radio"][aria-checked="true"],button,[tabindex]');
    if (f) f.focus({ preventScroll: true });
  }, 50);
}
function closeSheet() {
  sheet.classList.remove("coverage-panel");
  sheetSp.to(104);
  scrim.classList.remove("show");
  overlay = drawerOpen ? "drawer" : null;
  if (drawerOpen) scrim.classList.add("show");
  if (S.sheetClose) { var fn = S.sheetClose; S.sheetClose = null; fn(); }
  updateModals();
  maybeLegend();
}
function openSheetInner(html) {
  if (overlay === "sheet") {
    // pi-lens-ignore: no-inner-html-js
    sheet.innerHTML = '<div class="grip"></div>' + html;
    updateModals();
  } else {
    openSheet(html, function() {
      if (S.state === "picking") {
        S.state = S.prevState === "picking" ? "first" : (S.prevState || "first");
        render();
      }
    });
  }
}

var nativeDrives = [], nativeChatFolders = [];

function openPicker(preferMode) {
  closeDrawer();
  S.prevState = S.state;
  S.hasResult = (S.state === "done" || S.state === "stopped" || S.state === "paused");
  pickerMode = typeof preferMode === "string" ? preferMode : "quick";

  REFRESH_PICKER = function() {
    var drives = nativeDrives;
    var chatFolders = nativeChatFolders;
    if (pickerMode === "chat" && !chatFolders.length) pickerMode = "quick";
    var quickOn = pickerMode === "quick";
    var chatOn = pickerMode === "chat" && chatFolders.length > 0;
    var anyDrive = !quickOn && !chatOn && drives.some(function(d) { return d.selected; });
    var any = quickOn || chatOn || anyDrive;

    var quickRow = '<button class="rowbtn row" type="button" data-i="quick" role="radio" aria-checked="' + quickOn + '">' +
      '<span class="cb' + (quickOn ? " on" : "") + '"></span>' +
      '<span class="nm">常见缓存位置（快速）<span class="pth">直达浏览器、聊天纯缓存、桌面软件、显卡着色器、包管理器、缩略图、过期临时文件与错误报告目录，通常只需几秒</span></span>' +
      "</button>";

    var chatRow = "";
    if (chatFolders.length > 0) {
      var appNames = [];
      chatFolders.forEach(function(cf) {
        var an = cf && cf.appName ? String(cf.appName) : "";
        if (an && appNames.indexOf(an) < 0) appNames.push(an);
      });
      var appLabel = appNames.length ? appNames.join("、") : "微信、QQ";
      var pathPreview = chatFolders.slice(0, 2).map(function(cf) { return midPath(cf.path || ""); }).filter(Boolean).join(" · ");
      var chatSub = "已自动定位" + appLabel + (chatFolders.length > 1 ? "等 " : " ") + chatFolders.length + " 处存储目录（分拆朋友圈纯缓存与群聊大文件）" + (pathPreview ? "：" + pathPreview : "");
      chatRow = '<button class="rowbtn row" type="button" data-i="chat" id="pickChatScan" role="radio" aria-checked="' + chatOn + '">' +
        '<span class="cb' + (chatOn ? " on" : "") + '"></span>' +
        '<span class="nm">微信 / QQ 存储专向扫描<span class="pth">' + esc(chatSub) + "</span></span>" +
        "</button>";
    }

    var driveRows = drives.map(function(d, i) {
      var on = !quickOn && !chatOn && !!d.selected;
      return '<button class="rowbtn row" type="button" data-i="' + i + '" role="radio" aria-checked="' + on + '">' +
        '<span class="cb' + (on ? " on" : "") + '"></span>' +
        '<span class="nm">' + esc(d.title) + '<span class="pth">' + esc(d.desc) + "</span></span>" +
        "</button>";
    }).join("");

    openSheetInner(
      '<h2>选择扫描位置</h2><p class="sub">只读取文件信息，不会改动任何文件。</p><div class="rows">' +
      quickRow +
      chatRow +
      driveRows +
      '<button class="rowbtn row" type="button" id="addFolder"><span class="g">＋</span><span class="nm">添加文件夹</span></button></div>' +
      '<div class="sheet-foot">' +
      '<span class="sp sub sheet-hint">' + (any ? "" : "至少选择一个位置") + "</span>" +
      '<button class="tlink" type="button" id="pkCancel">取消</button>' +
      '<button class="pill" type="button" id="pkGo" ' + (any ? "" : "disabled") + ">开始扫描</button></div>"
    );

    sheet.querySelectorAll("[data-i]").forEach(function(b) {
      b.onclick = function() {
        var key = b.dataset.i;
        if (key === "quick") {
          pickerMode = "quick";
          drives.forEach(function(d) { d.selected = false; });
        } else if (key === "chat") {
          pickerMode = "chat";
          drives.forEach(function(d) { d.selected = false; });
        } else {
          pickerMode = "drive";
          drives.forEach(function(d, idx) { d.selected = idx === +key; });
        }
        REFRESH_PICKER();
        var focusBtn = safeQuery(sheet, '[data-i="' + cssAttrVal(key) + '"]');
        if (focusBtn) focusBtn.focus({ preventScroll: true });
      };
    });

    var btnAdd = $("addFolder");
    if (btnAdd) {
      btnAdd.onclick = function() {
        if (nativeDetail()) window.chrome.webview.postMessage(JSON.stringify({ action: "browseFolder" }));
        else toast("请在桌面程序中浏览并添加文件夹");
      };
    }

    var btnCancel = $("pkCancel");
    if (btnCancel) btnCancel.onclick = function() { closeSheet(); };

    var btnGo = $("pkGo");
    if (btnGo) {
      btnGo.onclick = function() {
        if (pickerMode === "quick") {
          closeSheet();
          startQuickScan();
          return;
        }
        if (pickerMode === "chat") {
          closeSheet();
          startChatScan();
          return;
        }
        var targets = drives.filter(function(d) { return d.selected; }).map(function(d) { return d.path; });
        if (!targets.length) return;
        closeSheet();
        S.lastScanMode = "targets";
        if (nativeDetail()) {
          window.chrome.webview.postMessage(JSON.stringify({ action: "startScan", targets: targets }));
        } else {
          S.scanRoot = targets[0];
          startScan();
        }
      };
    }
  };

  if (S.state === "first") S.state = "picking";
  REFRESH_PICKER();
  if (nativeDetail()) {
    window.chrome.webview.postMessage(JSON.stringify({ action: "getDrives" }));
  }
}

function openSkipped() {
  if (nativeDetail() || S.coverage) {
    var c = S.coverage || {}, pending = c.PendingPaths || [], skipped = c.SkippedPaths || [];
    function rows(list) {
      return list.length
        ? list.map(function(p) { return '<div class="row"><span class="nm sel">' + wbrPath(p) + "</span></div>"; }).join("")
        : '<p class="sub">没有记录到此类边界。</p>';
    }
    openSheet(
      '<h2>扫描覆盖范围</h2><div class="coverage-body"><p class="sub">根目录：' + esc(S.scanRoot) +
      "<br>已检查 " + fmtCount(S.fileCount || 0) + " 个文件 · 共扫描 " + fmtCount(c.DirectoriesStarted || 0) +
      " 个文件夹（已完成 " + fmtCount(c.DirectoriesCompleted || 0) + " 个，含起始目录）。<br>只统计已分析文件的逻辑大小，不等于磁盘物理占用。</p>" +
      '<section class="coverage-block"><h3>待处理位置</h3><div class="rows">' + rows(pending) + '</div><p class="sub">待处理目录 ' + fmtCount(c.PendingDirectories || 0) + " 个；以下是当前目录剩余部分与未进入目录的前 64 条边界预览，不是未扫文件数。其内部文件及子目录总量未知。</p></section>" +
      '<section class="coverage-block"><h3>未覆盖的位置</h3><div class="rows">' + rows(skipped) + '</div><p class="sub">不可读取目录 ' + fmtCount(c.UnreadableDirectories || 0) + " 个，跳过重解析点 " + fmtCount(c.ReparseSkipped || 0) + " 个，属性读取失败 " + fmtCount(c.MetadataFailures || 0) + " 项。预览最多 64 条，不代表完整边界清单。不会跟随重解析点。" + esc(S.budgetReason || "") + "</p></section></div>" +
      '<div class="sheet-foot"><span class="sp"></span><button class="pill" type="button" id="coverageClose">关闭</button></div>'
    );
    sheet.classList.add("coverage-panel");
    $("coverageClose").onclick = closeSheet;
    return;
  }
  openSheet(
    '<h2>无权限，已跳过的位置</h2><p class="sub">这些位置没有被读取，因此不在结果中。按平不会因此改动任何文件。</p><div class="rows">' +
    S.skipped.map(function(s) { return '<div class="row"><span class="nm sel">' + wbrPath(s[0]) + '</span><span class="tm">' + esc(s[1]) + "</span></div>"; }).join("") +
    '</div><div class="sheet-foot"><span class="sp"></span><button class="pill" type="button" id="skClose">关闭</button></div>'
  );
  $("skClose").onclick = closeSheet;
}

scrim.onclick = function() {
  if ($("dialog").classList.contains("show")) return;
  if (overlay === "sheet") closeSheet();
  else if (overlay === "drawer") closeDrawer();
};

/* ================= scan control ================= */
var scanTimer = null;
function startScan() {
  if (nativeDetail()) {
    if (S.lastScanMode === "quick") {
      window.chrome.webview.postMessage(JSON.stringify({ action: "startQuickScan" }));
      return;
    }
    if (S.lastScanMode === "chat") {
      window.chrome.webview.postMessage(JSON.stringify({ action: "startChatScan" }));
      return;
    }
    if (!S.scanRoot) { openPicker(); return; }
    window.chrome.webview.postMessage(JSON.stringify({ action: "startScan", targets: [S.scanRoot] }));
    return;
  }
  closeDrawer();
  resetData(false);
  S.state = "scanning";
  S.capOverride = null;
  S.suffix = null;
  S.stopped = false;
  render();
  clearTimeout(scanTimer);
  scanTimer = setTimeout(function() { finishScan(false); }, 220);
}
function stopScan() {
  if (nativeDetail()) {
    window.chrome.webview.postMessage(JSON.stringify({ action: "stopScan" }));
    return;
  }
  clearTimeout(scanTimer);
  finishScan(true);
}
function finishScan(stopped) {
  S.state = stopped ? "stopped" : (CATS.length ? "done" : "empty");
  S.hasResult = true;
  render();
  if (!stopped && S.state === "done" && !S.legendSeen) {
    setTimeout(function() { if (S.state === "done" && !overlay) showLegend($("legendBtn")); }, 900);
  }
}

/* ================= bars ================= */
function onBar(sl) {
  if (!sl.g || sl.block.disabled) return;
  hideTip();
  openDrawer(sl.g);
}

/* ================= drawer & single-file recycle ================= */
var drawer = $("drawer"), drawerOpen = false;
var dState = { g: null, filter: "all", sort: "size", open: Object.create(null) };
var drSp = new Spring(104, function(x) {
  drawer.style.transform = "translateX(" + x + "%)";
  var p = 1 - Math.min(1, Math.max(0, x / 104));
  var compact = document.body.classList.contains("compact");
  $("main").style.transform = compact ? "" : "translateX(" + (-40 * p) + "px) scale(" + (1 - 0.08 * p) + ")";
  $("main").style.opacity = String(1 - 0.25 * p);
}, { k: 190, d: 27 });

var filesRequest = 0, techRequest = 0;
function nativeDetail() { return !!(typeof window !== "undefined" && window.chrome && window.chrome.webview); }

function loadDrawerPage(offset) {
  if (!nativeDetail()) { drawRender(); return; }
  dState.previousPage = dState.page || dState.previousPage;
  dState.wantOffset = offset || 0;
  dState.error = "";
  dState.focusToken = focusToken();
  dState.page = null;
  dState.loading = true;
  dState.request = ++filesRequest;
  if (dState.listShell && drawer.querySelector(".seg-ctl")) {
    syncDrawerTabs();
    var list = $("flist");
    list.inert = true;
    list.setAttribute("aria-busy", "true");
  } else {
    drawRender();
  }
  var cats = dState.g ? dState.g.cats : (dState.snapshotCats || CATS).slice().sort(function(a, b) { return b.total - a.total; });
  if (dState.g && dState.g.group && dState.catId && dState.catId !== "other" && dState.catId !== "all") {
    cats = cats.filter(function(c) { return c.id === dState.catId; });
  }
  var categoryIds = cats.map(function(c) { return c.id; });
  if (dState.snapshot && !categoryIds.length) {
    categoryIds = ["wx", "pkg", "br", "thumb", "shader", "dump", "log", "draft", "dl", "upd", "user", "tmp"];
  }
  var payload = {
    action: "filesPage",
    request: dState.request,
    offset: offset || 0,
    categories: categoryIds,
    query: dState.query || "",
    group: dState.reviewGroup || "",
    snapshot: dState.snapshot || 0,
    filter: dState.filter,
    sort: dState.sort
  };
  if (dState.g && dState.g.group) {
    payload.category = (dState.catId && dState.catId !== "all") ? dState.catId : "other";
  }
  window.chrome.webview.postMessage(JSON.stringify(payload));
}

function openDrawer(g, waitSnapshot) {
  hideTip();
  tock();
  lastFocus = document.activeElement;
  dState = { g: g, catId: "other", filter: "all", sort: "size", open: Object.create(null), waitSnapshot: !!waitSnapshot };
  drawerOpen = true;
  overlay = "drawer";
  if (waitSnapshot) { dState.loading = true; dState.page = null; drawRender(); }
  else loadDrawerPage(0);
  drSp.to(0);
  scrim.classList.add("show");
  updateModals();
  setTimeout(function() {
    var c = drawer.querySelector(".close");
    if (c) c.focus({ preventScroll: true });
  }, 60);
}

function closeDrawer() {
  filesRequest++;
  if (!drawerOpen) return;
  clearDetailSprings();
  drawerOpen = false;
  drSp.to(104);
  scrim.classList.remove("show");
  overlay = null;
  updateModals();
  maybeLegend();
}

function drawerText(text) {
  return String(text || "")
    .replace(/（技术标识[^）]*）/g, "")
    .replace(/当前版本未实现目录内容的逐项核验/g, "目录内文件按现有规则分别检查，不授权整目录清理")
    .replace(/\[开关：RecursiveDirectoryDeleteEnabled=false\]/g, "目录清理功能未开放")
    .replace(/RecursiveDirectoryDeleteEnabled=false/g, "目录清理功能未开放");
}
function drawerRule(text) {
  var label = String(text || "");
  return label.indexOf("FALLBACK-UNKNOWN") >= 0 || /^[A-Z][A-Z0-9_-]*$/.test(label) ? "暂未识别文件类型" : drawerText(label);
}
function purposeHTML(p) {
  if (!p) return "";
  return '<section class="review-intro" aria-label="文件用途说明"><b>' + esc(p.title) + "</b><p>" + esc(p.use) + "</p><p>" + esc(p.advice) + "</p><p>" + esc(p.owner) + "</p><small>依据：" + esc(p.basis) + " · " + esc(p.source) + '<br><span class="sel">' + esc(p.url) + "</span><br>用途说明不改变现有判断、规则或执行许可。</small></section>";
}
function fileInfo(f) {
  return (f.x && f.x.detail) || {
    type: "未知文件",
    confidence: "无法确定",
    purpose: "按平无法确定这个文件的用途。",
    basis: "没有匹配的规则",
    risk: "无法判断",
    riskText: "不知道它属于哪个程序，删除后的影响无法预估。",
    steps: ["不确定时，保留它。"],
    evidence: [{ state: "u", text: "文件用途尚未核实", strength: "未检查" }]
  };
}
function fileSubLine(detail, withConfidence) {
  var t = (detail && detail.type) ? String(detail.type) : "";
  var s = (detail && detail.summary) ? String(detail.summary) : "";
  if (s) {
    if (!t || s === t || s.indexOf(t + " · ") === 0 || s.indexOf(t + "·") === 0) return s;
    return t + " · " + s;
  }
  return (withConfidence && detail && detail.confidence) ? (t + " · " + detail.confidence) : t;
}
function visibleFiles() {
  if (dState.page) return dState.page.files || [];
  var cats = dState.g ? dState.g.cats : (dState.snapshotCats || CATS), files = [];
  if (dState.g && dState.g.group && dState.catId && dState.catId !== "other" && dState.catId !== "all") {
    cats = cats.filter(function(c) { return c.id === dState.catId; });
  }
  cats.forEach(function(c) { files = files.concat(c.files || []); });
  return files.filter(function(f) { return dState.filter === "all" || f.j === dState.filter; })
    .sort(dState.sort === "size" ? function(a, b) { return b.s - a.s; } : function(a, b) { return a.n.localeCompare(b.n, "zh"); });
}
function keyOf(f) { return f.id != null ? "id|" + f.id : f.catId + "|" + f.n; }
function clearDetailSprings() {
  (dState.detailSprings || []).forEach(function(s) {
    var i = springs.indexOf(s);
    if (i >= 0) springs.splice(i, 1);
  });
  dState.detailSprings = [];
}

function openDetail(key) {
  var f = findFile(key);
  if (!f) return;
  dState.listScroll = $("flist") ? $("flist").scrollTop : 0;
  dState.detailKey = key;
  drawDetail();
  if (nativeDetail() && f.id != null) {
    dState.techRequest = ++techRequest;
    window.chrome.webview.postMessage(JSON.stringify({ action: "fileTech", request: dState.techRequest, id: f.id }));
  }
}

function applyFileTech(msg) {
  if (!drawerOpen || !dState || !dState.detailKey) return;
  if (msg.request != null && dState.techRequest && msg.request < dState.techRequest) return;
  var f = findFile(dState.detailKey);
  if (!f || String(f.id) !== String(msg.id)) return;
  f.x = f.x || {};
  var body = $("techBody");
  ["created", "accessed", "attributes", "process"].forEach(function(k) {
    if (typeof msg[k] === "string" && msg[k]) {
      f.x[k] = msg[k];
      var dd = body && safeQuery(body, '[data-tech="' + cssAttrVal(k) + '"]');
      if (dd) {
        dd.textContent = msg[k];
        dd.classList.toggle("u", /未读取|未检查|未知/.test(msg[k]));
      }
    }
  });
  var toggle = $("techToggle"), content = body && body.querySelector(".tech-content");
  if (toggle && content && dState.techSpring && toggle.getAttribute && toggle.getAttribute("aria-expanded") === "true") {
    dState.techSpring.to(content.scrollHeight);
  }
}

function backToList() {
  var key = dState.detailKey, scroll = dState.listScroll;
  clearDetailSprings();
  dState.detailKey = null;
  dState.focusToken = key ? '[data-k="' + cssAttrVal(key) + '"] .fhead' : ".fhead";
  drawRender();
  var row = Array.from(drawer.querySelectorAll(".file")).find(function(el) { return el.dataset.k === key; });
  if ($("flist")) $("flist").scrollTop = scroll || 0;
  if (row) row.querySelector(".fhead").focus({ preventScroll: true });
}

function confidenceHTML(label) {
  var safe = esc(label);
  var n = label === "已确认" ? 3 : label === "很可能" ? 2 : 0;
  return '<span class="conf" aria-label="可信程度：' + safe + '">' +
    [0, 1, 2].map(function(i) { return '<i class="' + (i < n ? "f" : "") + '" aria-hidden="true"></i>'; }).join("") +
    "<span>" + safe + "</span></span>";
}
function reviewMarkHTML(f) {
  if (f.j !== "review") return "";
  var key = f.p + f.n;
  return '<div class="review-marks">' +
    [["pending", "待核实"], ["seen", "已看"], ["keep", "保留"]].map(function(x) {
      return '<button class="sbtn" type="button" data-mark="' + x[0] + '" aria-pressed="' + ((reviewMarks[key] || "pending") === x[0]) + '">' + x[1] + "</button>";
    }).join("") +
    "</div>";
}

function openRecycleConfirm(f) {
  if (!f || f.j === "keep" || f.id == null || S.cleaning || S.recyclingRequest != null) return;
  var dlg = $("dialog");
  dlg.classList.remove("clean-dlg");
  dlg.classList.add("recycle-dlg");
  dlg.setAttribute("aria-describedby", "recycleNote");
  var fullPath = (f.p || "") + f.n;
  // pi-lens-ignore: no-inner-html-js
  dlg.innerHTML = '<h2>将这个文件移入系统回收站？</h2>' +
    '<p class="recycle-file"><b class="sel">' + esc(f.n) + "</b> <span>· " + fs(f.s) + "</span></p>" +
    '<div class="path sel recycle-path">' + wbrPath(fullPath) + "</div>" +
    '<p class="recycle-note" id="recycleNote">此文件将移入 Windows 系统回收站（需要时可从桌面回收站还原；不会处理其他文件）。</p>' +
    '<div class="dfoot">' +
    '<button class="tlink clean-cancel" type="button" id="rCancel">取消</button>' +
    '<button class="pill clean-danger" type="button" id="rGo">移入回收站</button>' +
    "</div>";

  $("rCancel").onclick = function() {
    if (S.recyclingRequest != null) return;
    closeDialogModal();
  };
  $("rGo").onclick = function() {
    if (this.disabled || S.recyclingRequest != null || S.cleaning) return;
    var req = ++filesRequest;
    S.recyclingRequest = req;
    S.recyclingId = f.id;
    S.recyclingName = f.n;
    this.disabled = true;
    this.textContent = "正在移入回收站…";
    if ($("rCancel")) $("rCancel").disabled = true;
    var dBtn = drawer.querySelector('[data-a="recycle"]');
    if (dBtn) {
      dBtn.disabled = true;
      dBtn.textContent = "正在移入回收站…";
    }
    if (nativeDetail()) {
      window.chrome.webview.postMessage(JSON.stringify({
        action: "recycleSingleFile",
        request: req,
        scanSessionId: currentScanSession,
        id: f.id
      }));
    }
  };
  dlg.classList.add("show");
  updateModals();
  $("rCancel").focus({ preventScroll: true });
}

function receiveRecycleSingleResult(msg) {
  if (S.recyclingRequest == null || msg.request !== S.recyclingRequest) return;
  var fileName = msg.name || S.recyclingName || "";
  var recycledId = S.recyclingId;
  S.recyclingRequest = null;
  S.recyclingId = null;
  S.recyclingName = "";

  var dlg = $("dialog");
  dlg.classList.remove("show", "clean-dlg", "recycle-dlg");
  dlg.removeAttribute("aria-describedby");

  if (msg.locked) S.cleanLocked = true;

  if (msg.error || !msg.success) {
    var dBtn = drawer.querySelector('[data-a="recycle"]');
    if (dBtn) {
      dBtn.disabled = false;
      dBtn.textContent = "移入回收站";
    }
    if (msg.locked) render();
    updateModals();
    var errText = msg.error || "未能移入回收站";
    toast(errText);
    $("a11yStatus").textContent = errText;
    return;
  }

  if (Array.isArray(msg.categories)) {
    adoptCategories(msg.categories);
  } else {
    CATS.forEach(function(c) {
      if (Array.isArray(c.files)) {
        c.files = c.files.filter(function(item) { return String(item.id) !== String(recycledId); });
      }
    });
  }
  if (S.state === "done" && CATS.length === 0) S.state = "empty";

  var fromDirOrLarge = !!(drawerOpen && dState && dState.directoryFile);
  if (fromDirOrLarge) {
    closeDrawer();
    directoryState.loading = false;
    render();
    if (S.view === "largeFiles") loadLargeFiles();
  } else if (drawerOpen && dState) {
    var wantOff = dState.wantOffset || 0;
    clearDetailSprings();
    dState.detailKey = null;
    dState.listShell = false;
    render();
    loadDrawerPage(wantOff);
    updateModals();
  } else {
    render();
    updateModals();
  }

  var okText = "已移入系统回收站：" + fileName;
  toast(okText);
  $("a11yStatus").textContent = okText;
}

function drawDetail() {
  var f = findFile(dState.detailKey);
  if (!f) { backToList(); return; }
  f.x = f.x || {};
  clearDetailSprings();
  var d = fileInfo(f), files = visibleFiles();
  var position = files.findIndex(function(x) { return keyOf(x) === dState.detailKey; });
  var page = dState.page;
  var cat = (dState.snapshotCats || CATS).find(function(c) { return c.id === f.catId; });
  var catLabel = cat ? cat.name : shortName({ id: f.catId, cats: [{}], name: "当前分类" });

  var canRecycle = f.j !== "keep" && f.id != null && !S.cleaning;
  var recyclingThis = canRecycle && S.recyclingRequest != null && String(S.recyclingId) === String(f.id);
  var recycleBtn = canRecycle
    ? '<button class="sbtn" type="button" data-a="recycle"' + (recyclingThis ? " disabled" : "") + ">" + (recyclingThis ? "正在移入回收站…" : "移入回收站") + "</button>"
    : "";

  var posNum = (page ? safeInt(page.offset) : 0) + position + 1;
  var totNum = page ? safeInt(page.total) : files.length;
  var stepsList = Array.isArray(d.steps) ? d.steps : [];
  var evList = Array.isArray(d.evidence) ? d.evidence : [];
  var h = '<div class="dvbar"><button class="back" type="button" id="detailBack" title="Esc / Backspace">‹ 返回列表</button><span class="pos">' + posNum + " / " + totNum + '</span></div><div class="dv file" data-k="' + esc(dState.detailKey) + '"><h2 class="fn sel">' + esc(f.n) + '</h2><div class="fmeta">' + esc(fs(f.s)) + " · 修改于 " + esc(f.mt) + " · " + esc(catLabel) + '</div><span class="chip">' + esc(judgeGlyph(f.j)) + " " + esc(judgeLabel(f.j)) + "</span>";
  h += '<section class="blk"><h3>这是什么</h3><div class="typ"><b>' + esc(d.type) + "</b>" + confidenceHTML(d.confidence) + "</div><p>" + esc(d.purpose) + '</p><div class="basis">判断依据：' + esc(d.basis) + "</div></section>";
  h += '<section class="blk"><h3>删除会怎样</h3><div class="risk">' + esc(d.risk) + "</div><p>" + esc(d.riskText) + "</p></section>";
  h += '<section class="blk"><h3>建议你</h3><ol class="steps">' + stepsList.map(function(s) { return "<li>" + esc(s) + "</li>"; }).join("") + '</ol><div class="acts"><button class="sbtn" type="button" data-a="reveal">在资源管理器中显示</button><button class="sbtn" type="button" data-a="copy">复制路径</button>' + recycleBtn + "</div></section>";
  h += '<section class="blk"><h3>为什么这样判断</h3><ul class="ev">' + evList.map(function(e) { var ev = e && typeof e === "object" ? e : {}; var stGlyph = ev.state === "y" ? "✓" : (ev.state === "n" ? "✕" : "?"); return '<li><span class="st ' + (ev.state === "u" ? "u" : "") + '">' + stGlyph + "</span><span>" + esc(ev.text) + '</span><span class="str">' + esc(ev.strength) + "</span></li>"; }).join("") + '</ul><div class="rulenote">原有规则 ' + esc(f.x.ruleId || f.r) + " · 标“?”的项目没有检查，不参与判断。用途说明不改变真实分类或执行许可。</div>" + (d.source ? '<p class="rulenote sel">' + esc(d.source) + (d.sourceUrl ? "<br>" + esc(d.sourceUrl) : "") + "</p>" : "") + reviewMarkHTML(f) + "</section>";
  h += '<section class="tech"><button class="tech-toggle" type="button" id="techToggle" aria-expanded="false" aria-controls="techBody">› 技术详情</button><div class="tech-body" id="techBody" inert aria-hidden="true"><div class="tech-content"><div class="path sel">' + wbrPath((f.p || "") + f.n) + '</div><dl class="tkv">' +
    [
      ["精确大小", typeof f.x.bytes === "number" ? f.x.bytes.toLocaleString("en-US") + " 字节" : "未读取"],
      ["修改时间", f.mt],
      ["创建时间", f.x.created, "created"],
      ["访问时间", f.x.accessed, "accessed"],
      ["属性", f.x.attributes, "attributes"],
      ["文件头签名", f.x.header],
      ["占用进程", f.x.process, "process"],
      ["规则编号", f.x.ruleId || f.r],
      ["规则库版本", f.x.ruleVersion],
      ["原始判断依据", f.why],
      ["原始限制说明", f.x.why2 || "未读取"],
      ["原始结论强度", f.x.conclusion || "未读取"],
      ["原始清理后果", f.x.consequence || "未读取"],
      ["原始内容证据", f.x.evidence || "未检查"],
      ["适用范围", f.x.scope || "未读取"],
      ["限制条件", f.x.excludes || "未读取"]
    ].map(function(v) {
      var s = v[1] || "未读取", dk = v[2] ? ' data-tech="' + v[2] + '"' : "";
      return "<dt>" + esc(v[0]) + "</dt><dd" + dk + ' class="' + (/未读取|未检查|未知/.test(s) ? "u" : "") + '">' + esc(s) + "</dd>";
    }).join("") +
    '</dl></div></div></section></div><div class="dfoot"><span>' + (canRecycle ? "可查看详情、定位文件或单独移入回收站。" : "建议保留的文件仅支持查看详情、复制路径与定位。") + "</span><span>Esc 返回</span></div>";

  // pi-lens-ignore: no-inner-html-js
  drawer.innerHTML = h;
  $("detailBack").onclick = dState.directoryFile ? closeDrawer : backToList;
  if (dState.directoryFile && dState.backLabel) $("detailBack").textContent = dState.backLabel;

  drawer.querySelectorAll("[data-mark]").forEach(function(b) {
    b.onclick = function() {
      reviewMarks[f.p + f.n] = b.dataset.mark;
      drawer.querySelectorAll("[data-mark]").forEach(function(bb) { bb.setAttribute("aria-pressed", String(bb === b)); });
      toast(reviewCount());
    };
  });
  var body = $("techBody"), content = body.querySelector(".tech-content"), tech = body.parentElement;
  var hs = new Spring(0, function(x) { body.style.height = Math.max(0, x) + "px"; });
  dState.techSpring = hs;
  dState.detailSprings.push(hs);
  $("techToggle").onclick = function() {
    var open = this.getAttribute("aria-expanded") !== "true";
    this.setAttribute("aria-expanded", String(open));
    body.inert = !open;
    body.setAttribute("aria-hidden", String(!open));
    tech.classList.toggle("open", open);
    hs.to(open ? content.scrollHeight : 0);
  };
  var dv = drawer.querySelector(".dv");
  var slide = new Spring(28, function(x) { dv.style.transform = "translateX(" + x + "px)"; });
  dState.detailSprings.push(slide);
  slide.to(0);
  updateModals();
  $("detailBack").focus({ preventScroll: true });
}

function syncDrawerTabs() {
  var bar = drawer.querySelector(".seg-ctl");
  if (!bar) return;
  var keys = ["all", "ok", "review", "keep"];
  bar.style.setProperty("--tab-index", Math.max(0, keys.indexOf(dState.filter)));
  bar.querySelectorAll("[data-f]").forEach(function(b) {
    var on = b.dataset.f === dState.filter;
    b.classList.toggle("on", on);
    b.setAttribute("aria-selected", String(on));
    b.tabIndex = on ? 0 : -1;
  });
  var curSub = (dState.catId && dState.catId !== "all") ? dState.catId : "other";
  drawer.querySelectorAll("[data-subcat]").forEach(function(b) {
    var subOn = b.dataset.subcat === curSub;
    b.classList.toggle("on", subOn);
    b.setAttribute("aria-pressed", String(subOn));
  });
  drawer.querySelectorAll("[data-s]").forEach(function(b) {
    b.classList.toggle("on", b.dataset.s === dState.sort);
  });
}

function baseDrawerRender() {
  var g = dState.g, allGroupCats = (g && g.group && Array.isArray(g.cats) && g.cats.length > 1) ? g.cats : null;
  var curSub = (allGroupCats && dState.catId && dState.catId !== "all") ? dState.catId : "other";
  var cats = g ? g.cats : (dState.snapshotCats || CATS).slice().sort(function(a, b) { return b.total - a.total; });
  if (allGroupCats && curSub !== "other") {
    cats = cats.filter(function(c) { return c.id === curSub; });
  }
  var page = dState.page;
  if (nativeDetail()) {
    cats = cats.map(function(c) {
      return Object.assign({}, c, { files: page ? (page.files || []).filter(function(f) { return f.catId === c.id; }) : [] });
    });
  }
  var title = dState.groupName || (g ? g.name : "全部文件"), ok = 0, rv = 0, kp = 0;
  var cnt = Object.assign(Object.create(null), { all: 0, ok: 0, review: 0, keep: 0 });
  cats.forEach(function(c) {
    ok += c.ok; rv += c.review; kp += c.keep;
    (c.files || []).forEach(function(f) { cnt.all++; if (hasOwn(cnt, f.j)) cnt[f.j]++; });
  });
  if (nativeDetail()) {
    var pc = page && page.counts && typeof page.counts === "object" ? page.counts : null;
    cnt = Object.assign(Object.create(null), pc
      ? {
          all: pc.all === "—" ? "—" : safeInt(pc.all),
          ok: pc.ok === "—" ? "—" : safeInt(pc.ok),
          review: pc.review === "—" ? "—" : safeInt(pc.review),
          keep: pc.keep === "—" ? "—" : safeInt(pc.keep)
        }
      : { all: cats.reduce(function(n, c) { return n + safeInt(c.count); }, 0), ok: "—", review: "—", keep: "—" });
  }
  var h = '<div class="dhead"><div class="t"><h2>' + esc(title) + '</h2><div class="dtot">' +
    (page && typeof page.logicalBytes === "number" ? esc(fs(page.logicalBytes / 1073741824)) + " 逻辑大小" : esc(fs(ok + rv + kp)) + (ok ? " · ● " + esc(sh(ok)) : "") + (rv ? " · ◐ " + esc(sh(rv)) : "") + (kp ? " · ○ " + esc(sh(kp)) : "")) +
    "</div>" + (g && g.group ? '<div class="dtot">包含：' + esc(g.cats.map(function(c) { return c.name; }).join("、")) + "</div>" : "") +
    '</div><button class="close" type="button" aria-label="关闭明细"><svg width="10" height="10" viewBox="0 0 10 10" stroke="currentColor" stroke-width="1.2"><line x1="1" y1="1" x2="9" y2="9"/><line x1="9" y1="1" x2="1" y2="9"/></svg></button></div>';
  h += '<div class="seg-ctl" role="tablist">' +
    [["all", "全部"], ["ok", "● 符合清理规则"], ["review", "◐ 需复核"], ["keep", "○ 建议保留"]].map(function(x) {
      return '<button role="tab" type="button" data-f="' + x[0] + '" class="' + (dState.filter === x[0] ? "on" : "") + '" aria-selected="' + (dState.filter === x[0]) + '"><span>' + x[1] + '</span> <span class="tabcount">' + esc(hasOwn(cnt, x[0]) ? cnt[x[0]] : 0) + "</span></button>";
    }).join("") +
    "</div>";
  if (allGroupCats) {
    var allOn = curSub === "other";
    h += '<div class="subcat-bar" id="drawerSubcats" role="group" aria-label="子分类筛选">' +
      '<button type="button" class="subcat-pill' + (allOn ? " on" : "") + '" data-subcat="other" aria-pressed="' + allOn + '"><span>全部</span><span class="subcat-sz">' + esc(fs(gv(g).total)) + "</span></button>" +
      allGroupCats.map(function(sc) {
        var on = curSub === sc.id;
        var rem = Math.max(0, sc.total - (hasOwn(S.moved, sc.id) ? (Number(S.moved[sc.id]) || 0) : 0));
        return '<button type="button" class="subcat-pill' + (on ? " on" : "") + '" data-subcat="' + esc(sc.id) + '" aria-pressed="' + on + '"><span>' + esc(sc.name) + '</span><span class="subcat-sz">' + esc(fs(rem)) + "</span></button>";
      }).join("") +
      "</div>";
  }
  h += '<div class="sortbar">排序：<button class="tlink ' + (dState.sort === "size" ? "on" : "") + '" type="button" data-s="size">按大小</button><button class="tlink ' + (dState.sort === "name" ? "on" : "") + '" type="button" data-s="name">按名称</button></div><div class="flist" id="flist">';
  if (nativeDetail()) {
    var pgOff = page ? Math.max(0, safeInt(page.offset)) : 0;
    var pgLim = page ? Math.max(0, safeInt(page.limit)) : 0;
    var pgTot = page ? Math.max(0, safeInt(page.total)) : 0;
    h += '<div class="sortbar pagebar"><button class="tlink" type="button" id="pagePrev" ' + (!page || pgOff === 0 ? "disabled" : "") + '>上一页</button><span role="status">' + (page ? (pgTot ? (pgOff + 1) + "–" + Math.min(pgOff + pgLim, pgTot) + " / " + pgTot : "0 / 0") : "正在加载…") + '</span><button class="tlink" type="button" id="pageNext" ' + (!page || pgOff + pgLim >= pgTot ? "disabled" : "") + ">下一页</button></div>";
  }
  var any = false;
  cats.forEach(function(c) {
    var fl = (c.files || []).filter(function(f) { return dState.filter === "all" || f.j === dState.filter; });
    if (!fl.length) return;
    any = true;
    fl = fl.slice().sort(dState.sort === "size" ? function(a, b) { return b.s - a.s; } : function(a, b) { return a.n.localeCompare(b.n, "zh"); });
    if (cats.length > 1) h += '<div class="sect"><span>' + esc(c.name) + "</span><span>" + esc(fs(c.total)) + "</span></div>";
    fl.forEach(function(f) {
      f.x = f.x || {};
      var key = f.id != null ? "id|" + f.id : c.id + "|" + f.n, detail = fileInfo(f);
      var fsub = fileSubLine(detail, true);
      h += '<div class="file" data-k="' + esc(key) + '"><button class="fhead" type="button" aria-label="' + esc(judgeLabel(f.j) + "，" + f.n + "，" + fsub + "，" + fs(f.s)) + '"><span class="gl">' + esc(judgeGlyph(f.j)) + '</span><span class="mid"><span class="fname">' + esc(f.n) + '</span><span class="ftype" title="' + esc(fsub) + '">' + esc(fsub) + '</span><span class="fdir">' + esc(midDir(f.p)) + '</span></span><span class="fsz">' + (f.x.sizeComplete === false ? "≥ " : "") + esc(fs(f.s)) + '</span><span class="chev">›</span></button></div>';
    });
    if (!nativeDetail() && c.count > c.files.length) {
      h += '<div class="dfoot dfoot-plain"><span>仅列出最大的 ' + fl.length + " 个，共 " + esc(fmtCount(safeInt(c.count))) + " 个</span><span>按大小排序</span></div>";
    }
  });
  if (!any) {
    var emptyMsg = dState.loading
      ? "正在加载明细…"
      : (dState.filter === "all" ? "这一类里没有符合条件的文件。" : "这一类里没有「" + esc(judgeLabel(dState.filter)) + "」的文件。");
    h += '<p class="sub flist-empty">' + emptyMsg + "</p>";
  }
  h += '</div><div class="dfoot"><span>可查看、复制路径、定位文件。</span><span>Esc 关闭</span></div>';

  // pi-lens-ignore: no-inner-html-js
  if (dState.listShell && drawer.querySelector(".seg-ctl")) {
    var next = document.createElement("div");
    next.innerHTML = h;
    drawer.querySelector(".dtot").textContent = next.querySelector(".dtot").textContent;
    drawer.querySelectorAll("[data-f]").forEach(function(b) {
      var count = b.querySelector(".tabcount"), text = String(hasOwn(cnt, b.dataset.f) ? cnt[b.dataset.f] : 0);
      if (count.textContent !== text) count.textContent = text;
    });
    $("flist").replaceWith(next.querySelector("#flist"));
  } else {
    drawer.innerHTML = h;
  }
  dState.listShell = true;
  syncDrawerTabs();
  drawer.querySelector(".close").onclick = closeDrawer;
  drawer.querySelectorAll("[data-f]").forEach(function(b) {
    b.onclick = function() { dState.filter = b.dataset.f; dState.open = Object.create(null); loadDrawerPage(0); };
  });
  drawer.querySelectorAll("[data-subcat]").forEach(function(b) {
    b.onclick = function() {
      var nextSub = b.dataset.subcat || "other";
      if ((dState.catId || "other") === nextSub) return;
      dState.catId = nextSub;
      dState.open = Object.create(null);
      dState.listShell = false;
      loadDrawerPage(0);
    };
  });
  drawer.querySelectorAll("[data-s]").forEach(function(b) {
    b.onclick = function() { dState.sort = b.dataset.s; dState.open = Object.create(null); loadDrawerPage(0); };
  });
  var prev = drawer.querySelector("#pagePrev"), nextBtn = drawer.querySelector("#pageNext");
  if (prev) prev.onclick = function() { loadDrawerPage(Math.max(0, page.offset - page.limit)); };
  if (nextBtn) nextBtn.onclick = function() { loadDrawerPage(page.offset + page.limit); };
  drawer.querySelectorAll(".file").forEach(function(el) {
    var key = el.dataset.k, hb = el.querySelector(".fhead");
    hb.onclick = function() { openDetail(key); };
    hb.onkeydown = function(e) {
      var all = Array.from(drawer.querySelectorAll(".fhead")), i = all.indexOf(hb);
      if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        e.preventDefault();
        var nx = all[i + (e.key === "ArrowDown" ? 1 : -1)];
        if (nx) nx.focus({ preventScroll: true });
      }
    };
  });
}

function drawRender() {
  if (dState.detailKey) { drawDetail(); return; }
  if (dState.groupsMode) { if (dState.groupReply) drawReviewGroups(dState.groupReply); return; }
  baseDrawerRender();
  var tools = drawer.querySelector(".review-tools");
  if (!tools) {
    tools = document.createElement("div");
    tools.className = "review-tools";
    // pi-lens-ignore: no-inner-html-js
    tools.innerHTML = '<button class="tlink" type="button" id="reviewGroups">' + (dState.reviewGroup ? "返回复核分组" : "按来源/原因复核") + '</button><label class="sr-only" for="fileSearch">搜索当前范围的名称或路径</label><input id="fileSearch" maxlength="200" placeholder="搜索名称或完整路径（Enter）" value="' + esc(dState.query || "") + '"><span class="sub">分类内排序 · ' + (dState.snapshot ? "已分析文件的固定快照；扫描继续" : "已分析文件的逻辑大小") + "</span>";
    var sb = drawer.querySelector(".subcat-bar") || drawer.querySelector(".sortbar");
    if (sb && sb.before) sb.before(tools);
  }
  if ($("reviewGroups")) {
    $("reviewGroups").onclick = function() {
      if (dState.reviewGroup && dState.savedGroups) {
        dState.groupsMode = true;
        dState.reviewGroup = "";
        drawReviewGroups(dState.savedGroups);
      } else {
        requestGroups(0);
      }
    };
  }
  if ($("fileSearch")) {
    $("fileSearch").onkeydown = function(e) {
      if (e.key === "Enter") { dState.query = this.value; loadDrawerPage(0); }
    };
  }
  if (dState.page && dState.snapshot && dState.page.total === 0) {
    var empty = drawer.querySelector(".flist .sub");
    if (empty) empty.textContent = "这份快照还没有已分析文件。扫描正在继续，可关闭后重新打开查看。";
  }
  if (dState.error) {
    var loading = drawer.querySelector(".flist .sub");
    if (loading) loading.textContent = "明细加载失败";
    var counter = drawer.querySelector(".flist [role=status]");
    if (counter) counter.textContent = "加载失败";
    var er = document.createElement("div");
    er.setAttribute("role", "alert");
    // pi-lens-ignore: no-inner-html-js
    er.innerHTML = "<p>" + esc(dState.error) + '</p><button class="sbtn" type="button" id="pageRetry">重试</button><button class="sbtn" type="button" id="pageBack">返回上一页</button>';
    var fl = drawer.querySelector(".flist");
    if (fl && fl.prepend) fl.prepend(er);
    if ($("pageRetry")) $("pageRetry").onclick = function() { loadDrawerPage(dState.wantOffset); };
    if ($("pageBack")) $("pageBack").onclick = function() {
      if (dState.previousPage) { dState.page = dState.previousPage; dState.error = ""; drawRender(); }
      else closeDrawer();
    };
  }
  updateModals();
  setTimeout(function() {
    if (drawerOpen && overlay === "drawer" && !dState.detailKey) {
      var f = dState.focusToken && safeQuery(drawer, dState.focusToken);
      if (!f || f.disabled || (f.closest && f.closest("[inert],[hidden]"))) f = drawer.querySelector(".fhead,.close");
      if (f) f.focus({ preventScroll: true });
    }
  }, 0);
}

function findFile(key) {
  if (!key) return null;
  var p = key.split("|");
  if (p[0] === "id" && dState && dState.page && Array.isArray(dState.page.files)) {
    var pf = dState.page.files.find(function(f) { return String(f.id) === p[1]; });
    if (pf) return pf;
  }
  if (p[0] === "id") {
    for (var i = 0; i < CATS.length; i++) {
      var f = (CATS[i].files || []).find(function(item) { return String(item.id) === p[1]; });
      if (f) return f;
    }
    return null;
  }
  var c = CATS.find(function(cat) { return cat.id === p[0]; });
  return c ? (c.files || []).find(function(item) { return item.n === p.slice(1).join("|"); }) : null;
}

function copyPath(el, btn) {
  var f = findFile(el.dataset.k);
  if (!f) return;
  if (nativeDetail()) {
    if (f.id != null) window.chrome.webview.postMessage(JSON.stringify({ action: "copyPath", id: f.id }));
    return;
  }
  var txt = (f.p || "") + f.n;
  var done = function() {
    btn = btn || (el.querySelector && el.querySelector('[data-a="copy"]'));
    if (btn) {
      btn.textContent = "已复制 ✓";
      setTimeout(function() { btn.textContent = "复制路径"; }, 1500);
    }
  };
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(txt).then(done, function() { fallbackCopy(txt); done(); });
    } else { fallbackCopy(txt); done(); }
  } catch (e) { done(); }
}
function fallbackCopy(t) {
  var ta = document.createElement("textarea");
  ta.value = t;
  document.body.appendChild(ta);
  ta.select();
  try { document.execCommand("copy"); } catch (e) {}
  document.body.removeChild(ta);
}

/* touch swipe to close drawer / sheet */
(function initTouchSwipe() {
  var sx = 0, sy = 0, dragging = null, pointer = null, capture = null;
  function reset() {
    var w = dragging;
    dragging = null; pointer = null;
    var el = capture; capture = null;
    if (el) { try { el.releasePointerCapture(el._dragId); } catch (e) {} }
    if (w === "drawer") { drawer.style.transform = ""; drSp.to(drawerOpen ? 0 : 104); }
    if (w === "sheet") sheetSp.to(overlay === "sheet" ? 0 : 104);
  }
  function down(e, which) {
    if (e.pointerType !== "touch" || dragging || (e.target.closest && e.target.closest("button,input,.flist,.dv,.rows,.coverage-body"))) return;
    sx = e.clientX; sy = e.clientY; dragging = which; pointer = e.pointerId; capture = e.currentTarget; capture._dragId = pointer;
    try { capture.setPointerCapture(pointer); } catch (error) { reset(); }
  }
  drawer.addEventListener("pointerdown", function(e) { down(e, "drawer"); });
  sheet.addEventListener("pointerdown", function(e) { down(e, "sheet"); });
  window.addEventListener("pointermove", function(e) {
    if (!dragging || e.pointerId !== pointer) return;
    var compact = document.body.classList.contains("compact");
    if (dragging === "drawer") {
      if (compact) drawer.style.transform = "translateY(" + Math.max(0, e.clientY - sy) + "px)";
      else drSp.to(Math.max(0, e.clientX - sx) / drawer.offsetWidth * 100, true);
    } else {
      sheetSp.to(Math.max(0, e.clientY - sy) / sheet.offsetHeight * 100, true);
    }
  });
  window.addEventListener("pointerup", function(e) {
    if (!dragging || e.pointerId !== pointer) return;
    var w = dragging, dist = (w === "sheet" || document.body.classList.contains("compact")) ? e.clientY - sy : e.clientX - sx;
    reset();
    if (dist > 80) { if (w === "drawer") closeDrawer(); else closeSheet(); }
  });
  window.addEventListener("pointercancel", reset);
  [drawer, sheet].forEach(function(el) { el.addEventListener("lostpointercapture", reset); });
  window.addEventListener("blur", reset);
  document.addEventListener("keydown", function(e) { if (e.key === "Escape") reset(); }, true);
})();

/* ================= sound (application only, first launch off; remember user choice) ================= */
var soundOn = false, currentScanSession = null, audioWarned = Object.create(null);
try { soundOn = localStorage.getItem("anping.sound.enabled") === "true"; } catch (_) {}
var audio = new AnPingAudio.Controller({
  onResult: function(r) {
    if (/failed|timeout|unavailable/.test(r.status) && !Object.prototype.hasOwnProperty.call(audioWarned, r.status)) {
      audioWarned[r.status] = true;
      soundState();
      toast("应用提示音未能播放（" + r.status + "）；未更改系统声音设置。");
    }
  }
});
function completionReady(msg) {
  return msg.action === "scanComplete" && msg.completed === true && !msg.stopped && !msg.limited && !msg.error;
}
function soundState() {
  var b = $("soundBtn");
  if (!b) return;
  b.classList.toggle("on", soundOn);
  b.setAttribute("aria-pressed", String(soundOn));
  b.setAttribute("aria-label", soundOn ? "提示音：已开启，点击关闭" : "提示音：已关闭，点击开启");
  b.title = soundOn ? "提示音已开启" : "提示音已关闭";
  var w = b.querySelector(".w"), m = b.querySelector(".m");
  if (w) w.setAttribute("opacity", soundOn ? 1 : 0);
  if (m) m.setAttribute("opacity", soundOn ? 0 : 1);
}
if ($("soundBtn")) {
  $("soundBtn").onclick = function() {
    soundOn = !soundOn;
    audioWarned = Object.create(null);
    audio.setEnabled(soundOn);
    soundState();
    try { localStorage.setItem("anping.sound.enabled", String(soundOn)); }
    catch (_) { toast("提示音已切换，但无法保存设置；下次打开需重新开启。"); }
    if (soundOn) tock("click");
  };
}
function tock(kind) { return audio.play(kind || "click", currentScanSession); }
function notifyEnd(msg) {
  if (!completionReady(msg)) return;
  if (msg.scanSessionId != null && msg.scanSessionId !== currentScanSession) return;
  var id = msg.scanSessionId;
  audio.play("complete", id).then(function(scheduled) {
    if (scheduled && currentScanSession === id) S.completionNotified = true;
  });
}
audio.setEnabled(soundOn);
soundState();
["pointerdown", "keydown"].forEach(function(type) {
  document.addEventListener(type, function(e) { if (e.isTrusted) audio.unlock(); }, true);
});
chart.addEventListener("pointerenter", function(e) {
  if (e.target && e.target.classList && e.target.classList.contains("block") && !e.target.disabled) tock("hover");
}, true);

/* ================= bounded readonly review and accessibility ================= */
var reviewMarks = Object.create(null), pendingLegend = false;
function focusToken() {
  var a = document.activeElement;
  if (!a || !drawer.contains || !drawer.contains(a)) return "";
  if (a.id) return "#" + cssEsc(a.id);
  if (a.dataset && a.dataset.subcat) return '[data-subcat="' + cssAttrVal(a.dataset.subcat) + '"]';
  if (a.dataset && a.dataset.f) return '[data-f="' + cssAttrVal(a.dataset.f) + '"]';
  if (a.dataset && a.dataset.s) return '[data-s="' + cssAttrVal(a.dataset.s) + '"]';
  return ".fhead";
}
function maybeLegend() {
  if (pendingLegend && !overlay && !drawerOpen && !legend.classList.contains("show")) {
    pendingLegend = false;
    showLegend($("legendBtn"));
  }
}
function reviewCount() {
  var n = Object.assign(Object.create(null), { pending: 0, seen: 0, keep: 0 });
  Object.keys(reviewMarks).forEach(function(k) { var v = reviewMarks[k]; if (hasOwn(n, v)) n[v]++; });
  return "本次会话标记：已看 " + n.seen + " · 保留 " + n.keep + "（不改变系统判断/许可，关闭程序后不保存）";
}
function requestGroups(offset) {
  dState.groupsMode = true;
  dState.request = ++filesRequest;
  if (nativeDetail()) {
    window.chrome.webview.postMessage(JSON.stringify({
      action: "reviewGroups",
      offset: offset || 0,
      request: dState.request,
      snapshot: dState.snapshot || 0
    }));
  }
}
function reviewFolderTitle(folder) {
  var parts = String(folder || "").split(/[\\/]/).filter(Boolean);
  return parts.length ? parts[parts.length - 1] + " · 待核实" : "来源未知 · 待核实";
}
function renderReviewGroup(g, i) {
  return '<button class="review-group" type="button" data-group="' + i + '"><b>' + esc(reviewFolderTitle(g.folder)) + '</b><span class="review-meta">' + fmtCount(g.count) + " 个文件 · " + fs(g.bytes / 1073741824) + " 逻辑大小" + (g.incomplete ? "（部分大小未知）" : "") + '</span><span class="review-conclusion">先保留，确认用途后再决定。当前证据不足以判为「符合清理规则」。</span><span class="review-reason">复核原因：' + esc(drawerText(g.reason || "用途与来源尚未确认")) + '</span><small class="review-path">位置：' + esc(g.folder || "未知") + "</small><small>打开查看全部文件、具体依据与处理后果 →</small></button>";
}
function drawReviewGroups(m) {
  var list = Array.isArray(m && m.groups) ? m.groups : [];
  var mCount = Math.max(0, safeInt(m && m.count));
  var mOffset = Math.max(0, safeInt(m && m.offset));
  var mLimit = Math.max(1, safeInt(m && m.limit) || 30);
  var mTotalGroups = Math.max(0, safeInt(m && m.totalGroups));
  // pi-lens-ignore: no-inner-html-js
  drawer.innerHTML = '<div class="dhead"><h2>需复核 · 分组</h2><button class="close" type="button" aria-label="关闭复核抽屉">×</button></div><p class="sub">按文件夹与现有复核原因分组，不以来源、大小或抽样证明安全。' + mCount + " 个文件 · " + esc(fs((Number(m && m.bytes) || 0) / 1073741824)) + ' 逻辑大小</p><p class="sub">' + esc(reviewCount()) + '</p><div class="flist">' + (m && m.error ? '<p role="alert">' + esc(m.error) + "</p>" : "") + list.map(renderReviewGroup).join("") + (list.length ? "" : '<p class="sub">没有需复核分组。</p>') + '</div><div class="dfoot"><button class="tlink" type="button" id="groupPrev" ' + (!mOffset ? "disabled" : "") + ">上页组</button><span>" + (mOffset + 1) + " / " + mTotalGroups + ' 组</span><button class="tlink" type="button" id="groupNext" ' + (mOffset + mLimit >= mTotalGroups ? "disabled" : "") + ">下页组</button></div>";
  drawer.querySelector(".close").onclick = closeDrawer;
  drawer.querySelectorAll("[data-group]").forEach(function(b) {
    b.onclick = function() {
      var chosen = list[+b.dataset.group];
      dState.groupsMode = false;
      dState.reviewGroup = chosen.key;
      dState.groupName = reviewFolderTitle(chosen.folder);
      dState.groupFolder = chosen.folder;
      dState.filter = "review";
      dState.query = "";
      dState.savedGroups = m;
      dState.g = null;
      dState.listShell = false;
      loadDrawerPage(0);
    };
  });
  $("groupPrev").onclick = function() { requestGroups(Math.max(0, m.offset - m.limit)); };
  $("groupNext").onclick = function() { requestGroups(m.offset + m.limit); };
  updateModals();
}

var modalFocus = null, modalReturn = "", modalTop = null;
function validFocus(el) {
  return el && document.body.contains && document.body.contains(el) && !el.disabled && !(el.closest && el.closest("[inert],[hidden]")) && (!el.getClientRects || el.getClientRects().length);
}
function returnFocus() {
  var el = validFocus(modalFocus) ? modalFocus : (modalReturn && safeQuery(document, modalReturn));
  if (!validFocus(el)) el = document.querySelector("#allFiles,#quickScanBtn,#pick,#firstChatScanBtn,#snapshotFiles") || $("soundBtn");
  if (validFocus(el)) el.focus({ preventScroll: true });
  modalFocus = null;
  modalReturn = "";
}
function updateModals() {
  var dlg = $("dialog");
  var dlgShown = dlg.classList.contains("show");
  scrim.classList.toggle("dialog-dim", dlgShown);
  var top = dlgShown ? dlg : (legend.classList.contains("show") ? legend : (overlay === "sheet" ? sheet : (drawerOpen ? drawer : null)));
  if (top && top !== modalTop) {
    modalFocus = lastFocus && document.body.contains && document.body.contains(lastFocus) ? lastFocus : document.activeElement;
    modalReturn = modalFocus && modalFocus.id ? "#" + cssEsc(modalFocus.id) : "";
  }
  var changed = modalTop !== top;
  modalTop = top;
  $("main").inert = !!top;
  var tb = document.querySelector(".titlebar");
  if (tb) tb.inert = !!top;

  [drawer, sheet, legend, dlg].forEach(function(el) {
    var visible = el === drawer ? drawerOpen : (el === sheet ? overlay === "sheet" : el.classList.contains("show"));
    el.inert = el !== top;
    el.setAttribute("aria-hidden", String(el !== top));
    if (visible) el.hidden = false;
    else setTimeout(function() {
      var still = el === drawer ? drawerOpen : (el === sheet ? overlay === "sheet" : el.classList.contains("show"));
      if (!still) el.hidden = true;
    }, 320);
    var h = el.querySelector("h2,h3");
    if (h) { h.id = el.id + "Title"; el.setAttribute("aria-labelledby", h.id); }
  });

  [drawer, sheet].forEach(function(box) {
    box.querySelectorAll("[role=tablist]").forEach(function(l) {
      l.querySelectorAll("[role=tab]").forEach(function(b) {
        b.tabIndex = b.getAttribute("aria-selected") === "true" ? 0 : -1;
      });
    });
    var radio = box.querySelector("[role=radio]");
    if (radio && radio.parentElement) {
      radio.parentElement.setAttribute("role", "radiogroup");
      radio.parentElement.setAttribute("aria-label", "扫描位置");
      radio.parentElement.querySelectorAll("[role=radio]").forEach(function(b) {
        b.tabIndex = b.getAttribute("aria-checked") === "true" ? 0 : -1;
      });
    }
  });

  if (changed && top && (!top.contains || !top.contains(document.activeElement))) {
    var first = top.querySelector("#cCancel,#rCancel,button:not(:disabled),[tabindex='0']");
    if (first || top) (first || top).focus({ preventScroll: true });
  }
  if (!top && (modalFocus || modalReturn)) returnFocus();
}

if (typeof MutationObserver === "function") {
  var modalObserver = new MutationObserver(function() { updateModals(); });
  [drawer, sheet, legend, $("dialog")].forEach(function(el) {
    modalObserver.observe(el, { childList: true, attributes: true, attributeFilter: ["class"] });
  });
}

document.addEventListener("click", function(e) {
  if (e.target && e.target.closest && e.target.closest(".fhead")) {
    tock();
    setTimeout(updateModals, 0);
  }
}, true);

document.addEventListener("keydown", function(e) {
  var dlg = $("dialog");
  var top = dlg.classList.contains("show") ? dlg : (legend.classList.contains("show") ? legend : (overlay === "sheet" ? sheet : (drawerOpen ? drawer : null)));
  if ((e.key === "Escape" || (e.key === "Backspace" && !(e.target && e.target.matches && e.target.matches("input,textarea,[contenteditable]")))) && top) {
    e.preventDefault();
    e.stopImmediatePropagation();
    if (top === dlg && S.recyclingRequest != null) return;
    if (top === drawer && dState.detailKey) {
      if (dState.directoryFile) closeDrawer();
      else backToList();
      return;
    }
    if (e.key === "Backspace") return;
    if (top === legend || top === dlg) {
      if (top === dlg) { cleanSummaryRequest++; closeDialogModal(); return; }
      top.classList.remove("show");
    } else if (top === sheet) closeSheet();
    else closeDrawer();
    updateModals();
    return;
  }
  if (e.key === "Tab" && top) {
    var f = Array.from(top.querySelectorAll("button:not(:disabled),input:not(:disabled),summary,[tabindex='0']")).filter(function(x) {
      return !(x.closest && x.closest("[inert],[hidden]")) && (!x.getClientRects || x.getClientRects().length);
    });
    e.preventDefault();
    e.stopImmediatePropagation();
    if (f.length) {
      var i = f.indexOf(document.activeElement);
      var nextEl = f[(i + (e.shiftKey ? -1 : 1) + f.length) % f.length];
      nextEl.focus({ preventScroll: true });
      var scroller = nextEl.closest && nextEl.closest(".clean-list,.flist,.dv,.rows,.coverage-body");
      if (scroller) {
        var anchor = (nextEl.closest && nextEl.closest(".clean-group")) || nextEl;
        if (typeof anchor.scrollIntoView === "function") anchor.scrollIntoView({ block: "nearest" });
      }
    } else {
      top.focus();
    }
  }
  var a = e.target;
  if (a && a.getAttribute && ["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown", "Home", "End"].indexOf(e.key) >= 0 && (a.getAttribute("role") === "tab" || a.getAttribute("role") === "radio")) {
    var items = Array.from(a.parentElement.querySelectorAll("[role=" + a.getAttribute("role") + "]"));
    var n = items.indexOf(a), d = (e.key === "ArrowLeft" || e.key === "ArrowUp") ? -1 : 1;
    n = e.key === "Home" ? 0 : (e.key === "End" ? items.length - 1 : (n + d + items.length) % items.length);
    e.preventDefault();
    items[n].focus({ preventScroll: true });
    items[n].click();
    setTimeout(function() {
      var role = a.getAttribute("role"), attribute = role === "tab" ? "data-f" : "data-i", value = items[n].getAttribute(attribute);
      var live = top && value != null && safeQuery(top, '[' + attribute + '="' + cssAttrVal(value) + '"]');
      if (live) live.focus({ preventScroll: true });
    }, 0);
  }
}, true);

// 切走窗口不应截断扫描结束通知；关闭声音、停止/新扫描仍由会话逻辑取消。
window.addEventListener("blur", function() { hideTip(); });

/* ================= fit / responsive ================= */
function fit() {
  document.documentElement.style.setProperty("--ts", String(textScale()));
  if (document.body.classList.contains("desktop-native")) {
    var st = $("stage");
    st.style.transform = "";
    st.style.margin = "";
    st.style.width = "100%";
    st.style.height = "100%";
    document.body.classList.toggle("compact", window.innerWidth < 720);
    requestAnimationFrame(function() { layoutMax(); renderBars(true); });
    return;
  }
  var compact = window.innerWidth < 720;
  document.body.classList.toggle("compact", compact);
  var stEl = $("stage");
  if (compact) {
    stEl.style.transform = "";
    stEl.style.margin = "";
  } else {
    var avW = window.innerWidth - 32, avH = window.innerHeight - 32;
    var s = Math.min(1, avW / 960, avH / 640) * S.zoom;
    stEl.style.transform = "scale(" + s + ")";
    var dw = 960 * (s - 1) / 2, dh = 640 * (s - 1) / 2;
    stEl.style.margin = dh + "px " + dw + "px";
  }
  requestAnimationFrame(function() { layoutMax(); renderBars(true); });
}
window.addEventListener("resize", fit);
$("win").addEventListener("scroll", function() { this.scrollLeft = 0; this.scrollTop = 0; });
if (motionQuery && motionQuery.matches) RM = true;

/* ================= directory & large files views (observed files only) ================= */
var directoryState = { request: 0, page: null, loading: false };
var largeFilesState = { request: 0, page: null, loading: false, filterMode: "independent", excludeCacheShards: true };

function currentLargeFilesMode() {
  if (largeFilesState.filterMode === "chat") return "chat";
  if (largeFilesState.filterMode === "all" || largeFilesState.excludeCacheShards === false) return "all";
  return "independent";
}

function syncLargeFilesMode() {
  var mode = currentLargeFilesMode();
  var bIndep = $("lfModeIndep"), bChat = $("lfModeChat"), bAll = $("lfModeAll");
  if (bIndep) {
    bIndep.classList.toggle("on", mode === "independent");
    bIndep.setAttribute("aria-pressed", String(mode === "independent"));
  }
  if (bChat) {
    bChat.classList.toggle("on", mode === "chat");
    bChat.setAttribute("aria-pressed", String(mode === "chat"));
    var chatCnt = (largeFilesState.page && typeof largeFilesState.page.chatFileCount === "number") ? largeFilesState.page.chatFileCount : 0;
    // pi-lens-ignore: no-inner-html-js
    bChat.innerHTML = chatCnt > 0 ? ('聊天接收文件<span class="lf-badge">' + fmtCount(chatCnt) + "</span>") : "聊天接收文件";
  }
  if (bAll) {
    bAll.classList.toggle("on", mode === "all");
    bAll.setAttribute("aria-pressed", String(mode === "all"));
  }
  var src = $("largeFilesSource");
  if (src) {
    // pi-lens-ignore: no-inner-html-js
    src.innerHTML = mode === "chat"
      ? "<span>仅列出微信、企业微信与 QQ 聊天接收保存的文档、视频与压缩包原件（不含朋友圈纯缓存与聊天记录数据库）。</span>"
      : (mode === "independent"
        ? "<span>默认已过滤浏览器、桌面软件与开发工具的内部零碎缓存块；点击文件可查看用途、所在位置或单独处理。</span>"
        : "<span>当前包含浏览器、桌面软件与工具的内部缓存块文件；符合规则的缓存可在「分类概况」点「清理」一键清理。</span>");
  }
}

function setLargeFilesMode(modeOrExclude) {
  if (modeOrExclude === "chat") {
    largeFilesState.filterMode = "chat";
    largeFilesState.excludeCacheShards = true;
  } else if (modeOrExclude === "all" || modeOrExclude === false) {
    largeFilesState.filterMode = "all";
    largeFilesState.excludeCacheShards = false;
  } else {
    largeFilesState.filterMode = "independent";
    largeFilesState.excludeCacheShards = true;
  }
  syncLargeFilesMode();
  if (currentScanSession != null) loadLargeFiles();
  else if (largeFilesState.page) renderLargeFiles();
}

function closeDirMenu() {
  var m = $("directoryMoreMenu"), b = $("directoryMoreBtn");
  if (m) m.hidden = true;
  if (b) b.setAttribute("aria-expanded", "false");
}
function switchMainView(view) {
  closeDirMenu();
  S.view = view || "categories";
  var isCat = S.view === "categories", isDir = S.view === "directories", isLarge = S.view === "largeFiles";
  $("directoryPanel").hidden = !isDir;
  $("largeFilesPanel").hidden = !isLarge;
  ["chart", "barlist", "readout", "caption", "summary", "skipline", "track", "ptext"].forEach(function(id) {
    var el = id === "readout" ? document.querySelector(".readout") : $(id);
    if (el) el.hidden = !isCat;
  });
  $("viewCategories").setAttribute("aria-pressed", String(isCat));
  $("viewDirectories").setAttribute("aria-pressed", String(isDir));
  $("viewLargeFiles").setAttribute("aria-pressed", String(isLarge));
  if (isCat) {
    if (typeof requestAnimationFrame === "function") requestAnimationFrame(function() { layoutMax(); renderBars(true); });
  } else if (isDir && currentScanSession != null) {
    loadDirectory(0, 0);
  } else if (isLarge && currentScanSession != null) {
    loadLargeFiles();
  }
}
function showDirectoryView(on) { switchMainView(on ? "directories" : "categories"); }

function loadDirectory(id, offset) {
  if (S.cleaning || currentScanSession == null || !nativeDetail()) return;
  closeDirMenu();
  directoryState.loading = true;
  directoryState.request++;
  $("directoryRows").inert = true;
  $("directoryRows").setAttribute("aria-busy", "true");
  $("directoryStatus").textContent = "正在读取已分析结果…";
  window.chrome.webview.postMessage(JSON.stringify({
    action: "directoriesPage",
    request: directoryState.request,
    scanSessionId: currentScanSession,
    directoryId: id,
    offset: offset || 0
  }));
}
function receiveDirectory(msg) {
  if (S.view !== "directories" || msg.request !== directoryState.request || msg.scanSessionId !== currentScanSession) return;
  directoryState.loading = false;
  $("directoryRows").inert = false;
  $("directoryRows").setAttribute("aria-busy", "false");
  if (msg.error) { $("directoryStatus").textContent = msg.error; return; }
  directoryState.page = msg;
  renderDirectory();
}
function renderDirectory() {
  var p = directoryState.page;
  if (!p) return;
  $("directoryTitle").textContent = p.currentName;
  $("directoryPath").textContent = p.currentPath;
  $("directoryStatus").textContent = (p.partial ? "部分结果 · " : "") + fs(p.totalBytes / 1073741824) + " · " + fmtCount(p.totalFileCount) + " 个已分析文件";
  // pi-lens-ignore: no-inner-html-js
  $("directorySource").innerHTML = "<span>" + esc(p.source) + '</span><span class="dir-leg-items" aria-label="图例"><span class="dir-leg-item"><i class="dir-sw ok" aria-hidden="true"></i>符合清理规则</span><span class="dir-leg-item"><i class="dir-sw review" aria-hidden="true"></i>需复核</span><span class="dir-leg-item"><i class="dir-sw keep" aria-hidden="true"></i>建议保留</span></span>';
  $("directoryCrumbs").title = p.currentPath || "";
  var crumbs = Array.isArray(p.breadcrumb) ? p.breadcrumb : [];
  var dirId = safeInt(p.directoryId);
  // pi-lens-ignore: no-inner-html-js
  $("directoryCrumbs").innerHTML = crumbs.map(function(b) {
    var bid = safeInt(b.id);
    return '<button class="tlink" type="button" data-dir="' + bid + '"' + (bid === dirId ? ' aria-current="location"' : "") + ' title="' + esc(b.path || b.name) + '">' + esc(b.name) + "</button>";
  }).join('<span aria-hidden="true"> › </span>');
  var dirRows = Array.isArray(p.rows) ? p.rows : [];
  if ($("directoryHead")) $("directoryHead").hidden = !dirRows.length;
  // pi-lens-ignore: no-inner-html-js
  $("directoryRows").innerHTML = dirRows.map(function(r, i) {
    var pct = p.totalBytes ? 100 * (Number(r.bytes) || 0) / p.totalBytes : 0;
    var eb = typeof r.eligibleBytes === "number" ? Math.max(0, r.eligibleBytes) : 0;
    var rb = typeof r.reviewBytes === "number" ? Math.max(0, r.reviewBytes) : 0;
    var kb = typeof r.keepBytes === "number" ? Math.max(0, r.keepBytes) : 0;
    var btot = eb + rb + kb;
    var ep = btot > 0 ? Math.min(100, Math.max(0, eb / btot * 100)) : 0;
    var rp = btot > 0 ? Math.min(100, Math.max(0, rb / btot * 100)) : 0;
    var kp = btot > 0 ? Math.min(100, Math.max(0, 100 - ep - rp)) : 0;
    var barAria = (eb > 0 ? "符合清理规则 " + fs(eb / 1073741824) + " " : "") +
      (rb > 0 ? "需复核 " + fs(rb / 1073741824) + " " : "") +
      (kb > 0 ? "建议保留 " + fs(kb / 1073741824) : "");
    return '<div class="directory-row"><button class="directory-name" type="button" data-row="' + i + '" aria-label="' + esc(r.name + (r.isDirectory ? "，进入目录" : "，查看文件")) + '"><span class="' + (r.isDirectory ? "fi-dir" : "fi-file") + '" aria-hidden="true"></span><span>' + esc(r.name) + '</span></button><span class="directory-size">' + (r.sizeComplete ? "" : "≥ ") + esc(fs((Number(r.bytes) || 0) / 1073741824)) + '<span class="pct">· ' + pct.toFixed(1) + '%</span></span><span class="directory-count">' + esc(fmtCount(safeInt(r.fileCount))) + ' 个</span><span class="dir-bars" role="img" aria-label="' + esc(barAria.trim() || "0 B") + '"><i class="ok" data-w="' + ep.toFixed(2) + '"></i><i class="review" data-w="' + rp.toFixed(2) + '"></i><i class="keep" data-w="' + kp.toFixed(2) + '"></i></span></div>';
  }).join("") || '<p class="sub dir-empty">这里没有符合清理规则的文件；未进入的目录和空目录不在此列。</p>';
  $("directoryRows").querySelectorAll(".dir-bars i[data-w]").forEach(function(barSeg) {
    barSeg.style.width = barSeg.dataset.w + "%";
  });
  $("directoryPrev").disabled = p.pageOffset === 0;
  $("directoryNext").disabled = p.pageOffset + p.pageLimit >= p.totalRows;
  $("directoryPage").textContent = p.totalRows ? (p.pageOffset + 1) + "–" + Math.min(p.totalRows, p.pageOffset + p.pageLimit) + " / " + p.totalRows : "0 / 0";
  $("directoryUp").disabled = !p.parent;
  $("directoryUp").onclick = function() { if (p.parent) loadDirectory(p.parent.id, 0); };
  $("directoryRefresh").disabled = !!S.cleaning;
  $("directoryRefresh").onclick = function() { closeDirMenu(); loadDirectory(p.directoryId, p.pageOffset); };
  $("directoryCrumbs").querySelectorAll("[data-dir]").forEach(function(b) { b.onclick = function() { loadDirectory(+b.dataset.dir, 0); }; });
  $("directoryRows").querySelectorAll("[data-row]").forEach(function(b) {
    b.onclick = function() {
      var r = p.rows[+b.dataset.row];
      if (r.isDirectory) loadDirectory(r.id, 0);
      else if (r.file) openDirectoryFile(r.file, "‹ 返回目录");
    };
  });
  $("directoryPrev").onclick = function() { loadDirectory(p.directoryId, p.pageOffset - p.pageLimit); };
  $("directoryNext").onclick = function() { loadDirectory(p.directoryId, p.pageOffset + p.pageLimit); };
}

function loadLargeFiles() {
  if (S.cleaning || currentScanSession == null || !nativeDetail()) return;
  var mode = currentLargeFilesMode();
  syncLargeFilesMode();
  largeFilesState.loading = true;
  var req = ++largeFilesState.request;
  $("largeFilesRows").inert = true;
  $("largeFilesRows").setAttribute("aria-busy", "true");
  $("largeFilesStatus").textContent = "正在读取已分析结果…";
  window.chrome.webview.postMessage(JSON.stringify({
    action: "largeFiles",
    request: req,
    scanSessionId: currentScanSession,
    limit: 100,
    filterMode: mode,
    excludeCacheShards: mode !== "all"
  }));
}
function receiveLargeFiles(msg) {
  if (S.view !== "largeFiles" || msg.request !== largeFilesState.request || msg.scanSessionId !== currentScanSession) return;
  largeFilesState.loading = false;
  $("largeFilesRows").inert = false;
  $("largeFilesRows").setAttribute("aria-busy", "false");
  if (msg.error) { $("largeFilesStatus").textContent = msg.error; return; }
  largeFilesState.page = msg;
  renderLargeFiles();
}
function renderLargeFiles() {
  var p = largeFilesState.page;
  if (!p) return;
  syncLargeFilesMode();
  var mode = (typeof p.filterMode === "string" && (p.filterMode === "independent" || p.filterMode === "chat" || p.filterMode === "all"))
    ? p.filterMode
    : (typeof p.excludeCacheShards === "boolean" ? (p.excludeCacheShards ? currentLargeFilesMode() : "all") : currentLargeFilesMode());
  var indep = mode === "independent";
  var isChat = mode === "chat";
  var files = (p.files || []).map(function(f) { f.x = f.x || {}; return f; });
  var totFiles = typeof p.totalFiles === "number" ? p.totalFiles : files.length;
  var indepCount = typeof p.independentCount === "number" ? p.independentCount : totFiles;
  var chatCount = typeof p.chatFileCount === "number" ? p.chatFileCount : (isChat ? totFiles : 0);
  var allCount = typeof p.allFileCount === "number" ? p.allFileCount : Math.max(totFiles, S.fileCount || 0);
  var totBytes = typeof p.totalBytes === "number" ? p.totalBytes : 0;
  var chatBytes = typeof p.chatFileBytes === "number" ? p.chatFileBytes : totBytes;
  $("largeFilesTitle").textContent = rootLabel();
  if (isChat) {
    $("largeFilesStatus").textContent = (p.partial ? "部分结果 · " : "") +
      (files.length
        ? ("前 " + fmtCount(files.length) + " 个聊天接收文件 · 共 " + fmtCount(chatCount) + " 个聊天原件（" + fs(chatBytes / 1073741824) + "）")
        : ("0 个聊天接收文件 · 本次已分析 " + fmtCount(allCount) + " 个文件"));
  } else if (indep) {
    $("largeFilesStatus").textContent = (p.partial ? "部分结果 · " : "") +
      (files.length
        ? ("前 " + fmtCount(files.length) + " 个独立大文件 · 共 " + fmtCount(indepCount) + " 个非缓存文件" + (allCount > indepCount ? "（已隐藏 " + fmtCount(allCount - indepCount) + " 个内部缓存碎片）" : "（" + fs(totBytes / 1073741824) + "）") + (chatCount > 0 ? " · 含 " + fmtCount(chatCount) + " 个聊天接收文件" : ""))
        : ("0 个独立大文件 · 本次已分析 " + fmtCount(allCount) + " 个文件"));
  } else {
    $("largeFilesStatus").textContent = (p.partial ? "部分结果 · " : "") + "前 " + fmtCount(files.length) + " 个最大文件（含缓存内部文件） · 共已分析 " + fmtCount(allCount) + " 个文件（" + fs(totBytes / 1073741824) + "）";
  }
  if ($("largeFilesHead")) $("largeFilesHead").hidden = !files.length;
  var modePoolCount = isChat ? chatCount : (indep ? indepCount : allCount);
  $("largeFilesPage").textContent = files.length ? ("显示前 " + fmtCount(files.length) + " 项 / 共 " + fmtCount(modePoolCount) + " 个文件") : "0 项";

  if (files.length) {
    // pi-lens-ignore: no-inner-html-js
    $("largeFilesRows").innerHTML = files.map(function(f, i) {
      var detail = fileInfo(f);
      var subLine = fileSubLine(detail, false);
      return '<button type="button" class="directory-row large-file-row" data-lf="' + i + '" aria-label="' + esc(f.n + "，" + subLine + "，" + judgeLabel(f.j) + "，" + fs(f.s) + "，查看文件详情") + '">' +
        '<span class="lf-name"><span class="fi-file" aria-hidden="true"></span><span class="lf-name-body"><span class="lf-fn">' + esc(f.n) + '</span><span class="lf-sub" title="' + esc(subLine) + '">' + esc(subLine) + '</span></span></span>' +
        '<span class="lf-judge' + (f.j === "keep" ? " keep" : "") + '"><span class="g">' + esc(judgeGlyph(f.j)) + "</span> " + esc(judgeLabel(f.j)) + "</span>" +
        '<span class="lf-loc" title="' + esc(f.p) + '">' + esc(midDir(f.p)) + "</span>" +
        '<span class="directory-size">' + (f.x.sizeComplete === false ? "≥ " : "") + esc(fs(f.s)) + "</span></button>";
    }).join("");
  } else if (isChat) {
    // pi-lens-ignore: no-inner-html-js
    $("largeFilesRows").innerHTML = '<div class="lf-empty">' +
      '<p class="lf-empty-lead">本次扫描范围没有发现微信、企业微信或 QQ 的聊天接收文件。常规快扫只读取纯缓存子目录，可打开「选择位置 → 微信 / QQ 存储专向扫描」定位聊天大文件。</p>' +
      '<div class="lf-empty-acts">' +
      '<button type="button" class="sbtn" id="lfPickChatBtn">选择位置（微信 / QQ 专向扫描）</button>' +
      '<button type="button" class="sbtn" id="lfScanChatNowBtn">直接扫描微信 / QQ 存储</button>' +
      "</div></div>";
  } else if (indep) {
    var hasAnyCache = allCount > 0 || CATS.length > 0;
    // pi-lens-ignore: no-inner-html-js
    $("largeFilesRows").innerHTML = '<div class="lf-empty">' +
      '<p class="lf-empty-lead">' + (hasAnyCache
        ? "本次扫描的都是缓存目录，缓存碎片已归入「分类概况」（点右下角「清理」即可按组一键清理）。"
        : "本次扫描位置没有发现独立大文件。") + "</p>" +
      '<div class="lf-empty-acts">' +
      (hasAnyCache ? '<button type="button" class="sbtn" id="lfShowCacheBtn">查看缓存内部大文件</button>' : "") +
      '<button type="button" class="sbtn" id="lfPickDiskBtn">扫描磁盘或文件夹查找独立大文件</button>' +
      "</div></div>";
  } else {
    // pi-lens-ignore: no-inner-html-js
    $("largeFilesRows").innerHTML = '<p class="sub dir-empty">这里没有已分析的文件。</p>';
  }

  $("largeFilesRows").querySelectorAll("[data-lf]").forEach(function(b) {
    b.onclick = function() {
      var f = files[+b.dataset.lf];
      if (f) openDirectoryFile(f, "‹ 返回大文件");
    };
  });
  if ($("lfShowCacheBtn")) $("lfShowCacheBtn").onclick = function() { setLargeFilesMode(false); };
  if ($("lfPickDiskBtn")) $("lfPickDiskBtn").onclick = function() { openPicker(); };
  if ($("lfPickChatBtn")) $("lfPickChatBtn").onclick = function() { openPicker("chat"); };
  if ($("lfScanChatNowBtn")) $("lfScanChatNowBtn").onclick = function() { switchMainView("categories"); startChatScan(); };
}

function openDirectoryFile(file, backLabel) {
  lastFocus = document.activeElement;
  file.x = file.x || {};
  dState = {
    directoryFile: true,
    backLabel: backLabel || "‹ 返回目录",
    g: null,
    filter: "all",
    sort: "size",
    open: Object.create(null),
    page: { files: [file], offset: 0, total: 1 }
  };
  drawerOpen = true;
  overlay = "drawer";
  drSp.to(0);
  scrim.classList.add("show");
  openDetail(keyOf(file));
  updateModals();
}

if ($("viewCategories")) $("viewCategories").onclick = function() { switchMainView("categories"); };
if ($("viewDirectories")) $("viewDirectories").onclick = function() { switchMainView("directories"); };
if ($("viewLargeFiles")) $("viewLargeFiles").onclick = function() { syncLargeFilesMode(); switchMainView("largeFiles"); };
if ($("lfModeIndep")) $("lfModeIndep").onclick = function() { setLargeFilesMode("independent"); };
if ($("lfModeChat")) $("lfModeChat").onclick = function() { setLargeFilesMode("chat"); };
if ($("lfModeAll")) $("lfModeAll").onclick = function() { setLargeFilesMode("all"); };
if ($("directoryMoreBtn")) {
  $("directoryMoreBtn").onclick = function(e) {
    e.stopPropagation();
    var m = $("directoryMoreMenu");
    if (!m) return;
    var open = m.hidden;
    m.hidden = !open;
    this.setAttribute("aria-expanded", String(open));
  };
  document.addEventListener("click", function(e) {
    if (!e.target || !e.target.closest || !e.target.closest(".dir-more-wrap")) closeDirMenu();
  });
}

/* ================= category adoption (shared with bridge & recycle) ================= */
function adoptCategories(list) {
  CATS = Array.isArray(list) ? list : [];
  if (CATS.length === 0) {
    S.found = Object.create(null); S.moved = Object.create(null); S.failed = Object.create(null); S.selected = Object.create(null);
  }
  CATS.forEach(function(c) {
    S.found[c.id] = 1;
    if (!hasOwn(S.moved, c.id)) S.moved[c.id] = 0;
    if (!hasOwn(S.failed, c.id)) S.failed[c.id] = 0;
    if (!hasOwn(S.selected, c.id)) S.selected[c.id] = c.ok > 0;
    c.files = (c.files || []).map(function(f) { f.x = f.x || {}; return f; });
  });
  var positions = slots.filter(function(sl) { return sl.g; }).map(function(sl) {
    return { id: sl.g.id, x: sl.el.getBoundingClientRect().left, v: sl.shift.v };
  });
  GROUPS = groups();
  var same = slots.length === 5 && slots.every(function(sl, i) {
    var g = GROUPS[i];
    return (!sl.g && !g) || (sl.g && g && sl.g.id === g.id && sl.g.cats.map(function(c) { return c.id; }).join("|") === g.cats.map(function(c) { return c.id; }).join("|"));
  });
  if (same) {
    slots.forEach(function(sl, i) { sl.g = GROUPS[i]; });
  } else {
    var old = slots.slice();
    slots = [];
    buildSlots();
    GROUPS.forEach(function(g, i) {
      var previous = old.find(function(sl) { return sl.g && sl.g.id === g.id; });
      if (!previous) return;
      var fresh = slots[i];
      [fresh.h, fresh.lift, fresh.shift].concat(fresh.mix).forEach(function(s) {
        var k = springs.indexOf(s);
        if (k >= 0) springs.splice(k, 1);
      });
      chart.replaceChild(previous.el, fresh.el);
      previous.g = g;
      previous.i = i;
      previous.block.dataset.id = i;
      slots[i] = previous;
    });
    old.forEach(function(sl) {
      if (slots.indexOf(sl) >= 0) return;
      [sl.h, sl.lift, sl.shift].concat(sl.mix).forEach(function(s) {
        var k = springs.indexOf(s);
        if (k >= 0) springs.splice(k, 1);
      });
    });
    slots.forEach(function(sl) {
      sl.el.className = sl.g ? "slot" : (CATS.length ? "slot hide" : "slot slotEmpty");
      sl.shift.to(0, true);
    });
    layoutMax();
    var scale = chart.offsetWidth ? chart.getBoundingClientRect().width / chart.offsetWidth : 1;
    slots.forEach(function(sl) {
      if (!sl.g) return;
      var p = positions.find(function(pos) { return pos.id === sl.g.id; });
      if (p) {
        sl.shift.to((p.x - sl.el.getBoundingClientRect().left) / scale, true);
        if (!RM) sl.shift.v = p.v;
        sl.shift.to(0);
      }
    });
  }
}

/* Delegated file actions in detail drawer */
document.addEventListener("click", function(e) {
  if (!e.target || !e.target.closest) return;
  var btn = e.target.closest("button[data-a]");
  if (!btn) return;
  var fileRow = btn.closest(".file");
  if (!fileRow) return;
  e.stopPropagation();
  e.preventDefault();
  var act = btn.dataset.a;
  var file = findFile(fileRow.dataset.k);
  if (!file || file.id == null) return;
  if (act === "copy") {
    copyPath(fileRow, btn);
  } else if (act === "reveal") {
    if (nativeDetail()) window.chrome.webview.postMessage(JSON.stringify({ action: "revealFile", id: file.id }));
  } else if (act === "recycle") {
    openRecycleConfirm(file);
  }
}, true);

render(true);
fit();

/* ================= C# Native Bridge Integration ================= */
(function initNativeBridge() {
  if (!nativeDetail()) {
    console.log("Running in standard browser mode");
    return;
  }

  console.log("Running in C# WebView2 Native Host");
  document.body.classList.add("desktop-native");
  S.mode = "readonly";

  var btnMin = $("wMin"), btnMax = $("wMax"), btnClose = $("wClose");
  if (btnMin) btnMin.onclick = function() { window.chrome.webview.postMessage(JSON.stringify({ action: "window", op: "min" })); };
  if (btnMax) btnMax.onclick = function() { window.chrome.webview.postMessage(JSON.stringify({ action: "window", op: "max" })); };
  if (btnClose) btnClose.onclick = function() { window.chrome.webview.postMessage(JSON.stringify({ action: "window", op: "close" })); };

  var tb = document.querySelector(".titlebar");
  if (tb) {
    tb.addEventListener("mousedown", function(e) {
      if (e.target.closest("button") || e.target.closest(".tag")) return;
      window.chrome.webview.postMessage(JSON.stringify({ action: "drag" }));
    });
  }

  window.chrome.webview.addEventListener("message", function(event) {
    var msg = event && event.data;
    if (typeof msg === "string") {
      try { msg = JSON.parse(msg); } catch (e) { return; }
    }
    if (!msg || typeof msg !== "object" || Array.isArray(msg) || typeof msg.action !== "string" || !msg.action) return;

    if (msg.action === "scanStarted") {
      if (typeof msg.scanSessionId !== "number" || !Number.isFinite(msg.scanSessionId)) return;
      currentScanSession = msg.scanSessionId;
      audio.beginSession(currentScanSession);
    } else if (/^scan(Progress|Complete|Paused|Stopping|Continued)$/.test(msg.action)) {
      if (typeof msg.scanSessionId !== "number" || msg.scanSessionId !== currentScanSession) return;
    }

    switch (msg.action) {
      case "initState":
        if (msg.appName) {
          var appEl = document.querySelector(".appname");
          if (appEl) appEl.textContent = msg.appName;
        }
        var tagEl = document.querySelector(".tag");
        if (tagEl) {
          tagEl.textContent = "缓存清理";
          tagEl.title = "批量清理只会永久删除内容已校验的缓存；单文件可在详情页手动移入回收站";
        }
        applyAdminState(msg);
        if (S.state === "first" || (S.state === "picking" && !S.hasResult) || !(S.driveTotalBytes > 0)) {
          applyDriveInfo(msg);
        }
        S.chatFolderCount = msg.chatFolderCount || 0;
        if (S.state === "first" || (S.state === "picking" && !S.hasResult)) render(true);
        break;

      case "relaunchAdminResult":
        S.elevating = false;
        if (msg.ok) break;
        var uacText = msg.cancelled
          ? "已取消管理员授权，继续在普通模式下使用"
          : (msg.error || "未能切换至管理员模式，继续在普通模式下使用");
        toast(uacText);
        $("a11yStatus").textContent = uacText;
        break;

      case "drivesList":
        nativeDrives = Array.isArray(msg.drives) ? msg.drives : [];
        nativeChatFolders = Array.isArray(msg.chatFolders) ? msg.chatFolders : [];
        if (REFRESH_PICKER && overlay === "sheet") REFRESH_PICKER();
        break;

      case "folderAdded":
        if (msg.folder && typeof msg.folder === "object" && !Array.isArray(msg.folder)) {
          nativeDrives.forEach(function(d) { d.selected = false; });
          msg.folder.selected = true;
          nativeDrives.push(msg.folder);
          pickerMode = "drive";
          if (REFRESH_PICKER && overlay === "sheet") REFRESH_PICKER();
        }
        break;

      case "systemPreferences":
        nativeReduce = !!msg.reduceMotion;
        nativeContrast = !!msg.highContrast;
        if (typeof msg.textScale === "number") {
          nativeTextScale = Math.max(1, Math.min(2.25, msg.textScale));
          fit();
        }
        syncSystemPreferences();
        break;

      case "windowState":
        document.body.classList.toggle("maximized", !!msg.maximized);
        $("wMax").setAttribute("aria-label", msg.maximized ? "还原" : "最大化");
        $("wMax").setAttribute("aria-pressed", String(!!msg.maximized));
        break;

      case "reviewGroups":
        if (drawerOpen && dState && dState.groupsMode && msg.request === filesRequest) {
          dState.groupReply = msg;
          drawReviewGroups(msg);
        }
        break;

      case "snapshotReady":
        if (drawerOpen && dState && dState.waitSnapshot && msg.request === filesRequest) {
          dState.waitSnapshot = false;
          dState.snapshot = msg.snapshot;
          dState.snapshotCount = msg.count;
          dState.snapshotCats = (msg.categories || []).map(function(c) { return Object.assign({}, c, { files: [] }); });
          loadDrawerPage(0);
        }
        break;

      case "filesPage":
        if (!drawerOpen || !dState || msg.request !== filesRequest || msg.request !== dState.request) break;
        dState.loading = false;
        if (msg.error) {
          dState.error = msg.error;
          toast(msg.error);
          drawRender();
          break;
        }
        if (msg.offset > 0 && msg.total > 0 && (!msg.files || msg.files.length === 0)) {
          loadDrawerPage(Math.max(0, msg.offset - (msg.limit || 100)));
          break;
        }
        dState.page = msg;
        drawRender();
        break;

      case "cleanSummary":
        receiveCleanSummary(msg);
        break;

      case "directoriesPage":
        receiveDirectory(msg);
        break;

      case "largeFilesPage":
        receiveLargeFiles(msg);
        break;

      case "fileTechResult":
        applyFileTech(msg);
        break;

      case "recycleSingleResult":
        receiveRecycleSingleResult(msg);
        break;

      case "fileActionResult":
        if (!msg.success) { toast(msg.error || "文件操作失败"); break; }
        if (msg.op === "copy") {
          var copyBtn = safeQuery(drawer, '[data-k="id|' + cssAttrVal(msg.id) + '"] [data-a="copy"]');
          if (copyBtn) {
            copyBtn.textContent = "已复制完整路径";
            setTimeout(function() { copyBtn.textContent = "复制路径"; }, 1500);
          }
        }
        break;

      case "scanContinued":
        audio.beginSession(currentScanSession);
        closeDrawer();
        closeSheet();
        S.state = "scanning";
        S.stopping = false;
        S.limited = false;
        render();
        break;

      case "scanStarted":
        directoryState.page = null; directoryState.request++; directoryState.loading = false;
        cleanSummaryRequest++; cleanList = null;
        S.recyclingRequest = null; S.recyclingId = null; S.recyclingName = "";
        if ($("directoryHead")) $("directoryHead").hidden = true;
        $("directoryRows").inert = false; $("directoryRows").textContent = "";
        $("directoryTitle").textContent = "正在扫描";
        $("directoryStatus").textContent = "部分结果 · 尚无已分析文件";
        $("directoryCrumbs").textContent = "";
        $("directoryPath").textContent = msg.target || "";

        largeFilesState.page = null; largeFilesState.request++; largeFilesState.loading = false;
        largeFilesState.filterMode = "independent";
        largeFilesState.excludeCacheShards = true;
        syncLargeFilesMode();
        if ($("largeFilesHead")) $("largeFilesHead").hidden = true;
        $("largeFilesRows").inert = false; $("largeFilesRows").textContent = "";
        $("largeFilesTitle").textContent = "正在扫描";
        $("largeFilesStatus").textContent = "部分结果 · 尚无已分析文件";
        $("largeFilesPage").textContent = "0 项";

        closeDrawer();
        if ($("dialog").classList.contains("show")) closeDialogModal();
        S.rejection = "";
        S.completionNotified = false;
        reviewMarks = Object.create(null);
        S.state = "scanning";
        S.scanRoot = msg.target || "选择的位置";
        if (msg.chat === true || /^微信\s*\/\s*QQ/.test(S.scanRoot)) S.lastScanMode = "chat";
        else if (msg.quick === true || /^常见缓存位置/.test(S.scanRoot)) S.lastScanMode = "quick";
        else S.lastScanMode = "targets";
        S.hasResult = false;
        S.skipped = [];
        S.checked = 0;
        S.lockedCacheBytes = 0;
        S.driveLabel = "";
        S.driveFreeBytes = 0;
        S.driveTotalBytes = 0;
        applyDriveInfo(msg);
        applyAdminState(msg);
        S.incomplete = false;
        S.analysisWarning = false;
        S.failedItems = 0;
        S.endKind = null;
        S.coverage = null;
        S.fileCount = 0;
        S.canContinue = false;
        S.limited = false;
        S.scanError = "";
        S.stopping = false;
        S.phase = "idle";
        S.freedNote = null;
        S.cleanBand = null;
        S.cleanMaxT = 0;
        S.cleanByCat = null;
        S.cleanDetail = null;
        S.capOverride = S.suffix = null;
        adoptCategories([]);
        render();
        break;

      case "scanRejected":
        S.rejection = msg.error || "无法启动扫描";
        if (msg.continueBlocked) { S.canContinue = false; S.resumeBlocked = S.rejection; }
        render();
        toast(S.rejection);
        break;

      case "scanStopping":
        audio.stopSession();
        S.stopping = true;
        $("caption").textContent = "正在停止扫描，等待已发现的结果交付…";
        var stopBtn = $("stopScan");
        if (stopBtn) { stopBtn.disabled = true; stopBtn.textContent = "正在停止…"; }
        break;

      case "scanProgress":
        if (S.state !== "scanning") S.state = "scanning";
        adoptCategories(msg.categories || []);
        S.checked = msg.analyzed || 0;
        S.fileCount = msg.fileCount || 0;
        S.directoryCount = msg.directoryCount || 0;
        S.coverage = msg.coverage || S.coverage;
        if (typeof msg.lockedCacheBytes === "number") S.lockedCacheBytes = Math.max(0, msg.lockedCacheBytes);
        applyDriveInfo(msg);
        applyAdminState(msg);
        setNum(totals().all);
        $("caption").textContent = S.stopping ? "正在停止扫描，等待已发现的结果交付…" : ("正在分析 " + rootLabel() + "…" + driveSpaceSuffix());
        // pi-lens-ignore: no-inner-html-js
        $("summary").innerHTML = lockedCacheHintHTML();
        $("ptext").textContent = "已检查 " + fmtCount(S.fileCount) + " 个文件 · " + (msg.currentPath || rootLabel());
        $("ptext").title = msg.currentPath || "";
        $("track").className = "track show indet";
        if (chart && !chart.hidden && chart.clientHeight > 0) layoutMax();
        renderBars();
        break;

      case "cleanProgress":
        if (msg.request !== S.cleanRequest) break;
        S.cleanProg = { done: msg.done, total: msg.total };
        if (typeof msg.deleted === "number" || typeof msg.deletedBytes === "number" || msg.currentPath || msg.deletedByCat) {
          S.cleanDetail = { deleted: msg.deleted || 0, deletedBytes: msg.deletedBytes || 0, currentPath: msg.currentPath || "" };
          if (msg.deletedByCat && typeof msg.deletedByCat === "object" && !Array.isArray(msg.deletedByCat)) {
            var byCat = Object.create(null);
            Object.keys(msg.deletedByCat).forEach(function(k) {
              var v = Number(msg.deletedByCat[k]);
              if (Number.isFinite(v) && v >= 0) byCat[k] = v;
            });
            S.cleanByCat = byCat;
          }
        }
        render();
        break;

      case "cleanResult":
        if (msg.request !== S.cleanRequest) break;
        if (msg.scanSessionId != null && currentScanSession != null && msg.scanSessionId !== currentScanSession) break;
        S.cleanRequest = null; S.cleaning = false; S.cleanStopping = false; S.cleanProg = null;
        S.cleanMaxT = 0; S.cleanByCat = null; S.cleanDetail = null;
        if (msg.locked) S.cleanLocked = true;
        if (typeof msg.lockedCacheBytes === "number") S.lockedCacheBytes = Math.max(0, msg.lockedCacheBytes);
        if (msg.error) { S.freedNote = null; S.cleanBand = null; render(); toast(msg.error); break; }
        if (msg.categories) adoptCategories(msg.categories);
        var parts = [], otherParts = [];
        if (msg.untouched) { var uTxt = msg.untouched + " 个未删除（原文件未动）"; parts.push(uTxt); otherParts.push(uTxt); }
        if (msg.stillPresent) { var spTxt = msg.stillPresent + " 个删除失败（核对后仍在原处）"; parts.push(spTxt); otherParts.push(spTxt); }
        if (msg.changed) { var chTxt = msg.changed + " 个已跳过（扫描后已消失或被改动）"; parts.push(chTxt); otherParts.push(chTxt); }
        if (msg.notExecuted) parts.push(msg.notExecuted + " 个" + (msg.stopped ? "因停止" : "因前一项结果不明") + "未执行");
        if (msg.unknown) { var ukTxt = msg.unknown + " 个结果无法确认"; parts.push(ukTxt); otherParts.push(ukTxt); }
        var szSum = fs((msg.freedBytes || 0) / 1073741824);
        S.freedNote = msg.stopped
          ? ("已停止。已永久删除 " + msg.deleted + " 个文件，共 " + szSum + "（文件大小合计）" + (parts.length ? " · " + parts.join(" · ") : ""))
          : (msg.deleted === 0
            ? ("没有删除任何文件" + (parts.length ? "：" + parts.join(" · ") : ""))
            : ("已永久删除 " + msg.deleted + " 个文件，共 " + szSum + "（文件大小合计）" + (parts.length ? " · " + parts.join(" · ") : "")));
        var leadMsg = msg.unknown > 0
          ? ("有 " + msg.unknown + " 个文件的结果无法确认：可能已删除，也可能还在。已停止后续清理。请重新扫描核对后再清理。")
          : (msg.deleted < msg.attempted ? "部分文件未删除或未处理，明细如下。" : "全部已选文件均已永久删除并确认原路径已不存在。");
        S.cleanBand = {
          deleted: msg.deleted,
          freedBytes: msg.freedBytes || 0,
          attempted: msg.attempted,
          notExecuted: msg.notExecuted || 0,
          stopped: !!msg.stopped,
          unknown: msg.unknown || 0,
          subText: parts.join(" · "),
          otherParts: otherParts,
          raw: msg,
          lead: leadMsg
        };
        S.state = CATS.length === 0 ? "empty" : "done";
        render();
        if (S.view === "largeFiles") loadLargeFiles();
        if (msg.unknown > 0) showCleanProblems(msg, leadMsg);
        $("a11yStatus").textContent = S.freedNote;
        break;

      case "pendingClean":
        S.cleanLocked = true;
        render();
        showCleanProblems(
          {
            problems: (Array.isArray(msg.items) ? msg.items : []).map(function(i) {
              var item = i && typeof i === "object" ? i : {};
              return { name: item.name || "", detail: item.exists ? "文件仍在原处" : "文件已不在原处（可能已删除）" };
            })
          },
          "上次清理在 " + safeInt(msg.count) + " 个文件上中断（程序被关闭或崩溃），无法确定这些文件是否已被删除。请重新扫描核对。详细记录：" + (msg.log || ""),
          "上次清理未完成"
        );
        break;

      case "scanPaused":
      case "scanComplete":
        S.freedNote = null; S.cleanBand = null; S.cleaning = false; S.cleanLocked = false;
        S.cleanRequest = null; S.cleanMaxT = 0; S.cleanByCat = null; S.cleanDetail = null;
        S.recyclingRequest = null; S.recyclingId = null; S.recyclingName = "";
        adoptCategories(msg.categories || []);
        S.scanError = msg.error || "";
        S.incomplete = !!msg.incomplete;
        S.analysisWarning = !!msg.analysisWarning;
        S.failedItems = msg.failed || 0;
        S.endKind = msg.endKind;
        S.limited = !!msg.limited;
        S.resumeBlocked = msg.resumeBlocked || "";
        S.canContinue = !!msg.canContinue;
        S.budgetReason = msg.budgetReason || "";
        S.coverage = msg.coverage || S.coverage;
        S.fileCount = msg.fileCount || 0;
        S.directoryCount = msg.directoryCount || 0;
        if (typeof msg.lockedCacheBytes === "number") S.lockedCacheBytes = Math.max(0, msg.lockedCacheBytes);
        applyDriveInfo(msg);
        applyAdminState(msg);
        S.stopping = false;
        S.state = msg.action === "scanPaused" ? "paused" : (S.scanError && CATS.length === 0 ? "failed" : (msg.stopped ? "stopped" : (CATS.length === 0 ? "empty" : "done")));
        S.hasResult = true;
        S.checked = msg.analyzed || 0;
        S.skipped = (msg.inaccessibles || []).map(function(s) { return [String(s), "拒绝访问"]; });
        render();
        if (S.view === "largeFiles") loadLargeFiles();
        if (completionReady(msg)) {
          notifyEnd(msg);
          if (!S.legendSeen) { pendingLegend = true; maybeLegend(); }
        } else {
          audio.stopSession();
        }
        $("a11yStatus").textContent = $("caption").textContent;
        break;
    }
  });

  adoptCategories([]);
  render(true);
  bindControls();

  function notifyInit() {
    try { window.chrome.webview.postMessage(JSON.stringify({ action: "init" })); } catch (e) {}
  }
  if (document.readyState === "complete" || document.readyState === "interactive") {
    notifyInit();
  } else {
    document.addEventListener("DOMContentLoaded", notifyInit);
  }
  setTimeout(notifyInit, 200);
  setTimeout(notifyInit, 600);
})();
