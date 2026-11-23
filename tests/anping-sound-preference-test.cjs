'use strict';
// Actual page sound wiring with storage/DOM stand-ins; native endpoint checks are separate.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..');

const appJs = fs.readFileSync(process.argv[2] || path.join(root, 'ui/app.js'), 'utf8');
const wiring = appJs.slice(appJs.indexOf('/* ================= sound'), appJs.indexOf('/* ================= bounded readonly'));
const blurMatch = appJs.match(/window\.addEventListener\(['"]blur['"],\s*function\(\)\s*\{\s*hideTip\(\);[^\n]*\}\);/);
assert(blurMatch, 'blur listener must exist in app.js');
const blur = blurMatch[0];

function boot(storage) {
  const button = { classList: { toggle() {} }, setAttribute() {}, querySelector() { return { setAttribute() {} }; } };
  const events = {};
  const c = vm.createContext({
    setTimeout,
    clearTimeout,
    performance,
    localStorage: storage,
    chart: { addEventListener() {} },
    S: {},
    $: () => button,
    toast: t => { c.warning = t; },
    hideTip() {},
    document: { addEventListener: (k, f) => { events[k] = f; } },
    window: { addEventListener: (k, f) => { events[k] = f; } }
  });
  vm.runInContext(fs.readFileSync(path.join(root, 'ui/anping-audio.js'), 'utf8'), c);
  c.AnPingAudio = c.window.AnPingAudio;
  vm.runInContext(wiring + '\n' + blur, c);
  return { c, events, button };
}

const saved = new Map();
const storage = { getItem: k => saved.get(k), setItem: (k, v) => saved.set(k, v) };
const first = boot(storage);
assert(!first.c.soundOn && !first.c.audio.enabled, 'first launch defaults off');
first.c.tock = () => true;
first.button.onclick();
assert.equal(saved.get('anping.sound.enabled'), 'true');

const second = boot(storage);
assert(second.c.soundOn && second.c.audio.enabled, 'reopen restores enabled preference');
let stopped = 0;
second.c.audio.nodes.add({ stop() { stopped++; } });
second.events.blur();
assert.equal(stopped, 0, 'blur must not cancel the completion cue');

let unlocked = 0;
second.c.audio.unlock = () => unlocked++;
second.events.pointerdown({ isTrusted: true });
second.events.keydown({ isTrusted: true });
second.events.pointerdown({ isTrusted: false });
assert.equal(unlocked, 2);

second.button.onclick();
assert.equal(stopped, 1, 'explicit mute stops active audio');
assert.equal(saved.get('anping.sound.enabled'), 'false');
assert(!boot(storage).c.soundOn, 'mute survives reopen');

const unavailable = boot({ getItem() { throw Error('blocked'); }, setItem() { throw Error('blocked'); } });
assert(!unavailable.c.soundOn);
unavailable.c.tock = () => true;
unavailable.button.onclick();
assert(unavailable.c.soundOn);
assert(unavailable.c.warning.includes('无法保存'));

console.log('PASS first launch muted; on/off survives reopen; blur keeps audio; trusted gestures unlock; inaccessible storage is reported');
