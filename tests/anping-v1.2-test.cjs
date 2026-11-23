'use strict';
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');

const h = fs.readFileSync(path.join(__dirname, '../ui/index.html'), 'utf8');
const s = fs.readFileSync(path.join(__dirname, '../ui/app.js'), 'utf8');
new vm.Script(s);

const ctx = vm.createContext({});
vm.runInContext(s.slice(s.indexOf('var nativeTextScale ='), s.indexOf('function esc(')), ctx);

assert.equal(ctx.fs(423 / 1024), '423 MB');
assert.equal(ctx.num3(167.2), '167');
assert.equal(ctx.num3(0.01), '<0.1');
assert.equal(ctx.fs(1.5 / 1048576), '1.5 KB');
assert.equal(ctx.unitOf(1023), 'GB');
assert.equal(ctx.unitOf(1024), 'TB');

assert(s.includes('if (top === drawer && dState.detailKey)'));
assert(s.includes('if (dState.directoryFile) closeDrawer();'));
assert(s.includes('else backToList();'));
assert(s.includes('$("flist") ? $("flist").scrollTop : 0'));
assert(!s.includes('toggleFile'));
assert(h.includes('src="anping-audio.js"') && h.includes('src="app.js"') && h.includes('href="styles.css"'));

console.log('PASS v1.2 units, modular 3-file UI links, and detail return wiring; sound behavior tested by anping-audio-test');
