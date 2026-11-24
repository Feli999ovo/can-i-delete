'use strict';
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..');

const ctx = vm.createContext({ setTimeout, clearTimeout, performance });
vm.runInContext(fs.readFileSync(path.join(root, 'ui/anping-audio.js'), 'utf8'), ctx);
const { Controller, cues } = ctx.AnPingAudio;

function fake(state = 'running') {
  const calls = [];
  return {
    state,
    currentTime: 1,
    destination: {},
    calls,
    resume() { this.state = 'running'; return Promise.resolve(); },
    createOscillator() {
      const o = {
        type: '',
        frequency: { setValueAtTime(f, t) { calls.push({ f, t }); } },
        connect() {},
        disconnect() {},
        start(t) { calls.push({ start: t }); },
        stop(t) { calls.push({ stop: t }); }
      };
      return o;
    },
    createGain() {
      return {
        gain: { setValueAtTime() {}, linearRampToValueAtTime() {}, exponentialRampToValueAtTime() {} },
        connect() {},
        disconnect() {}
      };
    }
  };
}

(async () => {
  const context = fake(), events = [], audio = new Controller({ createContext: () => context, onScheduled: e => events.push(e) });
  audio.beginSession(1);
  assert.equal(await audio.play('complete', 1), false);
  audio.setEnabled(true);
  assert.equal(await audio.play('toString', 1), false, 'prototype key must be rejected without throwing');
  assert.equal(audio.lastResult.status, 'invalid-event');
  assert.equal(await audio.play('constructor', 1), false);
  assert.equal(await audio.play('__proto__', 1), false);
  for (const kind of ['hover', 'click', 'complete']) assert.equal(await audio.play(kind, 1), true);
  assert.equal(events.length, 3);
  assert.equal(await audio.play('complete', 1), false);

  let fakeNow = 1000;
  const debounced = new Controller({ createContext: () => fake(), now: () => fakeNow });
  debounced.setEnabled(true);
  assert.equal(await debounced.play('click'), true);
  fakeNow += 10;
  assert.equal(await debounced.play('click'), false, 'rapid click within 25ms must be debounced');
  assert.equal(debounced.lastResult.status, 'throttled');
  fakeNow += 20;
  assert.equal(await debounced.play('click'), true, 'click after 25ms debounce must play');
  assert(cues.hover.duration >= 0.04 && cues.hover.duration <= 0.065);
  assert(cues.click.duration >= 0.09 && cues.click.duration <= 0.13);
  assert(cues.complete.duration >= 0.35 && cues.complete.duration <= 0.5);
  assert.equal(cues.complete.notes.length, 2);
  assert(cues.complete.notes[1].frequency > cues.complete.notes[0].frequency);
  assert(cues.complete.notes[1].at >= cues.complete.notes[0].duration);
  assert.notEqual(cues.click.notes[0].frequency, cues.hover.notes[0].frequency);

  audio.setEnabled(false);
  assert.equal(audio.nodes.size, 0);
  assert.equal(await audio.play('click'), false);

  const suspended = fake('suspended'), restored = new Controller({ createContext: () => suspended });
  restored.setEnabled(true); restored.beginSession(2);
  assert(await restored.play('complete', 2));
  assert.equal(suspended.state, 'running');

  const fail = fake('suspended');
  fail.resume = () => Promise.reject(new Error('resume denied'));
  const bad = new Controller({ createContext: () => fail });
  bad.setEnabled(true); bad.beginSession(3);
  assert.equal(await bad.play('complete', 3), false);
  assert.equal(bad.notified, null);
  assert.equal(bad.lastResult.status, 'schedule-or-resume-failed');
  fail.resume = () => { fail.state = 'running'; return Promise.resolve(); };
  assert(await bad.play('complete', 3));

  let resolve;
  const delayed = fake('suspended');
  delayed.resume = () => new Promise(r => { resolve = () => { delayed.state = 'running'; r(); }; });
  const old = new Controller({ createContext: () => delayed });
  old.setEnabled(true); old.beginSession(4);
  const promise = old.play('complete', 4);
  old.beginSession(5);
  resolve();
  assert.equal(await promise, false);
  assert.equal(old.notified, null);
  assert.equal(delayed.calls.length, 0);
  assert.equal(await old.play('complete', 4), false);

  const muted = fake('suspended');
  let release;
  muted.resume = () => new Promise(r => { release = () => { muted.state = 'running'; r(); }; });
  const stop = new Controller({ createContext: () => muted });
  stop.setEnabled(true); stop.beginSession(6);
  const pending = stop.play('complete', 6);
  stop.setEnabled(false);
  release();
  assert.equal(await pending, false);
  assert.equal(stop.nodes.size, 0);

  const cancelled = fake('running'), held = new Controller({ createContext: () => cancelled });
  held.setEnabled(true); held.beginSession(9); held.stopSession();
  assert.equal(await held.play('complete', 9), false);

  const unavailable = fake('suspended');
  unavailable.resume = () => Promise.resolve();
  const unresolved = new Controller({ createContext: () => unavailable });
  unresolved.setEnabled(true); unresolved.beginSession(7);
  assert.equal(await unresolved.play('complete', 7), false);
  assert.equal(unresolved.lastResult.status, 'resume-failed');
  assert.equal(unresolved.notified, null);

  const timeoutContext = fake('suspended');
  timeoutContext.resume = () => new Promise(() => {});
  const timed = new Controller({ createContext: () => timeoutContext });
  timed.setEnabled(true); timed.beginSession(8);
  assert.equal(await timed.play('complete', 8), false);
  assert.equal(timed.lastResult.status, 'resume-timeout');
  assert.equal(timed.notified, null);

  const warm = fake('suspended'), unlock = new Controller({ createContext: () => warm });
  unlock.unlock();
  assert.equal(unlock.context, null, 'muted gestures do not create audio context');
  unlock.setEnabled(true);
  unlock.unlock();
  await Promise.resolve(); await Promise.resolve();
  assert.equal(warm.state, 'running');
  assert.equal(warm.calls.length, 0, 'unlock produces no cue');
  warm.state = 'closed';
  const replacement = fake();
  unlock.options.createContext = () => replacement;
  unlock.beginSession(10);
  assert(await unlock.play('complete', 10));
  assert.equal(unlock.context, replacement, 'closed context is recreated');

  const script = fs.readFileSync(path.join(root, 'ui/app.js'), 'utf8');
  new vm.Script(script);
  const predicate = script.slice(script.indexOf('function completionReady('), script.indexOf('function soundState('));
  vm.runInContext(predicate, ctx);
  for (const m of [
    { action: 'scanPaused', completed: false },
    { action: 'scanComplete', completed: false, stopped: true },
    { action: 'scanComplete', completed: false, error: 'failed' }
  ]) assert(!ctx.completionReady(m));
  assert(ctx.completionReady({ action: 'scanComplete', completed: true, incomplete: true, analysisWarning: true }));

  console.log('PASS distinct event timing/pitches; two ascending complete notes; muted/once/stale; suspended resume/failure/retry/cancel; neutral end vs pause/stop/failure');
})().catch(e => { console.error(e); process.exitCode = 1; });
