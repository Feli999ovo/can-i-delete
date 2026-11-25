'use strict';
// Identify both completion notes by DFT frequency & duration (supports WAV folder arg or offline cue synthesis).
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');

function detectNotes(samples, rate) {
  const bins = [], width = Math.max(1, Math.round(rate * 0.01));
  for (let i = 0; i < samples.length; i += width) {
    const q = samples.slice(i, i + width);
    bins.push(Math.sqrt(q.reduce((s, x) => s + x * x, 0) / q.length));
  }
  const notes = [];
  for (let i = 0; i < bins.length; i++) {
    if (bins[i] <= 0.0002) continue;
    const start = i;
    while (i + 1 < bins.length && bins[i + 1] > 0.0002) i++;
    const end = i + 1, lo = Math.round(start * 0.01 * rate), hi = Math.round(Math.min(end * 0.01, start * 0.01 + 0.08) * rate);
    let hz = 0, power = 0;
    for (let f = 600; f < 2200; f += 2) {
      let re = 0, im = 0;
      for (let j = lo; j < hi; j++) {
        const a = 2 * Math.PI * f * j / rate;
        re += samples[j] * Math.cos(a);
        im += samples[j] * Math.sin(a);
      }
      const p = re * re + im * im;
      if (p > power) { power = p; hz = f; }
    }
    notes.push({ start: start * 0.01, end: end * 0.01, hz });
  }
  return notes;
}

const dir = process.argv[2];
if (!dir) {
  const ctx = vm.createContext({ setTimeout, clearTimeout, performance });
  vm.runInContext(fs.readFileSync(path.join(__dirname, '../ui/anping-audio.js'), 'utf8'), ctx);
  const cue = ctx.AnPingAudio.cues.complete;
  const rate = 48000;
  const samples = new Array(Math.ceil(rate * 0.6)).fill(0);
  for (const n of cue.notes) {
    const s0 = Math.round((0.05 + n.at) * rate);
    const s1 = Math.round((0.05 + n.at + n.duration) * rate);
    for (let i = s0; i < s1 && i < samples.length; i++) {
      const t = (i - s0) / rate;
      const env = Math.min(1, t / 0.008) * Math.max(0.05, 1 - t / (n.duration + 0.02));
      samples[i] += 0.05 * env * Math.sin(2 * Math.PI * n.frequency * t);
    }
  }
  const notes = detectNotes(samples, rate);
  assert.equal(notes.length, 2, 'two separated notes');
  assert(Math.abs(notes[0].hz - 784) < 15 && Math.abs(notes[1].hz - 1046.5) < 15, 'accepted ascending completion melody');
  assert(notes[0].end - notes[0].start >= 0.10 && notes[1].end - notes[1].start >= 0.12, 'not truncated');
  console.log('PASS synthesized complete cue waveform contains two full ascending completion notes (784 Hz -> 1046.5 Hz)');
  process.exit(0);
}

for (const name of ['01-enabled-real-end', '02-reopened-real-end', '03-blur-at-real-end', '04-minimized-real-end', '05-restarted-real-end']) {
  const b = fs.readFileSync(path.join(dir, name + '.wav'));
  assert(b.length >= 44, 'Invalid WAV header (too short): ' + name);
  const fmtTag = b.readUInt16LE(20), ch = b.readUInt16LE(22), rate = b.readUInt32LE(24), bits = b.readUInt16LE(34), floating = fmtTag === 3;
  assert(rate >= 8000 && rate <= 384000, 'Invalid WAV sample rate: ' + rate);
  assert(ch >= 1 && ch <= 8, 'Invalid WAV channels: ' + ch);
  assert((!floating && fmtTag === 1 && bits === 16) || (floating && bits === 32), 'Unsupported WAV format/bits: ' + fmtTag + '/' + bits);
  const step = (bits / 8) * ch, samples = [];
  assert(step > 0, 'Invalid WAV frame step');
  for (let i = 44; i + step <= b.length; i += step) {
    let x = 0;
    for (let c = 0; c < ch; c++) x += floating ? b.readFloatLE(i + c * bits / 8) : b.readInt16LE(i + c * bits / 8) / 32768;
    samples.push(x / ch);
  }
  assert(samples.length > 0, 'Empty WAV data: ' + name);
  const notes = detectNotes(samples, rate);
  const report = { name, seconds: samples.length / rate, notes };
  fs.writeFileSync(path.join(dir, name + '-waveform.json'), JSON.stringify(report, null, 2));
  console.log(JSON.stringify(report));
  assert.equal(notes.length, 2, 'two separated notes');
  assert(Math.abs(notes[0].hz - 784) < 15 && Math.abs(notes[1].hz - 1046.5) < 15, 'accepted ascending completion melody');
  assert(notes[0].end - notes[0].start >= 0.10 && notes[1].end - notes[1].start >= 0.12, 'not truncated');
  const event = JSON.parse(fs.readFileSync(path.join(dir, name + '-events.json'), 'utf8'));
  assert(event.report.completed && event.notified, 'real scan completion');
  assert.equal(event.events.filter(x => x.kind === 'complete' && x.session === event.report.scanSessionId).length, 1);
}
console.log('PASS five real-scan endpoint recordings contain two full ascending completion notes');
