import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { assigned151, canonicalText151, normalizeNFC151, unicodeVersion } from "./transport-v4-unicode.mjs";

const root=path.resolve(import.meta.dirname,".."),directory=path.join(root,"testdata/unicode15_1");

test("pinned NFC tables reproduce from exact Unicode 15.1 sources",()=>{
  assert.equal(unicodeVersion,"15.1.0");
  const manifest=JSON.parse(fs.readFileSync(path.join(directory,"normalization_sources.json"),"utf8"));
  for(const [name,source] of Object.entries(manifest.sources))assert.equal(createHash("sha256").update(fs.readFileSync(path.join(directory,name))).digest("hex"),source.sha256);
  const result=spawnSync(process.execPath,[path.join(directory,"generate_normalization.mjs"),"--check"],{encoding:"utf8"});
  assert.equal(result.status,0,result.stderr);
});

test("NFC passes the complete Unicode 15.1 normalization conformance corpus",()=>{
  const raw=fs.readFileSync(path.join(directory,"NormalizationTest.txt"),"utf8");
  const covered=new Set();
  let cases=0,part;
  for(const line of raw.split(/\r?\n/u)) {
    if(line.startsWith("@Part")){part=line.split(" ")[0];continue;}
    const source=line.split("#")[0].trim();
    if(!source || source.startsWith("@"))continue;
    const cols=source.split(";").slice(0,5).map(col=>col.trim().split(/ +/u).map(value=>Number.parseInt(value,16)));
    if(part==="@Part1")for(const cp of cols[0])covered.add(cp);
    const [c1,c2,c3,c4,c5]=cols.map(col=>col.map(cp=>String.fromCodePoint(cp)).join(""));
    // UAX15 conformance: c2=NFC(c1)=NFC(c2)=NFC(c3), c4=NFC(c4)=NFC(c5).
    for(const source of [c1,c2,c3])assert.equal(normalizeNFC151(source),c2,`canonical case ${cases}`);
    for(const source of [c4,c5])assert.equal(normalizeNFC151(source),c4,`compatibility case ${cases}`);
    cases++;
  }
  assert.equal(cases,19074);
  // The normative corpus also requires every scalar absent from Part1 to be
  // unchanged. This includes later/unassigned values at the algorithm layer;
  // wire acceptance separately rejects values outside the pinned assigned set.
  for(let cp=0;cp<=0x10ffff;cp++) {
    if((cp>=0xd800 && cp<=0xdfff)||covered.has(cp))continue;
    const text=String.fromCodePoint(cp);assert.equal(normalizeNFC151(text),text,cp.toString(16));
  }
});

test("wire text distinguishes canonical bytes, assigned scalars and malformed UTF-16",()=>{
  assert.equal(canonicalText151("\u00e9"),true);
  assert.equal(canonicalText151("e\u0301"),false);
  assert.equal(normalizeNFC151("e\u0301"),"\u00e9");
  assert.equal(normalizeNFC151("\u1100\u1161\u11a8"),"\uac01");
  assert.equal(normalizeNFC151("\uac00\u11a8"),"\uac01");
  assert.equal(canonicalText151(String.fromCodePoint(0x1cc00)),false); // Added after Unicode 15.1.
  for(const value of ["\ud800","\udc00","x\ud800y"])assert.throws(()=>normalizeNFC151(value),/unpaired/u);
  for(const cp of [-1,0xd800,0x110000,1.1,NaN])assert.equal(assigned151(cp),false);
  // Stable equal-class marks must keep their order and block composition.
  assert.equal(normalizeNFC151("A\u0305\u0301"),"A\u0305\u0301");
  const long="A"+"\u0315\u0300".repeat(10000);
  assert.equal(normalizeNFC151(normalizeNFC151(long)),normalizeNFC151(long));
});
