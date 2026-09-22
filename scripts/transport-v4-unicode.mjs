// Reference normalization from pinned UCD data; no platform normalize/ICU call.
import fs from "node:fs";
import { fileURLToPath } from "node:url";

const data = JSON.parse(fs.readFileSync(fileURLToPath(new URL("../testdata/unicode15_1/normalization_generated.json",import.meta.url)),"utf8"));
export const unicodeVersion = data.unicode_version;
const classes = new Map(data.ccc), decomposition = new Map(data.decompositions);
const composition = new Map(data.compositions.map(([a,b,c])=>[a*0x110000+b,c]));
const S=0xac00,L=0x1100,V=0x1161,T=0x11a7,NL=19,NV=21,NT=28,NS=NL*NV*NT;
const combiningClass = (cp) => classes.get(cp) ?? 0;

export function assigned151(cp) {
  if (!Number.isInteger(cp) || cp<0 || cp>0x10ffff || (cp>=0xd800 && cp<=0xdfff)) return false;
  let lo=0,hi=data.assigned.length;
  while(lo<hi) {
    const mid=(lo+hi)>>>1,[start,end]=data.assigned[mid];
    if(cp<start)hi=mid; else if(cp>end)lo=mid+1; else return true;
  }
  return false;
}

function scalars(text) {
  if(typeof text!=="string")throw new TypeError("Unicode input must be text");
  const result=[];
  for(const character of text) {
    const cp=character.codePointAt(0);
    if(cp>=0xd800 && cp<=0xdfff)throw new TypeError("unpaired UTF-16 surrogate");
    result.push(cp);
  }
  return result;
}

function decompose(cp,out) {
  if(cp>=S && cp<S+NS) {
    const n=cp-S;
    out.push(L+Math.floor(n/(NV*NT)),V+Math.floor((n%(NV*NT))/NT));
    if(n%NT)out.push(T+n%NT);
  } else if(decomposition.has(cp)) {
    for(const part of decomposition.get(cp))decompose(part,out);
  } else out.push(cp);
}

function compose(a,b) {
  if(a>=L && a<L+NL && b>=V && b<V+NV)return S+((a-L)*NV+b-V)*NT;
  if(a>=S && a<S+NS && (a-S)%NT===0 && b>T && b<T+NT)return a+b-T;
  return composition.get(a*0x110000+b);
}

export function normalizeNFC151(text) {
  const decomposed=[];
  for(const cp of scalars(text))decompose(cp,decomposed);
  // Stable ordering within each non-starter run avoids quadratic insertion
  // behavior for long reversed combining sequences. Class-zero starters stay.
  const ordered=[],marks=[];
  function flush() {
    marks.sort((a,b)=>combiningClass(a)-combiningClass(b));
    for(const cp of marks)ordered.push(cp);
    marks.length=0;
  }
  for(const cp of decomposed) {
    if(combiningClass(cp)===0){flush();ordered.push(cp);}else marks.push(cp);
  }
  flush();
  const output=[];
  let starter=-1,lastClass=0;
  for(const cp of ordered) {
    const cc=combiningClass(cp);
    const composite=starter<0 || !(lastClass===0 || lastClass<cc) ? undefined : compose(output[starter],cp);
    if(composite!==undefined)output[starter]=composite;
    else {
      if(cc===0)starter=output.length;
      output.push(cp);lastClass=cc;
    }
  }
  // Avoid argument-count limits from spreading an owner-bounded large string.
  return output.map(cp=>String.fromCodePoint(cp)).join("");
}

export function canonicalText151(text) {
  const points=scalars(text);
  return points.every(assigned151) && normalizeNFC151(text)===text;
}
