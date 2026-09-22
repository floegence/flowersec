// Fixed Unicode 15.1 reference algorithms. No URL, ICU or host IDNA mapping.
import fs from "node:fs";
import { assigned151, normalizeNFC151 } from "./transport-v4-unicode.mjs";

const data=JSON.parse(fs.readFileSync(new URL("../testdata/unicode15_1/idna_generated.json",import.meta.url),"utf8"));
export class IDNAValidationError extends Error {}
const requireThat=(condition,code)=>{if(!condition)throw new IDNAValidationError(code);};
const string=points=>points.map(cp=>String.fromCodePoint(cp)).join("");
function points(text) {
  requireThat(typeof text==="string","idna_text_type");
  const out=[];
  for(const ch of text){const cp=ch.codePointAt(0);requireThat(cp<0xd800 || cp>0xdfff,"idna_surrogate");out.push(cp);}
  return out;
}
function lookup(rows,cp,fallback) {
  let lo=0,hi=rows.length;
  while(lo<hi){const mid=(lo+hi)>>>1,row=rows[mid];if(cp<row[0])hi=mid;else if(cp>row[1])lo=mid+1;else return row;}
  return [cp,cp,fallback];
}
const property=(table,cp,fallback)=>lookup(data[table],cp,fallback)[2];
const safe=n=>{requireThat(Number.isSafeInteger(n) && n>=0 && n<=0x7fffffff,"punycode_overflow");return n;};
const threshold=(k,bias)=>Math.min(26,Math.max(1,k-bias));
function adapt(delta,count,first) {
  delta=first ? Math.floor(delta/700) : Math.floor(delta/2);delta+=Math.floor(delta/count);
  let k=0;while(delta>455){delta=Math.floor(delta/35);k+=36;}
  return k+Math.floor(36*delta/(delta+38));
}
const digit=n=>String.fromCharCode(n<26 ? n+97 : n-26+48);
const value=cp=>cp>=65 && cp<=90 ? cp-65 : cp>=97 && cp<=122 ? cp-97 : cp>=48 && cp<=57 ? cp-48+26 : -1;

// RFC3492 Bootstring with the Punycode parameter set; lengths are checked by IDNA.
export function punycodeEncode151(text) {
  const input=points(text),out=input.filter(cp=>cp<128).map(cp=>String.fromCodePoint(cp));
  let handled=out.length,basic=handled,n=128,delta=0,bias=72;
  if(basic)out.push("-");
  while(handled<input.length) {
    let next=0x110000;for(const cp of input)if(cp>=n && cp<next)next=cp;
    delta=safe(delta+(next-n)*(handled+1));n=next;
    for(const cp of input) {
      if(cp<n)delta=safe(delta+1);
      if(cp!==n)continue;
      let q=delta;
      for(let k=36;;k+=36) {
        const t=threshold(k,bias);if(q<t)break;
        out.push(digit(t+(q-t)%(36-t)));q=Math.floor((q-t)/(36-t));
      }
      out.push(digit(q));bias=adapt(delta,handled+1,handled===basic);delta=0;handled++;
    }
    delta=safe(delta+1);n++;
  }
  return out.join("");
}

export function punycodeDecode151(text) {
  requireThat(typeof text==="string" && /^[\x00-\x7f]*$/u.test(text),"punycode_ascii");
  const out=[],dash=text.lastIndexOf("-");let index=0,n=128,i=0,bias=72;
  if(dash>0){for(const cp of points(text.slice(0,dash)))out.push(cp);index=dash+1;}
  while(index<text.length) {
    const old=i;let weight=1;
    for(let k=36;;k+=36) {
      requireThat(index<text.length,"punycode_truncated");const d=value(text.charCodeAt(index++));
      requireThat(d>=0,"punycode_digit");i=safe(i+d*weight);
      const t=threshold(k,bias);if(d<t)break;weight=safe(weight*(36-t));
    }
    const count=out.length+1;bias=adapt(i-old,count,old===0);n=safe(n+Math.floor(i/count));i%=count;
    requireThat(n<=0x10ffff && (n<0xd800 || n>0xdfff),"punycode_scalar");out.splice(i,0,n);i++;
  }
  return string(out);
}

function contextJ(label,index) {
  if(index>0 && property("ccc",label[index-1],0)===9)return true;
  if(label[index]===0x200d)return false;
  let left=index-1,right=index+1;
  while(left>=0 && property("joining",label[left],"U")==="T")left--;
  while(right<label.length && property("joining",label[right],"U")==="T")right++;
  return left>=0 && right<label.length && ["L","D"].includes(property("joining",label[left],"U")) && ["R","D"].includes(property("joining",label[right],"U"));
}
function contextO(label,index) {
  const cp=label[index],script=(n,name)=>property("scripts",n,"Unknown")===name;
  if(cp===0xb7)return index>0 && index+1<label.length && label[index-1]===0x6c && label[index+1]===0x6c;
  if(cp===0x375)return index+1<label.length && script(label[index+1],"Greek");
  if(cp===0x5f3 || cp===0x5f4)return index>0 && script(label[index-1],"Hebrew");
  if(cp===0x30fb)return label.some(n=>["Hiragana","Katakana","Han"].includes(property("scripts",n,"Unknown")));
  if(cp>=0x660 && cp<=0x669)return !label.some(n=>n>=0x6f0 && n<=0x6f9);
  if(cp>=0x6f0 && cp<=0x6f9)return !label.some(n=>n>=0x660 && n<=0x669);
  return false;
}
function bidi(label) {
  const directions=label.map(cp=>property("bidi",cp,"Unknown"));
  const rtl=["R","AL"].includes(directions[0]);requireThat(rtl || directions[0]==="L","idna_bidi_start");
  const allowed=rtl ? ["R","AL","AN","EN","ES","CS","ET","ON","BN","NSM"] : ["L","EN","ES","CS","ET","ON","BN","NSM"];
  requireThat(directions.every(direction=>allowed.includes(direction)),"idna_bidi_character");
  const last=directions.findLast(direction=>direction!=="NSM");
  requireThat((rtl ? ["R","AL","EN","AN"] : ["L","EN"]).includes(last),"idna_bidi_end");
  requireThat(!rtl || !directions.includes("AN") || !directions.includes("EN"),"idna_bidi_digits");
}
function validUTSLabel(label) {
  requireThat(label.length>0,"idna_empty_label");
  const text=string(label);requireThat(normalizeNFC151(text)===text,"idna_nfc");
  requireThat(label[0]!==45 && label.at(-1)!==45 && !(label[2]===45 && label[3]===45),"idna_hyphen");
  requireThat(!property("categories",label[0],"Cn").startsWith("M"),"idna_initial_mark");
  for(const [index,cp] of label.entries()) {
    requireThat(["valid","deviation"].includes(property("mapping",cp,"disallowed")),"idna_validity");
    if(cp===0x200c || cp===0x200d)requireThat(contextJ(label,index),"idna_contextj");
  }
}
function processUTS(text) {
  const mapped=[];
  for(const cp of points(text)) {
    const [,,status,target]=lookup(data.mapping,cp,"disallowed");
    // UTS46 revision 31 defers rejection until after NFC. For example, an
    // ASCII comparison sign followed by U+0338 can compose to a valid symbol.
    if(["valid","deviation","disallowed","disallowed_STD3_valid","disallowed_STD3_mapped"].includes(status))mapped.push(cp);
    else if(status==="mapped")for(const point of target)mapped.push(point);
    else requireThat(status==="ignored","idna_mapping");
  }
  const names=normalizeNFC151(string(mapped)).split("."),trailingDot=names.at(-1)==="";
  if(trailingDot)names.pop();requireThat(names.length>0,"idna_empty_domain");
  const labels=names.map(name=>{
    if(name.startsWith("xn--")) {
      requireThat(name.length<=63,"idna_label_length");
      const decoded=punycodeDecode151(name.slice(4)),label=points(decoded);
      requireThat(label.some(cp=>cp>=128),"idna_fake_alabel");
      requireThat("xn--"+punycodeEncode151(decoded)===name,"idna_alabel_roundtrip");
      validUTSLabel(label);return label;
    }
    const label=points(name);validUTSLabel(label);return label;
  });
  // RFC5893 applies to every label of a Bidi domain, including ASCII siblings.
  if(labels.some(label=>label.some(cp=>["R","AL","AN"].includes(property("bidi",cp,"Unknown")))))for(const label of labels)bidi(label);
  const ascii=labels.map(label=>{
    const value=label.every(cp=>cp<128) ? string(label) : "xn--"+punycodeEncode151(string(label));
    requireThat(value.length>=1 && value.length<=63,"idna_label_length");return value;
  }).join(".");
  requireThat(ascii.length<=253,"idna_domain_length");
  return {ascii:ascii+(trailingDot ? "." : ""),labels,trailingDot};
}

// This reference entry point exists to exercise the full official UTS corpus.
// Flowersec host construction additionally applies IDNA2008 and no trailing dot.
export function uts46ASCII151(text) {return processUTS(text).ascii;}
export function issuerDNS151(text) {
  requireThat(points(text).every(assigned151),"idna_unassigned");
  const result=processUTS(text);requireThat(!result.trailingDot,"idna_trailing_dot");
  for(const label of result.labels)for(const [index,cp] of label.entries()) {
    requireThat(assigned151(cp),"idna_unassigned");const kind=property("classes",cp,"DISALLOWED");
    if(kind==="PVALID")continue;
    requireThat(kind==="CONTEXTJ" ? contextJ(label,index) : kind==="CONTEXTO" && contextO(label,index),"idna2008_validity");
  }
  return result.ascii;
}
export function validateWireDNS151(text) {
  requireThat(typeof text==="string" && /^[\x00-\x7f]+$/u.test(text),"idna_wire_ascii");
  requireThat(issuerDNS151(text)===text,"idna_wire_noncanonical");return text;
}
