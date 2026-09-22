import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { IDNAValidationError, issuerDNS151, validateWireDNS151, uts46ASCII151, punycodeEncode151, punycodeDecode151 } from "./transport-v4-idna.mjs";

const directory=path.resolve(import.meta.dirname,"../testdata/unicode15_1");
const unescape=text=>text.replace(/\\u([0-9A-Fa-f]{4})|\\x\{([0-9A-Fa-f]+)\}/gu,(_,a,b)=>String.fromCodePoint(Number.parseInt(a??b,16)));

test("pinned IDNA tables reproduce from the complete exact Unicode sources",()=>{
  const result=spawnSync(process.execPath,[path.join(directory,"generate_idna.mjs"),"--check"],{encoding:"utf8"});
  assert.equal(result.status,0,result.stderr);
});

test("nontransitional UTS46 passes all official Unicode 15.1 ToASCII cases",()=>{
  let cases=0;const failures=[];
  for(const line of fs.readFileSync(path.join(directory,"IdnaTestV2.txt"),"utf8").split(/\r?\n/u)) {
    const source=line.split("#")[0].trim();if(!source)continue;
    const cols=source.split(";").map(col=>unescape(col.trim()));
    const input=cols[0],unicode=cols[1]||input,expected=cols[3]||unicode,status=cols[4]||cols[2]||"[]";
    let actual,error;try{actual=uts46ASCII151(input);}catch(err){error=err;}
    if(status==="[]" ? error || actual!==expected : !(error instanceof IDNAValidationError))failures.push({case:cases,input,expected,status,actual,error:error?.message});
    cases++;
  }
  assert.equal(cases,6265);assert.deepEqual(failures.slice(0,20),[],`${failures.length}/${cases} conformance failures`);
});

test("IDNA2008 contextual classes and cross-label Bidi remain enforced",()=>{
  for(const input of [
    "\u0375\u03b1.example", "\u05d0\u05f3.example", "\u05d0\u05f4.example",
    "\u30ab\u30fb\u30ca.example", "\u30fb\u4e00.example", "\u0627\u0660\u0661.example", "\u0627\u06f0\u06f1.example",
    "\u0915\u094d\u200d\u0937.example", "\u0915\u094d\u200c\u0937.example", "نامه‌ای.example", "a1.مثال",
  ])assert.equal(validateWireDNS151(issuerDNS151(input)),issuerDNS151(input),input);
  for(const input of [
    "\u0375a.example", "\u05f3\u05d0.example", "\u05f4\u05d0.example", "a\u30fbb.example", "\u0627\u0660\u06f0.example",
    "\u0915\u200d\u0937.example", "\u0628\u200c\u0301a.example", "a\u200c\u0628.example", "1.مثال", "a-.مثال",
  ])assert.throws(()=>issuerDNS151(input),IDNAValidationError,input);
  assert.throws(()=>validateWireDNS151("xn--"+punycodeEncode151(String.fromCodePoint(0x1e030))+".example"),IDNAValidationError);
  for(const input of ["xn--zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "xn--a!", "xn--abc-", "\ud800.example", "\udc00.example"])
    assert.throws(()=>issuerDNS151(input),IDNAValidationError,input);
});

test("Flowersec DNS uses IDNA2008 and original wire bytes beyond UTS conformance",()=>{
  for(const [input,expected] of [
    ["Faß.de","xn--fa-hia.de"],["l·l.example","xn--ll-0ea.example"],
    ["例子.测试","xn--fsqu00a.xn--0zwm56d"],["ｅｘａｍｐｌｅ.com","example.com"],
    ["e\u0301.example","xn--9ca.example"],[String.fromCodePoint(0x2ebf0)+".example","xn--8g0n.example"],
  ]){assert.equal(issuerDNS151(input),expected);assert.equal(validateWireDNS151(expected),expected);}
  for(const input of ["a·b.example","😀.example","xn--e28h.example","example.com.","example\u3002", "a..b","-x.example","ab--x.example","a_b.example","xn--abc-.example","xn--.example","a\u200cb.example","a\u200db.example",String.fromCodePoint(0x1cc00)+".example","a".repeat(64)+".example"])
    assert.throws(()=>issuerDNS151(input),IDNAValidationError,input);
  for(const input of ["EXAMPLE.com","Faß.de","e\u0301.example","ｅｘａｍｐｌｅ.com","example.com.","xn--FA-hia.de"])
    assert.throws(()=>validateWireDNS151(input),IDNAValidationError,input);
  assert.equal(uts46ASCII151("😀.example"),"xn--e28h.example"); // The extra RFC5892 predicate is mandatory.
  const max=[63,63,63,61].map(n=>"a".repeat(n)).join(".");assert.equal(max.length,253);
  assert.equal(issuerDNS151(max),max);assert.throws(()=>issuerDNS151(max+"a"),/domain_length/u);
  for(const text of ["bücher","mañana","例子","παράδειγμα","россия","faß","😀"])
    assert.equal(punycodeDecode151(punycodeEncode151(text)),text);
  for(const text of ["-9ca","-"])assert.throws(()=>punycodeDecode151(text),IDNAValidationError);
});
