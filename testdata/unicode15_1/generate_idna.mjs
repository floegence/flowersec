// Reproduce UTS46 and RFC5892 data from exact Unicode inputs, without host ICU.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { normalizeNFC151 } from "../../scripts/transport-v4-unicode.mjs";

const directory=import.meta.dirname, manifest=JSON.parse(fs.readFileSync(path.join(directory,"idna_sources.json"),"utf8"));
const args=process.argv.slice(2),check=args[0]==="--check",importing=args[0]==="--import-sources";
assert.ok(args.length===0 || (check && args.length===1) || (importing && args.length===2 && path.isAbsolute(args[1])),"usage: generate_idna.mjs [--check | --import-sources ABSOLUTE_DIRECTORY]");
assert.equal(manifest.unicode_version,"15.1.0");assert.equal(manifest.uts46_revision,31);
const digest=bytes=>createHash("sha256").update(bytes).digest("hex");
assert.equal(digest(fs.readFileSync(path.join(directory,"normalization_generated.json"))),manifest.nfc_data_sha256,"NFC basis drift");
const sources=new Map();
for(const [name,entry] of Object.entries(manifest.sources)) {
  assert.match(name,/^[A-Za-z0-9]+\.txt$/u);
  const local=path.join(directory,name),input=importing && name!=="UnicodeData.txt" ? path.join(args[1],name) : local;
  const bytes=fs.readFileSync(input);assert.equal(digest(bytes),entry.sha256,`${name}: source SHA drift`);
  if(importing && fs.existsSync(local))assert.deepEqual(fs.readFileSync(local),bytes,`${name}: refusing to replace different source`);
  sources.set(name,bytes);
}
if(importing)for(const [name,bytes] of sources)if(!fs.existsSync(path.join(directory,name)))fs.writeFileSync(path.join(directory,name),bytes,{flag:"wx"});
const hex=value=>Number.parseInt(value,16),string=points=>points.map(cp=>String.fromCodePoint(cp)).join("");
const lines=name=>sources.get(name).toString("utf8").split(/\r?\n/u).map(line=>line.split("#")[0].trim()).filter(Boolean);
const points=text=>text.trim().split(/\s+/u).map(hex);
function rows(name) {
  return lines(name).map(line=>{
    const cols=line.split(";").map(col=>col.trim()),ends=cols[0].split("..").map(hex);
    return [ends[0],ends[1]??ends[0],...cols.slice(1)];
  });
}
function properties(name,accepted) {
  const result=new Set();
  for(const [lo,hi,prop] of rows(name))if(accepted.includes(prop))for(let cp=lo;cp<=hi;cp++)result.add(cp);
  return result;
}
const records=new Map(),decompositions=new Map();let first;
for(const line of lines("UnicodeData.txt")) {
  const fields=line.split(";");assert.equal(fields.length,15);const cp=hex(fields[0]);
  if(fields[1].endsWith(", First>")){assert.equal(first,undefined);first=cp;continue;}
  const lo=fields[1].endsWith(", Last>") ? first : cp;assert.ok(Number.isInteger(lo));first=undefined;
  for(let value=lo;value<=cp;value++)records.set(value,{category:fields[2],ccc:Number(fields[3]),bidi:fields[4]});
  if(fields[5])decompositions.set(cp,points(fields[5].replace(/^<[^>]+>\s*/u,"")));
}
assert.equal(first,undefined);
const folds=new Map();
for(const [cp,,status,mapping] of rows("CaseFolding.txt"))if(status==="C" || status==="F")folds.set(cp,points(mapping));
function decompose(cp,out) {
  const children=decompositions.get(cp);
  if(children)for(const child of children)decompose(child,out);else out.push(cp);
}
function nfkc(text) {
  const out=[];for(const ch of text)decompose(ch.codePointAt(0),out);
  return normalizeNFC151(string(out));
}
const ignored=properties("DerivedCoreProperties.txt",["Default_Ignorable_Code_Point"]);
for(const cp of properties("PropList.txt",["White_Space","Noncharacter_Code_Point"]))ignored.add(cp);
const noncharacters=properties("PropList.txt",["Noncharacter_Code_Point"]),joiners=properties("PropList.txt",["Join_Control"]);
const oldHangul=properties("HangulSyllableType.txt",["L","V","T"]);
const ignoredBlocks=properties("Blocks.txt",["Combining Diacritical Marks for Symbols","Musical Symbols","Ancient Greek Musical Notation"]);
// RFC5892 section 2.6 exceptions take precedence over derived properties.
const exceptions=new Map();
for(const cp of [0xdf,0x3c2,0x6fd,0x6fe,0xf0b,0x3007])exceptions.set(cp,"PVALID");
for(const cp of [0xb7,0x375,0x5f3,0x5f4,0x30fb,...Array.from({length:10},(_,i)=>0x660+i),...Array.from({length:10},(_,i)=>0x6f0+i)])exceptions.set(cp,"CONTEXTO");
for(const cp of [0x640,0x7fa,0x302e,0x302f,0x3031,0x3032,0x3033,0x3034,0x3035,0x303b])exceptions.set(cp,"DISALLOWED");
// The RFC5892 BackwardCompatible set has no assignments for this version.
const allowedCategories=new Set(["Ll","Lu","Lo","Nd","Lm","Mn","Mc"]);
function derived(cp) {
  if(cp>=0xd800 && cp<=0xdfff)return "DISALLOWED"; // Not Unicode scalars.
  if(exceptions.has(cp))return exceptions.get(cp);
  if(!records.has(cp) && !noncharacters.has(cp))return "UNASSIGNED";
  if(cp===0x2d || (cp>=0x30 && cp<=0x39) || (cp>=0x61 && cp<=0x7a))return "PVALID";
  if(joiners.has(cp))return "CONTEXTJ";
  const original=String.fromCodePoint(cp),folded=[];
  for(const ch of nfkc(original))folded.push(...(folds.get(ch.codePointAt(0))??[ch.codePointAt(0)]));
  if(nfkc(string(folded))!==original)return "DISALLOWED";
  if(ignored.has(cp) || ignoredBlocks.has(cp) || oldHangul.has(cp))return "DISALLOWED";
  return allowedCategories.has(records.get(cp)?.category) ? "PVALID" : "DISALLOWED";
}
function appendRange(result,cp,value) {
  const last=result.at(-1);
  if(last && last[1]+1===cp && last[2]===value)last[1]=cp;else result.push([cp,cp,value]);
}
const classes=[],categories=[],bidi=[],ccc=[];
for(let cp=0;cp<=0x10ffff;cp++) {
  const property=derived(cp);if(["PVALID","CONTEXTJ","CONTEXTO"].includes(property))appendRange(classes,cp,property);
  const record=records.get(cp);if(!record)continue;
  appendRange(categories,cp,record.category);appendRange(bidi,cp,record.bidi);
  if(record.ccc)appendRange(ccc,cp,record.ccc);
}
function filteredRows(name,accepted) {
  const result=rows(name).filter(([, ,prop])=>!accepted || accepted.includes(prop)).map(([lo,hi,prop])=>[lo,hi,prop]);
  return result.sort((a,b)=>a[0]-b[0]);
}
const mapping=rows("IdnaMappingTable.txt").map(([lo,hi,status,target])=>[lo,hi,status,target ? points(target) : []]);
assert.equal(mapping[0][0],0);assert.equal(mapping.at(-1)[1],0x10ffff);
for(let i=1;i<mapping.length;i++)assert.equal(mapping[i-1][1]+1,mapping[i][0]);
const data={unicode_version:manifest.unicode_version,uts46_revision:manifest.uts46_revision,sources:manifest.sources,nfc_data_sha256:manifest.nfc_data_sha256,mapping,classes,categories,bidi,ccc,joining:filteredRows("DerivedJoiningType.txt"),scripts:filteredRows("Scripts.txt",["Greek","Han","Hebrew","Hiragana","Katakana"])};
const expected=JSON.stringify(data)+"\n",target=path.join(directory,"idna_generated.json");
if(check)assert.equal(fs.readFileSync(target,"utf8"),expected,"IDNA table drift");else fs.writeFileSync(target,expected);
console.log(`Unicode 15.1 IDNA tables ${check ? "verified" : "generated"}: ${mapping.length} mappings, ${classes.length} derived ranges.`);
