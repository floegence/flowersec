import { readFileSync } from "node:fs";
import { expect, test } from "vitest";
import { decodeProxyMetadata, encodeProxyMetadata, type ProxySchema, validateProxyTrailers } from "./wire.js";

test("production proxy codec matches the shared canonical octet corpus", () => {
 const corpus=JSON.parse(readFileSync(new URL("../../../testdata/transport_v4/corpus.json",import.meta.url),"utf8")) as {vectors:{id:string;schema?:string;hex:string;expected_error?:string}[]};
 let count=0;
 for(const v of corpus.vectors){
  if(!v.schema?.startsWith("Proxy"))continue;
  const bytes=new Uint8Array(Buffer.from(v.hex,"hex"));
  if(v.expected_error!==undefined)expect(()=>decodeProxyMetadata(v.schema as ProxySchema,bytes),v.id).toThrow();
  else expect(encodeProxyMetadata(v.schema as ProxySchema,decodeProxyMetadata(v.schema as ProxySchema,bytes)),v.id).toEqual(bytes);
  count++;
 }
 expect(count).toBe(8);
});

test("HTTP field values are ByteString octets with ordered duplicates",()=>{
 const value={v:2,request_id:"r",method:"pAtCh",path:"/a?x=+&x=%ff",headers:Array.from({length:2048},()=>({name:"x-field",value:"\t\x80\xff"}))};
 expect(decodeProxyMetadata("ProxyHTTPRequest",encodeProxyMetadata("ProxyHTTPRequest",value))).toEqual(value);
 for(const invalid of ["\r","\n","\0","\x1f","\x7f","\u0100"]){
  expect(()=>encodeProxyMetadata("ProxyHTTPRequest",{...value,headers:[{name:"x-field",value:invalid}]})).toThrow();
 }
 expect(()=>decodeProxyMetadata("ProxyHTTPRequest",new TextEncoder().encode('{"v":1}'))).toThrow();
 expect(()=>encodeProxyMetadata("ProxyHTTPResponse",{v:2,request_id:"r",ok:true,status:200,headers:[],error:{code:"x",message:"x"}})).toThrow();
 expect(()=>validateProxyTrailers([{name:"content-length",value:"1"}])).toThrow();
 expect(()=>validateProxyTrailers([{name:"x-tail",value:"ok"}],new Set(["x-tail"]))).toThrow();
});
