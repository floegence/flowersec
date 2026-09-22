// Stateless byte/reference matching only. The caller must separately establish
// trusted source/identity, current authorization, query resources and installation.
// A returned snapshot never grants admission or changes an execution owner.
import { decodeMap, VectorError } from "./transport-v4-codec.mjs";
import { evaluateDomain } from "./transport-v4-domains.mjs";
import { verifyServiceOffer } from "./transport-v4-services.mjs";

const requireThat = (condition,code) => { if (!condition) throw new VectorError(code); };
const field = (schema,name,map,key) => map.get(BigInt(Object.entries(schema.frame_maps[name].fields).find(([,v])=>v.name===key)[0]));
const digest = (schema,bytes) => Buffer.from(evaluateDomain(schema,"service_contract_digest",{contract:bytes}).output_hex,"hex");

function matchedContract(schema,target,bytes) {
  requireThat(Buffer.isBuffer(bytes),"query_contract_body");
  const owned=Buffer.from(bytes);
  const contract=decodeMap(schema,"ServiceContract",owned);
  for(const [targetKey,contractKey] of [["service_namespace","service_namespace"],["method_type_id","type_id"]]) {
    requireThat(field(schema,"ContractTarget",target,targetKey)===field(schema,"ServiceContract",contract,contractKey),"query_target_mismatch");
  }
  const actual=digest(schema,owned),wanted=field(schema,"ContractTarget",target,"wanted_contract_digest");
  requireThat(wanted===undefined || wanted.equals(actual),"query_wanted_mismatch");
  return {bytes:owned,contract,digest:actual};
}

function queryInputs(schema,targetsBytes,knownContracts) {
  const request=decodeMap(schema,"ContractTargets",targetsBytes),targets=field(schema,"ContractTargets",request,"targets");
  const known=knownContracts ?? Array(targets.length).fill(null);
  requireThat(Array.isArray(known) && known.length===targets.length,"query_known_count");
  const baselines=targets.map((target,index)=>{
    const expected=field(schema,"ContractTarget",target,"known_contract_digest");
    if (expected===undefined) {
      requireThat(known[index]===null,"query_unrequested_known");
      return null;
    }
    const baseline=matchedContract(schema,target,known[index]);
    requireThat(expected.equals(baseline.digest),"query_known_mismatch");
    return baseline;
  });
  return {targets,baselines};
}

export function verifyContractTargets(schema,targetsBytes,knownContracts) {
  const {targets}=queryInputs(schema,targetsBytes,knownContracts);
  return {target_count:targets.length,max_response_bytes:targets.length*schema.resource_caps.contract_query_response_bytes_per_target};
}

export function verifyContractSnapshots(schema,targetsBytes,snapshotsBytes,{knownContracts,offerWindowLimits}={}) {
  const {targets,baselines}=queryInputs(schema,targetsBytes,knownContracts);
  requireThat(snapshotsBytes.length<=targets.length*schema.resource_caps.contract_query_response_bytes_per_target,"query_response_size");
  const response=decodeMap(schema,"ContractSnapshots",snapshotsBytes),items=field(schema,"ContractSnapshots",response,"items");
  requireThat(items.length===targets.length,"query_response_count");
  const windows=offerWindowLimits ?? Array(targets.length).fill(null);
  requireThat(Array.isArray(windows) && windows.length===targets.length,"query_policy_count");
  const statuses=Object.values(schema.frame_maps.ContractSnapshot.fields).find(f=>f.name==="status").enum;
  return items.map((item,index)=>{
    const code=field(schema,"ContractSnapshot",item,"status"),status=Object.keys(statuses).find(k=>BigInt(statuses[k])===code);
    if(status==="denied" || status==="unavailable") return {target_index:index,status};
    let matched;
    if(status==="available_unchanged") {
      matched=baselines[index];
      requireThat(matched!==null,"query_unchanged_without_known");
      requireThat(field(schema,"ContractSnapshot",item,"contract_digest").equals(matched.digest),"query_unchanged_mismatch");
    } else matched=matchedContract(schema,targets[index],field(schema,"ContractSnapshot",item,"contract"));
    const contractFields=Object.values(schema.frame_maps.ServiceContract.fields);
    const shapeEnum=contractFields.find(f=>f.name==="call_shape").enum;
    const shape=Object.keys(shapeEnum).find(k=>BigInt(shapeEnum[k])===field(schema,"ServiceContract",matched.contract,"call_shape"));
    const semanticField=contractFields.find(f=>f.name===shape+"_semantics");
    const execution=field(schema,"ServiceContract",matched.contract,semanticField.name)===BigInt(semanticField.enum.execution);
    const offerBytes=field(schema,"ContractSnapshot",item,"offer");
    requireThat(execution ? offerBytes!==undefined : offerBytes===undefined,"query_offer_presence");
    const offer=execution ? verifyServiceOffer(schema,matched.bytes,offerBytes,windows[index]) : null;
    return {target_index:index,status,contract_bytes:matched.bytes,contract_digest:matched.digest,offer};
  });
}
