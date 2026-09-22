import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { WriteStateReference } from "./transport-v4-write-state.mjs";
import { validateApiResult } from "./transport-v4-api-results.mjs";

const schema = JSON.parse(fs.readFileSync(new URL("../stability/transport_v4_schema.json",import.meta.url)));
const make = (requested_bytes = 8192n) => new WriteStateReference(schema, { requested_bytes, max_write_operation_bytes: 16384n, prepared_at_ms: 100n, deadline_at_ms: 200n });
const pending = { status: "pending", core_cleanup: "pending", pending_callbacks: 0n };
const complete = { status: "complete", core_cleanup: "complete", pending_callbacks: 0n };

test("v4.write.acceptance: cancellation preserves the full local prefix independently of tickets", () => {
  const op = make(); op.start({ queue_available: true });
  op.accept(4096n); op.ticket(1024n);
  const result = op.cancel();
  assert.equal(result.accepted_bytes,4096n);
  assert.equal(result.terminal_reason,"canceled");
  assert.throws(() => op.accept(1n),/write_acceptance_closed/u);
  assert.deepEqual(op.ticket(3072n),result);
  assert.throws(() => op.ticket(1n),/write_ticket_bounds/u);
  assert.deepEqual(op.start({queue_available:true}),result);
  assert.deepEqual(op.fail("failed"),result);
  const late = op.cleanup({status:"cleanup_incomplete",core_cleanup:"pending",pending_callbacks:1n});
  assert.equal(late.accepted_bytes,4096n); assert.equal(late.terminal_reason,"canceled");
  assert.equal(op.cleanup(complete).cleanup_status.status,"complete");
  const reset = make();reset.start({queue_available:true});reset.accept(4096n);reset.cancel();
  assert.equal(reset.fail("stream_terminated").terminal_reason,"canceled");
  assert.throws(()=>reset.ticket(1n),/write_sender_closed/u);
});

test("v4.write.wait: dropped waits do not cancel, restart or extend the prepared deadline", () => {
  const op = make();
  assert.equal(op.wait({canceled:true}).wait_status,"wait_canceled");
  assert.equal(op.progress().phase,"prepared");
  op.observeTime(199n); op.start({queue_available:true}); op.accept(17n);
  assert.equal(op.wait({canceled:true}).progress.accepted_bytes,17n);
  assert.equal(op.progress().phase,"running");
  const expired = op.observeTime(200n);
  assert.equal(expired.terminal_reason,"deadline_exceeded");assert.equal(expired.accepted_bytes,17n);
  assert.deepEqual(op.start({queue_available:true}),expired);
  assert.equal(op.wait({canceled:true}).wait_status,"ready");
  assert.throws(() => op.observeTime(199n),/write_time_continuity/u);
  const neverStarted = make();assert.equal(neverStarted.observeTime(200n).accepted_bytes,0n);
});

test("v4.write.once: pre-start cancellation and full queues permanently consume Start", () => {
  for (const end of [op=>op.cancel(),op=>op.start({queue_available:false})]) {
    const op = make(), result = end(op);
    assert.equal(result.phase,"terminal");assert.equal(result.accepted_bytes,0n);
    assert.deepEqual(op.start({queue_available:true}),result);
    assert.throws(() => op.accept(1n),/write_acceptance_closed/u);
  }
  const op = make(0n);assert.equal(op.start({queue_available:true}).terminal_reason,"complete");
  const full = make(4096n);full.start({queue_available:true});full.accept(4096n);
  assert.equal(full.cancel().terminal_reason,"complete");
  assert.deepEqual(full.progress().cleanup_status,pending);
});

test("v4.write.bounds: per-request counters, result isolation and cleanup remain separate", () => {
  const a = make(8n), b = make(8n);a.start({queue_available:true});b.start({queue_available:true});
  a.accept(3n);b.accept(5n);assert.equal(a.cancel().accepted_bytes,3n);assert.equal(b.cancel().accepted_bytes,5n);
  const copy = a.progress();copy.accepted_bytes=8n;copy.cleanup_status.status="complete";
  assert.equal(a.progress().accepted_bytes,3n);assert.deepEqual(a.progress().cleanup_status,pending);
  assert.throws(() => new WriteStateReference(schema,{requested_bytes:17n,max_write_operation_bytes:16n,prepared_at_ms:1n,deadline_at_ms:2n}),/write_operation_capacity/u);
  assert.throws(() => new WriteStateReference(schema,{requested_bytes:1n,max_write_operation_bytes:16n,prepared_at_ms:2n,deadline_at_ms:2n}),/write_deadline/u);
  const live=make();assert.throws(()=>live.cleanup(complete),/write_live_cleanup/u);
  a.cleanup(complete);assert.throws(()=>a.cleanup(pending),/write_cleanup_regression/u);
});

test("v4.transfer.tail: exact one-chunk tail ownership and uint64 progress survive partial failure", () => {
  const context = {chunk_bytes:4n,tail_retained_by_source:false,retained_tail_bytes:0n};
  const partial = {source_read_bytes:100n,destination_accepted_bytes:97n,unaccepted_tail:new Uint8Array([1,2,3])};
  validateApiResult(schema,"TransferProgress",partial,context);
  for (const bad of [{...partial,destination_accepted_bytes:101n},{...partial,unaccepted_tail:new Uint8Array()}, {...partial,source_read_bytes:102n}]) {
    assert.throws(()=>validateApiResult(schema,"TransferProgress",bad,context));
  }
  validateApiResult(schema,"TransferProgress",{...partial,unaccepted_tail:new Uint8Array()},{...context,tail_retained_by_source:true,retained_tail_bytes:3n});
  assert.throws(()=>validateApiResult(schema,"TransferProgress",partial,{...context,tail_retained_by_source:true,retained_tail_bytes:3n}));
  const maximum=(1n<<64n)-1n;
  validateApiResult(schema,"TransferProgress",{source_read_bytes:maximum,destination_accepted_bytes:maximum,unaccepted_tail:new Uint8Array()},context);
  assert.throws(()=>validateApiResult(schema,"TransferProgress",{...partial,source_read_bytes:maximum+1n},context));
});
