// Real-carrier regressions inspect the original owner and publish through its
// normal deferred crypto/provider path. No replacement receiver is involved.
type SharedInputProof = ((u32, u64, u64), (u32, u64, u64), bool);

#[derive(Debug)]
pub(crate) struct SharedInputSnapshot {
    pub(crate) frontier: Option<(u32, u64, u64)>,
    pub(crate) record_next: Option<u64>,
    pub(crate) ack: u64,
    pub(crate) released: u64,
    pub(crate) first_error: bool,
    pub(crate) stopped_sent: bool,
    pub(crate) stop_sent: bool,
    pub(crate) proof: Option<SharedInputProof>,
    pub(crate) stable: bool,
    pub(crate) discard: (u64, u64, Option<Instant>),
    pub(crate) opens: u64,
}
impl Session {
    pub(crate) async fn wait_shared_input_for_test(
        &self,
        stream: &Stream,
        predicate: impl Fn(&SharedInputSnapshot) -> bool,
    ) -> SharedInputSnapshot {
        loop {
            let notified = self.owner.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let snapshot = self.shared_input_snapshot_for_test(stream);
            if predicate(&snapshot) {
                return snapshot;
            }
            notified.await;
        }
    }

    pub(crate) async fn wait_shared_termination_for_test(&self) {
        loop {
            let notified = self.owner.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.termination_cause().is_some() {
                return;
            }
            notified.await;
        }
    }

    pub(crate) fn shared_input_snapshot_for_test(&self, stream: &Stream) -> SharedInputSnapshot {
        self.owner
            .run_state(|session| {
                let engine = &session.engine;
                let scope = stream.inner.handle.scope();
                let slot = engine
                    .streams
                    .index(scope)
                    .map(|i| &engine.streams.slots[i]);
                let d = slot.map(|s| s.directions[usize::from(1 - engine.role)]);
                let tuple = |t: Tuple| (t.epoch, t.next, t.offset);
                Ok(SharedInputSnapshot {
                    frontier: d.map(|d| tuple(d.current)),
                    record_next: engine
                        .keys
                        .iter()
                        .find(|k| k.scope == scope && k.direction == 1 - engine.role)
                        .map(|k| k.next),
                    ack: d.map_or(0, |d| d.ack),
                    released: d.map_or(0, |d| d.released),
                    first_error: d.is_some_and(|d| d.first_error.is_some()),
                    stopped_sent: slot
                        .is_some_and(|s| s.directions[usize::from(engine.role)].stopped_sent),
                    stop_sent: d.is_some_and(|d| d.stop_sent),
                    proof: d.and_then(|d| {
                        d.proof
                            .map(|p| (tuple(p.terminal), tuple(p.observed), p.aborted))
                    }),
                    stable: engine.streams.authenticated_stable(scope).map_err(error)?,
                    discard: (
                        engine.streams.shared_discard.records,
                        engine.streams.shared_discard.bytes,
                        engine.streams.shared_discard.deadline,
                    ),
                    opens: engine.session_usage.opens,
                })
            })
            .unwrap()
    }

    pub(crate) fn shared_fault_data_for_test(&self, stream: &Stream, fault: &str, target: &Stream) {
        self.owner
            .run(|session, publisher| {
                let scope = stream.inner.handle.scope();
                let i = session
                    .engine
                    .streams
                    .resolve(&stream.inner.handle)
                    .map_err(error)?;
                let role = session.engine.role;
                let d = session.engine.streams.slots[i].directions[usize::from(role)];
                let epoch = session.current_epoch();
                let future = session.engine.candidate.as_ref().is_some_and(|c| c.sent);
                let key = session
                    .engine
                    .slot_for(future, scope, role)
                    .map_err(error)?;
                let sequence = session.engine.keys_for(future).map_err(error)?[key].next;
                let payload = if fault == "credit" {
                    vec![0x61; 129]
                } else {
                    vec![0x61; 4]
                };
                let mut body = map(7, payload.len() + 96).map_err(error)?;
                for (k, v) in [
                    (
                        0,
                        if fault == "target" {
                            target.inner.handle.scope()
                        } else {
                            scope
                        },
                    ),
                    (1, u64::from(role)),
                    (2, u64::from(epoch)),
                    (3, sequence),
                    (4, d.current.offset + u64::from(fault == "offset")),
                ] {
                    uint(&mut body, k);
                    uint(&mut body, v);
                }
                uint(&mut body, 5);
                body.push(if fault == "schema" { 0x00 } else { 0xf4 });
                uint(&mut body, 6);
                bytes(&mut body, &payload);
                publisher
                    .prepare_publication(body.len() + 44, 2)
                    .map_err(error)?;
                // The original sender admits four application bytes. Faults alter
                // only their authenticated encoding; STOPPED must still carry that
                // original legal frontier, including in the oversized-body case.
                let current = Tuple {
                    epoch,
                    next: sequence + 1,
                    offset: d.current.offset + 4,
                };
                let direction = &mut session.engine.streams.slots[i].directions[usize::from(role)];
                direction.current = current;
                direction.last = current;
                session
                    .send(scope, 8, &body, false, publisher)
                    .map_err(error)?;
                publisher.defer_publication(DeferredPublication::stream(
                    stream.inner.handle.view.clone(),
                    scope,
                    current.offset,
                    false,
                ));
                Ok(())
            })
            .unwrap();
        self.owner.changed.notify_waiters();
    }

    pub(crate) fn shared_raw_for_test(&self, wire: &[u8]) {
        // Fault traffic is already a complete wire message, so it deliberately
        // bypasses Stream admission and goes to the original carrier. A retired
        // Stream has no legitimate sender handle and cannot supply admission.
        self.owner.transport.lock().unwrap().publish(wire).unwrap();
    }

    pub(crate) fn expire_shared_discard_for_test(&self) {
        self.owner
            .run_state(|session| {
                let gate = &mut session.engine.streams.shared_discard;
                assert!(gate.deadline.is_some());
                gate.deadline = Some(Instant::now());
                Ok(())
            })
            .unwrap();
    }
}
impl Stream {
    pub(crate) fn scope_for_test(&self) -> u64 {
        self.inner.handle.scope()
    }
}
