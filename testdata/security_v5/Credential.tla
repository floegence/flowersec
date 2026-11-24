---------------------------- MODULE Credential ----------------------------
EXTENDS Naturals
CONSTANT Fault
Workers == {1, 2}
VARIABLES phase, owner, sends, unsound, admission, readers, accepts
vars == <<phase, owner, sends, unsound, admission, readers, accepts>>

Init == /\ phase = [worker \in Workers |-> "dial"]
        /\ owner = 0 /\ sends = 0 /\ unsound = FALSE
        /\ admission = "published" /\ readers = {} /\ accepts = 0

Advance(worker, before, after) ==
    /\ phase[worker] = before
    /\ phase' = [phase EXCEPT ![worker] = after]

TLS(worker) == /\ Advance(worker, "dial", "verified")
               /\ UNCHANGED <<owner, sends, unsound, admission, readers, accepts>>

Commit(worker) == /\ owner = 0 /\ Advance(worker, "verified", "committed")
                  /\ owner' = worker /\ UNCHANGED <<sends, unsound, admission, readers, accepts>>

Confirm(worker) == /\ Advance(worker, "committed", "confirmed")
                   /\ UNCHANGED <<owner, sends, unsound, admission, readers, accepts>>

Restart(worker) == /\ phase[worker] # "dial"
                   /\ phase' = [phase EXCEPT ![worker] = "dial"]
                   /\ UNCHANGED <<owner, sends, unsound, admission, readers, accepts>>

Write(worker) == /\ phase[worker] = "confirmed" \/ (Fault = "earlyWrite" /\ phase[worker] = "verified")
                 /\ phase' = [phase EXCEPT ![worker] = "sent"]
                 /\ sends' = sends + 1
                 /\ unsound' = (unsound \/ owner # worker \/ phase[worker] # "confirmed")
                 /\ UNCHANGED <<owner, admission, readers, accepts>>

ReadRecord(worker) == /\ sends > 0 /\ admission = "published"
                      /\ readers' = readers \cup {worker}
                      /\ UNCHANGED <<phase, owner, sends, unsound, admission, accepts>>

Admit(worker) == /\ worker \in readers /\ (admission = "published" \/ Fault = "staleAdmission")
                 /\ admission' = "leased" /\ accepts' = accepts + 1
                 /\ readers' = readers \ {worker}
                 /\ UNCHANGED <<phase, owner, sends, unsound>>

Release == /\ admission = "leased" /\ admission' = "released"
           /\ UNCHANGED <<phase, owner, sends, unsound, readers, accepts>>

Next == (\E worker \in Workers : TLS(worker) \/ Commit(worker) \/ Confirm(worker)
                                 \/ Restart(worker) \/ Write(worker)
                                 \/ ReadRecord(worker) \/ Admit(worker)) \/ Release
Spec == Init /\ [][Next]_vars

ConfirmedBeforeWrite == ~unsound
SingleUse == sends <= 1 /\ accepts <= 1
NoCompletedSession == admission # "released"
=============================================================================
