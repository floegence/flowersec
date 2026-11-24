----------------------------- MODULE EpochWindow -----------------------------
EXTENDS Naturals
CONSTANT Fault
Epochs == 0..3
VARIABLES current, windows, delivered, duplicate, stale, latePrevious
vars == <<current, windows, delivered, duplicate, stale, latePrevious>>

Init == /\ current = 0 /\ windows = {} /\ delivered = {}
        /\ duplicate = FALSE /\ stale = FALSE /\ latePrevious = FALSE

Rekey == /\ current < 3 /\ current' = current + 1
         /\ UNCHANGED <<windows, delivered, duplicate, stale, latePrevious>>

Receive(epoch) ==
    /\ epoch <= current /\ (current <= epoch + 1 \/ Fault = "retainedRoot")
    /\ epoch \notin windows
    /\ windows' = {kept \in windows : epoch <= kept + 1} \cup {epoch}
    /\ duplicate' = (duplicate \/ epoch \in delivered)
    /\ stale' = (stale \/ current > epoch + 1)
    /\ latePrevious' = (latePrevious \/ (epoch + 1 = current /\ current \in delivered))
    /\ delivered' = delivered \cup {epoch} /\ UNCHANGED current

Next == Rekey \/ (\E epoch \in Epochs : Receive(epoch))
Spec == Init /\ [][Next]_vars
AtMostOnce == ~duplicate
EligibleEpoch == ~stale
NoLatePrevious == ~latePrevious
=============================================================================
