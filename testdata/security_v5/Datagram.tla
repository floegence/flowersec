----------------------------- MODULE Datagram -----------------------------
EXTENDS Naturals
CONSTANT Fault
Width == 2
Numbers == 0..3
VARIABLES high, offsets, delivered, duplicate, invalid, lateAccepted
vars == <<high, offsets, delivered, duplicate, invalid, lateAccepted>>

Init == /\ high = 0 /\ offsets = {} /\ delivered = {}
        /\ duplicate = FALSE /\ invalid = FALSE /\ lateAccepted = FALSE

Receive(seq, authenticated, fresh) ==
    LET advance == seq > high
        ahead == IF advance THEN seq - high ELSE 0
        behind == IF advance THEN 0 ELSE high - seq
        within == advance \/ (behind < Width /\ behind \notin offsets)
        shifted == {delta + ahead : delta \in offsets} \cap (0..(Width-1))
    IN /\ within /\ ((authenticated /\ fresh) \/ Fault = "unchecked")
       /\ high' = IF advance THEN seq ELSE high
       /\ offsets' = IF advance THEN (IF Fault = "forgetWindow" THEN {0} ELSE shifted \cup {0})
                                ELSE offsets \cup {behind}
       /\ duplicate' = (duplicate \/ seq \in delivered)
       /\ invalid' = (invalid \/ (high >= seq + Width) \/ ~authenticated \/ ~fresh)
       /\ lateAccepted' = (lateAccepted \/ seq < high)
       /\ delivered' = delivered \cup {seq}

Next == \E seq \in Numbers, authenticated, fresh \in BOOLEAN : Receive(seq, authenticated, fresh)
Spec == Init /\ [][Next]_vars
WindowSafe == ~duplicate /\ ~invalid
NoOutOfOrder == ~lateAccepted
=============================================================================
