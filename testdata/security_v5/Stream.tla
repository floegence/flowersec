------------------------------ MODULE Stream ------------------------------
EXTENDS Naturals
CONSTANT Fault
MaxEpoch == 2
MaxSequence == 2
VARIABLES txEpoch, rxEpoch, txNext, rxNext, pending, history, delivered,
          badNonce, badDelivery, localFIN, readState, sawFIN, cleanEOF
tx == <<txEpoch, txNext, pending, history, badNonce, localFIN>>
rx == <<rxEpoch, rxNext, delivered, badDelivery, readState, sawFIN, cleanEOF>>
vars == <<tx, rx>>

Init == /\ txEpoch = 0 /\ rxEpoch = 0 /\ txNext = 0 /\ rxNext = 0
        /\ pending = FALSE /\ history = {} /\ delivered = {}
        /\ badNonce = FALSE /\ badDelivery = FALSE /\ localFIN = FALSE
        /\ readState = "open" /\ sawFIN = FALSE /\ cleanEOF = FALSE

Send(kind) ==
    LET nonce == <<txEpoch, txNext>> IN
    /\ ~localFIN /\ ~pending /\ txNext <= MaxSequence
    /\ kind \in {"data", "fin", "update"}
    /\ kind = "update" => txEpoch < MaxEpoch
    /\ badNonce' = (badNonce \/ \E entry \in history : entry[1] = nonce)
    /\ history' = history \cup {<<nonce, kind>>}
    /\ txNext' = txNext + 1 /\ localFIN' = (kind = "fin")
    /\ pending' = (kind = "update") /\ UNCHANGED <<txEpoch, rx>>

Receive(entry) ==
    LET nonce == entry[1] IN
    /\ readState = "open" /\ entry \in history
    /\ nonce = <<rxEpoch, rxNext>>
    /\ badDelivery' = (badDelivery \/ nonce \in delivered)
    /\ delivered' = delivered \cup {nonce}
    /\ rxEpoch' = IF entry[2] = "update" THEN rxEpoch + 1 ELSE rxEpoch
    /\ rxNext' = IF entry[2] = "update" THEN 0 ELSE rxNext + 1
    /\ sawFIN' = (entry[2] = "fin")
    /\ readState' = IF sawFIN' THEN "afterFIN" ELSE readState
    /\ UNCHANGED <<tx, cleanEOF>>

Ack(epoch) ==
    /\ epoch \in 1..rxEpoch /\ ~localFIN
    /\ (pending /\ epoch = txEpoch + 1) \/ (Fault = "staleAck" /\ epoch = txEpoch)
    /\ txEpoch' = epoch /\ txNext' = 0 /\ pending' = FALSE
    /\ UNCHANGED <<history, badNonce, localFIN, rx>>

End(signal) ==
    /\ readState \in {"open", "afterFIN"}
    /\ signal \in {"eof", "trailing", "reset"}
    /\ readState' = IF signal = "eof" /\ (sawFIN \/ Fault = "earlyEOF") THEN "clean" ELSE "failed"
    /\ cleanEOF' = (signal = "eof")
    /\ UNCHANGED <<tx, rxEpoch, rxNext, delivered, badDelivery, sawFIN>>

Next == (\E kind \in {"data", "fin", "update"} : Send(kind))
        \/ (\E entry \in history : Receive(entry)) \/ (\E epoch \in 1..MaxEpoch : Ack(epoch))
        \/ (\E signal \in {"eof", "trailing", "reset"} : End(signal))
Spec == Init /\ [][Next]_vars
UniqueNonce == ~badNonce
UniqueDelivery == ~badDelivery
OrderedEpochs == txEpoch <= rxEpoch /\ rxEpoch <= txEpoch + 1 /\ rxEpoch <= MaxEpoch
AuthenticatedEOF == readState = "clean" => sawFIN /\ cleanEOF
NoRekeyedClose == ~(readState = "clean" /\ txEpoch = MaxEpoch /\ rxEpoch = MaxEpoch)
=============================================================================
