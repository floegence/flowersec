---------------------------- MODULE Lifecycle ----------------------------
EXTENDS Naturals
CONSTANT Fault
VARIABLES phase, owner, sends, unsound, admission, readers, accepts,
          txEpoch, rxEpoch, txNext, rxNext, pending, history, delivered,
          badNonce, badDelivery, localFIN, readState, sawFIN, cleanEOF,
          session, unauthorized
Lease == INSTANCE Credential
Records == INSTANCE Stream
leaseVars == <<phase, owner, sends, unsound, admission, readers, accepts>>
recordVars == <<txEpoch, rxEpoch, txNext, rxNext, pending, history, delivered,
                badNonce, badDelivery, localFIN, readState, sawFIN, cleanEOF>>
vars == <<leaseVars, recordVars, session, unauthorized>>

Init == Lease!Init /\ Records!Init /\ session = "waiting" /\ unauthorized = FALSE
CredentialStep == /\ Lease!Next /\ admission' # "released"
                  /\ UNCHANGED <<recordVars, session, unauthorized>>
Bind == /\ session = "waiting" /\ admission = "leased" /\ session' = "established"
        /\ UNCHANGED <<leaseVars, recordVars, unauthorized>>
Traffic == /\ (session = "established" \/ Fault = "bypassBinding")
           /\ Records!Next /\ unauthorized' = (unauthorized \/
                 ((history' # history \/ delivered' # delivered) /\ session # "established"))
           /\ UNCHANGED <<leaseVars, session>>
Close == /\ Lease!Release /\ session' = "closed"
         /\ UNCHANGED <<recordVars, unauthorized>>

Next == CredentialStep \/ Bind \/ Traffic \/ Close
Spec == Init /\ [][Next]_vars
TrafficAuthorized == ~unauthorized /\ (session = "established" => admission = "leased" /\ accepts = 1)
SafeRecords == Records!UniqueNonce /\ Records!UniqueDelivery /\ Records!AuthenticatedEOF /\ Records!OrderedEpochs
SafeLease == Lease!SingleUse /\ Lease!ConfirmedBeforeWrite /\ (session = "closed" => admission = "released")
NoCompletedLifecycle == ~(session = "closed" /\ readState = "clean" /\ txEpoch = 2 /\ rxEpoch = 2
                           /\ (\E entry \in history : entry[2] = "data" /\ entry[1] \in delivered))
=============================================================================
