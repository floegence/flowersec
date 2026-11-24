------------------------------ MODULE Profile ------------------------------
EXTENDS Naturals
CONSTANT Fault
Modes == {"tls", "http", "loopback"}
Authorities == {"a", "b"}
VARIABLES entry, envelope, configured, observed, phase, tls, permission, local, origin
vars == <<entry, envelope, configured, observed, phase, tls, permission, local, origin>>

Init == /\ entry \in Modes /\ envelope \in Modes
        /\ configured \in Authorities /\ observed \in Authorities
        /\ phase = "decode" /\ tls = FALSE /\ permission = FALSE
        /\ local = FALSE /\ origin = FALSE

Decode == /\ phase = "decode" /\ (entry = envelope \/ Fault = "mixedHandles")
          /\ phase' = "verify"
          /\ UNCHANGED <<entry, envelope, configured, observed, tls, permission, local, origin>>
Verify == /\ phase = "verify" /\ phase' = "ready"
          /\ tls' \in BOOLEAN /\ permission' \in BOOLEAN /\ local' \in BOOLEAN /\ origin' \in BOOLEAN
          /\ UNCHANGED <<entry, envelope, configured, observed>>
Upgrade == /\ phase = "ready" /\ (observed = configured \/ Fault = "wrongAuthority")
           /\ IF entry = "tls" THEN tls ELSE (origin /\ (permission \/ Fault = "originOnly"))
           /\ (entry # "loopback" \/ local \/ Fault = "remoteLoopback")
           /\ phase' = "upgraded"
           /\ UNCHANGED <<entry, envelope, configured, observed, tls, permission, local, origin>>

Next == Decode \/ Verify \/ Upgrade
Spec == Init /\ [][Next]_vars
Isolated == phase = "upgraded" => entry = envelope /\ observed = configured
Authorized == phase = "upgraded" => (IF entry = "tls" THEN tls ELSE origin /\ permission)
LocalOnly == (phase = "upgraded" /\ entry = "loopback") => local
NoHTTP == ~(phase = "upgraded" /\ entry = "http" /\ ~tls /\ ~local)
NoLoopback == ~(phase = "upgraded" /\ entry = "loopback" /\ ~tls)
=============================================================================
