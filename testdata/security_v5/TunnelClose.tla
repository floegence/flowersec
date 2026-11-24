--------------------------- MODULE TunnelClose ---------------------------
EXTENDS Naturals
CONSTANT Fault
Sides == {"client", "server"}
Peer(side) == IF side = "client" THEN "server" ELSE "client"
VARIABLES sent, authenticated, fins, observed, relayNormal, normal, failed
vars == <<sent, authenticated, fins, observed, relayNormal, normal, failed>>

Init == /\ sent = {} /\ authenticated = {} /\ fins = {} /\ observed = {}
        /\ relayNormal = FALSE /\ normal = {} /\ failed = {}
Live(side) == side \notin (failed \cup normal)
Send(side) == /\ Live(side) /\ sent' = sent \cup {side}
              /\ UNCHANGED <<authenticated, fins, observed, relayNormal, normal, failed>>
Authenticate(side) == /\ Live(side) /\ Peer(side) \in sent
                      /\ authenticated' = authenticated \cup {side}
                      /\ UNCHANGED <<sent, fins, observed, relayNormal, normal, failed>>
SendFIN(side) == /\ Live(side) /\ side \in sent /\ side \in authenticated
                 /\ (side = "server" \/ side \in observed)
                 /\ fins' = fins \cup {side}
                 /\ UNCHANGED <<sent, authenticated, observed, relayNormal, normal, failed>>
ObserveFIN(side) == /\ Live(side) /\ side \in authenticated /\ Peer(side) \in fins
                    /\ observed' = observed \cup {side}
                    /\ UNCHANGED <<sent, authenticated, fins, relayNormal, normal, failed>>
RelayClose == /\ ~relayNormal /\ relayNormal' = TRUE
              /\ UNCHANGED <<sent, authenticated, fins, observed, normal, failed>>
Finish(side) == /\ Live(side)
                /\ ((side \in fins /\ side \in observed) \/ Fault = "carrierOnly")
                /\ (side = "server" \/ relayNormal \/ Fault = "skipRelayClose")
                /\ normal' = normal \cup {side}
                /\ UNCHANGED <<sent, authenticated, fins, observed, relayNormal, failed>>
Fail(side) == /\ Live(side) /\ failed' = failed \cup {side}
              /\ UNCHANGED <<sent, authenticated, fins, observed, relayNormal, normal>>

Next == RelayClose \/ (\E side \in Sides : Send(side) \/ Authenticate(side) \/ SendFIN(side)
                         \/ ObserveFIN(side) \/ Finish(side) \/ Fail(side))
Spec == Init /\ [][Next]_vars
AuthenticatedClose == normal \subseteq (sent \cap authenticated \cap fins \cap observed)
                      /\ (normal \cap failed = {})
ClientWaitsForRelay == "client" \in normal => relayNormal
NoCoordinatedClose == normal # Sides
=============================================================================
