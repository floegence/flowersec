------------------------------ MODULE Policy ------------------------------
EXTENDS Naturals
CONSTANT Fault
Policies == {"ca", "pinA", "pinB"}
VARIABLES stage, declared, blocked, replaced, tls, identity, live, wire, error
vars == <<stage, declared, blocked, replaced, tls, identity, live, wire, error>>

Init == /\ stage = "choose" /\ declared = "unset" /\ blocked = {}
        /\ replaced = FALSE /\ tls = FALSE /\ identity = FALSE /\ live = TRUE
        /\ wire = FALSE /\ error = FALSE

Choose(policy) == /\ stage = "choose" /\ policy \in Policies
                  /\ (blocked = {} \/ (policy \notin blocked /\ policy # "ca") \/ Fault = "downgrade")
                  /\ declared' = policy /\ stage' = "attempt"
                  /\ error' = (blocked # {} /\ (policy \in blocked \/ policy = "ca"))
                  /\ UNCHANGED <<blocked, replaced, tls, identity, live, wire>>

Verify(proof, match) ==
    /\ stage = "attempt" /\ tls' = proof /\ identity' = match
    /\ stage' = IF proof /\ match THEN "ready" ELSE "rejected"
    /\ UNCHANGED <<declared, blocked, replaced, live, wire, error>>

Replace == /\ stage = "rejected" /\ declared # "ca" /\ ~replaced
           /\ blocked' = blocked \cup {declared} /\ replaced' = TRUE
           /\ stage' = "choose" /\ tls' = FALSE /\ identity' = FALSE
           /\ UNCHANGED <<declared, live, wire, error>>

Expire == /\ live /\ ~wire /\ live' = FALSE
          /\ UNCHANGED <<stage, declared, blocked, replaced, tls, identity, wire, error>>
Spend == /\ stage = "ready" /\ live /\ stage' = "spent"
         /\ UNCHANGED <<declared, blocked, replaced, tls, identity, live, wire, error>>
Write == /\ stage = "spent" /\ (live \/ Fault = "staleTime") /\ wire' = TRUE /\ stage' = "sent"
         /\ UNCHANGED <<declared, blocked, replaced, tls, identity, live, error>>

Next == (\E policy \in Policies : Choose(policy)) \/ (\E proof, match \in BOOLEAN : Verify(proof, match))
        \/ Replace \/ Expire \/ Spend \/ Write
Spec == Init /\ [][Next]_vars
NoDowngrade == ~error
EligibleWrite == wire => tls /\ identity /\ live
NoSuccessfulRotation == ~(wire /\ replaced)
=============================================================================
