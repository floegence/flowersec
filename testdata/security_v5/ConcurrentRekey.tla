-------------------------- MODULE ConcurrentRekey --------------------------
EXTENDS Naturals
CONSTANT Fault
Directions == {"outbound", "inbound"}
Streams == {1, 2}
Other(direction) == IF direction = "outbound" THEN "inbound" ELSE "outbound"

VARIABLES lanes
InitialLane == [phase |-> "idle", prepared |-> {}, prior |-> {}, control |-> 0,
                roots |-> {0}, scan |-> FALSE]
Init == lanes = [direction \in Directions |-> InitialLane]
SetLane(direction, lane) == lanes' = [lanes EXCEPT ![direction] = lane]

Stage(direction, lane) ==
    /\ lane.phase = "idle"
    /\ SetLane(direction, [lane EXCEPT !.phase = "staged", !.roots = @ \cup {1}])

Prepare(direction, lane, stream) ==
    /\ lane.phase = "staged" /\ stream \notin lane.prepared
    /\ LET crossed == lanes[Other(direction)].phase = "staged"
       IN SetLane(direction, [lane EXCEPT !.prepared = @ \cup {stream},
                              !.prior = IF crossed THEN @ \cup {stream} ELSE @])

Commit(direction, lane) ==
    /\ lane.phase = "staged" /\ (lane.prepared = Streams \/ Fault = "earlyCommit")
    /\ SetLane(direction, [lane EXCEPT !.phase = "committed"])

TakeControl(direction, lane) ==
    /\ lane.phase \in {"committed", "acked"} /\ lane.control = 0
    /\ SetLane(direction, [lane EXCEPT !.control = 1])

ResolvePrior(direction, lane, stream) ==
    /\ stream \in lane.prior /\ 0 \in lane.roots
    /\ SetLane(direction, [lane EXCEPT !.prior = @ \ {stream}])

Scan(direction, lane) ==
    /\ lane.control = 1 /\ ~lane.scan
    /\ lane.prepared = Streams /\ (lane.prior = {} \/ Fault = "ignorePrior")
    /\ SetLane(direction, [lane EXCEPT !.scan = TRUE])

Collect(direction, lane) ==
    /\ lane.scan /\ 0 \in lane.roots
    /\ SetLane(direction, [lane EXCEPT !.roots = @ \ {0}, !.scan = FALSE])

ACK(direction, lane) ==
    /\ lane.phase = "committed" /\ SetLane(direction, [lane EXCEPT !.phase = "acked"])

Next == \E direction \in Directions : LET lane == lanes[direction] IN
    Stage(direction, lane) \/ Commit(direction, lane) \/ TakeControl(direction, lane)
    \/ Scan(direction, lane) \/ Collect(direction, lane) \/ ACK(direction, lane)
    \/ (\E stream \in Streams : Prepare(direction, lane, stream) \/ ResolvePrior(direction, lane, stream))

Spec == Init /\ [][Next]_lanes
AllStreamsReady == \A direction \in Directions : LET lane == lanes[direction] IN
    lane.phase \in {"committed", "acked"} => lane.prepared = Streams
LiveRoots == \A direction \in Directions : LET lane == lanes[direction] IN
    /\ lane.control \in lane.roots
    /\ ((lane.prior # {} \/ lane.prepared # Streams) => 0 \in lane.roots)
    /\ (lane.phase # "idle" => 1 \in lane.roots)
NoCrossedUpdates == ~(\A direction \in Directions : lanes[direction].prior = Streams)
NoReclamation == ~(\A direction \in Directions :
                         lanes[direction].phase = "acked" /\ lanes[direction].roots = {1})
=============================================================================
