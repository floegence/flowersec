package main

import "testing"

func TestNativePostLossStreamIDSelectsRealPostLossStream(t *testing.T) {
	qlog := []byte("\x1e{\"trace\":{\"common_fields\":{\"reference_time\":{\"wall_clock_time\":\"2026-01-01T00:00:00Z\"}}}}\n" +
		"\x1e{\"time\":1,\"name\":\"transport:packet_sent\",\"data\":{\"frames\":[{\"frame_type\":\"stream\",\"stream_id\":0}]}}\n" +
		"\x1e{\"time\":2,\"name\":\"recovery:packet_lost\",\"data\":{}}\n" +
		"\x1e{\"time\":3,\"name\":\"transport:packet_received\",\"data\":{\"frames\":[{\"frame_type\":\"stream\",\"stream_id\":4}]}}\n" +
		"\x1e{\"time\":4,\"name\":\"transport:packet_sent\",\"data\":{\"frames\":[{\"frame_type\":\"ack\"},{\"frame_type\":\"stream\",\"stream_id\":68}]}}\n" +
		"\x1e{\"time\":5,\"name\":\"transport:packet_received\",\"data\":{\"frames\":[{\"frame_type\":\"stream\",\"stream_id\":68}]}}\n")
	streamID, err := nativePostLossStreamID(qlog)
	if err != nil {
		t.Fatal(err)
	}
	if streamID != 68 {
		t.Fatalf("post-loss stream ID = %d, want 68", streamID)
	}
	observations := []nativeApplicationObservation{
		{event: "targeted_loss_released", streamID: streamID},
		{event: "rpc_completed", streamID: streamID},
	}
	times, completedAt, err := nativeObservationQLOGTimes(qlog, observations)
	if err != nil {
		t.Fatal(err)
	}
	if len(times) != 2 || times[0] <= 0 || times[1] < times[0] || completedAt < times[1] {
		t.Fatalf("targeted-loss observation times = %v, completed = %d", times, completedAt)
	}
}

func TestNativePostLossStreamIDFailsClosedWithoutPostLossStream(t *testing.T) {
	qlog := []byte("\x1e{\"time\":1,\"name\":\"recovery:packet_lost\",\"data\":{}}\n")
	if _, err := nativePostLossStreamID(qlog); err == nil {
		t.Fatal("targeted-loss qlog without post-loss STREAM frame was accepted")
	}
}
