package main

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestConcurrentReleaseAcknowledgments(t *testing.T) {
	dir := t.TempDir()
	markers := newAuthorizationMarkers(dir)
	const marker = "released-test"
	start := make(chan struct{})
	results := make(chan error, 8)
	for range cap(results) {
		go func() {
			<-start
			results <- markers.release(marker)
		}()
	}
	close(start)
	for range cap(results) {
		if err := <-results; err != nil {
			t.Error(err)
		}
	}
	data, err := os.ReadFile(filepath.Join(dir, marker))
	if err != nil || string(data) != markerContents {
		t.Fatalf("release marker = %q, err = %v", data, err)
	}
	if err := os.WriteFile(filepath.Join(dir, marker), []byte("invalid\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := markers.release(marker); err == nil {
		t.Fatal("acknowledged an invalid existing release marker")
	}
}

func TestAuthorizationMarkerPublicationBarrier(t *testing.T) {
	for _, failSecond := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "sync failure"}[failSecond], func(t *testing.T) {
			var calls int
			started := make(chan struct{})
			gate := make(chan struct{})
			failed := errors.New("directory sync failed")
			m := &authorizationMarkers{flush: func() error {
				calls++
				if calls == 1 {
					close(started)
					<-gate
				}
				if calls == 2 && failSecond {
					return failed
				}
				return nil
			}}
			first := make(chan error, 1)
			go func() { first <- m.commit() }()
			<-started
			var group sync.WaitGroup
			results := make(chan error, 8)
			// All eight links were published while the first sync was in flight.
			seen := m.started.Load()
			for range cap(results) {
				group.Go(func() { results <- m.commitSince(seen) })
			}
			close(gate)
			group.Wait()
			if err := <-first; err != nil {
				t.Fatal(err)
			}
			close(results)
			failures := 0
			for err := range results {
				if err == failed {
					failures++
				} else if err != nil {
					t.Fatal(err)
				}
			}
			if failSecond && (calls != 3 || failures != 1) || !failSecond && (calls != 2 || failures != 0) {
				t.Fatalf("failSecond=%t: calls=%d failures=%d", failSecond, calls, failures)
			}
		})
	}
}
