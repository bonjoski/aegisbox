package telemetry

import (
	"fmt"
	"testing"
	"time"
)

func TestRingBuffer_PushAndSnapshot(t *testing.T) {
	rb := NewRingBuffer[string](4) // power of 2: 4

	for i := 1; i <= 6; i++ {
		rb.Push(fmt.Sprintf("item-%d", i))
	}

	if rb.Len() != 4 {
		t.Fatalf("expected len 4, got %d", rb.Len())
	}

	snap := rb.Snapshot()
	if len(snap) != 4 {
		t.Fatalf("expected snapshot len 4, got %d", len(snap))
	}

	// Should contain the last 4 items: item-3, item-4, item-5, item-6
	expected := []string{"item-3", "item-4", "item-5", "item-6"}
	for i, v := range expected {
		if snap[i] != v {
			t.Errorf("at index %d: expected %s, got %s", i, v, snap[i])
		}
	}
}

func TestTelemetryCollector_FloodAndPriority(t *testing.T) {
	collector := NewTelemetryCollector()

	// 1. Simulate intense log burst exceeding burst token limit
	burstCount := 30000
	recorded := 0
	for i := 0; i < burstCount; i++ {
		if collector.RecordLogLine("vm-test", "flood line", false) {
			recorded++
		}
	}

	if recorded >= burstCount {
		t.Errorf("expected rate limiter to throttle flood, but recorded all %d", recorded)
	}

	if collector.DroppedLogCount() == 0 {
		t.Errorf("expected non-zero dropped log count")
	}

	// 2. Priority canary event must NEVER be dropped despite the log flood
	tripwireTarget := "169.254.169.254"
	collector.RecordCanaryTripwire("vm-test", tripwireTarget)

	select {
	case alert := <-collector.PriorityChannel():
		if !alert.CanaryTriggered || alert.CanaryTargetIP != tripwireTarget {
			t.Errorf("unexpected canary alert: %+v", alert)
		}
		if alert.Severity != SeverityCritical {
			t.Errorf("expected SeverityCritical, got %s", alert.Severity)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("timed out waiting for canary alert on priority channel")
	}
}

func TestTelemetryStreamer_Broadcast(t *testing.T) {
	collector := NewTelemetryCollector()
	streamer := NewTelemetryStreamer(collector)

	sub := streamer.Subscribe(10)
	defer streamer.Unsubscribe(sub)

	event := TelemetryEvent{
		TimestampNs: time.Now().UnixNano(),
		VMID:        "vm-01",
		Category:    "mcp",
		Severity:    SeverityNormal,
		Message:     "tool call initiated",
	}

	streamer.Broadcast(event)

	select {
	case received := <-sub:
		if received.Message != event.Message {
			t.Errorf("expected message %q, got %q", event.Message, received.Message)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("subscriber did not receive event")
	}
}
