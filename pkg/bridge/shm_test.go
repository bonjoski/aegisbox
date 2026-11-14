package bridge

import (
	"bytes"
	"sync"
	"testing"
)

func TestSPSCSharedMemoryRing_BasicWriteRead(t *testing.T) {
	// 1MB test arena
	ring, err := NewSPSCSharedMemoryRing(1024 * 1024)
	if err != nil {
		t.Fatalf("NewSPSCSharedMemoryRing failed: %v", err)
	}
	defer func() { _ = ring.Close() }()

	payload := []byte("hello zero-copy microvm bridge artifact payload")

	offset, err := ring.WritePayload(payload)
	if err != nil {
		t.Fatalf("WritePayload failed: %v", err)
	}
	if offset != 0 {
		t.Errorf("expected first offset to be 0, got %d", offset)
	}

	readData, err := ring.ReadPayload()
	if err != nil {
		t.Fatalf("ReadPayload failed: %v", err)
	}

	if !bytes.Equal(readData, payload) {
		t.Fatalf("payload mismatch: expected %q, got %q", string(payload), string(readData))
	}

	// Buffer should now be empty
	_, err = ring.ReadPayload()
	if err != ErrBufferEmpty {
		t.Errorf("expected ErrBufferEmpty, got %v", err)
	}
}

func TestSPSCSharedMemoryRing_WrapAround(t *testing.T) {
	// Small ring to easily force wrap-around: 64KB (65536 bytes)
	ring, err := NewSPSCSharedMemoryRing(65536)
	if err != nil {
		t.Fatalf("NewSPSCSharedMemoryRing failed: %v", err)
	}
	defer func() { _ = ring.Close() }()

	chunkSize := 1024 // 1KB chunks
	data := make([]byte, chunkSize)
	for i := range data {
		data[i] = byte(i % 256)
	}

	// Write and read 200 chunks (200KB total, exceeding 64KB buffer several times)
	for i := 0; i < 200; i++ {
		_, err := ring.WritePayload(data)
		if err != nil {
			t.Fatalf("write chunk %d failed: %v", i, err)
		}

		readChunk, err := ring.ReadPayload()
		if err != nil {
			t.Fatalf("read chunk %d failed: %v", i, err)
		}

		if len(readChunk) != len(data) {
			t.Fatalf("chunk %d length mismatch: expected %d, got %d", i, len(data), len(readChunk))
		}
	}
}

func TestSPSCSharedMemoryRing_ConcurrentProducerConsumer(t *testing.T) {
	ring, err := NewSPSCSharedMemoryRing(4 * 1024 * 1024) // 4MB
	if err != nil {
		t.Fatalf("NewSPSCSharedMemoryRing failed: %v", err)
	}
	defer func() { _ = ring.Close() }()

	const numItems = 1000
	itemSize := 512

	var wg sync.WaitGroup
	wg.Add(2)

	// Producer goroutine
	go func() {
		defer wg.Done()
		for i := 0; i < numItems; i++ {
			buf := make([]byte, itemSize)
			buf[0] = byte(i >> 8)
			buf[1] = byte(i & 0xFF)

			for {
				_, err := ring.WritePayload(buf)
				if err == nil {
					break
				}
				if err != ErrBufferFull {
					t.Errorf("unexpected write error: %v", err)
					return
				}
			}
		}
	}()

	// Consumer goroutine
	go func() {
		defer wg.Done()
		for i := 0; i < numItems; i++ {
			for {
				data, err := ring.ReadPayload()
				if err == nil {
					gotSeq := (int(data[0]) << 8) | int(data[1])
					if gotSeq != i {
						t.Errorf("sequence mismatch: expected %d, got %d", i, gotSeq)
					}
					break
				}
				if err != ErrBufferEmpty {
					t.Errorf("unexpected read error: %v", err)
					return
				}
			}
		}
	}()

	wg.Wait()
}

func TestSPSCSharedMemoryRing_Benchmark(t *testing.T) {
	ring, err := NewSPSCSharedMemoryRing(16 * 1024 * 1024) // 16MB
	if err != nil {
		t.Fatalf("NewSPSCSharedMemoryRing failed: %v", err)
	}
	defer func() { _ = ring.Close() }()

	elapsed, mbPerSec, err := BenchmarkArtifactTransfer(ring, 8*1024*1024) // 8MB
	if err != nil {
		t.Fatalf("BenchmarkArtifactTransfer failed: %v", err)
	}

	t.Logf("Transferred 8MB in %v (Throughput: %.2f MB/s)", elapsed, mbPerSec)
	if mbPerSec <= 0 {
		t.Error("expected positive throughput")
	}
}
