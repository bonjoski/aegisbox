// Package bridge provides host-to-microVM communication channels,
// signal routing, and high-performance zero-copy shared memory bridges.
package bridge

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// DefaultSHMCapacity is 64MB (must be a power of 2).
	DefaultSHMCapacity uint32 = 64 * 1024 * 1024

	// HeaderSize is 256 bytes, providing 64-byte cache line alignment for atomics.
	HeaderSize uint32 = 256

	// WrapSentinel indicates that the remainder of the buffer is padded and
	// the next record begins at index 0.
	WrapSentinel uint32 = 0xFFFFFFFF

	// Maximum single artifact slice size (32MB).
	MaxArtifactSliceSize uint32 = 32 * 1024 * 1024

	// Status flags
	FlagInitialized uint32 = 1
	FlagTeardown    uint32 = 2
)

var (
	ErrBufferFull   = errors.New("shm: shared memory ring buffer is full")
	ErrBufferEmpty  = errors.New("shm: shared memory ring buffer is empty")
	ErrCorruptRing  = errors.New("shm: corrupted ring buffer cursors or lengths")
	ErrPayloadLarge = errors.New("shm: artifact slice exceeds maximum capacity")
)

// RingHeader mirrors the memory layout of the 256-byte cache-line aligned shared header.
type RingHeader struct {
	Head     uint64    // Monotonic producer write cursor
	_pad0    [56]byte  // Align to cache-line (64 bytes)
	Tail     uint64    // Monotonic consumer read cursor
	_pad1    [56]byte  // Align to cache-line (128 bytes)
	Capacity uint32    // Total buffer capacity in bytes
	Flags    uint32    // Status / teardown flags
	_pad2    [56]byte  // Align to 256 bytes
}

// SPSCSharedMemoryRing implements a lock-free Single-Producer Single-Consumer
// ring buffer for sub-microsecond artifact pointer handoffs across microVM boundaries.
type SPSCSharedMemoryRing struct {
	mu         sync.Mutex
	file       *os.File
	mmapData   []byte
	capacity   uint32
	payloadCap uint32
	isOwner    bool
}

// NewSPSCSharedMemoryRing creates or attaches to an anonymous shared memory arena.
func NewSPSCSharedMemoryRing(capacity uint32) (*SPSCSharedMemoryRing, error) {
	if capacity == 0 {
		capacity = DefaultSHMCapacity
	}
	// Capacity must be power of two and greater than HeaderSize
	if capacity <= HeaderSize || (capacity&(capacity-1)) != 0 {
		return nil, fmt.Errorf("shm: capacity (%d) must be a power of 2 greater than %d", capacity, HeaderSize)
	}

	f, mmapData, err := createSharedMemoryFile("aegisbox_shm", int64(capacity))
	if err != nil {
		return nil, fmt.Errorf("shm: failed to allocate memory arena: %w", err)
	}

	ring := &SPSCSharedMemoryRing{
		file:       f,
		mmapData:   mmapData,
		capacity:   capacity,
		payloadCap: capacity - HeaderSize,
		isOwner:    true,
	}

	// Initialize ring header
	ring.setHead(0)
	ring.setTail(0)
	binary.LittleEndian.PutUint32(ring.mmapData[128:132], capacity)
	binary.LittleEndian.PutUint32(ring.mmapData[132:136], FlagInitialized)

	return ring, nil
}

// AttachSPSCSharedMemoryRing maps an existing shared memory descriptor created by supervisor.
func AttachSPSCSharedMemoryRing(f *os.File, capacity uint32) (*SPSCSharedMemoryRing, error) {
	mmapData, err := mapExistingMemory(f, int64(capacity))
	if err != nil {
		return nil, fmt.Errorf("shm: failed to map shared memory: %w", err)
	}

	return &SPSCSharedMemoryRing{
		file:       f,
		mmapData:   mmapData,
		capacity:   capacity,
		payloadCap: capacity - HeaderSize,
		isOwner:    false,
	}, nil
}

// File returns the underlying OS file descriptor passed to hypervisor / vhost-user.
func (r *SPSCSharedMemoryRing) File() *os.File {
	return r.file
}

// FD returns the integer file descriptor.
func (r *SPSCSharedMemoryRing) FD() uintptr {
	if r.file == nil {
		return 0
	}
	return r.file.Fd()
}

func (r *SPSCSharedMemoryRing) head() uint64 {
	return atomic.LoadUint64((*uint64)(unsafePointer(&r.mmapData[0])))
}

func (r *SPSCSharedMemoryRing) setHead(v uint64) {
	atomic.StoreUint64((*uint64)(unsafePointer(&r.mmapData[0])), v)
}

func (r *SPSCSharedMemoryRing) tail() uint64 {
	return atomic.LoadUint64((*uint64)(unsafePointer(&r.mmapData[64])))
}

func (r *SPSCSharedMemoryRing) setTail(v uint64) {
	atomic.StoreUint64((*uint64)(unsafePointer(&r.mmapData[64])), v)
}

func (r *SPSCSharedMemoryRing) payloadBase() []byte {
	return r.mmapData[HeaderSize:]
}

// WritePayload writes an artifact slice into the shared arena using atomic pointer increments.
// Returns the monotonic offset inside the stream.
func (r *SPSCSharedMemoryRing) WritePayload(data []byte) (uint64, error) {
	dataLen := uint32(len(data))
	if dataLen == 0 {
		return 0, errors.New("shm: cannot write zero-length payload")
	}
	if dataLen > MaxArtifactSliceSize || dataLen > (r.payloadCap/2) {
		return 0, fmt.Errorf("%w: requested %d bytes", ErrPayloadLarge, dataLen)
	}

	// 4 bytes length + payload + 4-byte alignment padding
	recordLen := 4 + dataLen
	alignedRecordLen := (recordLen + 3) &^ 3

	currentHead := r.head()
	currentTail := r.tail()

	// Check available space
	occupied := currentHead - currentTail
	if occupied+uint64(alignedRecordLen) > uint64(r.payloadCap) {
		return 0, ErrBufferFull
	}

	payload := r.payloadBase()
	writeOffset := uint32(currentHead % uint64(r.payloadCap))

	// Check if record would wrap past the boundary
	if writeOffset+alignedRecordLen > r.payloadCap {
		// Needs wrap sentinel
		padBytes := r.payloadCap - writeOffset
		if occupied+uint64(padBytes)+uint64(alignedRecordLen) > uint64(r.payloadCap) {
			return 0, ErrBufferFull
		}

		// Write WrapSentinel at the end
		binary.LittleEndian.PutUint32(payload[writeOffset:writeOffset+4], WrapSentinel)
		currentHead += uint64(padBytes)
		writeOffset = 0
	}

	// Write record: 4 bytes length, then data
	binary.LittleEndian.PutUint32(payload[writeOffset:writeOffset+4], dataLen)
	copy(payload[writeOffset+4:writeOffset+4+dataLen], data)

	offsetAssigned := currentHead

	// Release memory barrier: commit new head cursor
	r.setHead(currentHead + uint64(alignedRecordLen))

	return offsetAssigned, nil
}

// ReadPayload reads the next available contiguous payload from the shared memory ring.
func (r *SPSCSharedMemoryRing) ReadPayload() ([]byte, error) {
	currentTail := r.tail()
	currentHead := r.head()

	if currentTail >= currentHead {
		return nil, ErrBufferEmpty
	}

	payload := r.payloadBase()
	readOffset := uint32(currentTail % uint64(r.payloadCap))

	// Read 4-byte length prefix
	recordLen := binary.LittleEndian.Uint32(payload[readOffset : readOffset+4])

	// If wrap sentinel, skip to wrapped boundary (index 0)
	if recordLen == WrapSentinel {
		padBytes := r.payloadCap - readOffset
		currentTail += uint64(padBytes)
		r.setTail(currentTail)
		if currentTail >= currentHead {
			return nil, ErrBufferEmpty
		}
		readOffset = 0
		recordLen = binary.LittleEndian.Uint32(payload[readOffset : readOffset+4])
	}

	if recordLen == 0 || recordLen > MaxArtifactSliceSize || readOffset+4+recordLen > r.payloadCap {
		return nil, fmt.Errorf("%w: invalid record length %d at offset %d", ErrCorruptRing, recordLen, readOffset)
	}

	// Direct zero-copy slice from mapped memory
	data := make([]byte, recordLen)
	copy(data, payload[readOffset+4:readOffset+4+recordLen])

	alignedRecordLen := (4 + recordLen + 3) &^ 3

	// Release memory barrier: advance tail cursor
	r.setTail(currentTail + uint64(alignedRecordLen))

	return data, nil
}

// Close unmaps the shared memory arena and releases the underlying descriptor.
func (r *SPSCSharedMemoryRing) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.mmapData != nil {
		_ = unmapMemory(r.mmapData)
		r.mmapData = nil
	}

	if r.file != nil {
		err := r.file.Close()
		r.file = nil
		return err
	}

	return nil
}

// BenchmarkArtifactTransfer measures the latency and throughput of a simulated artifact transfer.
func BenchmarkArtifactTransfer(ring *SPSCSharedMemoryRing, sizeBytes int) (time.Duration, float64, error) {
	chunk := make([]byte, 1024*1024) // 1MB chunk
	for i := range chunk {
		chunk[i] = byte(i % 256)
	}

	numChunks := sizeBytes / (1024 * 1024)
	if numChunks <= 0 {
		numChunks = 1
	}

	start := time.Now()

	for i := 0; i < numChunks; i++ {
		if _, err := ring.WritePayload(chunk); err != nil {
			return 0, 0, fmt.Errorf("write chunk %d failed: %w", i, err)
		}
		readData, err := ring.ReadPayload()
		if err != nil {
			return 0, 0, fmt.Errorf("read chunk %d failed: %w", i, err)
		}
		if len(readData) != len(chunk) {
			return 0, 0, errors.New("read chunk size mismatch")
		}
	}

	elapsed := time.Since(start)
	totalMB := float64(sizeBytes) / (1024 * 1024)
	mbPerSec := totalMB / elapsed.Seconds()

	return elapsed, mbPerSec, nil
}
