package bridge

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"syscall"
)

// SignalPort defines the dedicated vsock port for signal and lifecycle coordination (0x5161 = "SIGA").
const SignalPort uint32 = 0x5161

// FrameSize is the fixed size in bytes of a vsock signal frame ([1-byte type][4-byte payload]).
const FrameSize = 5

// Message types for the bidirectional vsock signal protocol.
const (
	// MsgSignal represents an OS signal forwarded from host to guest (payload: signal number).
	MsgSignal byte = 0x01

	// MsgExit represents the process exit code returned from guest to host (payload: int32 exit code).
	MsgExit byte = 0x02

	// MsgOOM represents a guest kernel OOM killer event sent to host (payload: oom kill score / counter).
	MsgOOM byte = 0x03

	// MsgHeartbeat represents the 1-second host-to-guest keepalive ping (payload: sequence / timestamp).
	MsgHeartbeat byte = 0x04

	// MsgHeartbeatAck represents the guest keepalive acknowledgement sent back to host (payload: sequence).
	MsgHeartbeatAck byte = 0x05
)

// Frame represents a single protocol message on the vsock signal channel.
type Frame struct {
	Type    byte
	Payload uint32
}

// WriteFrame encodes and transmits a 5-byte frame over the given writer.
func WriteFrame(w io.Writer, f Frame) error {
	var buf [FrameSize]byte
	buf[0] = f.Type
	binary.BigEndian.PutUint32(buf[1:], f.Payload)

	if _, err := w.Write(buf[:]); err != nil {
		return fmt.Errorf("failed to write vsock frame (type=0x%02x): %w", f.Type, err)
	}
	return nil
}

// ReadFrame reads and decodes exactly 5 bytes from the reader into a Frame.
func ReadFrame(r io.Reader) (Frame, error) {
	var buf [FrameSize]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return Frame{}, fmt.Errorf("failed to read vsock frame: %w", err)
	}

	return Frame{
		Type:    buf[0],
		Payload: binary.BigEndian.Uint32(buf[1:]),
	}, nil
}

// SignalToPayload converts an os.Signal to a 32-bit payload.
func SignalToPayload(sig os.Signal) (uint32, error) {
	switch s := sig.(type) {
	case syscall.Signal:
		return uint32(s), nil
	default:
		return 0, fmt.Errorf("unsupported signal type: %T", sig)
	}
}

// PayloadToSignal converts a 32-bit payload back into a syscall.Signal.
func PayloadToSignal(payload uint32) syscall.Signal {
	return syscall.Signal(payload)
}

// ExitCodeToPayload safely encodes an integer exit code (including negative) to uint32.
func ExitCodeToPayload(exitCode int) uint32 {
	return uint32(int32(exitCode))
}

// PayloadToExitCode decodes a uint32 payload into an integer exit code.
func PayloadToExitCode(payload uint32) int {
	return int(int32(payload))
}

// MsgTypeName returns a human-readable representation of a message type.
func MsgTypeName(t byte) string {
	switch t {
	case MsgSignal:
		return "MSG_SIGNAL"
	case MsgExit:
		return "MSG_EXIT"
	case MsgOOM:
		return "MSG_OOM"
	case MsgHeartbeat:
		return "MSG_HEARTBEAT"
	case MsgHeartbeatAck:
		return "MSG_HEARTBEAT_ACK"
	default:
		return fmt.Sprintf("MSG_UNKNOWN(0x%02x)", t)
	}
}
