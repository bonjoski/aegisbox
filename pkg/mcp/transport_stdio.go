package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
)

// RunStdioPipeProxy handles bidirectional JSON-RPC streaming between client and downstream server over stdio streams.
func (p *Proxy) RunStdioPipeProxy(ctx context.Context, clientIn io.Reader, clientOut io.Writer, serverIn io.Writer, serverOut io.Reader) error {
	errChan := make(chan error, 2)
	doneChan := make(chan struct{}, 1)

	// Goroutine 1: Client -> Server (with Policy Interception & Re-serialization)
	go func() {
		scanner := bufio.NewScanner(clientIn)
		// Support up to 10MB frames for large code files/diffs
		buf := make([]byte, 64*1024)
		scanner.Buffer(buf, 10*1024*1024)

		for scanner.Scan() {
			select {
			case <-ctx.Done():
				return
			default:
			}

			line := scanner.Bytes()
			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}

			forwardBytes, rejectResp, err := p.ProcessClientRequest(ctx, line)
			if err != nil {
				errChan <- fmt.Errorf("client request processing error: %w", err)
				return
			}

			if rejectResp != nil {
				// Immediate policy denial or parse rejection
				respBytes, _ := json.Marshal(rejectResp)
				respBytes = append(respBytes, '\n')
				if _, writeErr := clientOut.Write(respBytes); writeErr != nil {
					errChan <- writeErr
					return
				}
				continue
			}

			// Forward normalized payload downstream to server
			forwardBytes = append(forwardBytes, '\n')
			if _, writeErr := serverIn.Write(forwardBytes); writeErr != nil {
				errChan <- writeErr
				return
			}
		}

		if err := scanner.Err(); err != nil {
			errChan <- err
			return
		}

		// Half-close server input if supported so downstream server knows client is done writing
		if cw, ok := serverIn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()

	// Goroutine 2: Server -> Client (direct streaming response forward)
	go func() {
		scanner := bufio.NewScanner(serverOut)
		buf := make([]byte, 64*1024)
		scanner.Buffer(buf, 10*1024*1024)

		for scanner.Scan() {
			select {
			case <-ctx.Done():
				return
			default:
			}

			line := scanner.Bytes()
			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}

			outBytes := append(line, '\n')
			if _, err := clientOut.Write(outBytes); err != nil {
				errChan <- err
				return
			}
		}

		if err := scanner.Err(); err != nil {
			errChan <- err
			return
		}
		doneChan <- struct{}{}
	}()

	select {
	case err := <-errChan:
		return err
	case <-doneChan:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
