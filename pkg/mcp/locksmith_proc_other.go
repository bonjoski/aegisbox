//go:build !darwin

package mcp

import "time"

var processFallbackStartNS = time.Now().UnixNano()

// getProcessStartTime returns a positive process start timestamp fallback on non-Darwin platforms.
func getProcessStartTime(_ int) (int64, error) {
	return processFallbackStartNS, nil
}
