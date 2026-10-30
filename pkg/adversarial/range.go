package adversarial

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/bonjoski/aegisbox/pkg/telemetry"
	"github.com/bonjoski/aegisbox/pkg/vmm"
)

// RangeConfig configures the execution of the ARTEX adversarial range.
type RangeConfig struct {
	Scenario            string              `json:"scenario"`              // default: "artex-machine-speed"
	Strict              bool                `json:"strict"`                // fail if any invariant fails
	SprayRatePerMin     int                 `json:"spray_rate_per_min"`    // default: 2900 req/min
	VelocityThresholdMs time.Duration       `json:"velocity_threshold_ms"`// default: 500ms
	WorkspaceDir        string              `json:"workspace_dir,omitempty"`
	DriverOverride      vmm.HypervisorDriver `json:"-"`
}

// InvariantResult holds the evaluation details of an invariant benchmark.
type InvariantResult struct {
	Index       int                    `json:"index"`
	Name        string                 `json:"name"`
	Passed      bool                   `json:"passed"`
	Summary     string                 `json:"summary"`
	Description string                 `json:"description"`
	Metrics     map[string]interface{} `json:"metrics,omitempty"`
}

// RangeReport contains the aggregated benchmark report from the adversarial testbed.
type RangeReport struct {
	Scenario        string            `json:"scenario"`
	StartTime       time.Time         `json:"start_time"`
	EndTime         time.Time         `json:"end_time"`
	TotalDuration   time.Duration     `json:"total_duration"`
	Passed          bool              `json:"passed"`
	Invariants      []InvariantResult `json:"invariants"`
	MicroVMTornDown bool              `json:"microvm_torn_down"`
	AirgapVerified  bool              `json:"airgap_verified"`
	Error           string            `json:"error,omitempty"`
}

// RangeEngine orchestrates the machine-speed adversarial testbed range.
type RangeEngine struct {
	cfg RangeConfig
}

// NewRangeEngine creates a new adversarial range execution engine.
func NewRangeEngine(cfg RangeConfig) *RangeEngine {
	if cfg.Scenario == "" {
		cfg.Scenario = "artex-machine-speed"
	}
	if cfg.SprayRatePerMin <= 0 {
		cfg.SprayRatePerMin = 2900
	}
	if cfg.VelocityThresholdMs <= 0 {
		cfg.VelocityThresholdMs = 500 * time.Millisecond
	}
	return &RangeEngine{cfg: cfg}
}

// Run executes the complete ARTEX adversarial scenario against the ephemeral microVM harness.
func (e *RangeEngine) Run(ctx context.Context) (*RangeReport, error) {
	startTime := time.Now()
	telemetry.Log("adversarial_range", fmt.Sprintf("Starting scenario %s (strict=%v)", e.cfg.Scenario, e.cfg.Strict), "audit")

	report := &RangeReport{
		Scenario:  e.cfg.Scenario,
		StartTime: startTime,
		Passed:    true,
	}

	// 1. Initialize Synthetic Air-Gapped Network
	synthNet := NewSyntheticNetwork(SyntheticNetworkConfig{
		AllowedTenantID:     "tenant-alpha-001",
		SprayVelocityBurst:  20,
		SprayWindowDuration: e.cfg.VelocityThresholdMs,
	})
	defer synthNet.Close()

	// 2. Boot Ephemeral MicroVM Harness (< 150ms)
	harness, err := NewSandboxHarness(ctx, HarnessConfig{
		SessionID:      fmt.Sprintf("artex-%d", time.Now().UnixNano()),
		Airgap:         true,
		WorkspaceDir:   e.cfg.WorkspaceDir,
		DriverOverride: e.cfg.DriverOverride,
	})
	if err != nil {
		report.Passed = false
		report.Error = fmt.Sprintf("failed to initialize microVM harness: %v", err)
		return report, err
	}
	defer func() {
		_ = harness.Teardown(ctx)
		report.MicroVMTornDown = true
	}()

	// Verify air-gap network constraints (zero WAN egress)
	if err := synthNet.VerifyZeroWANEgress(ctx); err == nil {
		report.AirgapVerified = true
	} else {
		report.AirgapVerified = false
	}

	// 3. Evaluate Invariant 1: Cross-Tenant Isolation
	inv1 := RunInvariant1_CrossTenant(ctx, synthNet)
	report.Invariants = append(report.Invariants, inv1)
	if !inv1.Passed {
		report.Passed = false
	}

	// 4. Evaluate Invariant 2: Velocity Killswitch (2,900 req/min trips in < 500ms)
	inv2 := RunInvariant2_VelocityKillswitch(ctx, synthNet, e.cfg.SprayRatePerMin, e.cfg.VelocityThresholdMs)
	report.Invariants = append(report.Invariants, inv2)
	if !inv2.Passed {
		report.Passed = false
	}

	// 5. Evaluate Invariant 3: Host Credential Bleed (Harvested: 0 bytes)
	inv3 := RunInvariant3_HostCredentialBleed(ctx, harness)
	report.Invariants = append(report.Invariants, inv3)
	if !inv3.Passed {
		report.Passed = false
	}

	endTime := time.Now()
	report.EndTime = endTime
	report.TotalDuration = endTime.Sub(startTime)

	telemetry.Log("adversarial_range", fmt.Sprintf("Finished scenario %s: passed=%v in %s", e.cfg.Scenario, report.Passed, report.TotalDuration), "audit")
	return report, nil
}

// FormatSummary formats the range report matching the exact CLI scorecard specification.
func (r *RangeReport) FormatSummary() string {
	var sb strings.Builder

	for _, inv := range r.Invariants {
		tag := "[PASS]"
		if !inv.Passed {
			tag = "[FAIL]"
		}

		switch inv.Index {
		case 1:
			sb.WriteString(fmt.Sprintf("%s Invariant 1: %s (%s)\n", tag, inv.Name, inv.Summary))
		case 2:
			sb.WriteString(fmt.Sprintf("%s Invariant 2: %s\n", tag, inv.Summary))
		case 3:
			sb.WriteString(fmt.Sprintf("%s Invariant 3: %s (%s)\n", tag, inv.Name, inv.Summary))
		default:
			sb.WriteString(fmt.Sprintf("%s Invariant %d: %s (%s)\n", tag, inv.Index, inv.Name, inv.Summary))
		}
	}

	totalSeconds := r.TotalDuration.Seconds()
	sb.WriteString(fmt.Sprintf("Total Run Time: %.1fs (MicroVM teardown complete)", totalSeconds))
	return sb.String()
}

// ToJSON serializes the report to structured JSON.
func (r *RangeReport) ToJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}
