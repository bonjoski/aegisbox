package main

import (
	"context"
	"testing"
	"time"
)

func TestCmdTest_RequiresSubcommand(t *testing.T) {
	ctx := context.Background()
	err := runTest(ctx, []string{})
	if err == nil {
		t.Fatalf("expected error when no subcommand provided to 'test'")
	}
}

func TestCmdTest_UnknownSubcommand(t *testing.T) {
	ctx := context.Background()
	err := runTest(ctx, []string{"unsupported-subcmd"})
	if err == nil {
		t.Fatalf("expected error for unknown test subcommand")
	}
}

func TestCmdTestRange_ArtexMachineSpeed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := runTestRange(ctx, []string{"--scenario", "artex-machine-speed", "--strict"})
	if err != nil {
		t.Fatalf("runTestRange failed: %v", err)
	}
}

func TestCmdTestRange_JSONOutput(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := runTestRange(ctx, []string{"--scenario", "artex-machine-speed", "--json"})
	if err != nil {
		t.Fatalf("runTestRange with json failed: %v", err)
	}
}

func TestCmdRange_RoutesToTestRangeWhenScenarioSpecified(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := runRange(ctx, []string{"--scenario", "artex-machine-speed", "--strict"})
	if err != nil {
		t.Fatalf("runRange with scenario flag failed to route: %v", err)
	}
}
