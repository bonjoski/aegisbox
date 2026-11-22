package main

import (
	"context"
	"flag"
	"fmt"
	"strings"

	"github.com/bonjoski/aegisbox/pkg/learn"
)

func runLearn(ctx context.Context, args []string) error {
	reordered := reorderFlagsBeforePositionals(args, map[string]bool{
		"--ollama-model": true,
		"-ollama-model":  true,
		"--trace-dir":    true,
		"-trace-dir":     true,
		"--workspace":    true,
		"-workspace":     true,
		"--export-dir":   true,
		"-export-dir":    true,
	})

	fs := flag.NewFlagSet("learn", flag.ContinueOnError)
	check := fs.Bool("check", false, "Verify the 5-line paved-road fix turns the kata green (or evaluate edited --workspace)")
	why := fs.Bool("why", false, "Show the full threat model and real-world precedent")
	jsonOut := fs.Bool("json", false, "Output structured JSON")
	useOllama := fs.Bool("ollama", false, "Use local loopback Ollama (127.0.0.1:11434) instead of offline DeterministicMockLLM")
	ollamaModel := fs.String("ollama-model", "llama3.2", "Local Ollama model tag when --ollama is set")
	traceDir := fs.String("trace-dir", "", "Override Flightdeck JSONL trace output directory")
	workspaceDir := fs.String("workspace", "", "Editable kata workspace directory (inspected on --check via os.OpenRoot)")
	exportDir := fs.String("export-dir", "", "Export self-contained toy vulnerable handler + README into a clean 0700 workspace")

	fs.Usage = func() {
		fmt.Println("Usage: aegisbox learn [list|<kata-id>] [--export-dir <dir>] [--workspace <dir>] [--check] [--why] [--json] [--ollama]")
		fs.PrintDefaults()
	}

	if err := fs.Parse(reordered); err != nil {
		return err
	}

	engine := learn.NewEngine()
	pos := fs.Args()
	if len(pos) == 0 || pos[0] == "list" {
		katas := engine.ListKatas()
		if *jsonOut {
			data, err := learn.FormatKataJSON(katas)
			if err != nil {
				return err
			}
			fmt.Println(string(data))
			return nil
		}
		fmt.Print(learn.FormatKataList(katas))
		return nil
	}

	kataID := pos[0]
	if strings.TrimSpace(*exportDir) != "" {
		exp, err := engine.ExportKata(kataID, *exportDir)
		if err != nil {
			return err
		}
		if *jsonOut {
			data, err := learn.FormatKataJSON(exp)
			if err != nil {
				return err
			}
			fmt.Println(string(data))
			return nil
		}
		fmt.Print(learn.FormatExportResult(exp))
		return nil
	}

	res, err := engine.RunKata(ctx, learn.RunOptions{
		KataID:       kataID,
		Check:        *check,
		Why:          *why,
		UseOllama:    *useOllama,
		OllamaModel:  *ollamaModel,
		TraceDir:     *traceDir,
		WorkspaceDir: *workspaceDir,
	})
	if err != nil {
		return err
	}

	if *jsonOut {
		data, err := learn.FormatKataJSON(res)
		if err != nil {
			return err
		}
		fmt.Println(string(data))
	} else {
		fmt.Print(learn.FormatKataResult(res, *why))
	}

	if *check && !res.Passed {
		return fmt.Errorf("kata %s check failed: %s", kataID, res.ObservedEffect)
	}
	return nil
}

// reorderFlagsBeforePositionals lets users write `aegisbox learn kata-03-rag-injection --check --why`
// naturally despite Go's standard flag.FlagSet stopping at the first positional argument.
func reorderFlagsBeforePositionals(args []string, valueFlags map[string]bool) []string {
	var flagsPart []string
	var posPart []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			posPart = append(posPart, args[i+1:]...)
			break
		}
		if strings.HasPrefix(arg, "-") && arg != "-" {
			flagsPart = append(flagsPart, arg)
			if !strings.Contains(arg, "=") && valueFlags[arg] && i+1 < len(args) {
				i++
				flagsPart = append(flagsPart, args[i])
			}
		} else {
			posPart = append(posPart, arg)
		}
	}
	return append(flagsPart, posPart...)
}
