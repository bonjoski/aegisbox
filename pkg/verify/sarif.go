package verify

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// FindingSeverity models scanner alert levels.
type FindingSeverity string

const (
	SeverityCritical FindingSeverity = "CRITICAL"
	SeverityHigh     FindingSeverity = "HIGH"
	SeverityMedium   FindingSeverity = "MEDIUM"
	SeverityLow      FindingSeverity = "LOW"
)

// Finding represents a normalized vulnerability report ingested from SARIF.
type Finding struct {
	RuleID      string          `json:"rule_id"`
	CWE         int             `json:"cwe"`
	FilePath    string          `json:"file_path"`
	StartLine   int             `json:"start_line"`
	Severity    FindingSeverity `json:"severity"`
	Description string          `json:"description"`
}

// rawSARIF structures for parsing SARIF v2.1.0
type sarifDocument struct {
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name  string      `json:"name"`
	Rules []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string                 `json:"id"`
	Name                 string                 `json:"name"`
	ShortDescription     *sarifMultiformat      `json:"shortDescription"`
	FullDescription      *sarifMultiformat      `json:"fullDescription"`
	DefaultConfiguration *sarifRuleConfig       `json:"defaultConfiguration"`
	Properties           map[string]interface{} `json:"properties"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifMultiformat struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string           `json:"ruleId"`
	Level     string           `json:"level"`
	Message   sarifMultiformat `json:"message"`
	Locations []sarifLocation  `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

// ParseSARIF parses a SARIF 2.1.0 document from a reader and normalizes findings.
func ParseSARIF(r io.Reader) ([]Finding, error) {
	var doc sarifDocument
	dec := json.NewDecoder(r)
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("failed decoding SARIF JSON: %w", err)
	}

	if len(doc.Runs) == 0 {
		return nil, fmt.Errorf("invalid SARIF document: runs array is empty or null")
	}

	ruleMap := make(map[string]sarifRule)
	var findings []Finding

	for _, run := range doc.Runs {
		for _, rule := range run.Tool.Driver.Rules {
			ruleMap[rule.ID] = rule
		}

		for _, res := range run.Results {
			f := Finding{
				RuleID:      res.RuleID,
				Description: res.Message.Text,
				Severity:    mapSARIFLevel(res.Level),
			}

			// Extract location
			if len(res.Locations) > 0 {
				loc := res.Locations[0].PhysicalLocation
				cleanPath := filepath.Clean(loc.ArtifactLocation.URI)
				// Prevent path traversal in location URI
				if !filepath.IsAbs(cleanPath) && !strings.HasPrefix(cleanPath, "..") {
					f.FilePath = cleanPath
				} else {
					f.FilePath = filepath.Base(cleanPath)
				}
				f.StartLine = loc.Region.StartLine
			}

			// Extract CWE from rule properties if present
			if rule, ok := ruleMap[res.RuleID]; ok {
				if f.Description == "" && rule.ShortDescription != nil {
					f.Description = rule.ShortDescription.Text
				}
				if f.Severity == SeverityMedium && rule.DefaultConfiguration != nil {
					f.Severity = mapSARIFLevel(rule.DefaultConfiguration.Level)
				}
				f.CWE = extractCWEFromRule(rule)
			}

			findings = append(findings, f)
		}
	}

	return findings, nil
}

// ParseSARIFFile reads a SARIF file from disk and parses findings.
func ParseSARIFFile(filePath string) ([]Finding, error) {
	clean := filepath.Clean(filePath)
	f, err := os.Open(clean)
	if err != nil {
		return nil, fmt.Errorf("failed opening SARIF file: %w", err)
	}
	defer f.Close()
	return ParseSARIF(f)
}

func mapSARIFLevel(level string) FindingSeverity {
	switch strings.ToLower(level) {
	case "error":
		return SeverityHigh
	case "warning":
		return SeverityMedium
	case "note", "none":
		return SeverityLow
	default:
		return SeverityMedium
	}
}

func extractCWEFromRule(rule sarifRule) int {
	if rule.Properties == nil {
		return 0
	}

	if tags, ok := rule.Properties["tags"].([]interface{}); ok {
		for _, tag := range tags {
			if strTag, ok := tag.(string); ok {
				if strings.HasPrefix(strings.ToUpper(strTag), "CWE-") {
					cweStr := strings.TrimPrefix(strings.ToUpper(strTag), "CWE-")
					if val, err := strconv.Atoi(cweStr); err == nil {
						return val
					}
				}
			}
		}
	}

	return 0
}
