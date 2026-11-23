package check

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
)

// ANSI color codes used for text report output.
const (
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorRed    = "\033[31m"
	colorReset  = "\033[0m"
)

func colorFor(s Status) string {
	switch s {
	case Pass:
		return colorGreen
	case Warn:
		return colorYellow
	case Fail:
		return colorRed
	default:
		return colorReset
	}
}

// WriteText renders results as a human-readable, grouped-by-category report.
func WriteText(w io.Writer, results []Result, color bool) {
	byCategory := map[string][]Result{}
	var categories []string
	for _, r := range results {
		if _, ok := byCategory[r.Category]; !ok {
			categories = append(categories, r.Category)
		}
		byCategory[r.Category] = append(byCategory[r.Category], r)
	}
	sort.Strings(categories)

	counts := map[Status]int{}
	for _, cat := range categories {
		fmt.Fprintf(w, "\n== %s ==\n", cat)
		for _, r := range byCategory[cat] {
			counts[r.Status]++
			label := r.Status.String()
			if color {
				label = colorFor(r.Status) + label + colorReset
			}
			fmt.Fprintf(w, "[%s] %-28s %s\n", label, r.Name, r.Message)
			if r.Remediation != "" && r.Status != Pass {
				fmt.Fprintf(w, "       -> %s\n", r.Remediation)
			}
		}
	}
	fmt.Fprintf(w, "\nSummary: %d pass, %d warn, %d fail, %d skip\n",
		counts[Pass], counts[Warn], counts[Fail], counts[Skip])
}

// WriteJSON renders results as machine-readable JSON, suitable for CI or
// automated alerting pipelines.
func WriteJSON(w io.Writer, results []Result) error {
	type statusResult struct {
		Name        string `json:"name"`
		Category    string `json:"category"`
		Status      string `json:"status"`
		Message     string `json:"message"`
		Remediation string `json:"remediation,omitempty"`
		Evidence    string `json:"evidence,omitempty"`
	}
	out := make([]statusResult, 0, len(results))
	for _, r := range results {
		out = append(out, statusResult{
			Name:        r.Name,
			Category:    r.Category,
			Status:      r.Status.String(),
			Message:     r.Message,
			Remediation: r.Remediation,
			Evidence:    r.Evidence,
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
