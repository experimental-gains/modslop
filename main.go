// Command modslop audits a Go module's dependencies for signs of
// slopsquatting: names that don't exist, names that are suspiciously
// close to a well-known module, and modules that are brand-new with
// no track record. See README.md for the full rationale.
package main

import (
	"encoding/json"
	"fmt"
	"os"
)

func main() {
	args := os.Args[1:]
	jsonOut := false
	var path string

	for _, a := range args {
		if a == "--json" {
			jsonOut = true
			continue
		}
		path = a
	}
	if path == "" {
		path = "go.mod"
	}

	reqs, err := LoadGoMod(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "modslop:", err)
		os.Exit(2)
	}

	proxy := NewProxyClient()
	var all []Finding
	for _, r := range reqs {
		all = append(all, CheckRequirement(r, proxy)...)
	}

	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(all); err != nil {
			fmt.Fprintln(os.Stderr, "modslop:", err)
			os.Exit(2)
		}
	} else {
		if len(all) == 0 {
			fmt.Printf("modslop: checked %d requirement(s), nothing flagged\n", len(reqs))
		} else {
			for _, f := range all {
				fmt.Printf("[%s] %s: %s (%s)\n", f.Severity, f.Module, f.Detail, f.Reason)
			}
			fmt.Printf("\nmodslop: %d finding(s) across %d requirement(s)\n", len(all), len(reqs))
		}
	}

	if len(all) > 0 {
		os.Exit(1)
	}
}
