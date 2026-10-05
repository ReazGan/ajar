// ajar scans a host or network for locally-hosted AI services that are exposed
// with no authentication (Ollama, ComfyUI, Stable Diffusion WebUI, vLLM, ...).
//
// Only scan hosts and networks you own or are authorised to test.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"
)

var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("ajar", flag.ContinueOnError)
	fl.SetOutput(stderr)
	jsonOut := fl.Bool("json", false, "print findings as JSON")
	concurrency := fl.Int("concurrency", 64, "number of concurrent probes")
	noColor := fl.Bool("no-color", false, "disable colored output")
	showVersion := fl.Bool("version", false, "print version and exit")
	fl.Usage = func() {
		fmt.Fprintf(stderr, "usage: ajar [flags] [host|CIDR]\n\n")
		fmt.Fprintf(stderr, "Scans for exposed, unauthenticated local AI services.\n")
		fmt.Fprintf(stderr, "Scans 127.0.0.1 when no target is given.\n")
		fmt.Fprintf(stderr, "Only scan hosts and networks you own or are authorised to test.\n\n")
		fl.PrintDefaults()
		fmt.Fprintf(stderr, "\nexit status: 0 nothing exposed, 1 something exposed, 2 error\n")
	}
	if err := fl.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, "ajar", version)
		return 0
	}
	if fl.NArg() > 1 {
		fl.Usage()
		return 2
	}
	target := ""
	if fl.NArg() == 1 {
		target = fl.Arg(0)
	}
	targets, err := expandTargets(target)
	if err != nil {
		fmt.Fprintln(stderr, "ajar:", err)
		return 2
	}

	findings := scan(targets, *concurrency)

	if *jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		enc.Encode(struct {
			Version  string    `json:"version"`
			Targets  int       `json:"targets_scanned"`
			Findings []Finding `json:"findings"`
		}{version, len(targets), findings})
	} else {
		color := !*noColor && os.Getenv("NO_COLOR") == "" &&
			(forceColor() || stdout == os.Stdout && enableColor(os.Stdout))
		printReport(stdout, findings, len(targets), color)
	}
	if len(findings) > 0 {
		return 1
	}
	return 0
}

var sevColor = map[severity]string{critical: "1;37;41", high: "1;31", medium: "33", low: "36"}

func paint(color bool, code, s string) string {
	if !color {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func printReport(w io.Writer, findings []Finding, targets int, color bool) {
	fmt.Fprintf(w, "%s %s\n", paint(color, "1", "ajar"), version)

	for _, f := range findings {
		tag := fmt.Sprintf(" %s ", strings.ToUpper(f.Severity.String()))
		fmt.Fprintf(w, "\n  %s  %s  %s\n", paint(color, sevColor[f.Severity], tag),
			paint(color, "1", f.Service), paint(color, "2", "exposed, no auth"))
		fmt.Fprintf(w, "      %s\n", paint(color, "2", f.URL))
		for _, line := range wrap(f.Risk, 84) {
			fmt.Fprintf(w, "      %s\n", paint(color, "2", line))
		}
	}

	fmt.Fprintf(w, "\n%d target(s) scanned\n", targets)
	if len(findings) == 0 {
		fmt.Fprintln(w, paint(color, "32", "clean, no exposed AI services found"))
		return
	}
	counts := map[severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	var parts []string
	for _, s := range []severity{critical, high, medium, low} {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[s], s))
		}
	}
	fmt.Fprintln(w, paint(color, sevColor[worstOf(counts)], strings.Join(parts, "  ")))
	fmt.Fprintln(w, "\nBind these services to 127.0.0.1, or put them behind authentication.")
}

func worstOf(c map[severity]int) severity {
	for _, s := range []severity{critical, high, medium, low} {
		if c[s] > 0 {
			return s
		}
	}
	return low
}

func wrap(s string, width int) []string {
	var lines []string
	line := ""
	for _, word := range strings.Fields(s) {
		if line != "" && len(line)+1+len(word) > width {
			lines = append(lines, line)
			line = ""
		}
		if line != "" {
			line += " "
		}
		line += word
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}

func forceColor() bool {
	v := os.Getenv("CLICOLOR_FORCE")
	return v != "" && v != "0"
}

func init() {
	if version != "dev" {
		return
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		version = bi.Main.Version
	}
}
