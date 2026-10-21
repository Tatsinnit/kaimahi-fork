// Command faketool is the small stdlib-only native fake CLI used by cmd/kmx
// tests on Windows. It mirrors fakeTool.run in fake_tool_test.go: it reads
// its replay table from os.Executable()+".kmx-fake-tool.json". Copying the
// whole test binary instead made each fake start too slow for short contexts.
package main

import (
	"encoding/json"
	"io"
	"os"
	"strings"
)

const specSuffix = ".kmx-fake-tool.json"

type rule struct {
	Match, Args, Stdout string
	Exit                int
}

type tool struct {
	Log, LogLine string
	TruncateLog  bool
	Rules        []rule
	DefaultExit  int
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--kmx-fixture-ready" {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		os.Exit(125)
	}
	raw, err := os.ReadFile(exe + specSuffix)
	if err != nil {
		os.Exit(125)
	}
	var t tool
	if err := json.Unmarshal(raw, &t); err != nil {
		os.Exit(125)
	}
	os.Exit(t.run(os.Args[1:]))
}

func (f tool) run(args []string) int {
	joined := strings.Join(args, " ")
	if f.Log != "" {
		line := os.Expand(f.LogLine, func(name string) string {
			if name == "ARGS" {
				return joined
			}
			return os.Getenv(name)
		})
		flags := os.O_WRONLY | os.O_CREATE | os.O_APPEND
		if f.TruncateLog {
			flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
		}
		file, err := os.OpenFile(f.Log, flags, 0o600)
		if err != nil {
			return 125
		}
		_, err = io.WriteString(file, line+"\n")
		if closeErr := file.Close(); err != nil || closeErr != nil {
			return 125
		}
	}
	for _, r := range f.Rules {
		matched := false
		switch r.Match {
		case "":
			matched = true
		case "exact":
			matched = joined == r.Args
		case "contains":
			matched = strings.Contains(joined, r.Args)
		case "suffix":
			matched = strings.HasSuffix(joined, r.Args)
		}
		if matched {
			if _, err := io.WriteString(os.Stdout, r.Stdout); err != nil {
				return 125
			}
			return r.Exit
		}
	}
	return f.DefaultExit
}
