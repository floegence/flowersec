package version

import (
	"runtime/debug"
	"strings"
)

// String formats a human-friendly version line for CLI tools.
//
// It prefers the provided version/commit/date values (usually injected via -ldflags),
// and falls back to Go module build info when those are unset or default placeholders.
func String(version string, commit string, date string) string {
	v := strings.TrimSpace(version)
	c := strings.TrimSpace(commit)
	d := strings.TrimSpace(date)

	if info, ok := debug.ReadBuildInfo(); ok {
		// Prefer module version when -ldflags were not provided.
		if v == "" || v == "dev" || v == "(devel)" {
			if mv := strings.TrimSpace(info.Main.Version); mv != "" && mv != "(devel)" {
				v = mv
			}
		}
		// Best-effort VCS metadata when -ldflags were not provided.
		if c == "" || c == "unknown" {
			if rev := buildSetting(info, "vcs.revision"); rev != "" {
				c = rev
			}
		}
		if d == "" || d == "unknown" {
			if t := buildSetting(info, "vcs.time"); t != "" {
				d = t
			}
		}
	}

	out := v
	if out == "" {
		out = "dev"
	}
	if c != "" && c != "unknown" {
		out += " (" + c + ")"
	}
	if d != "" && d != "unknown" {
		out += " " + d
	}
	return out
}

func buildSetting(info *debug.BuildInfo, key string) string {
	if info == nil {
		return ""
	}
	for _, s := range info.Settings {
		if s.Key == key {
			return s.Value
		}
	}
	return ""
}
