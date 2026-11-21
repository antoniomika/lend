package main

import (
	"errors"
	"flag"
	"io"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestParseSSHFlags(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want []string
	}{
		{"bare host", []string{"host"}, []string{"host"}},
		{"SSH options", []string{"-vvv", "-p", "2222", "-i", "key", "host", "printf", "%s", "a b"}, []string{"-vvv", "-p", "2222", "-i", "key", "host", "printf", "%s", "a b"}},
		{"lend prefix", []string{"--config", "policy.json", "--silent", "-p2222", "host"}, []string{"-p2222", "host"}},
		{"explicit separator", []string{"--config=policy.json", "--", "host", "-f"}, []string{"--", "host", "-f"}},
		{"SSH separator", []string{"--", "host", "-V"}, []string{"--", "host", "-V"}},
		{"untrusted host", []string{"--", "-oProxyCommand=cmd", "host"}, []string{"--", "-oProxyCommand=cmd", "host"}},
		{"remote flags", []string{"host", "command", "--config", "remote.json", "--silent"}, []string{"host", "command", "--config", "remote.json", "--silent"}},
		{"SSH help", []string{"-h"}, []string{"-h"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := flag.NewFlagSet("ssh", flag.ContinueOnError)
			fs.String("config", "", "")
			fs.Bool("silent", false, "")
			got, err := parseSSHFlags(fs, tc.args)
			if err != nil || !slices.Equal(got, tc.want) {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
	for _, args := range [][]string{{"--config"}, {"--silent=invalid"}, {"--help"}} {
		fs := flag.NewFlagSet("ssh", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		fs.String("config", "", "")
		fs.Bool("silent", false, "")
		_, err := parseSSHFlags(fs, args)
		if err == nil || (args[0] == "--help" && !errors.Is(err, flag.ErrHelp)) {
			t.Fatalf("%q: unexpected error %v", args, err)
		}
	}
}

func TestInspectSSHArgs(t *testing.T) {
	for _, tc := range []struct {
		args  []string
		host  string
		local bool
		bad   bool
	}{
		{args: []string{"-vvv", "-p", "2222", "-Jjump", "-i", "key", "user@host", "echo", "-f"}, host: "user@host"},
		{args: []string{"-o", "ProxyCommand=ssh -W %h:%p jump", "host"}, host: "host"},
		{args: []string{"-4NtL8080:localhost:80", "host"}, host: "host"},
		{args: []string{"host", "-p", "2222", "echo", "-M"}, host: "host"},
		{args: []string{"--", "host", "-f"}, host: "host"},
		{args: []string{"host", "--", "-f"}, host: "host"},
		{args: []string{"-G", "host"}, host: "host", local: true},
		{args: []string{"-S", "/path", "-G", "host"}, host: "host", local: true},
		{args: []string{"-V"}, local: true},
		{args: []string{"-Q", "cipher"}, local: true},
		{args: []string{"-h"}, local: true},
		{args: []string{"-vfN", "host"}, bad: true},
		{args: []string{"-M", "host"}, bad: true},
		{args: []string{"-S/path", "host"}, bad: true},
		{args: []string{"-O", "check", "host"}, bad: true},
		{args: []string{"host", "-f", "command"}, bad: true},
		{args: []string{"--", "-oProxyCommand=cmd", "host"}, host: "-oProxyCommand=cmd", local: true},
		{args: []string{"--", "host", "-V"}, host: "host"},
		{args: []string{"--foo", "host"}, local: true},
		{args: []string{"--socket", "/path", "host"}, local: true},
		{args: []string{"-zf", "host"}, local: true},
		{args: []string{"-p"}, local: true},
		{args: []string{"host", "-p"}, host: "host", local: true},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			host, local, err := inspectSSHArgs(tc.args)
			if host != tc.host || local != tc.local || (err != nil) != tc.bad {
				t.Fatalf("got %q, %t, %v", host, local, err)
			}
		})
	}
}

func TestEnvironmentDefaultsAndFlagOverrides(t *testing.T) {
	for _, override := range []bool{false, true} {
		t.Run(map[bool]string{false: "environment", true: "flags"}[override], func(t *testing.T) {
			t.Setenv("LEND_CONFIG", "env.json")
			t.Setenv("LEND_PROFILE", "env")
			t.Setenv("LEND_SILENT", "true")
			t.Setenv("LEND_COMMAND_TIMEOUT", "10m")
			fs := flag.NewFlagSet("ssh", flag.ContinueOnError)
			config := fs.String("config", "", "")
			profile := fs.String("profile", "", "")
			silent := fs.Bool("silent", false, "")
			timeout := fs.Duration("command-timeout", time.Minute, "")
			var args []string
			if override {
				args = []string{"--config=flag.json", "--profile=", "--silent=false", "--command-timeout=2m"}
				t.Setenv("LEND_COMMAND_TIMEOUT", "invalid")
				t.Setenv("LEND_SILENT", "invalid")
			}
			if err := fs.Parse(args); err != nil {
				t.Fatal(err)
			}
			if err := applyEnvDefaults(fs); err != nil {
				t.Fatal(err)
			}
			if override {
				if *config != "flag.json" || *profile != "" || *silent || *timeout != 2*time.Minute {
					t.Fatalf("flags did not override environment: %q %q %t %s", *config, *profile, *silent, *timeout)
				}
			} else if *config != "env.json" || *profile != "env" || !*silent || *timeout != 10*time.Minute {
				t.Fatalf("environment defaults missing: %q %q %t %s", *config, *profile, *silent, *timeout)
			}
		})
	}
}

func TestInvalidEnvironmentDefault(t *testing.T) {
	t.Setenv("LEND_SILENT", "invalid")
	fs := flag.NewFlagSet("ssh", flag.ContinueOnError)
	fs.Bool("silent", false, "")
	if err := applyEnvDefaults(fs); err == nil || !strings.Contains(err.Error(), "LEND_SILENT") {
		t.Fatalf("invalid environment value accepted: %v", err)
	}
}

func TestAllowAllOverridesEnvironmentPolicy(t *testing.T) {
	t.Setenv("LEND_CONFIG", "env.json")
	t.Setenv("LEND_PROFILE", "env")
	fs := flag.NewFlagSet("agent", flag.ContinueOnError)
	config := fs.String("config", "", "")
	profile := fs.String("profile", "", "")
	fs.Bool("allow-all", false, "")
	if err := fs.Parse([]string{"--allow-all"}); err != nil {
		t.Fatal(err)
	}
	if err := applyEnvDefaults(fs); err != nil || *config != "" || *profile != "" {
		t.Fatalf("environment policy applied with --allow-all: %q %q %v", *config, *profile, err)
	}
}

func TestEmptyDirectoryOverride(t *testing.T) {
	t.Setenv("LEND_DIR", "/custom")
	fs := flag.NewFlagSet("local", flag.ContinueOnError)
	directory := fs.String("dir", "", "")
	if err := fs.Parse([]string{"--dir="}); err != nil {
		t.Fatal(err)
	}
	if err := applyEnvDefaults(fs); err != nil {
		t.Fatal(err)
	}
	home, err := os.UserHomeDir()
	if err != nil || *directory != home {
		t.Fatalf("empty directory did not select home: %q %v", *directory, err)
	}
}
