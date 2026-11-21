package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

func applyEnvDefaults(fs *flag.FlagSet) error {
	explicit := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { explicit[f.Name] = true })
	if f := fs.Lookup("allow-all"); f != nil && f.Value.String() == "true" {
		explicit["config"], explicit["profile"] = true, true
	}
	for _, name := range []string{"config", "profile", "upstream", "dir", "approval", "approval-timeout", "command-timeout", "silent", "system-agent"} {
		if fs.Lookup(name) == nil || explicit[name] {
			continue
		}
		env := "LEND_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
		if value := os.Getenv(env); value != "" {
			if err := fs.Set(name, value); err != nil {
				return fmt.Errorf("%s: %w", env, err)
			}
		}
	}
	if f := fs.Lookup("dir"); f != nil && f.Value.String() == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		return fs.Set("dir", home)
	}
	return nil
}

// Only leading lend flags are parsed here; SSH owns the rest of the arguments.
func parseSSHFlags(fs *flag.FlagSet, args []string) ([]string, error) {
	end := 0
	for end < len(args) {
		arg := args[end]
		if arg == "--" {
			break
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			break
		}
		name, _, hasValue := strings.Cut(strings.TrimPrefix(strings.TrimPrefix(arg, "-"), "-"), "=")
		f := fs.Lookup(name)
		if f == nil {
			if name == "help" {
				end++
			}
			break
		}
		end++
		boolean, ok := f.Value.(interface{ IsBoolFlag() bool })
		if !hasValue && !(ok && boolean.IsBoolFlag()) && end < len(args) {
			end++
		}
	}
	if err := fs.Parse(args[:end]); err != nil {
		return nil, err
	}
	return args[end:], nil
}

// Match SSH's option arity to find the local label without changing its argv.
func inspectSSHArgs(args []string) (host string, local bool, err error) {
	terminated := false
	var incompatible byte
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			if host != "" {
				break
			}
			terminated = true
			continue
		}
		if terminated || !strings.HasPrefix(arg, "-") || arg == "-" {
			if host != "" {
				break
			}
			host = arg
			if strings.HasPrefix(host, "-") {
				return host, true, nil
			}
			if terminated {
				break
			}
			continue
		}
		if strings.HasPrefix(arg, "--") {
			return host, true, nil
		}
		for j := 1; j < len(arg); j++ {
			option := arg[j]
			if !strings.ContainsRune("1246ACGKMNTVXYZafgknqstvxyBDEFIJLOPQRSWbceilmopw", rune(option)) {
				return host, true, nil
			}
			switch option {
			case 'G', 'V', 'Q', 'h', '?':
				local = true
			case 'f', 'M', 'O', 'S':
				incompatible = option
			}
			if strings.ContainsRune("BDEFIJLOPQRSWbceilmopw", rune(option)) {
				if j+1 == len(arg) {
					i++
					if i == len(args) {
						return host, true, nil
					}
				}
				break
			}
		}
	}
	if incompatible != 0 && !local {
		return "", false, fmt.Errorf("ssh -%c is incompatible with a supervised lend session; use a standalone lend agent for backgrounding or connection sharing", incompatible)
	}
	return host, local, nil
}
