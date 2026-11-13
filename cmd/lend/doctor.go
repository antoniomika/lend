package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/antoniomika/lend/internal/buildinfo"
	"github.com/antoniomika/lend/internal/doctor"
)

func diagnose(ctx context.Context, args []string) (int, error) {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	config := fs.String("config", "", "local policy file to check")
	profile := fs.String("profile", "", "policy profile")
	socket := fs.String("socket", "", "local proxy socket, or forwarded socket with --remote")
	upstream := fs.String("upstream", os.Getenv("SSH_AUTH_SOCK"), "original local SSH agent socket")
	home, _ := os.UserHomeDir()
	directory := fs.String("dir", home, "local command working directory")
	mode := fs.String("approval", "auto", "auto or terminal")
	remote := fs.Bool("remote", false, "check the forwarded lend socket on a remote host")
	timeout := fs.Duration("timeout", 5*time.Second, "timeout per local socket or desktop probe")
	asJSON := fs.Bool("json", false, "print a JSON report")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0, nil
		}
		return 2, err
	}
	if fs.NArg() != 0 || *timeout <= 0 || (*mode != "auto" && *mode != "terminal") {
		return 2, errors.New("doctor takes no positional arguments and requires a positive timeout and auto or terminal approval")
	}
	if *profile != "" && *config == "" {
		return 2, errors.New("--profile requires --config")
	}
	if *remote && (*config != "" || *profile != "") {
		return 2, errors.New("check local config on the laptop; --remote only checks the forwarded socket")
	}
	if *socket == "" {
		if *remote {
			*socket = os.Getenv("SSH_AUTH_SOCK")
		} else {
			*socket = defaultSocket()
		}
	}
	report := doctor.Run(ctx, doctor.Options{Config: *config, Profile: *profile, Socket: *socket, Upstream: *upstream, Directory: *directory, Approval: *mode, Remote: *remote, Timeout: *timeout})
	if *asJSON {
		if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
			return 1, err
		}
	} else {
		fmt.Fprintf(os.Stdout, "lend doctor (%s, %s, %s)\n", report.Version, report.Platform, report.Mode)
		for _, check := range report.Checks {
			message := strconv.QuoteToASCII(check.Message)
			fmt.Fprintf(os.Stdout, "%-5s %-20s %s\n", check.Status, check.Name, message[1:len(message)-1])
		}
	}
	if !report.Healthy() {
		return 1, nil
	}
	return 0, nil
}

func versionCommand(args []string) (int, error) {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print JSON build information")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0, nil
		}
		return 2, err
	}
	if fs.NArg() != 0 {
		return 2, errors.New("version takes no positional arguments")
	}
	if *asJSON {
		err := json.NewEncoder(os.Stdout).Encode(struct {
			Version string `json:"version"`
			Commit  string `json:"commit"`
			Date    string `json:"date"`
			Go      string `json:"go"`
			OS      string `json:"os"`
			Arch    string `json:"arch"`
		}{buildinfo.Version, buildinfo.Commit, buildinfo.Date, runtime.Version(), runtime.GOOS, runtime.GOARCH})
		if err != nil {
			return 1, err
		}
		return 0, nil
	}
	fmt.Fprintf(os.Stdout, "lend %s (%s, %s/%s)\n", buildinfo.Version, buildinfo.Commit, runtime.GOOS, runtime.GOARCH)
	return 0, nil
}
