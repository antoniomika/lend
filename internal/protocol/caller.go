package protocol

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"unicode/utf8"
)

type Caller struct {
	Source        string  `json:"source"`
	Host          string  `json:"host,omitempty"`
	User          string  `json:"user,omitempty"`
	UID           *uint32 `json:"uid,omitempty"`
	PID           int     `json:"pid,omitempty"`
	ParentPID     int     `json:"parent_pid,omitempty"`
	Executable    string  `json:"executable,omitempty"`
	ParentProcess string  `json:"parent_process,omitempty"`
	Directory     string  `json:"directory,omitempty"`
	SSHConnection string  `json:"ssh_connection,omitempty"`
	ClientName    string  `json:"client_name,omitempty"`
	ClientVersion string  `json:"client_version,omitempty"`
	Tool          string  `json:"tool,omitempty"`
	RequestID     string  `json:"request_id,omitempty"`
}

func (c Caller) Validate() error {
	if c.Source != "cli" && c.Source != "mcp" && c.Source != "client" {
		return errors.New("caller source must be cli, mcp, or client")
	}
	if c.PID < 0 || c.PID > math.MaxInt32 || c.ParentPID < 0 || c.ParentPID > math.MaxInt32 {
		return errors.New("invalid caller process ID")
	}
	for _, field := range []struct {
		name, value string
		max         int
	}{
		{"host", c.Host, 256}, {"user", c.User, 256}, {"executable", c.Executable, 4096},
		{"parent_process", c.ParentProcess, 4096}, {"directory", c.Directory, 4096},
		{"ssh_connection", c.SSHConnection, 512}, {"client_name", c.ClientName, 256},
		{"client_version", c.ClientVersion, 128}, {"tool", c.Tool, 128}, {"request_id", c.RequestID, 256},
	} {
		if len(field.value) > field.max || !utf8.ValidString(field.value) || strings.ContainsRune(field.value, 0) {
			return fmt.Errorf("invalid caller %s (maximum %d UTF-8 bytes without NUL)", field.name, field.max)
		}
	}
	return nil
}
