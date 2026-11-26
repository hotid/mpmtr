package cli

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// What a script sees without any measurement: the exit status and which
// stream the text goes to. Help and the version are answers (status 0,
// standard output); a wrong command line is an error (status 4, standard
// error, nothing on standard output for a pipe to swallow).
func TestRunStatusAndStreams(t *testing.T) {
	for _, tc := range []struct {
		name            string
		args            []string
		code            int
		stdout, stderr  string // must contain
		emptyOut, noErr bool
	}{
		{name: "help", args: []string{"--help"}, code: ExitOK, stdout: "USAGE\n", noErr: true},
		{name: "help, short", args: []string{"-h"}, code: ExitOK, stdout: "USAGE\n", noErr: true},
		{name: "help wins over a target", args: []string{"--help", "192.0.2.1"}, code: ExitOK, stdout: "USAGE\n", noErr: true},
		{name: "version", args: []string{"--version"}, code: ExitOK, stdout: "mpmtr " + Version + "\n", noErr: true},
		{name: "no target", args: nil, code: ExitError, stderr: "USAGE\n", emptyOut: true},
		{name: "unknown option", args: []string{"--no-such-option", "192.0.2.1"}, code: ExitError, stderr: "mpmtr:", emptyOut: true},
		{name: "bad value", args: []string{"--flows", "many", "192.0.2.1"}, code: ExitError, stderr: "mpmtr:", emptyOut: true},
		{name: "options that exclude each other", args: []string{"--discover", "--no-discovery", "192.0.2.1"}, code: ExitError, stderr: "mpmtr:", emptyOut: true},
		{name: "--json without a report", args: []string{"--json", "192.0.2.1"}, code: ExitError, stderr: "mpmtr:", emptyOut: true},
		{name: "bad target", args: []string{"-r", "192.0.2.1:99999"}, code: ExitError, stderr: "mpmtr:", emptyOut: true},
	} {
		var out, errb bytes.Buffer
		code := run(tc.args, &out, &errb)
		if code != tc.code {
			t.Errorf("%s: status %d, want %d (stderr %q)", tc.name, code, tc.code, errb.String())
		}
		if !strings.Contains(out.String(), tc.stdout) {
			t.Errorf("%s: standard output lacks %q: %q", tc.name, tc.stdout, out.String())
		}
		if !strings.Contains(errb.String(), tc.stderr) {
			t.Errorf("%s: standard error lacks %q: %q", tc.name, tc.stderr, errb.String())
		}
		if tc.emptyOut && out.Len() != 0 {
			t.Errorf("%s: an error wrote to standard output: %q", tc.name, out.String())
		}
		if tc.noErr && errb.Len() != 0 {
			t.Errorf("%s: wrote to standard error: %q", tc.name, errb.String())
		}
	}
}

// Without the capabilities nothing can be measured: status 4 and a message
// that says what to do, in report mode with --json too (no half-written
// JSON on standard output).
func TestRunWithoutCapabilities(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: the capabilities are there")
	}
	for _, args := range [][]string{
		{"-r", "-c", "1", "-n", "192.0.2.1"},
		{"-r", "-c", "1", "-n", "--json", "192.0.2.1"},
		{"--discover", "-n", "192.0.2.1"},
	} {
		var out, errb bytes.Buffer
		code := run(args, &out, &errb)
		if code != ExitError {
			t.Errorf("%v: status %d, want %d", args, code, ExitError)
		}
		if out.Len() != 0 {
			t.Errorf("%v: wrote to standard output: %q", args, out.String())
		}
		if e := errb.String(); !strings.Contains(e, "setcap") {
			t.Errorf("%v: the message does not say how to get the capabilities: %q", args, e)
		}
	}
}
