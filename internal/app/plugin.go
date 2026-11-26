package app

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/hotid/mpmtr/internal/core"
)

// Plugin protocol (application checks). See docs/PLUGINS.md.
//
// mpmtr starts the plugin executable with one extra descriptor, fd 3: a
// unix SOCK_SEQPACKET socket; every message is one JSON object in one
// packet. The plugin speaks first ("hello"); then mpmtr sends "check"
// messages, each with a connected TCP socket attached (SCM_RIGHTS), and the
// plugin answers each with a "result" carrying the same id. Checks may run
// concurrently. The plugin closes its copy of the socket before answering;
// mpmtr closes the last copy (SO_LINGER 0: RST).

type pluginMsg struct {
	Type    string  `json:"type"`
	ID      uint64  `json:"id,omitempty"`
	Name    string  `json:"name,omitempty"`
	Version string  `json:"version,omitempty"`
	Src     string  `json:"src,omitempty"`
	SPort   uint16  `json:"sport,omitempty"`
	Dst     string  `json:"dst,omitempty"`
	DPort   uint16  `json:"dport,omitempty"`
	Server  string  `json:"server,omitempty"`
	Timeout int64   `json:"timeout_ms,omitempty"`
	OK      bool    `json:"ok,omitempty"`
	Stage   string  `json:"stage,omitempty"`
	Error   string  `json:"error,omitempty"`
	Ms      float64 `json:"ms,omitempty"`
}

// Plugin is a running application-check plugin.
type Plugin struct {
	Name, Version string
	cmd           *exec.Cmd
	fd            int
	mu            sync.Mutex
	wait          map[uint64]chan pluginMsg
	dead          error
	silent        int // checks in a row the plugin gave no result for
	errTail       *tail
}

// A plugin that answers nothing keeps the sockets it was handed, and a
// connection left open on a measured port's addresses spoils that port's
// probes. After pluginSilentMax unanswered checks in a row it is stopped:
// that closes them. pluginGrace is how long past the deadline a result is
// still waited for.
const pluginSilentMax = 3

var pluginGrace = time.Second

// FindPlugin resolves --app NAME to an executable: a path as given, else
// "mpmtr-app-NAME" next to the mpmtr binary, else in PATH.
func FindPlugin(name string) (string, error) { return findExe("mpmtr-app-", "--app", name) }

func findExe(prefix, flag, name string) (string, error) {
	if strings.ContainsRune(name, '/') {
		return name, nil
	}
	bin := prefix + name
	if exe, err := os.Executable(); err == nil {
		p := filepath.Join(filepath.Dir(exe), bin)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	p, err := exec.LookPath(bin)
	if err != nil {
		return "", fmt.Errorf("%s %s: %s not found next to mpmtr or in PATH", flag, name, bin)
	}
	return p, nil
}

// StartPlugin runs the plugin and waits for its hello.
func StartPlugin(path string, args []string) (*Plugin, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	child := os.NewFile(uintptr(fds[1]), "plugin")
	p := &Plugin{fd: fds[0], wait: map[uint64]chan pluginMsg{}, errTail: &tail{max: 20}}
	p.cmd = exec.Command(path, args...)
	p.cmd.ExtraFiles = []*os.File{child} // fd 3 in the plugin
	p.cmd.Stdout = io.Discard
	stderr, _ := p.cmd.StderrPipe()
	if err := p.cmd.Start(); err != nil {
		unix.Close(fds[0])
		child.Close()
		return nil, fmt.Errorf("plugin %s: %w", path, err)
	}
	child.Close()
	go p.errTail.read(stderr)
	hello, err := p.recv(5 * time.Second)
	if err == nil && hello.Type != "hello" {
		err = fmt.Errorf("its first message is %q", hello.Type)
	}
	if err != nil {
		p.Close()
		return nil, fmt.Errorf("plugin %s did not say hello: %w %s", path, err, p.errTail.String())
	}
	p.Name, p.Version = clean(hello.Name, 32), clean(hello.Version, 32)
	go p.readLoop()
	go func() {
		if err := p.cmd.Wait(); err != nil {
			p.fail(fmt.Errorf("plugin exited: %w %s", err, p.errTail.String()))
		} else {
			p.fail(fmt.Errorf("plugin exited %s", p.errTail.String()))
		}
	}()
	return p, nil
}

func (p *Plugin) recv(timeout time.Duration) (pluginMsg, error) {
	var m pluginMsg
	if timeout > 0 {
		tv := unix.NsecToTimeval(int64(timeout))
		_ = unix.SetsockoptTimeval(p.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
		defer unix.SetsockoptTimeval(p.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{})
	}
	buf := make([]byte, 64<<10)
	var n int
	var err error
	for end := time.Now().Add(timeout); ; {
		// A signal (the Go runtime sends them to its own threads) may
		// interrupt the wait: that is not the plugin failing to answer.
		if n, _, _, _, err = unix.Recvmsg(p.fd, buf, nil, 0); !errors.Is(err, unix.EINTR) || (timeout > 0 && time.Now().After(end)) {
			break
		}
	}
	if err != nil {
		return m, err
	}
	if n == 0 {
		return m, io.EOF
	}
	return m, json.Unmarshal(buf[:n], &m)
}

func (p *Plugin) readLoop() {
	for {
		m, err := p.recv(0)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			p.fail(fmt.Errorf("plugin connection: %w", err))
			return
		}
		if m.Type != "result" {
			continue
		}
		p.mu.Lock()
		ch := p.wait[m.ID]
		delete(p.wait, m.ID)
		p.silent = 0
		p.mu.Unlock()
		if ch != nil {
			ch <- m
		}
	}
}

func (p *Plugin) fail(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.dead == nil {
		p.dead = err
	}
	for id, ch := range p.wait {
		ch <- pluginMsg{Type: "result", ID: id, Stage: core.StagePlugin, Error: p.dead.Error()}
		delete(p.wait, id)
	}
}

// Dead reports why the plugin stopped working (nil while it runs).
func (p *Plugin) Dead() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.dead
}

// Check hands the connected socket to the plugin and waits for its
// verdict: passed, failed, or the plugin itself failed (not the server's
// fault). This is the one place where the plugin's stage "plugin" is read.
func (p *Plugin) Check(id uint64, conn int, m pluginMsg, timeout time.Duration) (out core.AppOutcome, stage, errText string, appTime time.Duration) {
	ch := make(chan pluginMsg, 1)
	p.mu.Lock()
	if p.dead != nil {
		err := p.dead
		p.mu.Unlock()
		return core.AppPluginFailed, core.StagePlugin, err.Error(), 0
	}
	p.wait[id] = ch
	p.mu.Unlock()
	m.Type, m.ID, m.Timeout = "check", id, int64(timeout/time.Millisecond)
	b, _ := json.Marshal(m)
	start := time.Now()
	if err := unix.Sendmsg(p.fd, b, unix.UnixRights(conn), nil, 0); err != nil {
		p.mu.Lock()
		delete(p.wait, id)
		p.mu.Unlock()
		return core.AppPluginFailed, core.StagePlugin, err.Error(), 0
	}
	select {
	case r := <-ch:
		// The plugin's words go to a terminal, and may quote the server's.
		r.Stage, r.Error = clean(r.Stage, 32), clean(r.Error, 200)
		switch {
		case r.OK:
			return core.AppPassed, r.Stage, r.Error, time.Since(start)
		case r.Stage == core.StagePlugin:
			return core.AppPluginFailed, r.Stage, r.Error, time.Since(start)
		}
		return core.AppFailed, r.Stage, r.Error, time.Since(start)
	case <-time.After(timeout + pluginGrace):
		p.mu.Lock()
		delete(p.wait, id)
		p.silent++
		stop := p.silent >= pluginSilentMax && p.dead == nil
		p.mu.Unlock()
		if stop {
			p.fail(fmt.Errorf("plugin stopped: no answer to %d checks in a row", pluginSilentMax))
			p.cmd.Process.Kill()
		}
		return core.AppPluginFailed, core.StagePlugin, "no answer from the plugin", time.Since(start)
	}
}

// Close stops the plugin.
func (p *Plugin) Close() {
	if p.cmd != nil && p.cmd.Process != nil {
		p.cmd.Process.Kill()
	}
	unix.Close(p.fd)
}

// tail keeps the last lines of the plugin's stderr for diagnostics.
type tail struct {
	mu    sync.Mutex
	lines []string
	max   int
}

func (t *tail) read(r io.Reader) {
	if r == nil {
		return
	}
	s := bufio.NewScanner(r)
	for s.Scan() {
		t.mu.Lock()
		t.lines = append(t.lines, s.Text())
		if len(t.lines) > t.max {
			t.lines = t.lines[1:]
		}
		t.mu.Unlock()
	}
}

func (t *tail) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.lines) == 0 {
		return ""
	}
	return "(" + strings.Join(t.lines, " | ") + ")"
}
