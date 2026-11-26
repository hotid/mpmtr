// Command mpmtr-app-http is an example application-check plugin for mpmtr:
// it sends "HEAD / HTTP/1.0" (GET with --get) and expects an HTTP status line, over TLS when
// the port is 443.
//
//	mpmtr --app http example.com
//	mpmtr --app "http --plain" example.com:8443
//	mpmtr --app "http --get example.com/index.php" example.com
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strings"

	"github.com/hotid/mpmtr/plugin"
)

type options struct {
	tls, plain, verify, get bool
	host, path, agent       string
}

const usage = `mpmtr-app-http: usage: --app "http [--tls | --plain] [--verify] [--get [URL]] [--host NAME] [--user-agent TEXT]"`

// parse reads the plugin's own arguments. --get may be followed by what to
// ask for: a path ("/index.php"), or a URL with a host ("example.com/x",
// "https://example.com/x"), whose host is then the name asked for and whose
// scheme says whether TLS is spoken.
func parse(args []string) (options, error) {
	o := options{path: "/", agent: "mpmtr"}
	var target string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if (a == "--get" || a == "-get") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
			o.get, target = true, args[i+1]
			args = append(args[:i:i], args[i+2:]...)
			break
		}
	}
	fs := flag.NewFlagSet("mpmtr-app-http", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.BoolVar(&o.tls, "tls", false, "")
	fs.BoolVar(&o.plain, "plain", false, "")
	fs.BoolVar(&o.verify, "verify", false, "")
	get := fs.Bool("get", false, "")
	fs.StringVar(&o.host, "host", "", "")
	fs.StringVar(&o.agent, "user-agent", o.agent, "")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 || o.tls && o.plain || strings.ContainsAny(o.agent, "\r\n") {
		return o, errors.New(usage)
	}
	o.get = o.get || *get
	if target == "" {
		return o, nil
	}
	if strings.ContainsAny(target, " \t\r\n") {
		return o, errors.New(usage)
	}
	if !strings.HasPrefix(target, "/") && !strings.Contains(target, "://") {
		target = "//" + target // "example.com/x": a host, no scheme
	}
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "" && u.Scheme != "http" && u.Scheme != "https" {
		return o, fmt.Errorf("mpmtr-app-http: --get %s: not a path or an http(s) URL", target)
	}
	if p := u.RequestURI(); p != "" {
		o.path = p
	}
	if o.host == "" {
		o.host = u.Hostname()
	}
	if !o.tls && !o.plain { // said outright wins over the scheme
		o.tls, o.plain = u.Scheme == "https", u.Scheme == "http"
	}
	return o, nil
}

func main() {
	o, err := parse(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	err = plugin.Serve("http", "1", func(ctx context.Context, c net.Conn, req plugin.Request) plugin.Result {
		return check(c, req, o)
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "mpmtr-app-http:", err)
		os.Exit(1)
	}
}

// check sends one HEAD request over c (the deadline is already set on it)
// and reads the status line.
func check(c net.Conn, req plugin.Request, o options) plugin.Result {
	host := o.host
	if host == "" {
		host = req.Host
	}
	if host == "" {
		host = req.Dst.Addr().String()
	}
	if o.tls || !o.plain && req.Dst.Port() == 443 {
		cfg := &tls.Config{InsecureSkipVerify: !o.verify}
		if _, err := netip.ParseAddr(host); err != nil {
			cfg.ServerName = host // a name: sent as SNI, and what the certificate is checked against
		} else if o.verify {
			cfg.ServerName = host
		}
		t := tls.Client(c, cfg)
		if err := t.Handshake(); err != nil {
			return plugin.Result{Stage: "tls", Err: err}
		}
		c = t
	}
	hh := host
	if a, err := netip.ParseAddr(host); err == nil && a.Is6() {
		hh = "[" + host + "]"
	}
	method := "HEAD"
	if o.get {
		method = "GET" // only the status line is read; mpmtr then resets the connection
	}
	if _, err := fmt.Fprintf(c, "%s %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: %s\r\n\r\n", method, o.path, hh, o.agent); err != nil {
		return plugin.Result{Stage: "send", Err: err}
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return plugin.Result{Stage: "answer", Err: err}
	}
	if !strings.HasPrefix(line, "HTTP/") {
		return plugin.Result{Stage: "answer", Err: errors.New("not an HTTP status line")}
	}
	// The status code goes to the PLUGIN column of the server's row.
	note := ""
	if f := strings.Fields(line); len(f) >= 2 {
		note = f[1]
	}
	return plugin.Result{OK: true, Note: note}
}
