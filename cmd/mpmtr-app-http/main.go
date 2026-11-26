// Command mpmtr-app-http is an example application-check plugin for mpmtr:
// it sends "HEAD / HTTP/1.0" and expects an HTTP status line.
//
//	mpmtr --app http example.com:80
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/hotid/mpmtr/plugin"
)

func main() {
	err := plugin.Serve("http", "1", func(ctx context.Context, c net.Conn, req plugin.Request) plugin.Result {
		host := req.Dst.Addr().String()
		if _, err := fmt.Fprintf(c, "HEAD / HTTP/1.0\r\nHost: %s\r\nUser-Agent: mpmtr\r\n\r\n", host); err != nil {
			return plugin.Result{Stage: "send", Err: err}
		}
		line, err := bufio.NewReader(c).ReadString('\n')
		if err != nil {
			return plugin.Result{Stage: "answer", Err: err}
		}
		if !strings.HasPrefix(line, "HTTP/") {
			return plugin.Result{Stage: "answer", Err: errors.New("not an HTTP status line")}
		}
		return plugin.Result{OK: true}
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "mpmtr-app-http:", err)
		os.Exit(1)
	}
}
