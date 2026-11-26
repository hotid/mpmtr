// Command mpmtr is a multipath-aware MTR using TCP SYN probes: it discovers
// ECMP branches Paris-traceroute style, measures loss/RTT of individual TCP
// flows end to end and per hop, groups flows by observed route and helps
// localize partial failures — without presenting missing data or measurer
// errors as network problems.
package main

import (
	"os"

	"github.com/hotid/mpmtr/internal/cli"
)

func main() { os.Exit(cli.Main(os.Args[1:])) }
