// Command mpmtr-hop-snmp is a hop-information plugin for mpmtr: it asks a
// hop's router, over SNMP, for its name and for the interface that owns the
// address that answered.
//
//	mpmtr --hop-info "snmp /etc/mpmtr/snmp.conf" example.com:443
//	mpmtr --hop-info "snmp --descr /etc/mpmtr/snmp.conf" example.com:443
//
// With --descr the interface's description (ifAlias) follows its name.
// With --errors its receive errors follow: "crc:N", the frames that failed
// the checksum (dot3StatsFCSErrors), or "err:N", all input errors
// (ifInErrors), where the interface has no such counter (a port-channel, a
// VLAN interface). The counters run since the device booted; when mpmtr asks
// again (--hop-info-interval), the growth since this plugin's first look is
// added: "crc:1532 +12".
//
// Hop addresses come from the network, not from you: a router anywhere on
// the path chooses the address it answers with. So nothing is asked unless
// the configuration file allows that very address, and the file is the only
// place the credentials live. Each line is a prefix and how to ask the
// devices in it:
//
//	# SNMPv2c: the community travels in clear text to every address asked
//	10.0.0.0/8      community=public
//	# SNMPv3
//	192.0.2.0/24    user=monitor auth=sha256:secret-one priv=aes:secret-two
//	# options, any line: port=161 timeout=1s retries=1
//
// The longest matching prefix wins; an address in no prefix is never sent a
// packet. The file must not be readable by group or others.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/hotid/mpmtr/plugin"
)

const (
	oidSysName     = ".1.3.6.1.2.1.1.5.0"
	oidIPAdEntIf   = ".1.3.6.1.2.1.4.20.1.2"   // ipAdEntIfIndex.<a.b.c.d>
	oidIPAddressIf = ".1.3.6.1.2.1.4.34.1.3"   // ipAddressIfIndex.<type>.<len>.<bytes>
	oidIfName      = ".1.3.6.1.2.1.31.1.1.1.1" // ifName.<ifIndex>
	oidIfAlias     = ".1.3.6.1.2.1.31.1.1.1.18"
	oidFCSErrors   = ".1.3.6.1.2.1.10.7.2.1.3" // dot3StatsFCSErrors.<ifIndex>
	oidIfInErrors  = ".1.3.6.1.2.1.2.2.1.14"   // ifInErrors.<ifIndex>
	defaultTimeout = time.Second
	defaultRetries = 1
	minPassphrase  = 8 // SNMPv3 passphrases are at least 8 characters
)

// rule is one configuration line.
type rule struct {
	prefix    netip.Prefix
	community string
	user      string
	authProto gosnmp.SnmpV3AuthProtocol
	authPass  string
	privProto gosnmp.SnmpV3PrivProtocol
	privPass  string
	port      uint16
	timeout   time.Duration
	retries   int
}

var authProtos = map[string]gosnmp.SnmpV3AuthProtocol{"md5": gosnmp.MD5, "sha": gosnmp.SHA, "sha224": gosnmp.SHA224,
	"sha256": gosnmp.SHA256, "sha384": gosnmp.SHA384, "sha512": gosnmp.SHA512}
var privProtos = map[string]gosnmp.SnmpV3PrivProtocol{"des": gosnmp.DES, "aes": gosnmp.AES, "aes192": gosnmp.AES192,
	"aes256": gosnmp.AES256}

func parseConfig(text string) ([]rule, error) {
	var rules []rule
	for n, line := range strings.Split(text, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		bad := func(format string, a ...any) error {
			return fmt.Errorf("line %d: %s", n+1, fmt.Sprintf(format, a...))
		}
		p, err := netip.ParsePrefix(f[0])
		if err != nil {
			a, aerr := netip.ParseAddr(f[0])
			if aerr != nil {
				return nil, bad("%q is not a prefix", f[0])
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		r := rule{prefix: p.Masked(), port: 161, timeout: defaultTimeout, retries: defaultRetries}
		for _, kv := range f[1:] {
			k, v, ok := strings.Cut(kv, "=")
			if !ok || v == "" {
				return nil, bad("%q is not key=value", kv)
			}
			switch k {
			case "community":
				r.community = v
			case "user":
				r.user = v
			case "auth", "priv":
				proto, pass, ok := strings.Cut(v, ":")
				if !ok || len(pass) < minPassphrase {
					return nil, bad("%s wants PROTOCOL:PASSPHRASE with at least %d characters", k, minPassphrase)
				}
				if k == "auth" {
					if r.authProto, ok = authProtos[strings.ToLower(proto)]; !ok {
						return nil, bad("auth protocol %q (md5, sha, sha224, sha256, sha384, sha512)", proto)
					}
					r.authPass = pass
				} else {
					if r.privProto, ok = privProtos[strings.ToLower(proto)]; !ok {
						return nil, bad("priv protocol %q (des, aes, aes192, aes256)", proto)
					}
					r.privPass = pass
				}
			case "port":
				u, err := strconv.ParseUint(v, 10, 16)
				if err != nil || u == 0 {
					return nil, bad("port %q", v)
				}
				r.port = uint16(u)
			case "timeout":
				d, err := time.ParseDuration(v)
				if err != nil || d <= 0 || d > 10*time.Second {
					return nil, bad("timeout %q (up to 10s)", v)
				}
				r.timeout = d
			case "retries":
				u, err := strconv.ParseUint(v, 10, 8)
				if err != nil || u > 5 {
					return nil, bad("retries %q (0-5)", v)
				}
				r.retries = int(u)
			default:
				return nil, bad("unknown key %q", k)
			}
		}
		switch {
		case r.community != "" && r.user != "":
			return nil, bad("both community and user")
		case r.community == "" && r.user == "":
			return nil, bad("neither community nor user")
		case r.community != "" && (r.authPass != "" || r.privPass != ""):
			return nil, bad("auth and priv go with user (SNMPv3)")
		case r.privPass != "" && r.authPass == "":
			return nil, bad("priv needs auth")
		}
		rules = append(rules, r)
	}
	if len(rules) == 0 {
		return nil, errors.New("no prefixes: nothing would ever be asked")
	}
	// longest prefix first
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].prefix.Bits() > rules[j].prefix.Bits() })
	return rules, nil
}

// match returns the rule that allows asking a, if any.
func match(rules []rule, a netip.Addr) (rule, bool) {
	for _, r := range rules {
		if r.prefix.Contains(a) {
			return r, true
		}
	}
	return rule{}, false
}

func (r rule) client(ctx context.Context, a netip.Addr) *gosnmp.GoSNMP {
	g := &gosnmp.GoSNMP{Target: a.String(), Port: r.port, Transport: "udp", Timeout: r.timeout, Retries: r.retries,
		MaxOids: gosnmp.MaxOids, Context: ctx}
	if r.community != "" {
		g.Version, g.Community = gosnmp.Version2c, r.community
		return g
	}
	g.Version, g.SecurityModel = gosnmp.Version3, gosnmp.UserSecurityModel
	usm := &gosnmp.UsmSecurityParameters{UserName: r.user}
	switch {
	case r.privPass != "":
		g.MsgFlags = gosnmp.AuthPriv
	case r.authPass != "":
		g.MsgFlags = gosnmp.AuthNoPriv
	default:
		g.MsgFlags = gosnmp.NoAuthNoPriv
	}
	if r.authPass != "" {
		usm.AuthenticationProtocol, usm.AuthenticationPassphrase = r.authProto, r.authPass
	}
	if r.privPass != "" {
		usm.PrivacyProtocol, usm.PrivacyPassphrase = r.privProto, r.privPass
	}
	g.SecurityParameters = usm
	return g
}

// addrIndex is the address as an OID index: "a.b.c.d" for the IPv4-only
// table, "<type>.<len>.<bytes>" for the version-neutral one.
func addrIndex(a netip.Addr, neutral bool) string {
	b := a.AsSlice()
	parts := make([]string, 0, len(b)+2)
	if neutral {
		typ := "1" // ipv4
		if a.Is6() {
			typ = "2"
		}
		parts = append(parts, typ, strconv.Itoa(len(b)))
	}
	for _, x := range b {
		parts = append(parts, strconv.Itoa(int(x)))
	}
	return strings.Join(parts, ".")
}

func text(v gosnmp.SnmpPDU) string {
	if b, ok := v.Value.([]byte); ok && v.Type == gosnmp.OctetString {
		return strings.TrimSpace(string(b))
	}
	return ""
}

func integer(v gosnmp.SnmpPDU) int64 {
	if v.Type != gosnmp.Integer {
		return 0
	}
	return gosnmp.ToBigInt(v.Value).Int64()
}

// counter is the value of a counter varbind (ok = it is one).
func counter(v gosnmp.SnmpPDU) (uint64, bool) {
	switch v.Type {
	case gosnmp.Counter32, gosnmp.Counter64, gosnmp.Gauge32:
		return gosnmp.ToBigInt(v.Value).Uint64(), true
	}
	return 0, false
}

// snmp is the plugin: what may be asked, what is shown, and the first
// value seen of every error counter.
type snmp struct {
	rules  []rule
	descr  bool // the interface's description after its name
	errors bool // its receive errors after that
	mu     sync.Mutex
	base   map[netip.Addr]baseline
}

type baseline struct {
	kind  string // "crc" or "err"
	first uint64
}

// errNote renders an error counter and its growth since the first look.
func (s *snmp) errNote(a netip.Addr, kind string, v uint64) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.base == nil {
		s.base = map[netip.Addr]baseline{}
	}
	b, ok := s.base[a]
	if !ok || b.kind != kind || v < b.first { // new, or the device restarted its counters
		s.base[a] = baseline{kind: kind, first: v}
		return fmt.Sprintf("%s:%d", kind, v)
	}
	if v == b.first {
		return fmt.Sprintf("%s:%d", kind, v)
	}
	return fmt.Sprintf("%s:%d +%d", kind, v, v-b.first)
}

// lookup asks the device at a for its name and for the interface that owns
// a. An address that no rule allows is answered without a packet.
func (s *snmp) lookup(ctx context.Context, a netip.Addr) plugin.HopInfo {
	r, ok := match(s.rules, a)
	if !ok {
		return plugin.HopInfo{}
	}
	g := r.client(ctx, a)
	if err := g.Connect(); err != nil {
		return plugin.HopInfo{}
	}
	defer g.Conn.Close()
	first := []string{oidSysName, oidIPAddressIf + "." + addrIndex(a, true)}
	if a.Is4() {
		first = append(first, oidIPAdEntIf+"."+addrIndex(a, false))
	}
	res, err := g.Get(first)
	if err != nil || res == nil {
		return plugin.HopInfo{}
	}
	var out plugin.HopInfo
	var ifIndex int64
	for i, v := range res.Variables {
		if i == 0 {
			out.Name = text(v)
		} else if n := integer(v); n > 0 && ifIndex == 0 {
			ifIndex = n
		}
	}
	if ifIndex == 0 {
		return out
	}
	idx := "." + strconv.FormatInt(ifIndex, 10)
	second := []string{oidIfName + idx}
	if s.descr {
		second = append(second, oidIfAlias+idx)
	}
	if s.errors {
		second = append(second, oidFCSErrors+idx, oidIfInErrors+idx)
	}
	res, err = g.Get(second)
	if err != nil || res == nil {
		return out
	}
	var name, alias, errs string
	var fcs, inErr *uint64
	for _, v := range res.Variables {
		switch v.Name {
		case oidIfName + idx:
			name = text(v)
		case oidIfAlias + idx:
			alias = text(v)
		case oidFCSErrors + idx:
			if n, ok := counter(v); ok {
				fcs = &n
			}
		case oidIfInErrors + idx:
			if n, ok := counter(v); ok {
				inErr = &n
			}
		}
	}
	switch {
	case fcs != nil:
		errs = s.errNote(a, "crc", *fcs)
	case inErr != nil:
		errs = s.errNote(a, "err", *inErr)
	}
	if alias != "" {
		alias = "«" + alias + "»"
	}
	// One column per thing shown (tab-separated): mpmtr lines them up.
	cols := []string{name}
	if s.descr {
		cols = append(cols, alias)
	}
	if s.errors {
		cols = append(cols, errs)
	}
	out.Note = strings.TrimRight(strings.Join(cols, "\t"), "\t")
	return out
}

func loadConfig(path string) ([]rule, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is readable by group or others (mode %04o): it holds credentials, chmod 600 it", path, st.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	rules, err := parseConfig(string(b))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return rules, nil
}

func main() {
	fs := flag.NewFlagSet("mpmtr-hop-snmp", flag.ContinueOnError)
	descr := fs.Bool("descr", false, "show the interface's description (ifAlias) after its name")
	errs := fs.Bool("errors", false, "show the interface's receive errors: crc:N (FCS errors) or err:N (all input errors)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: mpmtr --hop-info \"snmp [--descr] [--errors] CONFIG\"\n"+
			"  CONFIG: lines of PREFIX community=... or PREFIX user=... auth=PROTO:PASS priv=PROTO:PASS\n"+
			"  --descr: show the interface's description (ifAlias) after its name\n"+
			"  --errors: show its receive errors, crc:N (FCS errors) or err:N (all input errors);\n"+
			"            with mpmtr --hop-info-interval also the growth since the first look")
	}
	if fs.Parse(os.Args[1:]) != nil || fs.NArg() != 1 {
		fs.Usage()
		os.Exit(2)
	}
	rules, err := loadConfig(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "mpmtr-hop-snmp:", err)
		os.Exit(1)
	}
	s := &snmp{rules: rules, descr: *descr, errors: *errs}
	err = plugin.ServeHops("snmp", "1", 8, s.lookup)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mpmtr-hop-snmp:", err)
		os.Exit(1)
	}
}
