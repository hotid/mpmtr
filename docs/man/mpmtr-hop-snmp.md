<!-- Generated from man/mpmtr-hop-snmp.1 by "make man-md": edit the man page, not this file. -->

[Русская версия](mpmtr-hop-snmp.ru.md)

# NAME

mpmtr-hop-snmp - hop-information plugin for mpmtr: router name,
interface and its errors over SNMP

# SYNOPSIS

**mpmtr --hop-info** "**snmp** \[**--descr**\] \[**--errors**\] *FILE*"
\[*options*\] *target*\[:*port*\]

# DESCRIPTION

**mpmtr-hop-snmp** is a plugin of **mpmtr**(1). It is not run by hand:
**mpmtr --hop-info** starts it, gives it the address of every hop shown,
and shows what the plugin answers.

For a hop address the plugin asks the router at that address, over SNMP:

- its name (**sysName**), shown as the hop's host name instead of the
  reverse-DNS one;

- the interface that owns the address (**ifName**), shown in the
  **PLUGIN** column;

- with **--descr**, that interface's description (**ifAlias**);

- with **--errors**, that interface's receive errors.

``` text
HOST                        ...  PLUGIN
core1.example (192.0.2.1)   ...  Ethernet1/2     «to spine 3»  crc:0
core2.example (192.0.2.5)   ...  Port-Channel37  «uplink»      err:12 +3
```

Hop addresses come from the network, not from you: a router anywhere on
the path chooses the address it answers with. So the plugin asks nothing
unless *FILE* allows that very address; see **CONFIGURATION**.

# OPTIONS

The plugin's options go inside the quotes of **--hop-info**, before the
file name.

**--descr**  
Show the interface's description (**ifAlias**) after its name, in «».

**--errors**  
Show the interface's receive errors after that; see **ERROR COUNTERS**.

*FILE*  
The configuration: which addresses may be asked and how. Required.

# CONFIGURATION

One line per prefix: the prefix (or a single address), then
*key*=*value* pairs separated by spaces. **\#** starts a comment.

``` text
# SNMPv2c: the community travels in clear text to every address asked
10.0.0.0/8      community=public
# SNMPv3 with authentication and encryption
192.0.2.0/24    user=monitor auth=sha256:secret-one priv=aes:secret-two
# another port and patience for one slow device
10.1.2.3        community=public port=1161 timeout=3s retries=0
```

<b>community=</b><i>TEXT</i>  
SNMPv2c with this community.

<b>user=</b><i>NAME</i>  
SNMPv3 with this user. Alone it means no authentication and no
encryption.

<b>auth=</b><i>PROTOCOL</i><b>:</b><i>PASSPHRASE</i>  
SNMPv3 authentication: **md5**, **sha**, **sha224**, **sha256**,
**sha384**, **sha512**.

<b>priv=</b><i>PROTOCOL</i><b>:</b><i>PASSPHRASE</i>  
SNMPv3 encryption: **des**, **aes**, **aes192**, **aes256**. Needs
**auth**.

<b>port=</b><i>N</i>  
UDP port of the agent (default 161).

<b>timeout=</b><i>D</i>  
How long to wait for one answer (default 1s, at most 10s).

<b>retries=</b><i>N</i>  
How many times a request is repeated after a timeout (default 1, 0-5).

Rules:

- The longest matching prefix wins.

- An address in no prefix is never sent a packet.

- A line has either **community** or **user**, not both.

- Passphrases are at least 8 characters and have no spaces (a value ends
  at the first space).

- The file must not be readable by group or others (**chmod 600**): it
  holds credentials, and the plugin refuses a file that is.

- A file with no prefixes is an error: nothing would ever be asked.

On any error in the file the plugin prints the line number and what is
wrong to standard error and exits.

# WHAT IS SENT

For one address, at most two SNMP GET requests, both to that address. No
table is walked. SNMPv3 adds the exchange in which the device tells its
engine ID.

1.  **sysName.0** and the interface index of the address:
    **ipAddressIfIndex** (the table for IPv4 and IPv6) and, for an IPv4
    address, also **ipAdEntIfIndex** (the older IPv4 table, for devices
    that fill only that one).

2.  If an interface index came back: **ifName**, with **--descr** also
    **ifAlias**, with **--errors** also **dot3StatsFCSErrors** and
    **ifInErrors**, all for that index, in one request.

If the device knows its name and not the interface of the address, only
the name is shown. If it does not answer, nothing is shown for that
address; nothing else changes.

The plugin asks at most 8 addresses at a time. One request waits
**timeout** and is repeated **retries** times, so a silent address costs
up to timeout × (retries + 1): 2 s by default.

How often an address is asked is decided by **mpmtr**: once, when the
hop is first shown. With **--hop-info-interval** *D* an address still on
the screen is asked again when its answer is that old. The old answer
stays until the new one is in, and a new answer that says nothing does
not erase it.

# ERROR COUNTERS

With **--errors** the note ends with one of:

<b>crc:</b><i>N</i>  
Frames received with a bad checksum (**dot3StatsFCSErrors**). Shown when
the interface has this counter: a physical Ethernet port.

<b>err:</b><i>N</i>  
All input errors together (**ifInErrors**). Shown when the interface has
no checksum counter: a port-channel, a VLAN interface.

nothing  
The device gives neither.

The counters run since the device booted (or since they were cleared),
so the number alone says little. When **mpmtr** asks again
(**--hop-info-interval**), the plugin adds the growth since its own
first look at that address:

``` text
crc:1532 +12
```

means 1532 in total, 12 of them since the plugin first asked. A counter
that went back (the device restarted, the counters were cleared) starts
the count anew. Without **--hop-info-interval** there is no second look
and only the total is shown.

# WHICH INTERFACE

The interface is the one that owns the address the router answered from.
That is usually the interface the probe came in through, but a router
may answer from another interface or from a loopback. The interface the
traffic leaves through is not told.

A hop on a port-channel or a VLAN interface shows the errors of that
logical interface, not of the physical ports under it.

# EXAMPLES

Names and interfaces:

``` text
mpmtr --hop-info "snmp /etc/mpmtr/snmp.conf" example.com
```

With descriptions and errors, refreshed every minute:

``` text
mpmtr --hop-info "snmp --descr --errors /etc/mpmtr/snmp.conf" \
      --hop-info-interval 60s example.com
```

Together with another plugin (their notes stand side by side):

``` text
mpmtr --hop-info "snmp /etc/mpmtr/snmp.conf" --hop-info rack example.com
```

# EXIT STATUS

**0**  
**mpmtr** closed the plugin's input.

**1**  
The configuration file cannot be read, is readable by others, or has an
error.

**2**  
Wrong command line.

# FILES

**mpmtr** looks for the executable **mpmtr-hop-snmp** next to itself,
then in **PATH**.

# SECURITY

- An SNMPv2c community travels in clear text to every address the file
  allows. Keep the prefixes as narrow as your own network.

- A prefix that covers addresses you do not control hands them the
  community: whoever answers from such an address on the path gets a
  request with it.

- **mpmtr** itself sends nothing for this and has no SNMP options: the
  credentials live only in the file.

- The plugin only reads (GET); it never writes to a device.

# SEE ALSO

**mpmtr**(1), **mpmtr-app-http**(1), **snmpget**(1)

IF-MIB (RFC 2863), IP-MIB (RFC 4293), EtherLike-MIB (RFC 3635).

**docs/PLUGINS.md** (the plugin protocol), **docs/WRITING_PLUGINS.md**
(how to write a plugin).

# LICENSE

MIT.
