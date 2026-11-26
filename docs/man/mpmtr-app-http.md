<!-- Generated from man/mpmtr-app-http.1 by "make man-md": edit the man page, not this file. -->

[Русская версия](mpmtr-app-http.ru.md)

# NAME

mpmtr-app-http - application-check plugin for mpmtr: does the server
answer HTTP

# SYNOPSIS

**mpmtr --app** "**http** \[**--tls**\|**--plain**\] \[**--verify**\]
\[**--get** \[*URL*\]\] \[**--host** *NAME*\] \[**--user-agent**
*TEXT*\]" \[*options*\] *target*\[:*port*\]

# DESCRIPTION

**mpmtr-app-http** is a plugin of **mpmtr**(1). It is not run by hand:
**mpmtr --app http** starts it and hands it connections. Its own options
go into the quotes after its name.

**mpmtr** measures with bare TCP SYN packets, which tell only that a
server accepts connections. With this plugin every measured source port
also gets, every **--app-interval** (default 10 s), one real HTTP
request to the server that port leads to. A server that accepts
connections and does not answer HTTP is then seen as such: its checks
fail while TCP answers, and after three failed checks in a row it is
DOWN.

# WHAT ONE CHECK DOES

1.  **mpmtr** opens a kernel TCP connection from the measured source
    port to the target: the same addresses and ports its probes use, so
    a load balancer leads the connection to the same server.

2.  The plugin gets the connected socket. On port 443 (or with
    **--tls**) it first makes a TLS handshake, with the target's name as
    the server name. Then it sends

    ``` text
    HEAD / HTTP/1.0
    Host: the target as given to mpmtr, without the port
    User-Agent: mpmtr
    ```

3.  It reads one line of the answer. A line that starts with **HTTP/**
    is a passed check, whatever the status code.

4.  **mpmtr** closes the connection with RST.

The whole check must fit in **--app-timeout** (default 5 s).

# OPTIONS

**--tls**  
Speak TLS. Without it TLS is spoken on port 443 only.

**--plain**  
Never speak TLS, also on port 443.

**--verify**  
A certificate that does not verify against the name fails the check
(stage **tls**). By default the certificate is not verified: the check
asks whether the server answers, not whether its certificate is in
order.

**--get** \[*URL*\]  
Send **GET** in place of **HEAD**. Some servers refuse HEAD or answer it
differently (a 418 or 405 where GET gets 200). Only the status line is
read either way. *URL* says what to ask for in place of **/**: a path
(**/index.php**), or a URL with a host (**example.com/index.php**,
**https://example.com/index.php**). The host of the URL is then the name
asked for (the **Host** header and the TLS server name), and its scheme
says whether TLS is spoken; **--host**, **--tls** and **--plain** win
over them. The connection still goes to the target given to **mpmtr**.

**--host** *NAME*  
The name for the **Host** header and the TLS server name, in place of
the target given to **mpmtr**.

**--user-agent** *TEXT*  
The **User-Agent** header (default **mpmtr**). Some sites answer a
client they do not take for a browser differently, for example with a
redirect to another version of the site.

# RESULTS

passed  
The server sent an HTTP status line. Its status code is shown in the
**PLUGIN** column of the server's row. Counts as an answer of that port
and server; its RTT is the time of the TCP handshake of this connection.

failed, stage **tls**  
The TLS handshake failed (or, with **--verify**, the certificate did not
verify).

failed, stage **send**  
The request could not be written (the server reset the connection).

failed, stage **answer**  
No line came before the timeout, the server closed the connection
without one, or the line is not an HTTP status line.

The checks are counted apart from the TCP probes: a failed one is shown
as <b>app-failed:</b><i>N</i><b>/</b><i>M</i> in the flags and as
**app_failed** of **app_checks** in JSON, with a rate of its own, and is
not part of the TCP failure share. Three failed checks in a row make the
port DOWN, reason **app_down**. A connection that was refused or never
established is counted by **mpmtr** itself, before the plugin sees
anything.

To see every check with its stage and error text, set
**MPMTR_DEBUG_APP=1** and read standard error.

# WHAT IT DOES NOT CHECK

- The status code. 404, 500 and a redirect all pass: the check answers
  "is an HTTP server alive here", not "does the site work".

- The certificate, unless **--verify** is given.

- More than one site. Every check asks for the target's own name; other
  sites of the same server are not asked.

A check of your own protocol is a small program: see
**docs/WRITING_PLUGINS.md** in the source tree.

# EXAMPLES

Every route to a web server, each measured port checked over HTTP:

``` text
mpmtr --app http example.com:80
```

Every server behind an anycast address, checked every 30 s:

``` text
mpmtr --anycast --app http --app-interval 30s example.com:80
```

# FILES

**mpmtr** looks for the executable **mpmtr-app-http** next to itself,
then in **PATH**.

# SECURITY

The plugin runs with the privileges **mpmtr** has. It sends nothing but
the request above, and only over connections **mpmtr** gave it.

# SEE ALSO

**mpmtr**(1), **mpmtr-hop-snmp**(1)

**docs/PLUGINS.md** (the plugin protocol), **docs/WRITING_PLUGINS.md**
(how to write a plugin).

# LICENSE

MIT.
