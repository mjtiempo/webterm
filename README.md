# webterm

A shell in the browser, behind a password. One Python file, no dependencies.

The server runs a real PTY, streams its output to the browser over
Server-Sent Events, and takes keystrokes back as small POSTs. The terminal is
[xterm.js](https://xtermjs.org/), vendored in `static/vendor/` so nothing is
loaded from a CDN at runtime.

## Run it

```bash
./server.py --port 7681
# webterm: generated password for this run: 7vK@mQ2xP#Rz4tL&nW8Yb$Hc
# webterm: http://127.0.0.1:7681/  shell=/bin/bash  cwd=/home/you
```

Open <http://127.0.0.1:7681/> and sign in with the passphrase it printed. With
neither a password nor a hash set, the server generates a 24-character one
(~150 bits, at least one of every character class, no look-alike characters)
and prints it once on startup, like Jupyter.

To pin your own instead, without putting it in your shell history or process
list:

```bash
export WEBTERM_PASSWORD='<your passphrase>'          # or:
./server.py --password-hash "$(./server.py --print-hash)"
```

## Options

| Flag | Default | |
| --- | --- | --- |
| `--host` | `127.0.0.1` | bind address |
| `--port` | `7681` | bind port |
| `--shell` | `$SHELL` | shell to run (`-l` is passed) |
| `--cwd` | current dir | initial working directory |
| `--password` | `$WEBTERM_PASSWORD` | plaintext password; omit and one is generated |
| `--password-hash` | `$WEBTERM_PASSWORD_HASH` | `scrypt$salt$hash` from `--print-hash` |
| `--secure-cookies` | off | add `Secure` to the session cookie when served over HTTPS |
| `--session-ttl` | `43200` | login lifetime, seconds |
| `--idle-timeout` | `1800` | kill a terminal with no browser attached after N seconds |
| `--max-terminals` | `8` | server-wide terminal cap |
| `--max-terminals-per-session` | `4` | per-session terminal cap |
| `--verbose` | off | log requests |

## How it works

```
browser ──POST /api/terminals/<id>/input──▶ server ──write──▶ pty master ──▶ shell
        ◀─GET  /api/terminals/<id>/stream─  server ◀──read─── pty master ◀── shell
```

- Output is base64 inside `text/event-stream` events (`reset`, `ready`,
  `output`, `exit`) plus a comment keepalive every 15s. Base64 avoids UTF-8
  chunk-splitting bugs and SSE survives proxies that would mangle a raw stream.
- Input and resize are ordinary authenticated POSTs.
- Each terminal keeps up to 1 MiB of scrollback. A client that reconnects with
  `?cursor=<bytes>` gets exactly what it missed; if it fell off the end of the
  buffer the server sends `reset` and resumes from there.
- Terminals outlive the page: reload, or close the tab and come back within
  `--idle-timeout`, and you land in the same shell. `sessionStorage` remembers
  which terminal the tab was using.

## Fonts

`static/vendor/JetBrainsMonoNerdFontMono-{Regular,Bold}.woff2` is JetBrains Mono
patched with the [Nerd Fonts](https://www.nerdfonts.com) icon set (v3.5.1,
OFL-1.1 — see `LICENSE-JetBrainsMono.txt`). It is first in the terminal's font
stack, so powerlevel10k/starship prompts, `eza` / `ls --icons` and powerline
separators render instead of showing blanks, and because it is the **Mono**
variant every icon is one cell wide — columns stay aligned.

The page waits for the font before xterm measures its cell, and refits when
`document.fonts.ready` fires. To use a different one, drop a Nerd Font *Mono*
`.woff2` into `static/vendor/` and update the `@font-face` in
`static/index.html` and the whitelist in `server.py`.

## Security

This serves a root-able shell to anyone who can reach it, so:

- **Bind to loopback** (the default) and put a tunnel or reverse proxy in
  front. If you bind elsewhere, the server warns.
- Passwords are hashed with scrypt at startup; only the hash is kept in memory.
- Sessions are random 256-bit tokens in an `HttpOnly; SameSite=Strict` cookie,
  expiring after `--session-ttl`, and POST/DELETE requests from a different
  origin are rejected.
- Login attempts are limited to 5 per IP per minute, and failures are logged.
- Use `--secure-cookies` whenever the browser sees HTTPS.
- The shell runs as whoever starts the server. Don't run it as root.

## Exposing it with opentunnel

```bash
opentunnel route add 7681 --name term
# https://term.<id>.opentunnel.xyz
```

The route is a public URL with no authentication of its own — the password is
the only door. TLS terminates on your machine, and long-lived SSE responses
pass through the tunnel fine. Use `--secure-cookies` so the session cookie is
marked `Secure` behind the tunnel's HTTPS.

## Files

```
server.py              the whole server
static/index.html      login page + xterm.js wiring
static/vendor/         xterm.js, addon-fit, addon-web-links
```
