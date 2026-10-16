# TunnelBar

A tiny macOS menu bar app that turns the SSH tunnels in your `~/.ssh/config` on and off.

Every `Host` (without wildcards) that has a `LocalForward`, `RemoteForward` or `DynamicForward`
line shows up as a row with a switch. Each tunnel runs as a plain `/usr/bin/ssh -N <host>`, so
everything OpenSSH supports — keys, agent, Keychain, `ProxyJump`, certificates — just works.

## Features

- Switch tunnels on and off from the menu bar; a coloured dot shows connecting / connected / failed
- Every forwarded port listed with an L / D / R badge, plain-English "from → to"
  (e.g. `localhost:5900 → omarchy:5900`) and a live dot per port: green when listening,
  red when another app holds the port
- Click a port to open it (web ports in the browser, 5900–5999 in Screen Sharing) or copy it
  (databases, SSH, SOCKS); ⌥-click always copies; right-click also copies the equivalent `-L/-D/-R` flag
- Forwards are read through `ssh -G`, so `Match` blocks and forwards split across several `Host` blocks work
- Shows ssh's actual error message when a tunnel fails
- Reconnects automatically after drops (backoff 5 s → 10 s → 30 s → 60 s) and after the Mac wakes
- Tunnels that were on when you quit come back on at the next launch
- Picks up edits to `~/.ssh/config` within a few seconds — no restart
- Connect All / Disconnect All, Edit SSH Config…, Launch at Login
- One Swift file, no dependencies, builds with the Xcode Command Line Tools

## Example config

```
# Plain host for interactive ssh (no forwards, so it doesn't appear in TunnelBar)
Host myserver myserver-tunnels
    HostName myserver.example.com
    User me
    IdentityFile ~/.ssh/id_ed25519

# Same server, with forwards: this is the row TunnelBar shows
Host myserver-tunnels
    LocalForward 5432 localhost:5432    # Postgres on the server → localhost:5432
    DynamicForward 1080                 # SOCKS proxy on localhost:1080
```

Keeping the forwards on a separate alias means other tools that ssh to `myserver`
don't fight over the same local ports.

## Requirements

- macOS 14 or later
- Key-based SSH auth. TunnelBar runs ssh with `BatchMode=yes`, so it never prompts for a password.
  Keys with a passphrase work if the passphrase is in your Keychain (`UseKeychain yes`).
- First connections to a new host are trusted automatically (`StrictHostKeyChecking=accept-new`);
  a host whose key has changed is still rejected.

## Build and install

```bash
./build.sh            # builds build/TunnelBar.app
./build.sh install    # also copies it to ~/Applications and starts it
```

## Testing without the UI

```bash
TUNNELBAR_SSH_CONFIG=/path/to/test_config build/TunnelBar.app/Contents/MacOS/TunnelBar --selftest=10
```

Starts every tunnel in that config, waits 10 seconds, prints each tunnel's state and exits.
`TUNNELBAR_SSH_CONFIG` also works for the normal app, to point it at a config other than `~/.ssh/config`.

## Limitations

- Hosts are discovered from `Host` lines in the main config file; hosts declared only in `Include`d files aren't listed.
- The app isn't notarized; it's ad-hoc signed by `build.sh` for local use.

## License

MIT, see [LICENSE](LICENSE).
