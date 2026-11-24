# Scripting, Agents, and Polkit

This guide covers automating Kestrel from scripts, streaming live D-Bus state changes, running the interactive terminal agent, and customizing polkit authorization rules.

---

## 1. Machine-Readable Output (`--json`, `monitor`, and Exit Codes)

The global `--json` flag emits structured JSON across `status`, `radio`, `monitor`, `wifi`, `profile`, `certificate`, `p2p`, and `hotspot` commands:

```sh
# Query active interface states and IP addresses
kestrel --json status | jq '.devices[] | {interface, state, ssid, addresses}'

# Stream D-Bus property and interface changes as NDJSON (one JSON object per line)
kestrel --json monitor
```

> `kestrel status --watch` cannot be combined with `--json`. Use `kestrel --json monitor` for reactive updates without polling.

Data and JSON always go to `stdout`; prompts, scan progress, empty-list notices, and errors go to `stderr`. Semantic exit codes are:

- `0`: success
- `1`: runtime, validation, authorization, or D-Bus error (with stable D-Bus short names such as `AccessDenied`, `Busy`, `NotSupported`, `InvalidArgument` on `stderr`)
- `2`: CLI argument usage error
- `124`: wait timeout elapsed
- `130`: interrupted by `Ctrl-C` while waiting

---

## 2. Non-Interactive Workflows

Kestrel never accepts passphrases, WPS PINs, or private key passphrases in command-line arguments (`argv`), preventing exposure in `/proc/<pid>/cmdline`. Use standard input flags and `-y` / `--no-wait` in scripts. On multi-radio hosts, pass `-d <iface>` (or export `KESTREL_DEVICE=<iface>`):

```sh
# Create a Wi-Fi profile without prompting
printf '%s\n' "$WIFI_PSK" | kestrel --json profile add "OfficeNet" \
  --security wpa-personal \
  --secret-stdin

# Connect and return immediately instead of waiting for L3
printf '%s\n' "$WIFI_PSK" | kestrel wifi connect "OfficeNet" \
  -d wlp0s20f3 \
  --secret-stdin \
  --no-wait

# Start a hotspot non-interactively and wait until active
printf '%s\n' "$AP_PSK" | kestrel --json hotspot start "kestrel-ap" \
  -d wlp0s20f3 \
  --secret-stdin

# Connect to a P2P peer using a WPS keypad PIN from stdin
printf '%s\n' "$PEER_PIN" | kestrel p2p connect 02:11:22:33:44:55 \
  -d wlp0s20f3 \
  --pin-stdin \
  -t 90

# Delete profiles, certificates, or P2P groups without confirmation prompts
kestrel profile delete "OfficeNet" -y
kestrel certificate delete "Corp CA" -y
kestrel p2p group delete <group> -y
```

Each stdin secret flag reads only the first line of standard input and strips the trailing newline.

---

## 3. Interactive Agent (`kestrel agent`)

Some events happen asynchronously while you are not actively running a `kestrel` command:

- A saved profile fails authentication (`auth-failed`) or its sealed credential was quarantined (`secrets-required`), and Kestrel needs a replacement passphrase.
- A remote Wi-Fi Direct peer initiates an incoming P2P connection (`AuthorizePeer`).
- A P2P connection using `--wps display` generates a WPS PIN that must be shown to the user (`DisplayPin`).

Run the terminal agent in a dedicated TTY:

```sh
kestrel agent
```

Key behaviors of `kestrel agent`:

- Requires an interactive terminal (`stdin` must be a TTY).
- Only one agent can be registered with `kestrel-daemon` at a time; a second registration fails with `Busy`. Desktop compositors or status bars that implement `com.hihusky.Kestrel.Agent` occupy the same slot.
- Watches `NameOwnerChanged` for `com.hihusky.Kestrel` and automatically re-registers if `kestrel-daemon` restarts.
- Agent prompts time out after `[timeouts].agent` seconds (default and maximum `120`).

---

## 4. Polkit Authorization and Custom Rules

Read operations (such as `status`, `radio`, `wifi scan --cached`, `wifi autoconnect`, `wifi history`, `profile list`, `p2p peer list`, `p2p session list`, `hotspot status`) are unrestricted. Mutating methods check one of five polkit actions defined in `data/com.hihusky.kestrel.policy`:

| Polkit Action | Operations | Active Local Session | Inactive / Remote Session |
| :--- | :--- | :--- | :--- |
| `com.hihusky.kestrel.connect` | Active scan, connect, disconnect, autoconnect mutation, P2P discovery/sessions/WFD | `yes` | `auth_admin_keep` |
| `com.hihusky.kestrel.hotspot` | Start and stop SoftAP hotspots | `yes` | `auth_admin_keep` |
| `com.hihusky.kestrel.modify-profiles` | Add/edit/delete profiles, import/delete certificates, delete persistent P2P groups | `yes` | `auth_admin_keep` |
| `com.hihusky.kestrel.toggle-wireless` | `radio on`, `radio off` | `yes` | `auth_admin_keep` |
| `com.hihusky.kestrel.register-agent` | `kestrel agent` / desktop agent registration | `yes` | `auth_admin_keep` |

Root is always authorized by polkit. When `kestrel` runs on the system bus, it checks polkit authorization **before** prompting for a Wi-Fi passphrase, WPS PIN, or delete confirmation, and automatically spawns `pkttyagent --fallback` on interactive terminals if no desktop polkit agent is running.

### Restricting Profile Changes on Multi-User Systems

On a shared multi-user machine where only administrators should modify saved networks, tighten `com.hihusky.kestrel.modify-profiles` with a polkit rule at `/etc/polkit-1/rules.d/50-kestrel.rules`:

```javascript
polkit.addRule(function(action, subject) {
    if (action.id === "com.hihusky.kestrel.modify-profiles" &&
        !subject.isInGroup("wheel")) {
        return polkit.Result.AUTH_ADMIN_KEEP;
    }
});
```

Avoid setting `[api].authorization = "bus-policy"` in `/etc/kestrel/kestrel.toml` on multi-user systems; `bus-policy` disables polkit checks and is intended for private or session-bus testing.
