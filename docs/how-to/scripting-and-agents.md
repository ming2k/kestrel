# Scripting, Agents, and Polkit

This guide covers automating Kestrel from scripts, streaming live D-Bus state changes, running the interactive terminal agent, and customizing polkit authorization rules.

---

## 1. Machine-Readable Output (`--json` and `monitor`)

The global `--json` flag emits structured JSON across `status`, `monitor`, `wifi`, `profile`, `certificate`, `p2p`, and `hotspot` commands:

```sh
# Query active interface states and IP addresses
kestrel --json status | jq '.devices[] | {interface, state, ssid, addresses}'

# Stream D-Bus property and interface changes as NDJSON (one JSON object per line)
kestrel --json monitor
```

> `kestrel status --watch` cannot be combined with `--json`. Use `kestrel --json monitor` for reactive updates without polling.

All `kestrel` subcommands exit `0` on success and `1` on error, printing stable D-Bus error short names (such as `AccessDenied`, `Busy`, `NotSupported`, `InvalidArgument`) to `stderr`.

---

## 2. Non-Interactive Workflows

Kestrel never accepts passphrases, WPS PINs, or private key passphrases in command-line arguments (`argv`), preventing exposure in `/proc/<pid>/cmdline`. Use standard input flags and `--yes` / `--no-wait` in scripts:

```sh
# Create a Wi-Fi profile without prompting
printf '%s\n' "$WIFI_PSK" | kestrel --json profile add \
  --ssid "OfficeNet" \
  --security wpa-personal \
  --secret-stdin

# Join and return immediately instead of waiting for L3
printf '%s\n' "$WIFI_PSK" | kestrel wifi join wlp0s20f3 "OfficeNet" \
  --secret-stdin \
  --no-wait

# Start a hotspot non-interactively
printf '%s\n' "$AP_PSK" | kestrel --json hotspot start wlp0s20f3 \
  --ssid "kestrel-ap" \
  --secret-stdin

# Connect to a P2P peer using a WPS keypad PIN from stdin
printf '%s\n' "$PEER_PIN" | kestrel p2p connect wlp0s20f3 02:11:22:33:44:55 \
  --pin-stdin \
  --wait \
  --timeout 90

# Delete profiles, certificates, or P2P groups without confirmation prompts
kestrel profile delete "OfficeNet" --yes
kestrel certificate delete "Corp CA" --yes
kestrel p2p groups delete <group> --yes
```

Each stdin secret flag reads only the first line of standard input and strips the trailing newline.

---

## 3. Interactive Agent (`kestrel agent`)

Some events happen asynchronously while you are not actively running a `kestrel` command:

- A saved profile fails authentication (`auth-failed`) or its sealed credential was quarantined (`secrets-required`), and Kestrel needs a replacement passphrase.
- A remote Wi-Fi Direct peer initiates an incoming P2P connection (`AuthorizePeer`).
- A P2P connection using `--display` generates a WPS PIN that must be shown to the user (`DisplayPin`).

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

Read operations (such as `status`, `wifi status`, `wifi list`, `wifi history`, `profile list`, `p2p peers`, `hotspot status`) are unrestricted. Mutating methods check one of five polkit actions defined in `data/com.hihusky.kestrel.policy`:

| Polkit Action | Operations | Active Local Session | Inactive / Remote Session |
| :--- | :--- | :--- | :--- |
| `com.hihusky.kestrel.connect` | Scan, connect, disconnect, autoconnect, P2P discovery/sessions/WFD | `yes` | `auth_admin` |
| `com.hihusky.kestrel.hotspot` | Start and stop SoftAP hotspots | `yes` | `auth_admin` |
| `com.hihusky.kestrel.modify-profiles` | Add/edit/delete profiles, import/delete certificates, delete persistent P2P groups | `auth_admin_keep` | `auth_admin` |
| `com.hihusky.kestrel.toggle-wireless` | `wifi on`, `wifi off` | `yes` | `auth_admin` |
| `com.hihusky.kestrel.register-agent` | `kestrel agent` / desktop agent registration | `yes` | `auth_admin` |

Root is always authorized by polkit.

### Allowing a Local Group to Modify Profiles Without a Password

On a single-user workstation or dedicated appliance, you can grant members of a group (for example `wheel` or `netdev`) passwordless profile changes by installing a polkit rule at `/etc/polkit-1/rules.d/50-kestrel.rules`:

```javascript
polkit.addRule(function(action, subject) {
    if (action.id === "com.hihusky.kestrel.modify-profiles" &&
        subject.isInGroup("wheel") &&
        subject.local &&
        subject.active) {
        return polkit.Result.YES;
    }
});
```

Avoid setting `[api].authorization = "bus-policy"` in `/etc/kestrel/kestrel.toml` on multi-user systems; `bus-policy` disables polkit checks and is intended for private or session-bus testing.
