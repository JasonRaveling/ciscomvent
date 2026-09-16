# ciscomvent

Restores host-to-container reachability on a Linux workstation while Cisco Secure
Client (formerly AnyConnect) is connected in `Tunnel All Traffic` mode, without
modifying the VPN client, its firewall chains, or its routes.

It does change your own host state: reclaim routes in a dedicated table selected by a
policy rule, and narrow accepts at the *top* of `INPUT` and `OUTPUT`, ahead of Cisco's
chains.

![Gob Bluth: "please allow me, I'll just ciscomvent you"](docs/ciscomvent.gif "Arrested Development")

---

## tl;dr

Cisco Secure Client in tunnel-all mode pulls your Docker bridge subnets into the tunnel,
so `curl localhost:8080` connects and then hangs. ciscomvent puts those subnets back on
their bridge using a routing table of its own (table 150, selected by an `ip rule` at
priority 100) plus narrow `INPUT`/`OUTPUT` accepts, and re-applies both every time the
client rebuilds its routes.

```bash
sudo env PYTHONPATH=src python3 -m ciscomvent install  # deploy, put `ciscomvent` on PATH
sudo ciscomvent daemon install
sudo systemctl start ciscomvent
ciscomvent status   # what the tunnel has captured
ciscomvent verify   # whether containers are actually reachable
```

Docker bridges are claimed by default; LAN and libvirt are listed but off. The daemon
asks before claiming, once per VPN session: approve from the tray applet, or with
`ciscomvent approve <scope> --session`, or drop the prompt with
`sudo ciscomvent config --automation auto`. Nothing wider than a `/16` is claimed without
an explicit opt-in, and `sudo ciscomvent revert` removes everything it added.

---

## The problem

On connect, Secure Client installs a scope-link route for every locally-discovered
subnet pointing at `cscotun0`, shadowing the Docker bridge routes:

```
172.18.0.0/16  dev cscotun0 proto unspec scope link   # shadows br-<id[:12]>
```

`127.0.0.1` is **not** what breaks. The kernel `local` table outranks anything the
client installs. The second hop does. `docker-proxy` accepts on loopback, dials the
container, and *that* lookup resolves to the tunnel, reaching a headend with no route
back to a local bridge.

Signature: **TCP connect succeeds, then the request hangs and times out**, making it
look like a TLS or application fault.

## The fix

Policy routing, in a table of our own:

```
ip route replace 172.18.0.0/16 dev br-1a1a1a1a1a1a table 150 src 172.18.0.1
ip rule add to 172.18.0.0/16 lookup 150 priority 100
```

Cisco writes to `main`. Priority 100 is consulted before `main` (32766) so prefix length
stops deciding anything, and after `local` (0) so host-owned addresses keep resolving.

Everything is ownership-tagged (routes in table 150, rules at priority 100, firewall
rules commented `ciscomvent:<scope>`), so teardown is exact and structurally cannot reach
Cisco's routes (`proto unspec`) or the kernel's (`proto kernel`). Ownership is read back
from the kernel rather than recorded, so there is no state file to fall out of step with
reality.

```
ip route show table 150    # ours
ip rule show priority 100  # ours
ip route flush table 150   # cannot touch main
```

## Install

From a clone of this repo, with Python 3.11 or later:

```bash
cd /path/to/this/repo
sudo env PYTHONPATH=src python3 -m ciscomvent install
```

Deploys to `/usr/local/lib/ciscomvent`, puts a `ciscomvent` wrapper on PATH, writes the
applet's menu entry and icon, and registers the route proto name. CLI and daemon both
run the **deployed** copy, so you must re-run install after changing code.
Alternatively, running `PYTHONPATH=src python3 -m ciscomvent <cmd>` works without the
need to install.

## Usage

```bash
ciscomvent status [--all]    # VPN state + per-scope diagnosis
ciscomvent verify            # routing *and* reachability: the "is it working?" check
ciscomvent scopes            # what was discovered, and how
ciscomvent plan              # preview reclaim routes
ciscomvent reconcile         # desired-vs-actual delta
ciscomvent config            # show settings
ciscomvent baseline capture  # snapshot; take one with the VPN *down* as the reference

sudo ciscomvent apply             # claim now: routes, then accepts if still unreachable
sudo ciscomvent revert            # remove every route and rule we added
sudo ciscomvent revert --layer 2  # firewall rules only, leaving routing in place
```

`verify --url` runs an end-to-end check. Always pass `--resolve` for a `Host()`-routed
proxy, since a bare IP request matches no router and fails misleadingly:

```bash
ciscomvent verify --url https://test.local/ --resolve test.local:443:127.0.0.1
```

`--json` works on `status`, `scopes`, `plan`, `verify`, `reconcile`, `config` and
`baseline show`, and is a top-level flag: `ciscomvent --json status`, not
`ciscomvent status --json`. `status` and `verify` exit `0` healthy, `1` needs fixing,
`2` on error. `--version` reports which copy is running.

## The daemon

```bash
sudo env PYTHONPATH=src python3 -m ciscomvent daemon install
sudo systemctl start ciscomvent
journalctl -fu ciscomvent
ciscomvent daemon status          # installed / enabled / active
sudo ciscomvent daemon uninstall  # stop, disable, remove the unit
```

`ip monitor` is the trigger, not a device unit: Secure Client reinstalls its routes on
**every network change**, not only at connect. One connect produces a burst of dozens of
route messages, so events are debounced: reconcile 1.5s after the last, or 10s after the
first if they keep coming.

It emits only the desired-vs-actual delta, so it is idempotent and cleanup falls out of
the same path: tunnel down means nothing is desired. Removals are never gated on
approval, since cleaning up after ourselves needs none. Desired state is deliberately
*not* conditioned on whether a scope is captured: applying the fix makes a captured scope
look healthy, so gating on the diagnosis would have the daemon tear down its own routes
and flap forever. The predicate is tunnel up, scope enabled, device live.

## Configuration

`/etc/ciscomvent/config.json`, reloaded every reconcile, so changes land within 60s, or
immediately on the next network change.

| Key | Default | |
|---|---|---|
| `automation` | `confirm` | `confirm` computes and waits; `auto` applies silently. Approval is **per VPN session**, not per event, since Cisco reinstalls routes repeatedly and per-event prompting would be continuous. Disconnect clears grants. |
| `firewall` | `true` | Install the layer 2 accepts. Off leaves routing correct and traffic dropped. |
| `min_claim_prefixlen` | `16` | Widest claimable network, and the widest host interface prefix offered as a scope. |
| `allow_wide_claims` | empty | Exact CIDRs to claim anyway. Root-edited only. |
| `socket_group` | auto | Group owning the control socket. |
| `enabled_scopes`, `disabled_scopes`, `always_allow` | empty | Managed by `approve` / `scope` and the GUI. |

The accepts are narrow on purpose: each is scoped to a claimed subnet, and `INPUT`
further to `ESTABLISHED,RELATED` and the host's own address on the device. The host
dialing the container is what breaks, so the return path is all that must be admitted; a
container opening a **new** connection to a host service falls through to your firewall,
where that decision belongs.

`min_claim_prefixlen` is a security boundary. A claim outranks `main` and therefore the
tunnel, and `docker network create --subnet 10.0.0.0/8` needs no root: without a ceiling,
a compose file from an untrusted repo pulls every corporate destination in 10/8 onto a
bridge where a container can answer for it. `/16` refuses nothing the usual tooling
produces. Overlap is *not* the test. It is the normal case and the reason this tool
exists. Refused are claims wider than the ceiling and claims that strictly *contain* a
headend-pushed prefix, both named in the journal and in `ciscomvent reconcile`. The
ceiling applies again at discovery: a LAN or libvirt prefix too wide to claim is not
offered as a scope at all.

### Approval

```bash
ciscomvent approve docker:app --session      # no root; cleared on disconnect
sudo ciscomvent approve docker:app           # standing
sudo ciscomvent approve docker:app --revoke  # withdraw it
sudo ciscomvent config --automation auto     # zero-touch
sudo ciscomvent scope docker:app --enable    # or --disable
```

| Tier | Commands | Requirement |
|---|---|---|
| Session | `status`, `reconcile`, `restart`, session approval and dismissal | Socket group membership, proven by the connection itself |
| Persisting | `set-scope`, `set-automation`, standing approval | uid 0, checked against `SO_PEERCRED` |

Both are enforced on the request path, not by the client. The uid comes from the kernel
at `connect(2)`, so a client cannot assert its own identity and the CLI's `sudo` gate is
a convenience, not the boundary.

The socket is `/run/ciscomvent/control.sock`, `root:<group> 0660`. The group is detected
at startup: `ciscomvent` if you create one, else `sudo` or `wheel`. If none exists, or
you name one that does not, it stays root-only and the daemon logs why. It **fails
closed**, since failing open would hand routing control to every local account; the
symptom is every unprivileged client being refused, GUI included.

## GUI

```bash
ciscomvent gui                           # tray applet + window
sudo ciscomvent gui --install-autostart  # start at login, for every account
```

Needs PyQt5 (`python3-pyqt5` on Debian and Ubuntu). The mark is drawn through Qt's SVG
image plugin, which that package brings in unless recommends are skipped (then add
`libqt5svg5`); without it the tray still works but draws a plain circle. Run it as your
normal user: under `sudo` there is no session bus and no tray to appear in, so it
refuses to start. Under Wayland the title-bar and taskbar icon is not the applet's to
set, since the compositor draws the icon named by the menu entry `sudo ciscomvent
install` writes, so it is the plain mark there.

The tray icon carries state at a glance (grey disconnected or daemon unreachable, green
healthy, amber needs you or not yet claimed, red claimed but still broken), with a dot
badge so it does not rely on color alone. Right-click gives *Status*, **Restart
daemon**, **Approve ▸**, **Open window**, **Reconcile**, **Approve automatically**,
**About ciscomvent** and **Quit applet** (the applet only; the daemon keeps maintaining
your routes).

The window adds a **Routes & rules** tab that doubles as the audit surface, and a
**Revert** menu button beside it: *Firewall rules* runs `revert --layer 2`, *Firewall
rules & routes* the full teardown. It sits apart from the other buttons, has no default
entry a single click can fire, and confirms with a count of what goes. Not an off
switch: the daemon reinstalls whatever it still wants within the minute, so disable the
scopes or stop the service for that.

**Not now** puts a pending scope off for the rest of the session. Not a weaker disable:
the scope stays listed, unclaimed and approvable. It only stops counting as outstanding,
so one you have decided not to approve cannot hold the tray amber and hide a scope that
is genuinely failing.

Two controls need root, and rather than offer buttons that can only fail, both escalate
through `pkexec` running the installed CLI: enable/disable, which is persisted, and
**Revert**, which has no socket command because teardown is the most destructive thing
the session tier could be handed. What crosses that boundary is narrow: an absolute path
to the installed, root-owned CLI rather than anything from your `PATH`, and a scope name
through the same validator the daemon uses. If that binary is missing, not root-owned, or
writable by anyone else, the GUI refuses and names the `sudo` command instead. **Approve
automatically** is not wired to this path and stays greyed below root; use
`sudo ciscomvent config --automation auto`.

## Scopes

Docker bridges are discovered and **enabled**. LAN and libvirt are discovered and listed
but **disabled by default**: repairing a local dev stack is a workstation concern,
whereas blanket LAN restoration under tunnel-all is a conversation to have with your VPN
admin.

The subnet is chosen by whoever created the network, not by you, so approval prompts name
the **CIDR**: `docker:app` does not say whether approving it diverts a dev bridge or
10.0.0.0/8. For a **LAN** scope the creator is the network you are attached to, since the
subnet is the interface prefix, and on DHCP that is whatever the lease says; on a network
you do not trust, the attacker picks the number. The ceiling bounds it (`status` and the
journal name a lease too wide to offer), but that is still not a reason to enable LAN on
untrusted wifi.

Nothing is hardcoded. Subnets, bridge names and container addresses are discovered at
runtime, and a bridge name is accepted outright only once the interface is confirmed to
hold the network's gateway address; with no gateway to check against, the derived
`br-<id[:12]>` name is labelled `derived-unverified`. Probe addresses exclude host-owned
addresses, since probing a bridge gateway resolves `local dev lo` and would report
healthy under a live capture.

## Design notes

Kept because most of it was arrived at by being wrong first.

**Specificity is not winnable.** Beating a `/16` with two `/17`s was built, tried and
lost: the client watches `main`, mirrors any new prefix onto the tunnel within seconds,
and wins an equal-length tie. Metric does not help either; a `/24` at metric 0 beat the
kernel's own route at 600. Policy routing sidesteps the contest, since there is nothing
to mirror. The prefix maths survives behind `apply --mechanism specific`, still tested
and documented as losing.

**A fix never re-tested across a state change has not been tested.** The firewall layer
was measured as unnecessary, and that was wrong: it generalised from one VPN session.
Secure Client rebuilds its chains on connect, and a *fresh* connect drops bridge traffic
where an established session's ruleset did not. So the accepts are part of the fix, and
are reconciled continuously because the client rebuilds them away: routing can be
entirely in sync while the rules that make it usable have been wiped.

**Is this split tunneling?** In effect yes; in Cisco's vocabulary no, since split
tunneling there is headend-pushed and this is unilateral. Docker bridges are **repair**:
the traffic is host-local, swept up by the client's enumeration, and black-holed rather
than inspected, so restoring it gives up no visibility (Secure Client already exempts
`lo+` for the same reason). LAN is a **genuine split-exclude**, hence opt-in.

**What this cannot do.** The primitive routes a prefix at a device that already owns it.
"Send this external destination out the physical NIC instead of the tunnel" would need a
via-gateway route, source-address handling and probably DNS interception. Deliberately
not built.

**Acceptance, stated honestly.** The bar was surviving a disconnect/reconnect without
manual intervention. `auto` meets it literally; `confirm` meets it with **one approval
per reconnect**, not zero. `confirm` passing is not evidence that `auto` works.

## Development

```bash
./run-tests.sh                    # fixtures only; needs neither Docker nor a VPN
tests/docker/testenv.sh up        # ...then integration tests run too
```

The test stack's subnet is deliberately unpinned, so discovery has to find the bridge at
runtime, the condition the tool exists for. Where `python3-venv` is unavailable, pytest
is bootstrapped into a repo-local `.devtools/`; nothing system-wide is modified. The core
is stdlib-only, because the daemon runs as root and every dependency is added attack
surface at that privilege level.

`daemon install --in-place` runs the daemon from the checkout instead of the deployed
copy, so an edit takes effect on restart without a reinstall. Development only: the root
daemon then imports code your user can write, and the install says so. Both installs
refuse an interpreter outside `/usr` (pyenv, conda, a venv), since the unit and the
wrapper run it as root.

## License

Free software under the **GNU General Public License v3 or later**. It comes with
ABSOLUTELY NO WARRANTY.

See [`LICENSE`](LICENSE), or <https://www.gnu.org/licenses/>.
