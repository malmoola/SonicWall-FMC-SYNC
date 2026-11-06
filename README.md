# SonicWall-FMC-SYNC

Migrate a SonicWall firewall configuration to Cisco Secure Firewall (FTD) managed by
Firepower Management Center (FMC), using only a SonicWall settings backup and the FMC REST API.

Cisco's Firewall Migration Tool does not accept SonicWall as a source. `sw2fmc.py` fills that gap:
it decodes a SonicOS `.exp` backup, works out which objects and rules matter, and creates them in
FMC with every item labelled by site.

- **Offline source.** It reads the `.exp` backup file. No access to the SonicWall is needed.
- **Dry run first.** `plan` writes review reports and sends nothing. `push` is a separate command.
- **Multi-site friendly.** One run per firewall, each with its own site label, into a shared FMC.
- **Additive only.** It creates new objects and a new, unassigned access policy. It never edits,
  deletes or deploys anything.
- **Never widens a rule.** If an object a rule needs can't be translated or created, the rule is
  skipped and reported rather than pushed with `any`.

## Contents

- [What gets migrated](#what-gets-migrated)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [How items are labelled](#how-items-are-labelled)
- [Step by step](#step-by-step)
- [Reports](#reports)
- [Options](#options)
- [How rules are selected](#how-rules-are-selected)
- [Translation reference](#translation-reference)
- [After the push](#after-the-push)
- [Re-running and backing out](#re-running-and-backing-out)
- [Troubleshooting](#troubleshooting)
- [The .exp format](#the-exp-format)
- [Security](#security)
- [Limitations](#limitations)

## What gets migrated

| SonicWall | Result in FMC | How |
|---|---|---|
| Address objects (host, network, range, FQDN) | Host / Network / Range / FQDN objects | Pushed |
| Address groups | Network groups, nesting preserved | Pushed |
| Service objects (TCP, UDP) | Port objects | Pushed |
| Service objects (ICMP) | ICMPv4 objects with type and code | Pushed |
| Service groups | Port groups, flattened | Pushed |
| Zones that have an addressed interface | Security zones (routed) | Pushed |
| Access rules (custom and default zone rules) | Access rules in a new access control policy | Pushed |
| NAT policies | `nat.csv` with the FTD equivalent of each | Report only |
| Interfaces, zones, IPs, gateways | `interfaces.csv` | Report only |
| Static routes | `routes.csv` | Report only |

Objects referenced by custom NAT policies and static routes are created too, so they already
exist (and are labelled) when you build NAT and routing by hand.

Not migrated: IPv6 objects and rules, MAC address objects, VPN, users and SSO, content filtering,
application control, gateway AV/IPS, DHCP, and schedules.

## Requirements

- Python 3.8 or later
- The `requests` package (only needed for `push`)
- A SonicOS settings backup (`.exp`). Developed against SonicOS 6.5 exports.
- An FMC with the REST API enabled, a user that can create objects and access policies, and
  HTTPS reachability to the FMC from the machine running the script

## Quick start

```bash
pip install requests

# 1. Dry run. Nothing is sent to FMC.
python sw2fmc.py plan site1.exp --site SITE1

# 2. Review sw2fmc_SITE1/rules.csv, skipped.csv and warnings.txt

# 3. Push
python sw2fmc.py push site1.exp --site SITE1 --fmc <fmc-ip> --user <api-user> --insecure
```

The password is read from the `FMC_PASS` environment variable, or prompted for if it isn't set.

Example output of a push:

```
site SITE1  <-  TZ 500 (SonicOS 6.5.5.1-6n)
  zones 2 | net objs 88 | net groups 7 | port objs 2 | port groups 1
  rules to push 12 (9 custom, 3 default) | skipped 96 {'unused-zone': 71, 'to-firewall': 25}
  NAT (report only) 11 | static routes 0 | warnings 1
  reports in sw2fmc_SITE1/
  SecurityZone: created 2, failed 0
  Host: created 71, failed 0
  Network: created 17, failed 0
  ProtocolPortObject: created 2, failed 0
  NetworkGroup: created 6, failed 0
  NetworkGroup: created 1, failed 0
  PortObjectGroup: created 1, failed 0
  AccessPolicy 'SITE1-ACP' created (...)
  AccessRules: created 12, failed 0, skipped 0
push log: sw2fmc_SITE1/push.log (0 entries, 0 need attention)
```

## How items are labelled

FMC has no tags, so the site label is carried in names, descriptions and comments. With
`--site SITE1`:

| Item | Name | Extra label |
|---|---|---|
| Objects and groups | `SITE1-<name>` | Description: `Site SITE1 \| SonicWall '<original name>'` |
| Security zones | `SITE1-LAN`, `SITE1-WAN`, ... | Description with the SonicWall zone |
| Access policy | `SITE1-ACP` | Description with the source model and serial |
| Access rules | `SITE1-<nn>-<name>` | Comment with the SonicWall priority, zone pair, name and comment |

Characters FMC rejects in names (spaces, parentheses and so on) become underscores. Name
collisions get a numeric suffix. Rule names use the SonicWall rule name when it has one,
otherwise the zone pair, for example `SITE1-06-WAN-LAN`.

Because every name carries the site prefix, objects from different sites never collide, and
anything already in FMC for other sites is left alone.

## Step by step

### 1. Export the SonicWall configuration

On the SonicWall, export the settings to a `.exp` file (in SonicOS 6.5: Manage > Firmware &
Backups > Import/Export Configuration > Export Configuration).

### 2. Prepare FMC

1. Take an FMC configuration backup (System > Tools > Backup/Restore).
2. Confirm the REST API is enabled (System > Configuration > REST API Preferences).
3. Create a dedicated user for the migration (System > Users > Create User). An API login
   with the same username as an active GUI session logs that session out, so don't reuse
   your own account. The Administrator role is the simplest that can create objects, zones
   and access policies.

Test the login and reachability:

```bash
curl -k -sS -D - -o /dev/null -X POST -u <api-user> https://<fmc-ip>/api/fmc_platform/v1/auth/generatetoken
```

`HTTP/1.1 204` with an `X-auth-access-token` header means it works. `401` is a credentials
problem. A timeout is a network problem.

### 3. Check the export is readable

```bash
python sw2fmc.py inventory site1.exp
```

This lists every table found in the export with its row count. If `plan` later prints
`KEYMAP:` warnings, your SonicOS version names a table differently; adjust the `K` map at the
top of the script using this listing.

### 4. Dry run

```bash
python sw2fmc.py plan site1.exp --site SITE1
```

Review the [reports](#reports) before going further. Any option you add here must also be
passed to `push`.

### 5. Push

```bash
python sw2fmc.py push site1.exp --site SITE1 --fmc <fmc-ip> --user <api-user> --insecure
```

`--insecure` skips TLS certificate verification, for an FMC with a self-signed certificate.
Check `push.log` afterwards: lines starting `FAILED`, `CONFLICT` or `SKIPPED` need attention,
and an empty log is a clean run.

### 6. Repeat per site

Run `plan` and `push` again with the next export and a different `--site`.

## Reports

Both `plan` and `push` write these to `sw2fmc_<SITE>/` (change with `-o`):

| File | Contents |
|---|---|
| `rules.csv` | Rules that will be pushed, in order, with FMC names alongside the original SonicWall source, destination, service, priority and hit count |
| `skipped.csv` | Every rule that will not be pushed, with a category and reason |
| `objects.csv` | Each FMC object: name, type, value or members, original SonicWall name |
| `nat.csv` | NAT policies with interfaces, original and translated fields, hit counts and the FTD equivalent |
| `interfaces.csv` | Interface name, SonicWall zone, FMC zone, IP, mask, gateway, comment |
| `routes.csv` | Configured static routes and the FMC objects created for them |
| `warnings.txt` | Dropped group members, unverified protocol objects, IPv6 notes, key-map problems |
| `plan.json` | The full plan in machine-readable form |
| `push.log` | (`push` only) Reused objects, conflicts, failures and skipped rules |

These files contain addresses and names from the firewall. Don't commit them; the included
`.gitignore` blocks them.

## Options

| Option | Purpose |
|---|---|
| `--site NAME` | Site label, required for `plan` and `push`. Letters, digits, `_` and `.`, up to 16 characters |
| `-o DIR` | Report directory. Default `sw2fmc_<SITE>` |
| `--zonemap A=X,B=Y` | Override zone names, for example `LAN=SITE1-INSIDE,WAN=SITE1-OUTSIDE` |
| `--policy NAME` | Access policy name to create. Default `<SITE>-ACP` |
| `--all-objects` | Also create user-defined objects that no rule, NAT policy or route references |
| `--skip-disabled` | Leave out rules that are disabled on the SonicWall (default: pushed as disabled) |
| `--skip-default-rules` | Leave out SonicWall's built-in zone-to-zone rules |
| `--rule-name-max N` | Maximum rule name length. Default 30 |
| `--fmc HOST` | FMC address (`push`) |
| `--user NAME` | FMC API user (`push`) |
| `--insecure` | Skip TLS certificate verification (`push`) |

## How rules are selected

A SonicWall export contains far more rules than anyone configured, because SonicOS auto-adds
management and default rules for every zone pair. The script keeps the rules that carry transit
traffic and reports the rest in `skipped.csv`:

| Category | Meaning | Why it's skipped |
|---|---|---|
| `to-firewall` | The destination is one of the firewall's own interface IPs (management, ping, SNMP) | On FTD this is handled by platform settings, not the access policy |
| `unused-zone` | A source or destination zone has no interface with an IP | The zone carries no traffic (commonly DMZ, VPN, WLAN, SSLVPN, MULTICAST) |
| `unusable-object` | A referenced object can't be translated (interface-bound, MAC, IPv6, dynamic port) | Pushing it would mean widening the rule |
| `disabled` | Disabled on the SonicWall | Only with `--skip-disabled` |
| `default-rule` | Built-in zone-to-zone rule | Only with `--skip-default-rules` |
| `unknown-action` | Action code not recognised | Can't be translated safely |

Rules are ordered the way SonicOS evaluates them: by zone pair, then priority. SonicWall's
default zone rules (for example LAN to WAN allow any, WAN to LAN deny any) are kept by default
and marked `default` in `rules.csv`, because traffic depends on them. Review whether you want
them on the FTD.

## Translation reference

| SonicWall | FMC |
|---|---|
| Action Allow | `ALLOW`, logging at end of connection |
| Action Deny | `BLOCK_RESET`, logging at beginning of connection |
| Action Discard | `BLOCK`, logging at beginning of connection |
| Service with port range 1-65535 | Port object for the protocol with no port (any) |
| ICMP service | ICMPv4 object. SonicOS stores type and code in one number (`code * 256 + type`) |
| Nested service groups | One flat port group, because FMC port groups can't contain groups |
| Group with an untranslatable member | Group is created without that member, and a warning is written |

The new access policy has a default action of Block.

A dropped group member narrows a rule. That is safe for an allow rule but also narrows a deny
rule, so read every `dropped member` line in `warnings.txt`.

## After the push

The script stops at objects and policy. To finish a site in FMC:

1. **Interfaces.** Configure the FTD interfaces from `interfaces.csv` and assign each to its
   security zone.
2. **Routing.** Add the default route (the gateway is in `interfaces.csv`) and any static
   routes from `routes.csv`.
3. **NAT.** Build the NAT policy from `nat.csv`. The `ftd_equivalent` column gives the type:
   - `identity NAT (no-NAT exemption)`: a static manual NAT rule with the same original and
     translated address, placed before the others. Enable "Do not proxy ARP on Destination
     Interface" and "Perform Route Lookup for Destination Interface".
   - `dynamic PAT to egress interface IP`: a dynamic rule translating to the destination
     interface IP. SonicOS adds one of these per LAN interface; a single rule from the inside
     zone to the outside zone usually replaces them all.
   - `review: static/policy NAT`: needs a manual decision.
4. **Policy options.** Add intrusion and file policies and adjust logging as needed.
5. **Assign and deploy.** Assign the policy to the device, preview the deployment and confirm
   it lists only the intended device.

## Re-running and backing out

- **Re-running `push`.** The script stops before changing anything if the access policy name
  already exists. Delete the policy in FMC (or pass `--policy` with a new name) and run again.
  Objects that already exist with the same value are reused.
- **Conflicts.** If an object with the same name exists but has a different value, it is not
  used. Groups that contain it and rules that reference it are skipped and logged.
- **Partial failures.** If FMC rejects a bulk request, the script retries that batch one object
  at a time so a single bad object doesn't sink the rest. It also handles token expiry and
  FMC's rate limit.
- **Backing out.** There is no delete function. Remove the policy first, then groups, then
  objects, filtering on the site prefix in Object Management.
- **Rule comments are permanent.** FMC does not allow saved rule comments to be edited or
  deleted. To remove them, delete and recreate the rule.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `curl` test or `push` times out | No route to the FMC from that machine. From WSL this is common when Windows reaches the FMC through a VPN: run the script with Windows Python instead |
| `HTTP 401` on login | Wrong username or password, or the user has no API access |
| `pip install` fails with `externally-managed-environment` | Debian/Ubuntu: use `sudo apt install python3-requests` |
| Windows: `Python was not found` | Install Python (`winget install -e --id Python.Python.3.12`), open a new terminal, and use `py` instead of `python` |
| `KEYMAP: '...' not found in export` | The export uses different table names. Run `inventory` and update the `K` map at the top of the script |
| `Access policy '...' already exists` | Delete it in FMC or pass `--policy <new name>` |
| Rule names are cut short | Default limit is 30 characters. Try `--rule-name-max 50` if your FMC version accepts it |
| `FAILED ProtocolPortObject ...` for an IP protocol | Non-TCP/UDP/ICMP protocols are pushed by number and may be rejected; create that object by hand |

## The .exp format

A SonicOS 6.5 `.exp` file is a single Base64 string. Decoded, it is a URL-encoded list of
`key=value` pairs joined by `&`:

```
addrObjId_12=Core-Router&addrObjType_12=1&addrObjIp1_12=192.0.2.7&addrObjIp2_12=255.255.255.255&...
```

- A trailing `_N` is a row number. All keys ending in `_12` describe row 12 of that table.
- Keys without a suffix are single settings such as `firewallName`.
- References are by name: a rule names its source object, and group membership is a pair of
  tables holding member and group names.

To read one yourself in PowerShell:

```powershell
$raw = (Get-Content .\site1.exp -Raw).Trim()
$txt = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($raw))
$txt -split '&' | ForEach-Object { [Uri]::UnescapeDataString($_.Replace('+',' ')) } |
    Set-Content .\site1_decoded.txt -Encoding UTF8
```

The tables the script reads:

| Prefix | Contents |
|---|---|
| `addrObj*`, `addro_*` | Address objects and group membership |
| `svcObj*`, `so_*` | Service objects and group membership |
| `policy*` | Access rules |
| `natPolicy*` | NAT policies |
| `pbrObj*` | Route policies (static routes) |
| `iface_*`, `interface_Zone` | Interfaces and their zones |

## Security

- A `.exp` backup is encoded, not encrypted. It contains password hashes and shared secrets.
  Treat backups and decoded copies as sensitive and delete them when the migration is done.
- The included `.gitignore` excludes backups, decoded files, CSV reports, spreadsheets, logs
  and report folders. Don't override it.
- Disable or delete the FMC migration user when you're finished.
- `--insecure` disables certificate verification. Use it only for an FMC you reach over a
  trusted network.

## Limitations

- Developed and tested with SonicOS 6.5 exports from TZ-series firewalls. Other versions,
  SonicOS 7 in particular, may use different table names or formats.
- IPv4 only.
- NAT, interfaces and routes are reported, not pushed.
- One access policy per site. It does not merge rules into an existing policy.
- The mapping of SonicWall action codes to Block versus Block with reset, and the ICMP
  type/code decoding, were inferred from exports. Spot-check them in your environment.
- Always run `plan` and review the reports before `push`, and test against a lab FMC or a
  test domain when you can.
