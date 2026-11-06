#!/usr/bin/env python3
"""sw2fmc.py - SonicWall (SonicOS 6.5) .exp export -> Cisco FMC via REST API, one site per run.

Every object, zone and rule is labelled with the site:
  objects  <SITE>-<name>, description "Site <SITE> | SonicWall '<original name>'"
  zones    <SITE>-<zone>            (override with --zonemap)
  rules    <SITE>-<nn>-<name>, in a NEW unassigned policy <SITE>-ACP, comment carries the SonicWall rule

Migrates: address objects/groups, service objects/groups (TCP/UDP/ICMP type+code), zones that have
          interfaces, access rules (custom + SonicWall default zone rules).
Reports:  nat.csv, interfaces.csv, routes.csv, skipped.csv, warnings.txt  (NAT/interfaces/routes not pushed)
Skips:    rules to the firewall itself (management), zones with no interface, IPv6, VPN, users, services.

  sw2fmc.py inventory site1.exp
  sw2fmc.py plan site1.exp --site SITE1                       # dry run, nothing sent
  sw2fmc.py push site1.exp --site SITE1 --fmc <fmc-ip> --user api --insecure

Password: env FMC_PASS, otherwise prompted. Requires: pip install requests
"""
import argparse, base64, csv, getpass, ipaddress, json, os, re, sys, time
from collections import Counter, defaultdict
from urllib.parse import unquote_plus

# ---- SonicOS 6.5 export key names (verified against TZ500 6.5.5.1 exports) ----
K = dict(
    addr_name="addrObjId", addr_type="addrObjType", addr_ip1="addrObjIp1", addr_ip2="addrObjIp2",
    addr_props="addrObjProperties",
    fqdn_name="addrObjFqdnId", fqdn_val="addrObjFqdn",
    ag_member="addro_atomToGrp", ag_group="addro_grpToGrp",
    svc_name="svcObjId", svc_type="svcObjType", svc_proto="svcObjIpType",
    svc_p1="svcObjPort1", svc_p2="svcObjPort2", svc_props="svcObjProperties",
    sg_member="so_atomToGrp", sg_group="so_grpToGrp",
    r_action="policyAction", r_szone="policySrcZone", r_dzone="policyDstZone",
    r_src="policySrcNet", r_dst="policyDstNet", r_svc="policyDstSvc",
    r_enabled="policyEnabled", r_comment="policyComment", r_name="policyName", r_pri="policyPriority",
    r_default="policyDefaultRule", r_hits="policyHitCount",
    if_name="iface_name", if_zone="interface_Zone", if_comment="iface_comment",
    if_lan_ip="iface_lan_ip", if_lan_mask="iface_lan_mask",
    if_wan_ip="iface_static_ip", if_wan_mask="iface_static_mask", if_wan_gw="iface_static_gateway",
)
OPTIONAL = {"fqdn_name", "fqdn_val", "r_name", "r_comment", "r_hits", "if_comment"}
ADDR_TYPE = {"1": "host", "2": "range", "4": "network", "8": "group"}   # others -> unsupported
SVC_GROUP_TYPE = "2"
ACTION = {"0": "BLOCK_RESET", "1": "BLOCK", "2": "ALLOW"}               # deny / discard / allow
CUSTOM = "14"                                                           # *ObjProperties of user-created objects
DEFAULT_RULE = "2"                                                      # policyDefaultRule of built-in zone rules
ANY = {"", "any"}
NAT_PREFIX = "natPolicy"


class Unusable(Exception):
    pass


# ------------------------------------------------------------------ decode
def load_exp(path):
    raw = open(path, "rb").read().strip()
    try:
        txt = base64.b64decode(raw + b"=" * (-len(raw) % 4)).decode("utf-8", "replace")
        if "=" not in txt or "&" not in txt:
            raise ValueError
    except Exception:
        txt = raw.decode("utf-8", "replace")            # already decoded
    tables, scalars = defaultdict(dict), {}
    for pair in txt.split("&"):
        if "=" not in pair:
            continue
        k, v = pair.split("=", 1)
        k, v = unquote_plus(k), unquote_plus(v)
        m = re.match(r"^(.+)_(\d+)$", k)
        if m:
            tables[m.group(1)][int(m.group(2))] = v
        else:
            scalars[k] = v
    return tables, scalars


def inventory(tables):
    for p, rows in sorted(tables.items(), key=lambda x: -len(x[1])):
        sample = next(iter(rows.values()))
        print(f"{len(rows):6d}  {p:32s} e.g. {sample[:50]!r}")


# ------------------------------------------------------------------ plan
def norm(s):
    return re.sub(r"\s+", " ", s.replace("\xa0", " ")).strip()


def clean(name, used, maxlen=64):
    n = re.sub(r"[^A-Za-z0-9_.\-]+", "_", norm(name)).strip("_") or "obj"
    n, base, i = n[:maxlen].rstrip("_-"), n[:maxlen].rstrip("_-"), 1
    while n.lower() in used:
        i += 1
        suffix = f"_{i}"
        n = base[:maxlen - len(suffix)] + suffix
    used.add(n.lower())
    return n


def desc(site, orig, extra=""):
    d = f"Site {site} | SonicWall '{norm(orig)}'" + (f" | {extra}" if extra else "")
    return re.sub(r"[^A-Za-z0-9 _.,:()/|'\-]", "", d)[:200]


def build_plan(tables, scalars, site, zonemap=None, skip_disabled=False, skip_default_rules=False,
               all_objects=False, rule_name_max=30):
    zonemap = zonemap or {}
    T = lambda key: tables.get(K[key], {})
    prefix = site + "-"
    warn = []
    for key, pfx in K.items():
        if key not in OPTIONAL and pfx not in tables:
            warn.append(f"KEYMAP: '{pfx}' ({key}) not found in export - check K at top of script")

    # --- source model
    addrs = {}
    for i, name in T("addr_name").items():
        kind = ADDR_TYPE.get(T("addr_type").get(i, ""), "unsupported:type" + T("addr_type").get(i, "?"))
        addrs[name] = dict(kind=kind, ip1=T("addr_ip1").get(i, ""), ip2=T("addr_ip2").get(i, ""),
                           custom=T("addr_props").get(i) == CUSTOM)
    for i, name in T("fqdn_name").items():
        addrs[name] = dict(kind="fqdn", ip1=T("fqdn_val").get(i, ""), ip2="", custom=True)
    agroups = defaultdict(list)
    for i, g in T("ag_group").items():
        agroups[g].append(T("ag_member").get(i, ""))
    svcs = {}
    for i, name in T("svc_name").items():
        svcs[name] = dict(group=T("svc_type").get(i) == SVC_GROUP_TYPE, proto=T("svc_proto").get(i, ""),
                          p1=T("svc_p1").get(i, "0"), p2=T("svc_p2").get(i, "0"),
                          custom=T("svc_props").get(i) == CUSTOM)
    sgroups = defaultdict(list)
    for i, g in T("sg_group").items():
        sgroups[g].append(T("sg_member").get(i, ""))

    # --- interfaces / zones in use
    ifaces = []
    for i, name in sorted(T("if_name").items()):
        z = T("if_zone").get(i, "")
        lan, wan = T("if_lan_ip").get(i, "0.0.0.0"), T("if_wan_ip").get(i, "0.0.0.0")
        ip, mask = (wan, T("if_wan_mask").get(i, "")) if wan != "0.0.0.0" else (lan, T("if_lan_mask").get(i, ""))
        gw = T("if_wan_gw").get(i, "0.0.0.0")
        ifaces.append(dict(index=i, name=name, sw_zone=z, ip="" if ip == "0.0.0.0" else ip,
                           mask=mask if ip != "0.0.0.0" else "", gateway="" if gw == "0.0.0.0" else gw,
                           comment=T("if_comment").get(i, "")))
    zones_in_use = {f["sw_zone"] for f in ifaces if f["sw_zone"] and f["ip"]}
    if not zones_in_use:
        zones_in_use = None                               # no interface table -> don't filter by zone
        warn.append("No interface/zone table found - rules are not filtered by zone usage")

    def fw_own(name, stack=()):
        """True if the object is the firewall's own interface IP(s): rules to it are management, not transit."""
        a = addrs.get(name)
        if a is None or a["custom"] or name in stack:
            return False
        if name in agroups:
            m = agroups[name]
            return bool(m) and all(fw_own(x, stack + (name,)) for x in m)
        return a["kind"] == "host"

    # --- target model
    plan = dict(site=site, source=dict(firewall=scalars.get("firewallName", ""), serial=scalars.get("serialNumber", ""),
                                       build=scalars.get("buildNum", ""), model=scalars.get("shortProdName", "")),
                zones={}, net={}, netgroups={}, ports={}, portgroups={}, rules=[], skipped=[], warnings=warn,
                interfaces=ifaces, objmap=[])
    net_used, port_used, rule_used = set(), set(), set()
    net_map, port_map, leaves_memo, why = {}, {}, {}, {}
    notes = defaultdict(list)                             # fmc object name -> caveats (dropped members etc.)

    def fail(store, name, msg):
        why[(id(store), name)] = msg
        store[name] = None
        raise Unusable(msg)

    def cached(store, name):
        if store[name] is None:
            raise Unusable(why.get((id(store), name), f"'{name}' unusable"))
        return store[name]

    def use_net(name, stack=()):
        if name.lower() in ANY:
            return None
        if name in net_map:
            return cached(net_map, name)
        if name not in addrs and name not in agroups:
            fail(net_map, name, f"address '{norm(name)}' not defined in export")
        if name in stack:
            raise Unusable(f"group loop at '{norm(name)}'")
        a = addrs.get(name, dict(kind="group"))
        if a["kind"] == "group" or name in agroups:
            members, dropped = [], []
            for m in agroups.get(name, []):
                try:
                    r = use_net(m, stack + (name,))
                    if r is None:
                        raise Unusable(f"member '{m}' is Any")
                    members.append(r)
                except Unusable as e:
                    dropped.append(str(e))
            if not members:
                fail(net_map, name, f"address group '{norm(name)}' has no usable members")
            fn = clean(prefix + name, net_used)
            plan["netgroups"][fn] = dict(members=members, description=desc(site, name))
            plan["objmap"].append(dict(fmc_name=fn, type="NetworkGroup", value=" ".join(members), sonicwall_name=norm(name)))
            for d in dropped:
                warn.append(f"GROUP '{norm(name)}' -> {fn}: dropped member ({d})")
                notes[fn].append(f"group {fn} lost a member: {d}")
            for m in members:
                notes[fn] += [n for n in notes.get(m, []) if n not in notes[fn]]
        else:
            try:
                if a["kind"] == "host":
                    if a["ip1"] in ("", "0.0.0.0"):
                        raise ValueError("interface-bound/dynamic (0.0.0.0)")
                    p = dict(type="Host", value=str(ipaddress.IPv4Address(a["ip1"])))
                elif a["kind"] == "range":
                    p = dict(type="Range", value=f"{ipaddress.IPv4Address(a['ip1'])}-{ipaddress.IPv4Address(a['ip2'])}")
                elif a["kind"] == "network":
                    if a["ip1"] in ("", "0.0.0.0"):
                        raise ValueError("interface-bound/dynamic (0.0.0.0)")
                    p = dict(type="Network", value=str(ipaddress.ip_network(f"{a['ip1']}/{a['ip2']}", strict=False)))
                elif a["kind"] == "fqdn":
                    p = dict(type="FQDN", value=a["ip1"].lstrip("*."), dnsResolution="IPV4_ONLY")
                    if a["ip1"].startswith("*"):
                        warn.append(f"FQDN '{name}': wildcard '{a['ip1']}' not supported on FTD, stripped - review")
                else:
                    raise ValueError(f"{a['kind']} (MAC/IPv6/other)")
            except ValueError as e:
                fail(net_map, name, f"address '{norm(name)}' unusable: {e}")
            fn = clean(prefix + name, net_used)
            plan["net"][fn] = dict(name=fn, description=desc(site, name), **p)
            plan["objmap"].append(dict(fmc_name=fn, type=p["type"], value=p["value"], sonicwall_name=norm(name)))
        net_map[name] = fn
        return fn

    def svc_leaf(name):
        if name in port_map:
            return cached(port_map, name)
        s = svcs[name]
        proto = {"6": "TCP", "17": "UDP"}.get(s["proto"])
        p1, p2 = int(s["p1"] or 0), int(s["p2"] or 0)
        if proto:
            if p1 == 0:
                fail(port_map, name, f"service '{norm(name)}' has no fixed port (dynamic)")
            p = dict(type="ProtocolPortObject", protocol=proto)
            if not (p1 == 1 and p2 == 65535):
                p["port"] = str(p1) if p2 in (0, p1) else f"{p1}-{p2}"
            val = f"{proto}/{p.get('port', 'any')}"
        elif s["proto"] == "1":                            # SonicWall packs ICMP as (code << 8) | type
            p = dict(type="ICMPV4Object", icmpType=str(p1 & 0xFF))
            if p1 > 0xFF:
                p["code"] = p1 >> 8
            val = f"ICMP type {p['icmpType']}" + (f" code {p['code']}" if "code" in p else "")
        elif s["proto"] == "58":
            fail(port_map, name, f"service '{norm(name)}' is ICMPv6 (not migrated)")
        elif s["proto"].isdigit() and s["proto"] != "0":
            p = dict(type="ProtocolPortObject", protocol=s["proto"])
            val = f"IP protocol {s['proto']}"
            warn.append(f"SERVICE '{norm(name)}': IP protocol {s['proto']} - verify FMC accepted it")
        else:
            fail(port_map, name, f"service '{norm(name)}' protocol '{s['proto']}' unsupported")
        fn = clean(prefix + name, port_used)
        plan["ports"][fn] = dict(name=fn, description=desc(site, name), **p)
        plan["objmap"].append(dict(fmc_name=fn, type=p["type"], value=val, sonicwall_name=norm(name)))
        port_map[name] = fn
        return fn

    def svc_leaves(name, stack=()):
        if name in leaves_memo:
            return leaves_memo[name]
        out, dropped = [], []
        for m in sgroups.get(name, []):
            try:
                if m in stack:
                    raise Unusable(f"group loop at '{m}'")
                if m in sgroups or (m in svcs and svcs[m]["group"]):
                    lv, dr = svc_leaves(m, stack + (name,))
                    out += lv
                    dropped += dr
                elif m in svcs:
                    out.append(svc_leaf(m))
                else:
                    raise Unusable(f"service '{m}' not defined")
            except Unusable as e:
                dropped.append(str(e))
        leaves_memo[name] = (sorted(set(out)), dropped)
        return leaves_memo[name]

    def use_svc(name):
        if name.lower() in ANY:
            return None
        if name in sgroups or (name in svcs and svcs[name]["group"]):
            if name not in port_map:
                lv, dropped = svc_leaves(name)
                if not lv:
                    fail(port_map, name, f"service group '{norm(name)}' has no usable members")
                fn = clean(prefix + name, port_used)
                plan["portgroups"][fn] = dict(members=lv, description=desc(site, name))   # FMC port groups can't nest -> flattened
                plan["objmap"].append(dict(fmc_name=fn, type="PortObjectGroup", value=" ".join(lv), sonicwall_name=norm(name)))
                v6 = [d for d in dropped if "ICMPv6" in d]
                if v6:
                    warn.append(f"SVCGROUP '{norm(name)}' -> {fn}: dropped {len(v6)} ICMPv6 members")
                for d in dropped:
                    if "ICMPv6" not in d:
                        warn.append(f"SVCGROUP '{norm(name)}' -> {fn}: dropped member ({d})")
                        notes[fn].append(f"service group {fn} lost a member: {d}")
                port_map[name] = fn
            return cached(port_map, name)
        if name not in svcs:
            fail(port_map, name, f"service '{norm(name)}' not defined in export")
        return svc_leaf(name)

    def zone(z):
        if z.lower() in ANY:
            return None
        fz = re.sub(r"[^A-Za-z0-9_.\-]", "_", zonemap.get(z, prefix + z))
        plan["zones"].setdefault(fz, dict(description=desc(site, f"zone {z}"), sw_zone=z))
        return fz

    # --- rules, in SonicWall evaluation order (zone pair, then priority)
    idx = sorted(T("r_action"))
    pri = lambda i: int(T("r_pri").get(i, "") or i)
    order = sorted(idx, key=lambda i: (T("r_szone").get(i, ""), T("r_dzone").get(i, ""), pri(i), i))
    n = 0
    for i in order:
        g = lambda key, d="": T(key).get(i, d)
        enabled = g("r_enabled", "1") not in ("0", "off", "false")
        is_default = g("r_default") == DEFAULT_RULE
        row = dict(sw_index=i, sw_priority=g("r_pri"), src_zone=g("r_szone"), dst_zone=g("r_dzone"),
                   source=norm(g("r_src")) or "Any", destination=norm(g("r_dst")) or "Any",
                   service=norm(g("r_svc")) or "Any", action=ACTION.get(g("r_action"), g("r_action")),
                   enabled=enabled, hits=g("r_hits"), sw_name=g("r_name"), comment=g("r_comment"))

        def skip(cat, reason):
            plan["skipped"].append(dict(category=cat, reason=reason, **row))

        if g("r_action") not in ACTION:
            skip("unknown-action", f"action code '{g('r_action')}'"); continue
        if zones_in_use is not None and not {g("r_szone"), g("r_dzone")} <= zones_in_use:
            skip("unused-zone", "zone has no interface with an IP on this firewall"); continue
        if fw_own(g("r_dst")):
            skip("to-firewall", "destination is the firewall's own IP (management) - use FTD platform settings"); continue
        if skip_disabled and not enabled:
            skip("disabled", "disabled on SonicWall (--skip-disabled)"); continue
        if skip_default_rules and is_default:
            skip("default-rule", "SonicWall default zone rule (--skip-default-rules)"); continue
        try:   # never widen: if any referenced object is unusable, skip the rule
            src, dst, svc = use_net(g("r_src")), use_net(g("r_dst")), use_svc(g("r_svc"))
        except Unusable as e:
            skip("unusable-object", str(e)); continue
        n += 1
        base = g("r_name") or f"{g('r_szone')}-{g('r_dzone')}" + ("-default" if is_default else "")
        name = clean(f"{prefix}{n:02d}-{base}", rule_used, rule_name_max)
        rn = [x for o in (src, dst, svc) if o for x in notes.get(o, [])]
        plan["rules"].append(dict(name=name, action=ACTION[g("r_action")], enabled=enabled,
                                  kind="default" if is_default else "custom",
                                  szone=zone(g("r_szone")), dzone=zone(g("r_dzone")), src=src, dst=dst, svc=svc,
                                  comment=f"Site {site} | SonicWall rule pri {g('r_pri')} {g('r_szone')}>{g('r_dzone')}"
                                          + (f" '{g('r_name')}'" if g("r_name") else "")
                                          + (f" | {norm(g('r_comment'))}" if g("r_comment") else ""),
                                  notes="; ".join(dict.fromkeys(rn)), sw=row))

    # --- NAT: report only, but create the objects custom NAT rules use so they exist (labelled) in FMC
    ifname = {f["index"]: f["name"] for f in ifaces}
    N = lambda k: tables.get(NAT_PREFIX + k, {})
    plan["nat"] = []
    for i in sorted(N("OrigSrc")):
        c = N("Comment").get(i, "")
        if "Management NAT Policy" in c or "Stack NAT Policy" in c:
            continue
        v = lambda k: norm(N(k).get(i, ""))
        ts, td, tsv = v("TransSrc"), v("TransDst"), v("TransSvc")
        if not ts and not td and not tsv:
            ftd = "identity NAT (no-NAT exemption)"
        elif ts and fw_own(N("TransSrc").get(i, "")) and not td:
            ftd = "dynamic PAT to egress interface IP"
        else:
            ftd = "review: static/policy NAT"
        iface = lambda k: ifname.get(int(N(k).get(i, "-1") or -1), "Any")
        fmc = {}
        if N("Enabled").get(i) == "1":
            for k in ("OrigSrc", "OrigDst", "TransSrc", "TransDst"):
                raw = N(k).get(i, "")
                if raw and not fw_own(raw):
                    try:
                        fmc[k] = use_net(raw)
                    except Unusable as e:
                        warn.append(f"NAT #{i}: {e}")
        plan["nat"].append(dict(sw_index=i, enabled=N("Enabled").get(i) == "1",
                                kind="auto" if c.startswith("Auto-added") else "custom",
                                in_iface=iface("SrcIface"), out_iface=iface("DstIface"),
                                orig_src=v("OrigSrc") or "Any", trans_src=ts or "Original",
                                orig_dst=v("OrigDst") or "Any", trans_dst=td or "Original",
                                orig_svc=v("OrigSvc") or "Any", trans_svc=tsv or "Original",
                                hits=N("HitCount").get(i, ""), ftd_equivalent=ftd,
                                fmc_objects=" ".join(f"{k}={o}" for k, o in fmc.items()), comment=c))

    if all_objects:                                       # also create custom objects no rule references
        for name, a in addrs.items():
            if a["custom"]:
                try:
                    use_net(name)
                except Unusable as e:
                    warn.append(f"--all-objects: {e}")
        for name, s in svcs.items():
            if s["custom"]:
                try:
                    use_svc(name)
                except Unusable as e:
                    warn.append(f"--all-objects: {e}")

    P = lambda k: tables.get("pbrObj" + k, {})
    plan["routes"] = [dict(name=P("Id").get(i, ""), source=norm(P("Src").get(i, "")) or "Any",
                           destination=norm(P("Dst").get(i, "")) or "Any", service=norm(P("Svc").get(i, "")) or "Any",
                           gateway=norm(P("Gw").get(i, "")), interface=P("IfaceName").get(i, ""),
                           metric=P("Metric").get(i, ""), comment=P("Comment").get(i, "")) for i in sorted(P("Id"))]
    for i in sorted(P("Id")):                             # objects static routes use, so they exist (labelled) in FMC
        for k in ("Dst", "Gw"):
            try:
                if P(k).get(i):
                    plan["routes"][sorted(P("Id")).index(i)]["fmc_" + k.lower()] = use_net(P(k)[i])
            except Unusable as e:
                warn.append(f"ROUTE '{P('Id').get(i, '')}': {e}")
    for f in ifaces:
        f["fmc_zone"] = next((z for z, d in plan["zones"].items() if d["sw_zone"] == f["sw_zone"]), "") if f["ip"] else ""
    v6 = len(tables.get("policyActionV6", {}))
    if v6:
        warn.append(f"{v6} IPv6 access rules in export were not migrated (IPv4 only)")
    plan["warnings"] = list(dict.fromkeys(warn))
    return plan


def write_csv(path, rows, cols):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def write_reports(plan, out):
    os.makedirs(out, exist_ok=True)
    json.dump(plan, open(f"{out}/plan.json", "w", encoding="utf-8"), indent=1)
    rows = [dict(r, order=n, src_zone=r["szone"] or "any", dst_zone=r["dzone"] or "any", source=r["src"] or "any",
                 destination=r["dst"] or "any", service=r["svc"] or "any", sw_priority=r["sw"]["sw_priority"],
                 sw_source=r["sw"]["source"], sw_destination=r["sw"]["destination"], sw_service=r["sw"]["service"],
                 sw_hits=r["sw"]["hits"]) for n, r in enumerate(plan["rules"], 1)]
    write_csv(f"{out}/rules.csv", rows, ["order", "name", "kind", "action", "enabled", "src_zone", "dst_zone", "source",
                                         "destination", "service", "notes", "sw_priority", "sw_source",
                                         "sw_destination", "sw_service", "sw_hits", "comment"])
    write_csv(f"{out}/skipped.csv", plan["skipped"], ["category", "reason", "sw_index", "sw_priority", "src_zone",
                                                      "dst_zone", "source", "destination", "service", "action",
                                                      "enabled", "hits", "sw_name", "comment"])
    write_csv(f"{out}/objects.csv", plan["objmap"], ["fmc_name", "type", "value", "sonicwall_name"])
    write_csv(f"{out}/nat.csv", plan["nat"], ["sw_index", "enabled", "kind", "in_iface", "out_iface", "orig_src",
                                              "trans_src", "orig_dst", "trans_dst", "orig_svc", "trans_svc", "hits",
                                              "ftd_equivalent", "fmc_objects", "comment"])
    write_csv(f"{out}/interfaces.csv", plan["interfaces"], ["name", "sw_zone", "fmc_zone", "ip", "mask", "gateway", "comment"])
    write_csv(f"{out}/routes.csv", plan["routes"], ["name", "source", "destination", "service", "gateway", "interface",
                                                    "metric", "fmc_dst", "fmc_gw", "comment"])
    with open(f"{out}/warnings.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(plan["warnings"]) + "\n")
    s = plan["source"]
    cats = Counter(x["category"] for x in plan["skipped"])
    print(f"site {plan['site']}  <-  {s['model']} {s['firewall']} (SonicOS {s['build']})")
    print(f"  zones {len(plan['zones'])} | net objs {len(plan['net'])} | net groups {len(plan['netgroups'])} | "
          f"port objs {len(plan['ports'])} | port groups {len(plan['portgroups'])}")
    print(f"  rules to push {len(plan['rules'])} ({sum(r['kind'] == 'custom' for r in plan['rules'])} custom, "
          f"{sum(r['kind'] == 'default' for r in plan['rules'])} default) | skipped {len(plan['skipped'])} {dict(cats)}")
    print(f"  NAT (report only) {len(plan['nat'])} | static routes {len(plan['routes'])} | warnings {len(plan['warnings'])}")
    print(f"  reports in {out}/")


# ------------------------------------------------------------------ FMC
class FMC:
    def __init__(self, host, user, pw, verify=True, session=None):
        if session is None:
            import requests, urllib3
            session = requests.Session()
            if not verify:
                urllib3.disable_warnings()
        self.s, self.base, self.auth = session, f"https://{host}", (user, pw)
        self.s.verify = verify
        self.login()

    def login(self):
        r = self.s.post(self.base + "/api/fmc_platform/v1/auth/generatetoken", auth=self.auth)
        r.raise_for_status()
        self.s.headers.update({"X-auth-access-token": r.headers["X-auth-access-token"],
                               "Content-Type": "application/json"})
        self.cfg = f"{self.base}/api/fmc_config/v1/domain/{r.headers['DOMAIN_UUID']}"

    def call(self, method, path, body=None, params=None):
        for _ in range(8):
            r = self.s.request(method, self.cfg + path, json=body, params=params)
            if r.status_code == 401:
                self.login()
            elif r.status_code == 429:
                time.sleep(15)                         # FMC limit: 120 requests/min
            elif r.status_code >= 400:
                raise RuntimeError(f"{method} {path} -> {r.status_code}: {r.text[:400]}")
            else:
                return r.json() if r.text else {}
        raise RuntimeError(f"{method} {path}: gave up after retries")

    def list(self, path):
        out, off = [], 0
        while True:
            items = self.call("GET", path, params={"limit": 1000, "offset": off, "expanded": "true"}).get("items", [])
            out += items
            if len(items) < 1000:
                return out
            off += 1000

    def create(self, path, payloads, size=500):
        """Bulk POST; if a chunk is rejected, retry it one by one so one bad object doesn't sink the rest."""
        done, failed = [], []
        for i in range(0, len(payloads), size):
            chunk = payloads[i:i + size]
            try:
                done += self.call("POST", path, chunk, {"bulk": "true"}).get("items", [])
            except RuntimeError:
                for p in chunk:
                    try:
                        done.append(self.call("POST", path, p))
                    except RuntimeError as e:
                        failed.append(f"{p.get('name')}: {e}")
        return done, failed


PATHS = {"Host": "/object/hosts", "Network": "/object/networks", "Range": "/object/ranges",
         "FQDN": "/object/fqdns", "NetworkGroup": "/object/networkgroups",
         "ProtocolPortObject": "/object/protocolportobjects", "ICMPV4Object": "/object/icmpv4objects",
         "PortObjectGroup": "/object/portobjectgroups", "SecurityZone": "/object/securityzones"}
NET_TYPES = ("Host", "Network", "Range", "FQDN", "NetworkGroup")
COMPARE = {"Host": ("value",), "Network": ("value",), "Range": ("value",), "FQDN": ("value",),
           "ProtocolPortObject": ("protocol", "port"), "ICMPV4Object": ("icmpType", "code")}


def same(t, existing, wanted):
    return all(str(existing.get(f, "")).upper() == str(wanted.get(f, "")).upper() for f in COMPARE.get(t, ()))


def push(plan, fmc, policy_name):
    log = []
    if any(p["name"].lower() == policy_name.lower() for p in fmc.list("/policy/accesspolicies")):
        sys.exit(f"Access policy '{policy_name}' already exists in FMC - delete it or pass --policy <new name>. Nothing was changed.")
    ids = {"net": {}, "port": {}, "zone": {}}
    existing = {}
    space = lambda t: "zone" if t == "SecurityZone" else "net" if t in NET_TYPES else "port"
    for t, path in PATHS.items():
        for it in fmc.list(path):
            existing[(space(t), it["name"].lower())] = it

    def ensure(payloads):
        by_type = defaultdict(list)
        for p in payloads:
            sp, key = space(p["type"]), p["name"].lower()
            ex = existing.get((sp, key))
            if ex is None:
                by_type[p["type"]].append(p)
            elif ex.get("type", p["type"]) != p["type"] or not same(p["type"], ex, p):
                log.append(f"CONFLICT {p['type']} '{p['name']}' exists in FMC with a different value - NOT used; "
                           f"rules referencing it are skipped")
            else:
                ids[sp][key] = dict(type=ex.get("type", p["type"]), id=ex["id"], name=ex["name"])
                log.append(f"REUSED existing {p['type']} '{p['name']}'" + ("" if p["type"] in COMPARE else " (members not compared)"))
        for t, items in by_type.items():
            done, failed = fmc.create(PATHS[t], items)
            for it in done:
                ids[space(t)][it["name"].lower()] = dict(type=it.get("type", t), id=it["id"], name=it["name"])
            log.extend(f"FAILED {t} {f}" for f in failed)
            print(f"  {t}: created {len(done)}, failed {len(failed)}")

    ref = lambda sp, name: ids[sp].get(name.lower())

    ensure([dict(type="SecurityZone", name=z, interfaceMode="ROUTED", description=d["description"])
            for z, d in plan["zones"].items()])
    ensure(list(plan["net"].values()))
    ensure(list(plan["ports"].values()))

    pending = {g: d for g, d in plan["netgroups"].items()}   # nested groups: create in dependency order
    while pending:
        ready = [g for g, d in pending.items() if not any(x in pending for x in d["members"])]
        if not ready:
            log.append(f"FAILED netgroups (unresolvable nesting): {list(pending)}")
            break
        batch = []
        for g in ready:
            d = pending.pop(g)
            objs = [ref("net", m) for m in d["members"]]
            if None in objs:                             # never push a partial group silently
                log.append(f"FAILED NetworkGroup '{g}': members missing in FMC "
                           f"{[m for m, o in zip(d['members'], objs) if o is None]}")
                continue
            batch.append(dict(type="NetworkGroup", name=g, description=d["description"], objects=objs))
        ensure(batch)
    batch = []
    for g, d in plan["portgroups"].items():
        objs = [ref("port", m) for m in d["members"]]
        if None in objs:
            log.append(f"FAILED PortObjectGroup '{g}': members missing in FMC "
                       f"{[m for m, o in zip(d['members'], objs) if o is None]}")
            continue
        batch.append(dict(type="PortObjectGroup", name=g, description=d["description"], objects=objs))
    ensure(batch)

    s = plan["source"]
    acp = fmc.call("POST", "/policy/accesspolicies",
                   dict(type="AccessPolicy", name=policy_name, defaultAction=dict(action="BLOCK"),
                        description=f"Site {plan['site']} - migrated from SonicWall {s['model']} {s['serial']}"[:200]))
    print(f"  AccessPolicy '{policy_name}' created ({acp['id']})")
    made = skipped = failed = 0
    for r in plan["rules"]:                             # one at a time: each POST appends, so order is preserved
        body = dict(type="AccessRule", name=r["name"], action=r["action"], enabled=r["enabled"],
                    sendEventsToFMC=True, logBegin=r["action"] != "ALLOW", logEnd=r["action"] == "ALLOW",
                    newComments=[r["comment"][:1000]])
        missing = []
        for field, sp, val in (("sourceZones", "zone", r["szone"]), ("destinationZones", "zone", r["dzone"]),
                               ("sourceNetworks", "net", r["src"]), ("destinationNetworks", "net", r["dst"]),
                               ("destinationPorts", "port", r["svc"])):
            if val is None:
                continue                                # Any
            o = ref(sp, val)
            if o is None:
                missing.append(val)
            else:
                body[field] = dict(objects=[o])
        if missing:                                     # never widen a rule to 'any' because an object failed
            log.append(f"SKIPPED rule '{r['name']}' (sw #{r['sw']['sw_index']}): objects missing in FMC: {missing}")
            skipped += 1
            continue
        try:
            fmc.call("POST", f"/policy/accesspolicies/{acp['id']}/accessrules", body)
            made += 1
        except RuntimeError as e:
            log.append(f"FAILED rule '{r['name']}': {e}")
            failed += 1
    print(f"  AccessRules: created {made}, failed {failed}, skipped {skipped}")
    return log


# ------------------------------------------------------------------ cli
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=["inventory", "plan", "push"])
    ap.add_argument("exp")
    ap.add_argument("--site", help="site label, e.g. SITE1 or BRANCH2 (required for plan/push)")
    ap.add_argument("-o", "--out", help="report directory (default sw2fmc_<SITE>)")
    ap.add_argument("--zonemap", default="", help="override zone names: LAN=SITE1-INSIDE,WAN=SITE1-OUTSIDE")
    ap.add_argument("--policy", help="access policy name to create (default <SITE>-ACP)")
    ap.add_argument("--all-objects", action="store_true", help="also create custom objects no rule/NAT references")
    ap.add_argument("--skip-disabled", action="store_true")
    ap.add_argument("--skip-default-rules", action="store_true", help="leave out SonicWall default zone-to-zone rules")
    ap.add_argument("--rule-name-max", type=int, default=30, help="max rule name length (30 is safe on all FMC versions)")
    ap.add_argument("--fmc"), ap.add_argument("--user")
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification")
    a = ap.parse_args()

    tables, scalars = load_exp(a.exp)
    if a.cmd == "inventory":
        return inventory(tables)
    if not a.site or not re.fullmatch(r"[A-Za-z0-9_.]{1,16}", a.site):
        sys.exit("--site is required: letters/digits/_ only, max 16 chars (e.g. --site SITE1)")
    out = a.out or f"sw2fmc_{a.site}"
    zonemap = dict(x.split("=", 1) for x in a.zonemap.split(",") if "=" in x)
    plan = build_plan(tables, scalars, a.site, zonemap, a.skip_disabled, a.skip_default_rules,
                      a.all_objects, a.rule_name_max)
    write_reports(plan, out)
    if a.cmd == "push":
        if not (a.fmc and a.user):
            sys.exit("push needs --fmc and --user")
        pw = os.environ.get("FMC_PASS") or getpass.getpass(f"FMC password for {a.user}: ")
        log = push(plan, FMC(a.fmc, a.user, pw, verify=not a.insecure), a.policy or f"{a.site}-ACP")
        open(f"{out}/push.log", "w", encoding="utf-8").write("\n".join(log) + "\n")
        print(f"push log: {out}/push.log ({len(log)} entries, "
              f"{sum(x.startswith(('FAILED', 'CONFLICT', 'SKIPPED')) for x in log)} need attention)")


if __name__ == "__main__":
    main()
