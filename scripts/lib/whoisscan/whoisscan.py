import os.path
import re
import json
import traceback
from time import sleep
from utils.output import Output
from utils.db import DB
import requests
import sys
import socket
import ipaddress

from ipwhois import IPWhois

HEADERS = {"Accept": "application/rdap+json, application/json"}
REDACTED = re.compile(
    r"redacted|privacy|withheld|not disclosed|data protected|proxy|whoisguard",
    re.I,
)


def whoisscan_worker(target, timeout):
    try:

        try:
            ipaddress.ip_address(target['hostname'])
            result = lookup_ip(target['hostname'], both=True)

            asn_cidr = dig(result, "rdap.network.cidr")
            if asn_cidr == None:
                asn_cidr = dig(result, "whois43.nets.0.cidr")

            name = dig(result, "rdap.network.name")
            if name == None:
                name = dig(result, "whois43.nets.0.name")

            country = dig(result, "rdap.network.country")
            if country == None:
                country = dig(result, "whois43.nets.0.country")

            Output.write({'target': '%s' % target['hostname'], 'message': "%s  %s  %s" % (asn_cidr.ljust(20), name.ljust(30), country)})

            DB.insert_whois_ip({
                'ip': target['hostname'],
                'cidr': asn_cidr,
                'name': name,
                'country': country,
            })


        except ValueError:
            result = lookup_domain(target['hostname'], timeout)

            registrar = dig(result, "registry_rdap.entities.0.fn")
            if registrar == None:
                registrar = dig(result, "whois43.parsed.registrar.0")

            Output.write({'target': '%s' % target['hostname'], 'message': "%s" % (registrar)})

            DB.insert_whois_domain({
                'domain': target['hostname'],
                'registrar': registrar,
            })



    except Exception as e:
        raise e

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def dig(obj, path, default=None):
    for key in path.split("."):
        if isinstance(obj, dict):
            obj = obj.get(key)
        elif isinstance(obj, list) and key.isdigit() and int(key) < len(obj):
            obj = obj[int(key)]
        else:
            return default
        if obj is None:
            return default
    return obj

def get_json(url, timeout=5):
    try:
        r = requests.get(url, headers=HEADERS, timeout=timeout)
        if r.status_code == 200:
            return r.json()
    except (requests.RequestException, ValueError):
        pass
    return None
 
 
def raw_whois(query, server, port=43, timeout=5):
    """Plain port-43 WHOIS query."""
    try:
        with socket.create_connection((server, port), timeout=timeout) as s:
            s.sendall((query + "\r\n").encode())
            out = b""
            while chunk := s.recv(4096):
                out += chunk
        return out.decode(errors="ignore")
    except OSError:
        return ""
 
 
def parse_vcard(arr):
    """Flatten an RDAP vcardArray into a simple dict."""
    out = {}
    if not arr or len(arr) < 2:
        return out
    for item in arr[1]:
        if len(item) < 4:
            continue
        name, params, _, val = item[0], item[1], item[2], item[3]
        if name == "adr":
            val = params.get("label") or ", ".join(
                v if isinstance(v, str) else " ".join(v) for v in val if v
            )
        if isinstance(val, list):
            val = ", ".join(str(v) for v in val if v)
        if not val:
            continue
        if name in ("email", "tel"):
            out.setdefault(name, []).append(val)
        else:
            out[name] = val
    return out
 
 
def walk_entities(entities, depth=0):
    """Recursively collect entities with roles and flattened vCard data."""
    found = []
    for e in entities or []:
        found.append(
            {
                "roles": e.get("roles", []),
                "handle": e.get("handle"),
                **parse_vcard(e.get("vcardArray")),
            }
        )
        if depth < 3:
            found += walk_entities(e.get("entities"), depth + 1)
    return found
 
 
def summarize_rdap(data):
    return {
        "events": {e["eventAction"]: e["eventDate"] for e in data.get("events", [])},
        "status": data.get("status"),
        "nameservers": [n.get("ldhName") for n in data.get("nameservers", [])],
        "entities": walk_entities(data.get("entities")),
    }
 
 
def has_usable_registrant(entities):
    """True if any registrant/admin/tech contact has non-redacted details."""
    for e in entities:
        if not set(e["roles"]) & {"registrant", "administrative", "technical"}:
            continue
        for key in ("fn", "org", "email"):
            v = e.get(key)
            v = " ".join(v) if isinstance(v, list) else v
            if v and not REDACTED.search(v):
                return True
    return False
 
 
def grep_whois(text, patterns):
    """Pull key: value lines from raw WHOIS text."""
    out = {}
    for label, pat in patterns.items():
        m = re.findall(rf"^\s*{pat}\s*:\s*(.+)$", text, re.I | re.M)
        m = [x.strip() for x in m if x.strip()]
        if m:
            out[label] = list(dict.fromkeys(m))
    return out
 
 
# --------------------------------------------------------------------------
# Domain
# --------------------------------------------------------------------------
def domain_rdap(domain, result, timeout):
    # rdap.org redirects to the correct registry via the IANA bootstrap
    reg = get_json(f"https://rdap.org/domain/{domain}", timeout)
    if not reg:
        result["notes"].append("No RDAP response from registry")
        return None
    result["registry_rdap"] = summarize_rdap(reg)
    merged = list(result["registry_rdap"]["entities"])
 
    # Follow the registrar's RDAP link (thin registries like .com/.net)
    for link in reg.get("links", []):
        href = link.get("href", "")
        is_rdap = "rdap" in link.get("type", "") or "/domain/" in href
        if link.get("rel") == "related" and is_rdap:
            if href.rstrip("/") == f"https://rdap.org/domain/{domain}":
                continue
            reg2 = get_json(href, timeout)
            if reg2:
                result["registrar_rdap"] = summarize_rdap(reg2)
                result["registrar_rdap"]["url"] = href
                merged += result["registrar_rdap"]["entities"]
                break
    else:
        result["notes"].append("No registrar RDAP link found")
 
    return merged
 
 
def domain_whois43(domain, result, timeout):
    """IANA -> TLD registry -> registrar WHOIS server (follows 'refer' chain)."""
    chain, server, text = [], "whois.iana.org", ""
    for _ in range(4):
        text = raw_whois(domain, server, timeout=timeout)
        chain.append(server)
        m = re.search(
            r"^\s*(?:refer|whois|registrar whois server)\s*:\s*(\S+)",
            text,
            re.I | re.M,
        )
        nxt = m.group(1).lower().replace("whois://", "") if m else None
        if not nxt or nxt in chain:
            break
        server = nxt
    result["whois43"] = {
        "servers_queried": chain,
        "parsed": grep_whois(
            text,
            {
                "registrar": r"registrar",
                "created": r"creation date|created",
                "updated": r"updated date|last[- ]updated",
                "expires": r"registry expiry date|expiration date|expires",
                "registrant_name": r"registrant name",
                "registrant_org": r"registrant organi[sz]ation",
                "registrant_email": r"registrant email",
                "registrant_country": r"registrant country",
                "admin_email": r"admin email",
                "tech_email": r"tech email",
                "name_servers": r"name server|nserver",
                "status": r"(?:domain )?status",
            },
        ),
        "raw": text,
    }
 
 
def lookup_domain(domain, timeout):
    result = {"query": domain, "type": "domain", "notes": []}
    entities = domain_rdap(domain, result, timeout)
 
    if entities is None:
        result["notes"].append("Falling back to port-43 WHOIS (RDAP missing)")
        domain_whois43(domain, result, timeout)
    elif not has_usable_registrant(entities):
        result["notes"].append(
            "RDAP thin/redacted; also running port-43 WHOIS for comparison"
        )
        domain_whois43(domain, result, timeout)
    return result
 
 
# --------------------------------------------------------------------------
# IP
# --------------------------------------------------------------------------
IP_FREE_TEXT = {
    "netname": r"netname|NetName",
    "descr": r"descr",
    "remarks": r"remarks",
    "org": r"org|OrgName|org-name",
    "mnt-by": r"mnt-by",
    "admin-c": r"admin-c",
    "tech-c": r"tech-c",
    "abuse-mailbox": r"abuse-mailbox|OrgAbuseEmail",
    "country": r"country",
    "created": r"created|RegDate",
    "last-modified": r"last-modified|Updated",
}
 
 
def lookup_ip(ip, both=False):
    from ipwhois import IPWhois
 
    result = {"query": ip, "type": "ip", "notes": []}
    obj = IPWhois(ip)
 
    try:
        rdap = obj.lookup_rdap(depth=1)
        result["rdap"] = {
            "asn": rdap.get("asn"),
            "asn_description": rdap.get("asn_description"),
            "asn_country": rdap.get("asn_country_code"),
            "asn_cidr": rdap.get("asn_cidr"),
            "registry": rdap.get("asn_registry"),
            "network": {
                k: (rdap.get("network") or {}).get(k)
                for k in ("name", "cidr", "country", "start_address",
                          "end_address", "parent_handle", "type", "events")
            },
            "contacts": [
                {
                    "key": k,
                    "roles": v.get("roles"),
                    "name": (v.get("contact") or {}).get("name"),
                    "email": [e["value"] for e in
                              ((v.get("contact") or {}).get("email") or [])],
                }
                for k, v in (rdap.get("objects") or {}).items()
            ],
            "remarks": (rdap.get("network") or {}).get("remarks"),
        }
        registry = rdap.get("asn_registry")
    except Exception as exc:  # noqa: BLE001
        result["notes"].append(f"RDAP failed: {exc}")
        registry = None
 
    # Legacy WHOIS: RIPE/APNIC keep richer free-text attributes
    if both or registry in (None, "ripencc", "apnic"):
        try:
            w = obj.lookup_whois(inc_raw=True, get_referral=False)
            raw = w.get("raw") or ""
            result["whois43"] = {
                "nets": w.get("nets"),
                "free_text": grep_whois(raw, IP_FREE_TEXT),
                "raw": raw,
            }
        except Exception as exc:  # noqa: BLE001
            result["notes"].append(f"WHOIS failed: {exc}")
    return result

