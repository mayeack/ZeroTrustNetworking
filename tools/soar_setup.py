#!/usr/bin/env python3
"""make soar-setup: roles, users, assets, the custom function and the playbook on Splunk SOAR (cloud), from
soar/zt_quarantine_workload/. Idempotent; secrets come from local/env and generated passwords go back there.

  soar_setup.py                 apply everything to the SOAR in local/env (SOAR_URL, SOAR_USER, SOAR_PASS)
  soar_setup.py --dry-run       build the packages and print what would be done, without calling SOAR
  soar_setup.py --package-only  build local/soar_package/*.tgz and validate them, nothing else
"""
import argparse
import base64
import io
import json
import os
import re
import secrets as _secrets
import sys
import tarfile
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ztrest  # noqa: E402

ROOT = ztrest.ROOT
SOAR_DIR = os.path.join(ROOT, "soar", "zt_quarantine_workload")
PACKAGE_DIR = os.path.join(ROOT, "local", "soar_package")
PLAYBOOK = "zt_quarantine_workload"
CUSTOM_FUNCTION = "zt_build_cnp"
REPO = "local"
LABEL = "es_soar_integration"

# SOAR roles for the approvers. Approvers only need to open the finding's container and answer the prompt.
# VERIFY: the permissions structure accepted by POST /rest/role on SOAR 8.7 (the REST reference shows this shape).
ROLES = {
    "SOC tier 2": {"description": "Zero trust quarantine approvers, first approval (kernel, DPU, switch).",
                   "permissions": {"containers": {"view": True, "edit": True, "delete": False}, "playbooks": {"view": True, "edit": False, "delete": False},
                                   "apps": {"view": True, "edit": False, "delete": False}, "assets": {"view": True, "edit": False, "delete": False}}},
    "NetOps": {"description": "Zero trust quarantine approvers, second approval for the DPU and switch enforcement points.",
               "permissions": {"containers": {"view": True, "edit": True, "delete": False}, "playbooks": {"view": True, "edit": False, "delete": False},
                               "apps": {"view": True, "edit": False, "delete": False}, "assets": {"view": True, "edit": False, "delete": False}}},
}
USERS = {"j.chen": ("SOC tier 2", "J.", "Chen"), "m.ruiz": ("SOC tier 2", "M.", "Ruiz"), "a.patel": ("NetOps", "A.", "Patel")}
PLACEHOLDER = re.compile(r"^<([A-Z0-9_]+) from local/env>$")


def env_key(user):
    return "SOAR_PASS_" + user.upper().replace(".", "_").replace("-", "_")


def say(msg):
    print(msg)


# ------------------------------------------------------------------------------------------------ packages
def build_tgz(names, src_dir, out_path, prefix=""):
    """<name>.py + <name>.json from src_dir into a gzip tar; returns the archive bytes."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name in names:
            path = os.path.join(src_dir, name)
            info = tar.gettarinfo(path, arcname=prefix + name)
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mode = 0o644
            with open(path, "rb") as fh:
                tar.addfile(info, fh)
    data = buf.getvalue()
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "wb") as fh:
        fh.write(data)
    return data


def validate_tgz(path, expected):
    with tarfile.open(path, "r:gz") as tar:
        names = sorted(m.name for m in tar.getmembers() if m.isfile())
    if names != sorted(expected):
        sys.exit("%s contains %s, expected %s" % (path, names, expected))
    say("package %s ok (%s, %.1f KB)" % (os.path.basename(path), ", ".join(names), os.path.getsize(path) / 1024))


def playbook_metadata():
    """Minimal export envelope of a full-code Python playbook, derived from a real SOAR 8.x export (local/soar_ref).
    The Python file is the playbook; the JSON carries the envelope SOAR expects on import."""
    now = time.strftime("%Y-%m-%dT%H:%M:%S.000000+00:00", time.gmtime())
    return {
        "blockly": False,
        "blockly_xml": "<xml></xml>",
        "category": "Zero Trust",
        "coa": {
            "data": {
                "description": "Quarantine a workload after the ZT finding-based detection: agent brief, Cilium policy, SOC tier 2 approval, apply, verify, audit trail, ES resolution.",
                "edges": [],
                "hash": "",  # VERIFY: SOAR recomputes the hash on import; an empty value is accepted by the importer
                "nodes": {
                    "0": {"data": {"advanced": {"join": []}, "functionName": "on_start", "id": "0", "type": "start"}, "errors": {}, "id": "0", "type": "start", "warnings": {}, "x": 360, "y": 0},
                    "1": {"data": {"advanced": {"join": []}, "functionName": "on_finish", "id": "1", "type": "end"}, "errors": {}, "id": "1", "type": "end", "warnings": {}, "x": 360, "y": 800},
                },
                "notes": "Full-code playbook: the Python file holds all blocks (see soar/zt_quarantine_workload/BUILD_SHEET.md).",
            },
            "input_spec": None,
            "output_spec": None,
            "playbook_trigger": "artifact_created",
            "playbook_type": "es",      # VERIFY: "es" is the type of the reference export for finding containers
            "python_version": "3.13",
            "schema": "5.0.15",
            "version": "8.7.0",
        },
        "create_time": now,
        "draft_mode": False,
        "labels": [LABEL],
        "tags": ["zero_trust", "quarantine"],
    }


def build_packages():
    os.makedirs(PACKAGE_DIR, exist_ok=True)
    pb_json = os.path.join(PACKAGE_DIR, PLAYBOOK + ".json")
    with open(pb_json, "w") as fh:
        json.dump(playbook_metadata(), fh, indent=4)
    pb_py = os.path.join(PACKAGE_DIR, PLAYBOOK + ".py")
    with open(os.path.join(SOAR_DIR, PLAYBOOK + ".py")) as src, open(pb_py, "w") as dst:
        dst.write(src.read())
    pb_tgz = os.path.join(PACKAGE_DIR, PLAYBOOK + ".tgz")
    build_tgz([PLAYBOOK + ".py", PLAYBOOK + ".json"], PACKAGE_DIR, pb_tgz)
    validate_tgz(pb_tgz, [PLAYBOOK + ".py", PLAYBOOK + ".json"])
    cf_tgz = os.path.join(PACKAGE_DIR, CUSTOM_FUNCTION + ".tgz")
    build_tgz([CUSTOM_FUNCTION + ".py", CUSTOM_FUNCTION + ".json"], os.path.join(SOAR_DIR, "custom_functions"), cf_tgz)
    validate_tgz(cf_tgz, [CUSTOM_FUNCTION + ".py", CUSTOM_FUNCTION + ".json"])
    return pb_tgz, cf_tgz


# ------------------------------------------------------------------------------------------------ SOAR objects
def find_one(soar, resource, **filters):
    rows = soar.find(resource, **filters)
    return rows[0] if rows else None


def ensure_roles(soar, dry_run):
    """Create the approver roles. SOAR wants `permissions` as a list of {name, view, edit, delete, execute} objects; start
    from the Observer role (view everything) and allow editing/executing on containers so approvers can answer prompts."""
    existing = {r["name"]: r for r in soar.get("rest/role", params={"page_size": 100})["data"]}
    observer = next((r for r in existing.values() if r["name"] == "Observer"), None)
    base = observer["permissions"] if observer else []
    role_ids = {}
    for name, desc in (("SOC tier 2", "Zero trust quarantine approvers, first approval (kernel, DPU, switch)."),
                       ("NetOps", "Zero trust quarantine approvers, second approval for the DPU and switch enforcement points.")):
        if name in existing:
            role_ids[name] = existing[name]["id"]
            print("role %-10s present (id %s)" % (name, existing[name]["id"]))
            continue
        perms = []
        for p in base:
            entry = {"name": p["name"], "view": "allow", "edit": "deny", "delete": "deny", "execute": "deny"}
            if p["name"] in ("containers", "case_management"):
                entry.update({"edit": "allow", "execute": "allow"})
            if p["name"] == "playbooks":
                entry.update({"execute": "allow"})
            perms.append(entry)
        body = {"name": name, "description": desc, "permissions": perms}
        if dry_run:
            print("role %-10s would be created with %d permission entries" % (name, len(perms)))
            continue
        r = soar.post("rest/role", json_body=body)
        role_ids[name] = r.get("id")
        print("role %-10s created (id %s)" % (name, r.get("id")))
    return role_ids

def ensure_users(soar, role_ids, dry):
    for user, (role, first, last) in USERS.items():
        pw = ztrest.env(env_key(user))
        if not pw:
            pw = _secrets.token_urlsafe(18)
            if not dry:
                ztrest.set_env_value(env_key(user), pw)
            say("password for %s generated (local/env %s)" % (user, env_key(user)))
        body = {"username": user, "first_name": first, "last_name": last, "email": "%s@example.invalid" % user, "type": "normal",
                "is_active": True, "roles": [role_ids[role]] if role in role_ids else [], "password": pw}
        existing = find_one(soar, "ph_user", username=user) if not dry else None
        if existing:
            # keep the role list and the password in step with local/env
            soar.post("rest/ph_user/%s" % existing["id"], json_body={"roles": body["roles"], "password": pw, "is_active": True})
            say("user %-8s updated (role %s)" % (user, role))
        elif dry:
            say("user %-8s would be created (role %s)" % (user, role))
        else:
            soar.post("rest/ph_user", json_body=body)
            say("user %-8s created (role %s)" % (user, role))


def resolve_value(value):
    """Fill the placeholders of assets.json from local/env. Returns (value, ok)."""
    if not isinstance(value, str):
        return value, True
    m = PLACEHOLDER.match(value)
    if m:
        v = ztrest.env(m.group(1))
        return v, bool(v)
    if "<" in value and ">" in value:
        # "Bearer <KEY from local/env>", "Splunk <KEY from local/env>", "<SPLUNK_URL host, ...>"
        inner = value[value.index("<") + 1:value.index(">")]
        m2 = re.match(r"([A-Z0-9_]+) from local/env", inner)
        if m2:
            v = ztrest.env(m2.group(1))
            return (value[:value.index("<")] + v + value[value.index(">") + 1:], True) if v else (value, False)
        if inner.startswith("SPLUNK_URL host"):
            url = ztrest.env("SPLUNK_URL") or ""
            host = urllib.parse.urlsplit(url).hostname or ""
            return host, bool(host)
        return value, False
    return value, True


def app_id_for(soar, app_name, dry):
    if dry:
        return None
    rows = soar.find("app", name=app_name)
    rows = sorted(rows, key=lambda r: r.get("app_version") or "", reverse=True)
    return rows[0]["id"] if rows else None


def ensure_assets(soar, dry):
    with open(os.path.join(SOAR_DIR, "assets.json")) as fh:
        spec = json.load(fh)
    for asset in spec["assets"]:
        if asset.get("managed") is False:
            say("asset %-18s left alone (%s)" % (asset["name"], asset["description"].split(".")[0]))
            continue
        config, missing = {}, []
        for k, v in asset["configuration"].items():
            val, ok = resolve_value(v)
            config[k] = val
            if not ok:
                missing.append(k)
        if missing:
            say("asset %-18s skipped: no value in local/env for %s" % (asset["name"], ", ".join(missing)))
            continue
        body = {"name": asset["name"], "description": asset["description"], "product_vendor": asset["product_vendor"], "product_name": asset["product_name"],
                "configuration": config, "tags": ["zero_trust"]}
        app_id = app_id_for(soar, asset["app"], dry)
        if app_id:
            body["app_id"] = app_id  # VERIFY: app_id is the way to bind an asset to an installed app through REST
        existing = find_one(soar, "asset", name=asset["name"]) if not dry else None
        shown = {k: ("***" if k in ("password", "auth_token") else v) for k, v in config.items()}
        if existing:
            soar.post("rest/asset/%s" % existing["id"], json_body=body)
            say("asset %-18s updated (id %s) %s" % (asset["name"], existing["id"], json.dumps(shown)))
        elif dry:
            say("asset %-18s would be created (%s %s) %s" % (asset["name"], asset["app"], asset["app_version"], json.dumps(shown)))
        else:
            r = soar.post("rest/asset", json_body=body)
            say("asset %-18s created (id %s) %s" % (asset["name"], r.get("id"), json.dumps(shown)))


def import_custom_function(soar, cf_tgz, dry):
    with open(cf_tgz, "rb") as fh:
        b64 = base64.b64encode(fh.read()).decode()
    body = {"custom_function": b64, "scm": REPO, "force": True}  # VERIFY: scm/force accepted by /rest/import_custom_function as by import_playbook
    if dry:
        say("custom function %s would be imported (%d bytes base64)" % (CUSTOM_FUNCTION, len(b64)))
        return
    r = soar.post("rest/import_custom_function", json_body=body)
    say("custom function %s imported: %s" % (CUSTOM_FUNCTION, json.dumps(r)[:200]))


def import_playbook(soar, pb_tgz, dry):
    with open(pb_tgz, "rb") as fh:
        b64 = base64.b64encode(fh.read()).decode()
    body = {"playbook": b64, "scm": REPO, "force": True}
    if dry:
        say("playbook %s would be imported (%d bytes base64); active=false (ES starts it through the automation rule; label activation would run it twice), label %s" % (PLAYBOOK, len(b64), LABEL))
        return
    r = soar.post("rest/import_playbook", json_body=body)
    say("playbook %s imported: %s" % (PLAYBOOK, json.dumps(r)[:200]))
    pb = find_one(soar, "playbook", name=PLAYBOOK)
    if pb:
        # ES 8.7 starts the playbook through its automation rule; "active" still lets the rule and manual runs use it
        soar.post("rest/playbook/%s" % pb["id"], json_body={"active": False})
        say("playbook %s (id %s) imported, label-inactive (the ES automation rule starts it)" % (PLAYBOOK, pb["id"]))


# ------------------------------------------------------------------------------------------------ main
def main(argv):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dry-run", action="store_true", help="build the packages and print the plan; no SOAR calls")
    ap.add_argument("--package-only", action="store_true", help="only build and validate local/soar_package/*.tgz")
    args = ap.parse_args(argv)

    pb_tgz, cf_tgz = build_packages()
    if args.package_only:
        return 0
    soar = None
    if not args.dry_run:
        soar = ztrest.Soar()
        say("SOAR %s: version %s" % (ztrest.env("SOAR_URL"), soar.get("rest/version").get("version")))
    role_ids = ensure_roles(soar, args.dry_run)
    ensure_users(soar, role_ids, args.dry_run)
    ensure_assets(soar, args.dry_run)
    import_custom_function(soar, cf_tgz, args.dry_run)
    import_playbook(soar, pb_tgz, args.dry_run)
    say("done%s. Next: create the Phantom utility asset in the SOAR UI if missing, then run tools/es_automation_rule.py (Mode A)." % (" (dry run)" if args.dry_run else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
