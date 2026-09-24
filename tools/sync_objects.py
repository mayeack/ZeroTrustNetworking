#!/usr/bin/env python3
"""make sync-objects: push knowledge objects from the source tree into the installed apps by REST, so saved searches,
macros, views, lookups and KV configs can be iterated without re-uploading a package. Writes land in the apps' local/."""
import configparser
import csv
import io
import os
import sys
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ztrest  # noqa: E402

ROOT = ztrest.ROOT
APPS = ["zt_incident_demo", "DA-ESS-zt_incident_demo"]


def read_conf(path):
    cp = configparser.RawConfigParser(strict=False, interpolation=None, delimiters=("=",), comment_prefixes=("#", ";"))
    cp.optionxform = str
    text = open(path).read().replace("\\\n", "")
    cp.read_string(text)
    return {s: dict(cp.items(s)) for s in cp.sections()}


def upsert(s, app, endpoint, name, values, key="name"):
    base = "servicesNS/nobody/%s/%s" % (app, endpoint)
    path = base + "/" + urllib.parse.quote(name, safe="")
    if s.exists(path):
        vals = {k: v for k, v in values.items() if k != key}
        s.post(path, data=vals)
        return "updated"
    vals = dict(values)
    vals[key] = name
    s.post(base, data=vals)
    return "created"


def share_global(s, app, endpoint, name):
    path = "servicesNS/nobody/%s/%s/%s/acl" % (app, endpoint, urllib.parse.quote(name, safe=""))
    try:
        s.post(path, data={"sharing": "global", "owner": "nobody", "perms.read": "*", "perms.write": "admin"})
    except ztrest.RestError:
        pass


def sync_savedsearches(s, app):
    path = os.path.join(ROOT, app, "default", "savedsearches.conf")
    if not os.path.exists(path):
        return
    for name, vals in read_conf(path).items():
        vals = {k: v for k, v in vals.items() if not k.startswith("action.notable.param._") }
        r = upsert(s, app, "saved/searches", name, vals)
        share_global(s, app, "saved/searches", name)
        print("  %-9s saved search %s" % (r, name))


def sync_macros(s, app):
    path = os.path.join(ROOT, app, "default", "macros.conf")
    if not os.path.exists(path):
        return
    for name, vals in read_conf(path).items():
        r = upsert(s, app, "admin/macros", name, vals)
        share_global(s, app, "admin/macros", name)
        print("  %-9s macro %s" % (r, name))


def sync_views(s, app):
    d = os.path.join(ROOT, app, "default", "data", "ui", "views")
    if not os.path.isdir(d):
        return
    for f in sorted(os.listdir(d)):
        if f.endswith(".xml"):
            name = f[:-4]
            data = open(os.path.join(d, f)).read()
            r = upsert(s, app, "data/ui/views", name, {"eai:data": data})
            share_global(s, app, "data/ui/views", name)
            print("  %-9s view %s" % (r, name))


def sync_nav(s, app):
    p = os.path.join(ROOT, app, "default", "data", "ui", "nav", "default.xml")
    if os.path.exists(p):
        r = upsert(s, app, "data/ui/nav", "default", {"eai:data": open(p).read()})
        print("  %-9s nav default" % r)


def sync_lookups(s, app):
    """Upload CSVs through the lookup-file editing endpoint when present, else through outputlookup."""
    d = os.path.join(ROOT, app, "lookups")
    if not os.path.isdir(d):
        return
    for f in sorted(os.listdir(d)):
        if not f.endswith(".csv"):
            continue
        rows = list(csv.DictReader(open(os.path.join(d, f), newline="")))
        if not rows:
            continue
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=list(rows[0].keys()), lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
        # build the CSV in-search: makeresults + eval per row is heavy; use a json-encoded field and spath
        import json
        payload = json.dumps(rows)
        spl = '| makeresults | eval _j="%s" | spath input=_j path={} output=r | mvexpand r | spath input=r | fields - _j r _time | outputlookup %s' % (payload.replace("\\", "\\\\").replace('"', '\\"'), f)
        try:
            s.search(spl, earliest="-1m", latest="now", timeout=300, namespace=app)
            print("  synced    lookup %s (%d rows)" % (f, len(rows)))
        except ztrest.RestError as e:
            print("  FAILED    lookup %s: %s" % (f, str(e)[:120]))


def main(argv):
    s = ztrest.Splunk()
    what = set(argv) or {"savedsearches", "macros", "views", "nav", "lookups"}
    for app in APPS:
        if not s.exists("services/apps/local/%s" % app):
            print("%s: not installed, skipped" % app)
            continue
        print("%s:" % app)
        if "savedsearches" in what:
            sync_savedsearches(s, app)
        if "macros" in what:
            sync_macros(s, app)
        if "views" in what:
            sync_views(s, app)
        if "nav" in what:
            sync_nav(s, app)
        if "lookups" in what:
            sync_lookups(s, app)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
