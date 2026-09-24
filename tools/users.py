#!/usr/bin/env python3
"""make users: roles and users on the stack for the demo. Passwords are generated once and kept in local/env."""
import os
import secrets as _secrets
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ztrest  # noqa: E402

ROLES = {
    "zt_soc_tier2": {"imported_roles": ["ess_analyst"], "srchIndexesAllowed": ["zero_trust", "zt_summary", "notable", "risk"], "capabilities": []},
    "zt_netops": {"imported_roles": ["user"], "srchIndexesAllowed": ["zero_trust", "zt_summary"], "capabilities": []},
    "zt_agent_mcp": {"imported_roles": ["user"], "srchIndexesAllowed": ["zero_trust", "zt_summary", "risk", "notable"], "capabilities": ["mcp_tool_execute"]},
    "zt_soar": {"imported_roles": ["ess_analyst"], "srchIndexesAllowed": ["zero_trust", "zt_summary", "notable", "risk"], "capabilities": []},
    "zt_service": {"imported_roles": ["user"], "srchIndexesAllowed": ["zero_trust", "zt_summary"], "capabilities": []},
}
USERS = {"j.chen": ("zt_soc_tier2", "J. Chen"), "m.ruiz": ("zt_soc_tier2", "M. Ruiz"), "a.patel": ("zt_netops", "A. Patel"),
         "zt-agent": ("zt_agent_mcp", "ZT agent service account"), "zt-soar": ("zt_soar", "ZT SOAR service account"), "zt-emulator": ("zt_service", "ZT emulator service account")}


def env_key(user):
    return "ZT_PASS_" + user.upper().replace(".", "_").replace("-", "_")


def main():
    s = ztrest.Splunk()
    existing_roles = {e["name"] for e in s.entries("services/authorization/roles")}
    for name, spec in ROLES.items():
        data = {"imported_roles": spec["imported_roles"], "srchIndexesAllowed": spec["srchIndexesAllowed"], "srchIndexesDefault": ["zero_trust"]}
        if spec["capabilities"]:
            data["capabilities"] = spec["capabilities"]
        if name in existing_roles:
            s.post("services/authorization/roles/" + name, data=data)
            print("role %-14s updated" % name)
        else:
            d = dict(data)
            d["name"] = name
            s.post("services/authorization/roles", data=d)
            print("role %-14s created" % name)
    existing_users = {e["name"] for e in s.entries("services/authentication/users")}
    for user, (role, realname) in USERS.items():
        pw = ztrest.env(env_key(user))
        if not pw:
            pw = _secrets.token_urlsafe(18)
            ztrest.set_env_value(env_key(user), pw)
        if user in existing_users:
            s.post("services/authentication/users/" + user, data={"roles": [role], "realname": realname, "password": pw})
            print("user %-12s updated (role %s)" % (user, role))
        else:
            s.post("services/authentication/users", data={"name": user, "password": pw, "roles": [role], "realname": realname, "force-change-pass": 0})
            print("user %-12s created (role %s); password in local/env as %s" % (user, role, env_key(user)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
