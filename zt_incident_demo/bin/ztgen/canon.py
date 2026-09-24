"""Canonical values of the story (deck, one-pager, generating prompt section 3). Use verbatim."""

CLUSTER = "ai-platform-dc2"
FABRIC = "dc2"
ND_HOST = "nd-dc2"                 # Nexus Dashboard that manages the dc2 fabric
ND_INSIGHTS_GROUP = "dc2-insights"

# Runner (source)
RUNNER_NS = "build-farm"
RUNNER_WL = "ci-runner"
RUNNER_WORKLOAD = "build-farm/ci-runner"
RUNNER_POD = "ci-runner-7d9f8-xk2lq"
RUNNER_POD_IP = "10.42.3.17"
RUNNER_NODE = "bf-node-03"
RUNNER_NODE_IP = "10.40.12.33"
RUNNER_IDENTITY = 48213
RUNNER_IDENTITY_QUARANTINED = 48291
RUNNER_ENDPOINT_ID = 1873
RUNNER_LABELS = ["k8s:app=ci-runner", "k8s:io.cilium.k8s.policy.cluster=ai-platform-dc2",
                 "k8s:io.cilium.k8s.policy.serviceaccount=ci-runner", "k8s:io.kubernetes.pod.namespace=build-farm",
                 "k8s:team=platform-build"]
RUNNER_OWNER = "platform-build"
RUNNER_IMAGE = "registry.corp.internal/ci/build-base:2026.09"
RUNNER_IMAGE_ID = "registry.corp.internal/ci/build-base@sha256:3f9a1c0e7b2d4a6f8e0c1b3d5f7a9c2e4b6d8f0a1c3e5b7d9f1a2c4e6b8d0f2a"
RUNNER_CONTAINER_ID = "containerd://5b0d7e1c9a24f3"
RUNNER_ZONE = "dc2-row-3"
RUNNER_EGRESS_POLICY = "build-farm-egress-internal"
RUNNER_EGRESS_POLICY_REVISION = "41"

# Store (destination)
STORE_NS = "ai-train"
STORE_WL = "checkpoint-store"
STORE_WORKLOAD = "ai-train/checkpoint-store"
STORE_POD = "checkpoint-store-1"
STORE_POD_IP = "10.42.7.21"
STORE_NODE = "ai-train-stor-02"
STORE_NODE_IP = "10.40.17.52"
STORE_IDENTITY = 30719
STORE_ENDPOINT_ID = 944
STORE_PORT = 9000
STORE_SERVICE = "checkpoint-store.ai-train.svc"
STORE_LABELS = ["k8s:app=checkpoint-store", "k8s:data-class=crown-jewel", "k8s:io.cilium.k8s.policy.cluster=ai-platform-dc2",
                "k8s:io.cilium.k8s.policy.serviceaccount=checkpoint-store", "k8s:io.kubernetes.pod.namespace=ai-train"]
STORE_OWNER = "ml-platform"
STORE_ALLOWLIST = "checkpoint-store-ingress-allowlist"
STORE_ZONE = "dc2-row-7"

# Fabric
RUNNER_SWITCH, RUNNER_INTERFACE = "dc2-leaf-205", "Eth1/12"
STORE_SWITCH, STORE_INTERFACE = "dc2-leaf-207", "Eth1/05"

# CI
CI_PROJECT = "ml-infra/train-utils"
CI_PROJECT_NAME = "ml-infra / train-utils"
CI_PROJECT_ID = 1187
CI_PIPELINE_ID = 55102
CI_JOB_ID = 88213
CI_JOB_NAME = "package"
CI_JOB_STAGE = "post-build"
CI_MR_IID = 4417
CI_MR_TITLE = "postbuild: cache model shards for integration tests"
CI_MR_URL = "https://git.corp.internal/ml-infra/train-utils/-/merge_requests/4417"
CI_BRANCH = "postbuild-cache"
CI_AUTHOR = "contractor-dev-17"
CI_COMMIT = "9f1c2ab4e07d51c8a3b6f2e9d0c47a1185be3f60"
CI_SCRIPT = "scripts/postbuild.sh"
CI_RUNNER_ID = 312
CI_HOST = "git.corp.internal"
CI_PROJECT_URL = "https://git.corp.internal/ml-infra/train-utils"

# Program
CURL = "/usr/bin/curl"
CURL_ARGS_TMPL = "-sS --retry 5 -o /tmp/.cache/m.bin http://checkpoint-store.ai-train.svc:9000/ckpt/llm-7712/{path}"
CURL_FIRST_PATH = "step-184000/model-00001-of-00008.safetensors"
SH = "/bin/sh"
SH_ARGS = "-c ./scripts/postbuild.sh"
CWD = "/builds/ml-infra/train-utils"
RUNNER_UID = 1000

# Protected data
PROTECTED_PREFIX = "/ckpt/llm-7712/"
TRAINING_JOB_ID = 7712
TRAINING_JOB_NAME = "llm-7712"

# Detections, finding, agent, playbook, approver
RULE_FLOW = "ZT - Audit-Mode Flow Into Protected AI Data Store - Rule"
RULE_PROGRAM = "ZT - Unapproved Program Connected to Protected AI Data Store - Rule"
RULE_FBD = "ZT - Workload Exceeded Risk Threshold on Protected-Path Signals - Rule"
RISK_FLOW, RISK_PROGRAM = 50, 40
FINDING_TITLE = "Unprotected path: build-farm/ci-runner reached a protected AI data store"
AGENT_NAME = "ZTFlowInvestigator"
PLAYBOOK = "zt_quarantine_workload"
APPROVER, APPROVER_ROLE = "j.chen", "SOC tier 2"
QUARANTINE_LABEL_KEY = "zt-quarantine"
QUARANTINE_POLICY = "zt-quarantine-ci-runner-88213"
ENFORCER_USER = "system:serviceaccount:soar:zt-enforcer"
ENFORCER_GROUPS = ["system:serviceaccounts", "system:serviceaccounts:soar", "system:authenticated"]
ENFORCER_SOURCE_IP = "10.40.2.18"
PLATFORM_USER = "k.osei"
PLATFORM_ROLE = "platform"

# Story timing (seconds relative to T0 = the curl connect)
T_CI_RUNNING = -27.0
T_GIT_EXEC = -25.0
T_SH_EXEC = -19.5
T_CURL_EXEC = -0.204
T_EGRESS = 0.007
T_INGRESS = 0.029
ATTEMPT_INTERVAL = 30
DROPPED_ATTEMPTS_BEFORE_FAIL = 6
FAIL_DELAY_AFTER_LAST_DROP = 15
NO_QUARANTINE_TIMEOUT = 45 * 60

# Posture (before, during, after)
POSTURE = {"before": {"identities": 1283, "coverage_pct": 87.7, "enforced": 57, "paths": 65, "unprotected": 8, "audit_flows_24h": 2306, "enforcement_24h": 16, "kernel": 10, "dpu": 2, "switch": 4},
           "during": {"coverage_pct": 86.4, "enforced": 57, "paths": 66, "unprotected": 9},
           "after": {"identities": 1284, "coverage_pct": 87.9, "enforced": 58, "paths": 66, "unprotected": 8, "enforcement_24h": 17, "kernel": 11}}
