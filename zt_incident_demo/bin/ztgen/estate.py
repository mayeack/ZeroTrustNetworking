"""The estate: one cluster, 1,283 workloads with deterministic identities, 92 nodes on a Nexus fabric,
four protected stores with allowlists, eight known gaps, the process allowlist and the enforcement history.

Everything derives from SEED; canonical values are pinned from canon.py.
"""
import hashlib
import random
from collections import OrderedDict

from . import SEED, canon


def _rng(*parts):
    return random.Random(hashlib.sha256((SEED + "|" + "|".join(str(p) for p in parts)).encode()).hexdigest())


def _h(*parts):
    return hashlib.sha256((SEED + "|" + "|".join(str(p) for p in parts)).encode()).hexdigest()


# --------------------------------------------------------------------------- workloads
BUILD_FARM = ["ci-runner", "build-cache", "artifact-proxy", "image-builder", "runner-metrics", "webhook-relay",
              "secrets-agent", "git-mirror", "build-scheduler", "dep-proxy", "npm-cache", "pip-cache", "go-proxy",
              "maven-cache", "registry-mirror", "test-reporter", "coverage-collector", "sbom-scanner", "sast-runner",
              "release-bot", "artifact-gc", "runner-autoscaler", "kaniko-worker", "buildkit", "ccache", "bazel-remote",
              "job-dispatcher", "pipeline-api", "queue-worker", "notify-bot", "status-page", "runner-registrar",
              "cleanup-cron", "metrics-exporter", "trivy-scanner", "changelog-bot"]
AI_TRAIN = ["trainer", "eval-runner", "ckpt-compactor", "checkpoint-store", "dataset-cache", "data-loader",
            "tokenizer-service", "shard-manager", "run-tracker", "metrics-db", "tensorboard", "sweep-controller",
            "hp-tuner", "eval-db", "feature-builder", "augmenter", "dedup-worker", "quality-filter",
            "curriculum-scheduler", "grad-monitor", "ckpt-verifier", "ckpt-replicator", "dataset-indexer",
            "label-service", "lineage-tracker", "experiment-api", "queue-controller", "gpu-allocator",
            "nccl-tester", "topology-probe", "rdma-monitor", "trainer-sidecar-metrics", "loss-dashboard",
            "run-archiver", "config-server", "secrets-broker", "artifact-signer", "eval-scheduler", "prompt-bank",
            "benchmark-runner", "reward-model-trainer", "rl-rollout-worker", "dpo-trainer", "sft-trainer",
            "merge-worker", "quant-worker", "export-worker", "safety-eval"]
AI_INFER_NAMED = ["model-registry", "vector-index", "eval-harness", "rag-gateway", "embed-service", "rerank-service",
                  "guardrail-service", "prompt-cache", "kv-cache-proxy", "inference-router", "api-gateway",
                  "token-budget", "usage-meter", "abuse-filter", "model-loader", "warm-pool-controller",
                  "canary-controller", "ab-router", "schema-registry", "feature-store-reader", "moderation-service",
                  "citation-service", "web-search-tool", "code-exec-sandbox", "session-store", "conversation-db",
                  "feedback-collector", "eval-replay", "latency-probe", "quota-service"]
PLATFORM = ["backup-agent", "argocd-repo", "dns", "ingress", "cert-manager", "external-dns", "argocd-server",
            "argocd-application-controller", "vault-agent-injector", "oidc-proxy", "kube-state-metrics",
            "cluster-autoscaler", "descheduler", "node-problem-detector", "image-pull-cache", "policy-controller",
            "admission-webhook", "cilium-operator", "hubble-relay", "hubble-ui", "tetragon-operator", "sealed-secrets",
            "harbor-core", "harbor-registry", "harbor-jobservice", "gitops-notifier", "cost-exporter", "chargeback",
            "quota-manager", "namespace-provisioner", "rbac-sync", "ldap-sync", "sso-gateway", "pki-issuer",
            "kms-proxy", "s3-gateway", "nfs-provisioner", "csi-controller", "snapshot-controller", "velero",
            "backup-scheduler", "restore-worker", "dr-replicator", "audit-forwarder", "syslog-relay",
            "ntp", "dhcp-relay", "ipam", "bgp-speaker", "service-mesh-control", "mesh-gateway", "egress-gateway",
            "nat-gateway", "bastion", "jump-host", "runbook-executor", "change-bot", "maintenance-window",
            "upgrade-controller", "license-server", "inventory-sync", "cmdb-connector", "ticket-bridge", "pager-bridge"]
DATA_ENG = ["spark-driver", "airflow-worker", "airflow-scheduler", "airflow-web", "spark-history", "kafka-connect",
            "schema-registry", "debezium", "flink-jobmanager", "flink-taskmanager", "trino-coordinator", "trino-worker",
            "hive-metastore", "iceberg-catalog", "dbt-runner", "great-expectations", "data-catalog", "lineage-api",
            "warehouse-loader", "lakehouse-compactor", "parquet-writer", "cdc-consumer", "event-router",
            "clickstream-ingest", "sessionizer", "dedupe-job", "pii-scrubber", "tokenization-service", "masking-proxy",
            "s3-sync", "gcs-sync", "sftp-gateway", "ftp-poller", "api-poller", "webhook-ingest", "log-parser",
            "metrics-rollup", "cost-model", "forecast-job", "anomaly-job", "report-builder", "dashboard-refresh",
            "notebook-scheduler", "query-cache", "result-store", "export-service", "share-service", "access-audit",
            "quota-enforcer", "retention-job", "archive-job", "restore-job", "replication-job", "backfill-job",
            "quality-monitor", "sla-monitor", "freshness-monitor", "schema-drift", "contract-checker", "test-runner",
            "staging-loader", "prod-loader", "sandbox-loader", "feature-pipeline", "embedding-pipeline",
            "label-pipeline", "sampling-job", "join-job", "aggregation-job", "window-job", "stream-enricher",
            "geo-enricher", "ip-enricher", "ua-parser", "currency-converter", "tax-calculator", "billing-export",
            "invoice-job", "ledger-sync", "finance-report"]
VM_LEGACY = ["erp-batch", "erp-web", "erp-db", "erp-print", "payroll-batch", "hr-portal", "crm-legacy", "crm-db",
             "file-server", "print-server", "fax-gateway", "edi-translator", "edi-gateway", "mainframe-bridge",
             "tn3270-proxy", "ldap-legacy", "wins", "legacy-backup", "report-server", "bi-cube", "jasper", "cognos"]
OBSERVABILITY = ["log-shipper", "metrics-collector", "otel-collector", "otel-gateway", "trace-collector",
                 "prometheus", "alertmanager", "grafana", "loki", "tempo", "mimir", "pushgateway", "blackbox-exporter",
                 "node-exporter", "snmp-exporter", "syslog-collector", "netflow-collector", "flow-aggregator",
                 "profiler", "synthetic-checker".replace("synthetic", "uptime"), "sla-reporter", "oncall-bridge",
                 "status-exporter", "cost-collector", "gpu-exporter", "dcgm-exporter", "nvlink-monitor", "fabric-poller"]
TEAM_APPS = ["api", "worker", "web", "cache", "cron"]

NAMESPACE_OWNERS = {"build-farm": ("platform-build", "platform-build"), "ai-train": ("ml-platform", "ml-platform"),
                    "ai-infer": ("ml-serving", "ml-serving"), "platform": ("platform", "platform"),
                    "data-eng": ("data-eng", "data-eng"), "vm-legacy": ("erp-ops", "erp-ops"),
                    "ml-notebooks": ("ml-research", "ml-research"), "observability": ("observability", "observability")}
WORKLOAD_OWNER_OVERRIDES = {"ai-train/trainer": "ml-research", "ai-train/eval-runner": "ml-research",
                            "ai-train/checkpoint-store": "ml-platform", "ai-train/dataset-cache": "ml-platform",
                            "ai-infer/eval-harness": "ml-eval", "ai-infer/model-registry": "ml-platform",
                            "ai-infer/vector-index": "ml-serving"}
STATEFUL = {"checkpoint-store", "dataset-cache", "model-registry", "vector-index", "metrics-db", "eval-db", "erp-db",
            "crm-db", "conversation-db", "session-store", "prometheus", "loki", "tempo", "mimir", "hive-metastore",
            "kafka-connect", "result-store", "harbor-registry", "file-server"}
DAEMON = {"log-shipper", "node-exporter", "dcgm-exporter", "gpu-exporter", "otel-collector", "dns", "csi-controller",
          "metrics-collector"}
DATA_CLASS = {"ai-train/checkpoint-store": "crown-jewel", "ai-train/dataset-cache": "restricted",
              "ai-infer/model-registry": "restricted", "ai-infer/vector-index": "confidential",
              "vm-legacy/erp-db": "restricted", "ai-infer/conversation-db": "confidential"}

FIRST = ["a", "b", "c", "d", "e", "f", "g", "h", "j", "k", "l", "m", "n", "p", "r", "s", "t", "v", "w", "y"]
SURNAMES = ["adler", "baptiste", "chen", "dubois", "eriksen", "fischer", "garcia", "haddad", "ito", "jensen", "kaur",
            "lindqvist", "moreau", "nakamura", "okafor", "patel", "quinn", "rossi", "singh", "tanaka", "ulrich",
            "varga", "weber", "xu", "yilmaz", "zhang", "almeida", "brennan", "castillo", "dimitrov", "esposito",
            "fontaine", "gupta", "hoffmann", "ibrahim", "jimenez", "kowalski", "larsson", "mendes", "nguyen",
            "olsen", "pereira", "rahman", "schneider", "torres", "usman", "vasquez", "wagner", "yamamoto", "zielinski"]


def _notebook_users():
    rng = _rng("nb-users")
    users = OrderedDict()
    while len(users) < 259:
        u = rng.choice(FIRST) + rng.choice(SURNAMES)
        if u not in users:
            users[u] = True
    return list(users)


def _ai_infer_workloads():
    names = list(AI_INFER_NAMED)
    models = ["llm-70b", "llm-7b", "llm-7712", "code-13b", "vision-2b", "asr-1b", "embed-l", "rerank-s", "guard-3b", "summ-8b"]
    i = 0
    while len(names) < 140:
        m = models[i % len(models)]
        names.append("serve-%s-%02d" % (m, i // len(models) + 1))
        i += 1
    return names


class Workload:
    __slots__ = ("namespace", "name", "kind", "owner", "team", "tier", "data_class", "description", "identity",
                 "node", "pods", "labels", "service_account", "image", "replicas", "zone")

    @property
    def key(self):
        return "%s/%s" % (self.namespace, self.name)

    def __repr__(self):
        return "Workload(%s id=%s node=%s)" % (self.key, self.identity, self.node)


class Pod:
    __slots__ = ("name", "ip", "node", "workload", "endpoint_id", "container_id")

    def __repr__(self):
        return "Pod(%s %s %s)" % (self.name, self.ip, self.node)


class Node:
    __slots__ = ("name", "ip", "switch", "interface", "vrf", "zone", "pod_cidr", "role", "mac")

    def __repr__(self):
        return "Node(%s %s %s %s)" % (self.name, self.ip, self.switch, self.interface)


# --------------------------------------------------------------------------- estate
class Estate:
    """Built once per process; cheap (a few thousand objects)."""

    def __init__(self):
        self.workloads = OrderedDict()   # key -> Workload
        self.nodes = OrderedDict()       # name -> Node
        self.pods = OrderedDict()        # pod name -> Pod
        self.identities = {}             # identity -> workload key
        self._build_nodes()
        self._build_workloads()
        self._assign_identities()
        self._place_pods()
        self._build_protected()
        self._build_enforcement_history()

    # ---- nodes -----------------------------------------------------------
    def _build_nodes(self):
        names = (["bf-node-%02d" % i for i in range(1, 9)] + ["ai-train-gpu-%02d" % i for i in range(1, 25)] +
                 ["ai-train-stor-%02d" % i for i in range(1, 5)] + ["ai-infer-%02d" % i for i in range(1, 17)] +
                 ["gen-node-%02d" % i for i in range(1, 41)])
        assert len(names) == 92
        leaves = ["dc2-leaf-%d" % i for i in range(201, 209)]
        used_ports = {(canon.RUNNER_SWITCH, canon.RUNNER_INTERFACE), (canon.STORE_SWITCH, canon.STORE_INTERFACE)}
        used_cidrs = {3, 7}
        used_ips = {canon.RUNNER_NODE_IP, canon.STORE_NODE_IP}
        rng = _rng("nodes")
        cidr_next = 10
        for idx, name in enumerate(names):
            n = Node()
            n.name = name
            n.role = name.rsplit("-", 1)[0]
            if name == canon.RUNNER_NODE:
                n.ip, n.switch, n.interface, n.pod_cidr, n.zone = canon.RUNNER_NODE_IP, canon.RUNNER_SWITCH, canon.RUNNER_INTERFACE, 3, canon.RUNNER_ZONE
            elif name == canon.STORE_NODE:
                n.ip, n.switch, n.interface, n.pod_cidr, n.zone = canon.STORE_NODE_IP, canon.STORE_SWITCH, canon.STORE_INTERFACE, 7, canon.STORE_ZONE
            else:
                row = {"bf-node": 12, "ai-train-gpu": 15, "ai-train-stor": 17, "ai-infer": 19, "gen-node": 21}[n.role]
                ip = None
                while ip is None or ip in used_ips:
                    ip = "10.40.%d.%d" % (row + rng.choice([0, 1]), rng.randint(10, 250))
                used_ips.add(ip)
                n.ip = ip
                leaf = leaves[(idx * 3 + rng.randint(0, 7)) % 8]
                port = None
                while port is None or (leaf, port) in used_ports:
                    port = "Eth1/%d" % rng.randint(1, 48)
                used_ports.add((leaf, port))
                n.switch, n.interface = leaf, port
                while cidr_next in used_cidrs:
                    cidr_next += 1
                n.pod_cidr = cidr_next
                used_cidrs.add(cidr_next)
                n.zone = "dc2-row-%d" % (int(leaf[-1]) + 1)
            n.vrf = {"bf-node": "k8s-build", "ai-train-gpu": "k8s-ai", "ai-train-stor": "k8s-ai", "ai-infer": "k8s-infer", "gen-node": "k8s-gen"}[n.role]
            n.mac = "3c:fd:fe:%02x:%02x:%02x" % (int(_h("mac", name)[:2], 16), int(_h("mac", name)[2:4], 16), idx + 1)
            if name == canon.RUNNER_NODE:
                n.mac = "3c:fd:fe:9a:12:03"
            self.nodes[name] = n

    # ---- workloads -------------------------------------------------------
    def _add(self, ns, name, kind=None):
        w = Workload()
        w.namespace, w.name = ns, name
        w.kind = kind or ("StatefulSet" if name in STATEFUL else "DaemonSet" if name in DAEMON else "Deployment")
        owner, team = NAMESPACE_OWNERS.get(ns, (ns, ns))
        w.owner = WORKLOAD_OWNER_OVERRIDES.get(w.key, owner)
        w.team = team
        w.data_class = DATA_CLASS.get(w.key, "internal")
        w.tier = "crown-jewel" if w.data_class == "crown-jewel" else ("tier-1" if ns in ("ai-train", "ai-infer", "platform") else "tier-2")
        w.description = "%s in %s" % (name.replace("-", " "), ns)
        w.service_account = name
        w.replicas = 1
        w.labels = ["k8s:app=%s" % name, "k8s:io.cilium.k8s.policy.cluster=%s" % canon.CLUSTER,
                    "k8s:io.cilium.k8s.policy.serviceaccount=%s" % name, "k8s:io.kubernetes.pod.namespace=%s" % ns]
        if ns == "build-farm":
            w.labels.append("k8s:team=platform-build")
        if w.key in DATA_CLASS:
            w.labels.insert(1, "k8s:data-class=%s" % w.data_class)
        w.labels.sort()
        reg = {"build-farm": "ci", "ai-train": "ml", "ai-infer": "serving", "platform": "platform", "data-eng": "data",
               "vm-legacy": "legacy", "ml-notebooks": "notebooks", "observability": "o11y"}.get(ns, "apps")
        w.image = "registry.corp.internal/%s/%s:2026.09" % (reg, name)
        self.workloads[w.key] = w
        return w

    def _build_workloads(self):
        for n in BUILD_FARM:
            self._add("build-farm", n)
        for n in AI_TRAIN:
            self._add("ai-train", n)
        for n in _ai_infer_workloads():
            self._add("ai-infer", n)
        for n in PLATFORM:
            self._add("platform", n)
        for n in DATA_ENG:
            self._add("data-eng", n)
        for n in VM_LEGACY:
            self._add("vm-legacy", n)
        self._add("ml-notebooks", "jupyter")
        for u in _notebook_users():
            self._add("ml-notebooks", "nb-" + u, "StatefulSet")
        for n in OBSERVABILITY:
            self._add("observability", n)
        for t in range(1, 122):
            for a in TEAM_APPS:
                self._add("team-%03d" % t, a)
        r = self.workloads[canon.RUNNER_WORKLOAD]
        r.replicas, r.image, r.labels = 6, canon.RUNNER_IMAGE, list(canon.RUNNER_LABELS)
        s = self.workloads[canon.STORE_WORKLOAD]
        s.replicas, s.labels = 2, list(canon.STORE_LABELS)
        assert len(self.workloads) == 1283, len(self.workloads)

    def _assign_identities(self):
        fixed = {canon.RUNNER_WORKLOAD: canon.RUNNER_IDENTITY, canon.STORE_WORKLOAD: canon.STORE_IDENTITY}
        used = set(fixed.values()) | {canon.RUNNER_IDENTITY_QUARANTINED}
        for key, w in self.workloads.items():
            if key in fixed:
                ident = fixed[key]
            else:
                h = _h("identity", key)
                ident = 10000 + int(h[:8], 16) % (65536 - 10000)
                bump = 0
                while ident in used:
                    bump += 1
                    ident = 10000 + int(_h("identity", key, bump)[:8], 16) % (65536 - 10000)
            used.add(ident)
            w.identity = ident
            self.identities[ident] = key

    def _place_pods(self):
        by_role = {"bf-node": [n for n in self.nodes if n.startswith("bf-node")],
                   "ai-train-gpu": [n for n in self.nodes if n.startswith("ai-train-gpu")],
                   "ai-train-stor": [n for n in self.nodes if n.startswith("ai-train-stor")],
                   "ai-infer": [n for n in self.nodes if n.startswith("ai-infer")],
                   "gen-node": [n for n in self.nodes if n.startswith("gen-node")]}
        next_ip = {n: 10 for n in self.nodes}
        next_ep = {n: 100 for n in self.nodes}
        rng = _rng("placement")

        def pick(role, key):
            lst = by_role[role]
            return lst[int(_h("node", key)[:6], 16) % len(lst)]

        for key, w in self.workloads.items():
            ns = w.namespace
            if ns == "build-farm":
                role = "bf-node"
            elif ns == "ai-train":
                role = "ai-train-stor" if w.name in ("checkpoint-store", "dataset-cache", "metrics-db", "eval-db", "ckpt-replicator", "run-archiver") else "ai-train-gpu"
            elif ns == "ai-infer":
                role = "ai-infer"
            else:
                role = "gen-node"
            w.pods = []
            rs = _h("rs", key)[:5]
            for i in range(w.replicas):
                p = Pod()
                p.workload = key
                if w.kind == "StatefulSet":
                    p.name = "%s-%d" % (w.name, i)
                else:
                    p.name = "%s-%s-%s" % (w.name, rs, _h("pod", key, i)[:5])
                p.node = pick(role, key + str(i)) if w.replicas > 1 else pick(role, key)
                if key == canon.RUNNER_WORKLOAD and i == 0:
                    p.name, p.node, p.ip, p.endpoint_id, p.container_id = canon.RUNNER_POD, canon.RUNNER_NODE, canon.RUNNER_POD_IP, canon.RUNNER_ENDPOINT_ID, canon.RUNNER_CONTAINER_ID
                elif key == canon.STORE_WORKLOAD and i == 1:
                    p.name, p.node, p.ip, p.endpoint_id, p.container_id = canon.STORE_POD, canon.STORE_NODE, canon.STORE_POD_IP, canon.STORE_ENDPOINT_ID, "containerd://" + _h("ctr", key, i)[:14]
                else:
                    if key == canon.RUNNER_WORKLOAD:
                        p.name = "ci-runner-7d9f8-" + _h("pod", key, i)[:5]
                    node = self.nodes[p.node]
                    ip = None
                    while ip is None or ip in (canon.RUNNER_POD_IP, canon.STORE_POD_IP):
                        ip = "10.42.%d.%d" % (node.pod_cidr, next_ip[p.node])
                        next_ip[p.node] += 1
                    p.ip = ip
                    p.endpoint_id = next_ep[p.node]
                    next_ep[p.node] += rng.randint(1, 3)
                    p.container_id = "containerd://" + _h("ctr", key, i)[:14]
                w.pods.append(p)
                self.pods[p.name] = p
            w.node = canon.STORE_NODE if key == canon.STORE_WORKLOAD else w.pods[0].node
            w.zone = self.nodes[w.node].zone
        assert self.pods[canon.RUNNER_POD].ip == canon.RUNNER_POD_IP
        assert self.pods[canon.STORE_POD].node == canon.STORE_NODE

    # ---- accessors -------------------------------------------------------
    def workload(self, key):
        return self.workloads[key]

    def pod_of(self, key, i=0):
        return self.workloads[key].pods[i]

    def node_of(self, key):
        return self.nodes[self.workloads[key].node]

    def workloads_on_node(self, node):
        return [w for w in self.workloads.values() if any(p.node == node for p in w.pods)]


# --------------------------------------------------------------------------- protected stores, paths, gaps
STORES = OrderedDict([
    ("ai-train/checkpoint-store", {"port": 9000, "allowlist_policy": "checkpoint-store-ingress-allowlist", "owner": "ml-platform",
                                   "data_class": "crown-jewel", "description": "Training checkpoint store (model weights and optimizer state)"}),
    ("ai-train/dataset-cache", {"port": 8443, "allowlist_policy": "dataset-cache-ingress-allowlist", "owner": "ml-platform",
                                "data_class": "restricted", "description": "Curated training dataset cache"}),
    ("ai-infer/model-registry", {"port": 443, "allowlist_policy": "model-registry-ingress-allowlist", "owner": "ml-platform",
                                 "data_class": "restricted", "description": "Model registry (released model artifacts)"}),
    ("ai-infer/vector-index", {"port": 6333, "allowlist_policy": "vector-index-ingress-allowlist", "owner": "ml-serving",
                               "data_class": "confidential", "description": "Vector index for retrieval"}),
])

ENFORCED_CLIENTS = {
    "ai-train/checkpoint-store": ["ai-train/trainer", "ai-train/eval-runner", "ai-train/ckpt-compactor"],
    "ai-train/dataset-cache": ["ai-train/trainer", "ai-train/eval-runner", "ai-train/data-loader", "ai-train/tokenizer-service",
                               "ai-train/shard-manager", "ai-train/run-tracker", "ai-train/sweep-controller", "ai-train/hp-tuner",
                               "ai-train/feature-builder", "ai-train/augmenter", "ai-train/dedup-worker", "ai-train/quality-filter",
                               "ai-train/curriculum-scheduler", "ai-train/dataset-indexer"],
    "ai-infer/model-registry": ["ai-infer/inference-router", "ai-infer/model-loader", "ai-infer/warm-pool-controller", "ai-infer/canary-controller",
                                "ai-infer/ab-router", "ai-infer/eval-replay", "ai-infer/latency-probe", "ai-infer/schema-registry"] +
                               ["ai-infer/serve-%s-%02d" % (m, n) for m, n in [("llm-70b", 1), ("llm-70b", 2), ("llm-7b", 1), ("llm-7b", 2), ("llm-7712", 1), ("llm-7712", 2),
                                                                                ("code-13b", 1), ("code-13b", 2), ("vision-2b", 1), ("vision-2b", 2), ("asr-1b", 1), ("asr-1b", 2),
                                                                                ("embed-l", 1), ("embed-l", 2), ("rerank-s", 1), ("rerank-s", 2), ("guard-3b", 1), ("guard-3b", 2),
                                                                                ("summ-8b", 1), ("summ-8b", 2)]],
    "ai-infer/vector-index": ["ai-infer/rag-gateway", "ai-infer/embed-service", "ai-infer/rerank-service", "ai-infer/citation-service",
                              "ai-infer/web-search-tool", "ai-infer/prompt-cache", "ai-infer/serve-embed-l-01", "ai-infer/serve-embed-l-02",
                              "ai-infer/serve-rerank-s-01", "ai-infer/serve-rerank-s-02", "ai-infer/feedback-collector", "ai-infer/eval-replay"],
}

KNOWN_GAPS = [
    # src_workload, dest_workload, port, audit flows per 24h, program, ticket, owner
    ("data-eng/spark-driver", "ai-train/dataset-cache", 8443, 612, "/opt/java/bin/java", "ZT-231", "data-eng"),
    ("vm-legacy/erp-batch", "ai-infer/model-registry", 443, 488, "/opt/erp/bin/sync", "ZT-236", "erp-ops"),
    ("ai-infer/eval-harness", "ai-train/checkpoint-store", 9000, 391, "/usr/bin/python3.11", "ZT-240", "ml-eval"),
    ("platform/backup-agent", "ai-train/checkpoint-store", 9000, 288, "/usr/bin/restic", "ZT-244", "platform"),
    ("ml-notebooks/jupyter", "ai-train/dataset-cache", 8443, 214, "/opt/conda/bin/python", "ZT-247", "ml-research"),
    ("platform/argocd-repo", "ai-infer/model-registry", 443, 167, "/usr/local/bin/argocd", "ZT-252", "platform"),
    ("observability/log-shipper", "ai-train/dataset-cache", 8443, 91, "/usr/bin/fluent-bit", "ZT-255", "observability"),
    ("data-eng/airflow-worker", "ai-infer/model-registry", 443, 55, "/usr/local/bin/python3.11", "ZT-258", "data-eng"),
]
ENFORCED_TOTAL = 11400

PROTECTED_DATA = [
    # dest_workload, path_prefix, dataset, training_job_id, job_name, scheduler, gpus, owner
    ("ai-train/checkpoint-store", "/ckpt/llm-7712/", "llm-7712 checkpoints", 7712, "llm-7712", "Slurm", 512, "ml-research"),
    ("ai-train/checkpoint-store", "/ckpt/llm-7690/", "llm-7690 checkpoints", 7690, "llm-7690", "Slurm", 256, "ml-research"),
    ("ai-train/checkpoint-store", "/ckpt/code-7701/", "code-7701 checkpoints", 7701, "code-7701", "Slurm", 128, "ml-research"),
    ("ai-train/checkpoint-store", "/ckpt/vision-7688/", "vision-7688 checkpoints", 7688, "vision-7688", "Kubernetes", 64, "ml-research"),
    ("ai-train/dataset-cache", "/datasets/pretrain-v9/", "pretrain-v9 shards", 7712, "llm-7712", "Slurm", 512, "ml-platform"),
    ("ai-train/dataset-cache", "/datasets/sft-mix-v3/", "sft-mix-v3", 7705, "sft-7705", "Slurm", 64, "ml-platform"),
    ("ai-infer/model-registry", "/models/llm-7b/", "llm-7b released weights", 0, "", "", 0, "ml-platform"),
    ("ai-infer/vector-index", "/collections/docs-prod/", "docs-prod embeddings", 0, "", "", 0, "ml-serving"),
]

APPROVERS = [("kernel", "zt_soc_tier2", "SOC tier 2", 1), ("dpu", "zt_soc_tier2,zt_netops", "SOC tier 2, NetOps", 2),
             ("switch", "zt_soc_tier2,zt_netops", "SOC tier 2, NetOps", 2)]
ROLE_LABELS = [("j.chen", "SOC tier 2"), ("m.ruiz", "SOC tier 2"), ("a.patel", "NetOps"), ("k.osei", "platform")]


def _program_for(src, dest):
    ns, name = src.split("/")
    if ns == "ai-train":
        return "/usr/bin/python3.11"
    if name.startswith("serve-"):
        return "/opt/vllm/bin/python3.11"
    return {"inference-router": "/usr/local/bin/envoy", "model-loader": "/usr/local/bin/model-loader", "warm-pool-controller": "/usr/local/bin/warm-pool",
            "canary-controller": "/usr/local/bin/canaryd", "ab-router": "/usr/local/bin/envoy", "eval-replay": "/opt/venv/bin/python3.11",
            "latency-probe": "/usr/local/bin/probe", "schema-registry": "/opt/java/bin/java", "rag-gateway": "/opt/venv/bin/python3.11",
            "embed-service": "/opt/venv/bin/python3.11", "rerank-service": "/opt/venv/bin/python3.11", "citation-service": "/usr/local/bin/node",
            "web-search-tool": "/usr/local/bin/node", "prompt-cache": "/usr/local/bin/redis-server", "feedback-collector": "/opt/venv/bin/python3.11"}.get(name, "/opt/venv/bin/python3.11")


def _largest_remainder(weights, total):
    s = float(sum(weights))
    raw = [w * total / s for w in weights]
    base = [int(x) for x in raw]
    rem = total - sum(base)
    order = sorted(range(len(raw)), key=lambda i: raw[i] - base[i], reverse=True)
    for i in order[:rem]:
        base[i] += 1
    return base


def _build_protected(self):
    """Paths: (src, dest, port) -> dict(count, program, enforced, ticket...). 57 enforced + 8 gaps."""
    self.stores = STORES
    self.paths = OrderedDict()
    rng = _rng("paths")
    store_share = {"ai-infer/model-registry": 6300, "ai-train/dataset-cache": 2700, "ai-infer/vector-index": 1750, "ai-train/checkpoint-store": 650}
    assert sum(store_share.values()) == ENFORCED_TOTAL
    for dest, clients in ENFORCED_CLIENTS.items():
        assert all(c in self.workloads for c in clients), [c for c in clients if c not in self.workloads]
        weights = [rng.uniform(1.0, 3.2) for _ in clients]
        counts = _largest_remainder(weights, store_share[dest])
        assert all(40 <= c <= 600 for c in counts), (dest, counts)
        for src, cnt in zip(clients, counts):
            self.paths[(src, dest, STORES[dest]["port"])] = {"count": cnt, "program": _program_for(src, dest), "enforced": True,
                                                              "policy": STORES[dest]["allowlist_policy"], "ticket": "", "owner": self.workloads[src].owner}
    for src, dest, port, cnt, prog, ticket, owner in KNOWN_GAPS:
        assert src in self.workloads and dest in STORES and STORES[dest]["port"] == port
        self.paths[(src, dest, port)] = {"count": cnt, "program": prog, "enforced": False, "policy": STORES[dest]["allowlist_policy"], "ticket": ticket, "owner": owner}
    self.enforced_paths = [k for k, v in self.paths.items() if v["enforced"]]
    self.gap_paths = [k for k, v in self.paths.items() if not v["enforced"]]
    assert len(self.enforced_paths) == 57 and len(self.gap_paths) == 8
    assert sum(self.paths[k]["count"] for k in self.enforced_paths) == ENFORCED_TOTAL
    assert sum(self.paths[k]["count"] for k in self.gap_paths) == 2306
    assert (canon.RUNNER_WORKLOAD, canon.STORE_WORKLOAD, canon.STORE_PORT) not in self.paths


Estate._build_protected = _build_protected


# --------------------------------------------------------------------------- enforcement history (16 per day)
# (time of day HH:MM:SS, id offset, enforcement point, action, target workload, approved_by, approver_role, comment, platform event)
ENFORCEMENT_SLOTS = [
    ("07:33:14", 0, "kernel", "CNP quarantine: team-044/worker-3391", "team-044/worker", "playbook (policy)", "policy", "Egress to unknown external endpoint from a tenant workload", "cnp"),
    ("09:41:12", 1, "switch", "Hypershield deny: legacy → ai", "vm-legacy/erp-batch", "a.patel + m.ruiz", "NetOps + SOC tier 2", "Legacy VM segment reaching the AI segment", "nexus"),
    ("10:12:40", 3, "kernel", "CNP allowlist update: dataset-cache", "ai-train/dataset-cache", "k.osei", "platform", "Added ai-train/dataset-indexer to the allowlist", "cnp-update"),
    ("10:50:05", 6, "kernel", "CNP quarantine: team-097/api-2210", "team-097/api", "playbook (policy)", "policy", "Port scan across tenant namespaces", "cnp"),
    ("11:20:47", 9, "kernel", "Tetragon enforce: sigkill", "ml-notebooks/nb-rgarcia", "playbook (policy)", "policy", "Crypto miner binary launched in a notebook", "sigkill"),
    ("12:05:33", 11, "dpu", "Hypershield DPU rule: block egress", "data-eng/ftp-poller", "j.chen + a.patel", "SOC tier 2 + NetOps", "Unapproved FTP egress from a data pipeline", "dpu"),
    ("13:47:21", 14, "kernel", "CNP quarantine: data-eng/sftp-gateway-7719", "data-eng/sftp-gateway", "m.ruiz", "SOC tier 2", "Credential stuffing against the SFTP gateway", "cnp"),
    ("14:30:58", 17, "switch", "Nexus ACL update: tenant probe", "team-012/web", "a.patel + m.ruiz", "NetOps + SOC tier 2", "Probe traffic from a tenant toward the scheduler", "nexus"),
    ("15:02:09", 20, "kernel", "CNP allowlist update: model-registry", "ai-infer/model-registry", "k.osei", "platform", "Added ai-infer/eval-replay to the allowlist", "cnp-update"),
    ("16:18:36", 23, "kernel", "Tetragon enforce: sigkill", "team-071/worker", "playbook (policy)", "policy", "Reverse shell from a worker pod", "sigkill"),
    ("17:33:09", 26, "switch", "Nexus shut Eth1/7", "vm-legacy/mainframe-bridge", "a.patel + j.chen", "NetOps + SOC tier 2", "Rogue device behind the legacy bridge port", "nexus"),
    ("18:20:44", 28, "kernel", "CNP quarantine: team-118/cron-4402", "team-118/cron", "playbook (policy)", "policy", "Cron job reaching the Kubernetes API from a tenant", "cnp"),
    ("19:12:50", 29, "dpu", "DPU egress block", "ai-infer/serve-llm-7b-03", "playbook (policy)", "policy", "Inference server contacting an unknown registry", "dpu"),
    ("20:45:17", 31, "kernel", "CNP quarantine: platform/jump-host-1180", "platform/jump-host", "j.chen", "SOC tier 2", "Lateral movement attempt from the jump host", "cnp"),
    ("22:05:36", 32, "kernel", "CNP allowlist update", "ai-train/checkpoint-store", "k.osei", "platform", "Allowlist revision for ckpt-compactor", "cnp-update"),
    ("23:30:02", 34, "switch", "Hypershield deny: tenant probe", "team-003/web", "a.patel + j.chen", "NetOps + SOC tier 2", "Tenant probing the observability segment", "nexus"),
]
ENFORCEMENT_ID_BASE = 1770
ENFORCEMENT_IDS_PER_DAY = 48
ENFORCEMENT_EPOCH_DAY = 20717  # days since 1970-01-01 for 2026-09-21 (UTC)


def _build_enforcement_history(self):
    self.enforcement_slots = []
    for tod, off, point, action, target, by, role, comment, platform in ENFORCEMENT_SLOTS:
        h, m, s = (int(x) for x in tod.split(":"))
        assert target in self.workloads, target
        self.enforcement_slots.append({"tod": h * 3600 + m * 60 + s, "id_offset": off, "point": point, "action": action, "target": target,
                                       "approved_by": by, "approver_role": role, "comment": comment, "platform": platform})
    assert len(self.enforcement_slots) == 16
    assert sum(1 for x in self.enforcement_slots if x["point"] == "kernel") == 10
    assert sum(1 for x in self.enforcement_slots if x["point"] == "dpu") == 2
    assert sum(1 for x in self.enforcement_slots if x["point"] == "switch") == 4
    assert sum(1 for x in self.enforcement_slots if x["platform"] == "sigkill") == 2
    assert sum(1 for x in self.enforcement_slots if x["platform"] == "nexus") == 4


Estate._build_enforcement_history = _build_enforcement_history


def finding_id_for(day_number, slot):
    """ES-style id that increases with time and never repeats: 48 ids per UTC day, offsets per slot."""
    return "ES-%d" % (ENFORCEMENT_ID_BASE + ENFORCEMENT_IDS_PER_DAY * (day_number - ENFORCEMENT_EPOCH_DAY) + slot["id_offset"])


# --------------------------------------------------------------------------- lookup rows
def lookup_rows(estate):
    """Return {lookup name: (header, rows)} for every CSV lookup the app ships."""
    out = {}
    out["zt_workload_inventory"] = (["workload", "namespace", "kind", "owner", "team", "tier", "data_class", "description"],
                                    [[w.key, w.namespace, w.kind, w.owner, w.team, w.tier, w.data_class, w.description] for w in estate.workloads.values()])
    out["zt_protected_stores"] = (["dest_workload", "port", "protected", "data_class", "owner", "allowlist_policy", "mode", "description"],
                                  [[k, v["port"], "true", v["data_class"], v["owner"], v["allowlist_policy"], "audit", v["description"]] for k, v in STORES.items()])
    out["zt_store_allowlist"] = (["dest_workload", "src_workload", "port", "policy"],
                                 [[d, s, p, estate.paths[(s, d, p)]["policy"]] for (s, d, p) in estate.enforced_paths])
    out["zt_process_allowlist"] = (["src_workload", "dest_workload", "process", "approved"],
                                   [[s, d, v["program"], "true"] for (s, d, p), v in estate.paths.items()])
    out["zt_known_gaps"] = (["src_workload", "dest_workload", "dest_port", "ticket", "owner", "status"],
                            [[s, d, p, t, o, "open"] for s, d, p, c, prog, t, o in KNOWN_GAPS])
    out["zt_protected_data"] = (["dest_workload", "path_prefix", "dataset", "training_job_id", "job_name", "scheduler", "gpus", "owner"],
                                [list(r) for r in PROTECTED_DATA])
    out["zt_node_fabric"] = (["node", "node_ip", "fabric", "switch", "interface", "vrf", "last_seen"],
                             [[n.name, n.ip, canon.FABRIC, n.switch, n.interface, n.vrf, ""] for n in estate.nodes.values()])
    out["zt_approvers"] = (["enforcement_point", "approver_roles", "approver_labels", "approvals_required"], [list(r) for r in APPROVERS])
    out["zt_role_labels"] = (["user", "role_label"], [list(r) for r in ROLE_LABELS])
    return out


_ESTATE = None


def get_estate():
    global _ESTATE
    if _ESTATE is None:
        _ESTATE = Estate()
    return _ESTATE
