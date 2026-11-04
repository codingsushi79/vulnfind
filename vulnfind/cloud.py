"""Live infrastructure checks: Kubernetes clusters, AWS and GCP accounts, Terraform plans.

Cluster/cloud checks are strictly read-only and use the CLIs you already have configured
(kubectl, aws, gcloud) - vulnfind never stores or handles credentials itself.
"""

from __future__ import annotations

import base64
import csv
import io
import json
import re
import shutil
import subprocess
import time
from datetime import datetime, timezone
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from .models import Finding, ScanResult, Severity as S

Runner = Callable[[Sequence[str]], Tuple[int, str, str]]
SENSITIVE_PORTS = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL", 6379: "Redis", 27017: "MongoDB",
                   9200: "Elasticsearch", 11211: "Memcached", 2375: "Docker API", 2379: "etcd", 5984: "CouchDB", 9000: "admin"}


def run_cli(cmd: Sequence[str], timeout: int = 120) -> Tuple[int, str, str]:
    try:
        p = subprocess.run(list(cmd), capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return 127, "", f"{cmd[0]}: command not found"
    except subprocess.TimeoutExpired:
        return 124, "", f"{' '.join(cmd[:3])}: timed out"
    return p.returncode, p.stdout, p.stderr


def _json(runner: Runner, cmd: Sequence[str], warnings: List[str], optional: bool = False):
    rc, out, err = runner(cmd)
    if rc != 0:
        if not optional:
            warnings.append(f"`{' '.join(cmd[:4])} …` failed: {(err.strip().splitlines() or ['error'])[-1][:200]}")
        return None
    try:
        return json.loads(out) if out.strip() else None
    except ValueError:
        warnings.append(f"`{' '.join(cmd[:4])} …` returned non-JSON output")
        return None


def F(rule, title, sev, where, desc, fix, cwe=None, snippet=None, **extra) -> Finding:
    return Finding(rule, title, sev, "config", where, snippet=snippet, description=desc, fix=fix, cwe=cwe, extra=extra)


def _require(tool: str, hint: str) -> None:
    if not shutil.which(tool):
        raise ValueError(f"`{tool}` is not installed or not on PATH. {hint}")


# ================================================================ Kubernetes

def _containers(spec: dict) -> Iterable[dict]:
    for key in ("initContainers", "containers", "ephemeralContainers"):
        for c in spec.get(key) or []:
            yield c


def k8s_pod_spec_findings(where: str, spec: dict) -> List[Finding]:
    out: List[Finding] = []
    psc = spec.get("securityContext") or {}
    for flag, label in (("hostNetwork", "host network"), ("hostPID", "host PID namespace"), ("hostIPC", "host IPC namespace")):
        if spec.get(flag):
            out.append(F("K8S-HOST-NAMESPACE", f"Uses the {label}", S.HIGH, where, f"{flag}: true breaks container isolation.",
                         f"Remove {flag}.", "CWE-668"))
    for v in spec.get("volumes") or []:
        hp = (v.get("hostPath") or {}).get("path")
        if hp:
            sev = S.CRITICAL if hp in ("/", "/var/run/docker.sock", "/run/containerd/containerd.sock", "/etc", "/root", "/var/lib/kubelet") else S.MEDIUM
            out.append(F("K8S-HOSTPATH", f"Mounts host path {hp}", sev, where,
                         "hostPath volumes give the pod direct access to the node's filesystem" +
                         (" - this path is equivalent to root on the node." if sev == S.CRITICAL else "."),
                         "Use PersistentVolumes, ConfigMaps or emptyDir instead.", "CWE-668", snippet=f"hostPath: {hp}"))
    if spec.get("automountServiceAccountToken") is not False and spec.get("serviceAccountName", "default") == "default":
        out.append(F("K8S-DEFAULT-SA-TOKEN", "Default service account token is mounted", S.INFO, where,
                     "The pod gets an API token it probably doesn't need.", "Set automountServiceAccountToken: false.", "CWE-250"))
    for c in _containers(spec):
        cname = c.get("name", "?")
        sc = c.get("securityContext") or {}
        cw = f"{where}/{cname}"
        if sc.get("privileged"):
            out.append(F("K8S-PRIVILEGED", f"Container '{cname}' is privileged", S.CRITICAL, cw,
                         "Privileged containers can trivially take over the node.", "Remove privileged: true.", "CWE-250"))
        if sc.get("allowPrivilegeEscalation", True) and not sc.get("privileged"):
            out.append(F("K8S-PRIV-ESCALATION", f"Container '{cname}' allows privilege escalation", S.LOW, cw,
                         "allowPrivilegeEscalation is true (the default), so setuid binaries can gain privileges.",
                         "Set allowPrivilegeEscalation: false.", "CWE-250"))
        run_as_non_root = sc.get("runAsNonRoot", psc.get("runAsNonRoot"))
        uid = sc.get("runAsUser", psc.get("runAsUser"))
        if uid == 0 or (not run_as_non_root and uid is None):
            out.append(F("K8S-RUN-AS-ROOT", f"Container '{cname}' may run as root", S.MEDIUM if uid == 0 else S.LOW, cw,
                         "No runAsNonRoot/runAsUser is enforced, so the image's default user (often root) is used.",
                         "Set runAsNonRoot: true and a non-zero runAsUser.", "CWE-250"))
        caps = ((sc.get("capabilities") or {}).get("add")) or []
        bad = [x for x in caps if x.upper().replace("CAP_", "") in ("SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "ALL", "DAC_READ_SEARCH", "BPF")]
        if bad:
            out.append(F("K8S-DANGEROUS-CAP", f"Container '{cname}' adds {', '.join(bad)}", S.HIGH, cw,
                         "These capabilities enable container escape.", "Drop ALL and add back only what's needed.", "CWE-250"))
        if not (c.get("resources") or {}).get("limits"):
            out.append(F("K8S-NO-LIMITS", f"Container '{cname}' has no resource limits", S.LOW, cw,
                         "A compromised or buggy pod can starve the node (DoS).", "Set resources.limits for CPU and memory.", "CWE-400"))
        image = c.get("image", "")
        if "@sha256:" not in image and (image.endswith(":latest") or ":" not in image.rsplit("/", 1)[-1]):
            out.append(F("K8S-IMAGE-UNPINNED", f"Container '{cname}' uses an unpinned image", S.LOW, cw,
                         "The running code can change without a deploy.", "Pin a tag and digest.", "CWE-1357", snippet=image))
        for env in c.get("env") or []:
            if "value" in env and env["value"] and re.search(r"(?i)pass|secret|token|api_?key|private", env.get("name", "")):
                out.append(F("K8S-SECRET-IN-ENV", f"Plain-text secret in env var {env['name']}", S.HIGH, cw,
                             "The value is stored in the workload spec, readable by anyone who can view it.",
                             "Use a Secret (valueFrom.secretKeyRef) or an external secret store.", "CWE-312",
                             snippet=f"{env['name']}={env['value'][:3]}…"))
    return out


def scan_k8s(context: Optional[str] = None, namespace: Optional[str] = None, runner: Runner = run_cli) -> ScanResult:
    if runner is run_cli:
        _require("kubectl", "Install kubectl and configure a context.")
    started = time.time()
    base = ["kubectl"] + (["--context", context] if context else [])
    ns_args = ["-n", namespace] if namespace else ["--all-namespaces"]
    warnings: List[str] = []
    if context:
        ctx = context
    else:
        rc, out, _ = runner(["kubectl", "config", "current-context"])
        ctx = out.strip()
        if rc != 0 or not ctx:
            raise ValueError("no kubectl context is configured; pass --context or run `kubectl config use-context …`")
    result = ScanResult(root=f"k8s:{ctx}", scanners=["k8s"])
    findings: List[Finding] = []

    workloads = _json(runner, base + ["get", "deployments,statefulsets,daemonsets,cronjobs,jobs,pods", *ns_args, "-o", "json"], warnings)
    if workloads is None:
        # never report "no findings" for a cluster we couldn't read
        raise ValueError(f"could not read workloads from {ctx}: " + (warnings[-1] if warnings else "kubectl failed"))
    seen_owners = set()
    for item in (workloads or {}).get("items", []):
        kind, meta = item.get("kind"), item.get("metadata") or {}
        if kind == "Pod" and meta.get("ownerReferences"):
            continue  # reported via its controller
        if kind == "Job" and meta.get("ownerReferences"):
            continue  # CronJob-owned
        spec = item.get("spec") or {}
        pod = (spec.get("jobTemplate") or {}).get("spec", {}).get("template", {}).get("spec") if kind == "CronJob" \
            else (spec.get("template") or {}).get("spec") if kind != "Pod" else spec
        if not pod:
            continue
        where = f"{meta.get('namespace', 'default')}/{kind.lower()}/{meta.get('name')}"
        if where in seen_owners:
            continue
        seen_owners.add(where)
        result.files_scanned += 1
        findings += k8s_pod_spec_findings(where, pod)

    crbs = _json(runner, base + ["get", "clusterrolebindings", "-o", "json"], warnings)
    for b in (crbs or {}).get("items", []):
        role = (b.get("roleRef") or {}).get("name")
        name = (b.get("metadata") or {}).get("name", "")
        if role not in ("cluster-admin", "admin", "edit") or name.startswith("system:"):
            continue
        for sub in b.get("subjects") or []:
            subject = f"{sub.get('kind')}/{sub.get('namespace', '')}/{sub.get('name')}".replace("//", "/")
            if sub.get("name") in ("system:anonymous", "system:unauthenticated", "system:authenticated"):
                findings.append(F("K8S-ANONYMOUS-ADMIN", f"{role} granted to {sub['name']}", S.CRITICAL, f"clusterrolebinding/{name}",
                                  "Every (or every anonymous) client gets cluster-wide privileges.", "Delete this binding.", "CWE-284"))
            elif sub.get("kind") == "ServiceAccount" and sub.get("namespace") not in ("kube-system",):
                findings.append(F("K8S-SA-CLUSTER-ADMIN", f"Service account has {role}: {subject}", S.HIGH, f"clusterrolebinding/{name}",
                                  "Any pod running as this service account can control the whole cluster.",
                                  "Bind a narrowly-scoped Role instead.", "CWE-269"))

    ings = _json(runner, base + ["get", "ingresses", *ns_args, "-o", "json"], warnings, optional=True)
    for ing in (ings or {}).get("items", []):
        meta = ing.get("metadata") or {}
        if not (ing.get("spec") or {}).get("tls"):
            hosts = [r.get("host") for r in (ing.get("spec") or {}).get("rules") or [] if r.get("host")]
            findings.append(F("K8S-INGRESS-NO-TLS", "Ingress without TLS", S.MEDIUM, f"{meta.get('namespace')}/ingress/{meta.get('name')}",
                              "Traffic to these hosts is served over plain HTTP.", "Add a tls: section (e.g. via cert-manager).",
                              "CWE-319", snippet=", ".join(hosts[:4]) or None))

    nps = _json(runner, base + ["get", "networkpolicies", "--all-namespaces", "-o", "json"], warnings, optional=True)
    namespaces = _json(runner, base + ["get", "namespaces", "-o", "json"], warnings, optional=True)
    covered = {(n.get("metadata") or {}).get("namespace") for n in (nps or {}).get("items", [])}
    for n in (namespaces or {}).get("items", []):
        name = (n.get("metadata") or {}).get("name")
        if name and not name.startswith("kube-") and name not in covered and (not namespace or name == namespace):
            findings.append(F("K8S-NO-NETWORKPOLICY", f"Namespace '{name}' has no NetworkPolicy", S.LOW, f"namespace/{name}",
                              "Every pod can talk to every other pod; one compromise spreads laterally.",
                              "Add a default-deny NetworkPolicy and allow required traffic explicitly.", "CWE-284"))

    result.findings = findings
    result.warnings = warnings
    result.duration = time.time() - started
    return result


# ================================================================ AWS

def scan_aws(profile: Optional[str] = None, region: Optional[str] = None, runner: Runner = run_cli, progress=None) -> ScanResult:
    if runner is run_cli:
        _require("aws", "Install the AWS CLI v2 and run `aws configure` (or `aws sso login`).")
    started = time.time()
    base = ["aws"] + (["--profile", profile] if profile else []) + (["--region", region] if region else []) + ["--output", "json"]
    warnings: List[str] = []
    who = _json(runner, base + ["sts", "get-caller-identity"], warnings)
    if not who:
        raise ValueError("AWS credentials not working: " + (warnings[-1] if warnings else "sts get-caller-identity failed"))
    account = who.get("Account", "?")
    result = ScanResult(root=f"aws:{account}", scanners=["aws"])
    out: List[Finding] = []
    step = (lambda s: progress.detail(s)) if progress else (lambda s: None)

    step("IAM account summary")
    summary = (_json(runner, base + ["iam", "get-account-summary"], warnings) or {}).get("SummaryMap", {})
    if summary.get("AccountMFAEnabled") == 0:
        out.append(F("AWS-ROOT-NO-MFA", "Root account has no MFA", S.CRITICAL, f"aws:{account}:root",
                     "Anyone with the root password controls the whole account.", "Enable a hardware/virtual MFA device for root.", "CWE-308"))
    if summary.get("AccountAccessKeysPresent"):
        out.append(F("AWS-ROOT-ACCESS-KEYS", "Root account has access keys", S.CRITICAL, f"aws:{account}:root",
                     "Long-lived root keys can't be scoped and are a top breach cause.", "Delete root access keys; use IAM roles.", "CWE-798"))

    step("IAM credential report")
    runner(base + ["iam", "generate-credential-report"])
    rep = _json(runner, base + ["iam", "get-credential-report"], warnings, optional=True)
    if rep and rep.get("Content"):
        rows = csv.DictReader(io.StringIO(base64.b64decode(rep["Content"]).decode("utf-8", "replace")))
        now = datetime.now(timezone.utc)
        for r in rows:
            user = r.get("user", "")
            if user == "<root_account>":
                continue
            if r.get("password_enabled") == "true" and r.get("mfa_active") == "false":
                out.append(F("AWS-USER-NO-MFA", f"IAM user '{user}' can log in without MFA", S.HIGH, f"aws:{account}:iam/{user}",
                             "A phished password is enough to access the console.", "Require MFA (IAM policy condition aws:MultiFactorAuthPresent).", "CWE-308"))
            for n in ("1", "2"):
                if r.get(f"access_key_{n}_active") == "true":
                    rotated = r.get(f"access_key_{n}_last_rotated", "")
                    try:
                        age = (now - datetime.strptime(rotated[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)).days
                    except ValueError:
                        continue
                    if age > 90:
                        out.append(F("AWS-OLD-ACCESS-KEY", f"Access key {n} of '{user}' is {age} days old", S.MEDIUM, f"aws:{account}:iam/{user}",
                                     "Long-lived keys accumulate exposure (laptops, CI logs, old repos).", "Rotate keys every 90 days or move to roles/SSO.",
                                     "CWE-324"))

    step("S3 buckets")
    buckets = (_json(runner, base + ["s3api", "list-buckets"], warnings) or {}).get("Buckets", [])
    for b in buckets:
        name = b["Name"]
        status = _json(runner, base + ["s3api", "get-bucket-policy-status", "--bucket", name], warnings, optional=True)
        if (status or {}).get("PolicyStatus", {}).get("IsPublic"):
            out.append(F("AWS-S3-PUBLIC", f"S3 bucket '{name}' is public (bucket policy)", S.CRITICAL, f"s3://{name}",
                         "The bucket policy grants access to everyone on the internet.", "Remove public statements; enable Block Public Access.", "CWE-284"))
        acl = _json(runner, base + ["s3api", "get-bucket-acl", "--bucket", name], warnings, optional=True)
        for g in (acl or {}).get("Grants", []):
            uri = (g.get("Grantee") or {}).get("URI", "")
            if uri.endswith(("/AllUsers", "/AuthenticatedUsers")):
                out.append(F("AWS-S3-PUBLIC-ACL", f"S3 bucket '{name}' ACL grants {g.get('Permission')} to {uri.rsplit('/', 1)[-1]}",
                             S.HIGH, f"s3://{name}", "Anyone (or any AWS user) can access this bucket.", "Remove the grant; disable ACLs (BucketOwnerEnforced).", "CWE-284"))
        pab = _json(runner, base + ["s3api", "get-public-access-block", "--bucket", name], warnings, optional=True)
        cfg = (pab or {}).get("PublicAccessBlockConfiguration") or {}
        if not all(cfg.get(k) for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")):
            out.append(F("AWS-S3-NO-BLOCK-PUBLIC", f"S3 bucket '{name}' doesn't fully block public access", S.LOW, f"s3://{name}",
                         "A future policy/ACL mistake could make it public.", "Enable all four Block Public Access settings.", "CWE-284"))

    step("security groups")
    sgs = (_json(runner, base + ["ec2", "describe-security-groups"], warnings) or {}).get("SecurityGroups", [])
    for sg in sgs:
        for perm in sg.get("IpPermissions", []):
            open_v4 = any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", []))
            open_v6 = any(r.get("CidrIpv6") == "::/0" for r in perm.get("Ipv6Ranges", []))
            if not (open_v4 or open_v6):
                continue
            lo, hi = perm.get("FromPort", 0), perm.get("ToPort", 65535)
            if perm.get("IpProtocol") == "-1":
                lo, hi = 0, 65535
            hits = [f"{p} ({n})" for p, n in SENSITIVE_PORTS.items() if lo <= p <= hi]
            if hits or hi - lo > 1000:
                out.append(F("AWS-SG-OPEN", f"Security group {sg.get('GroupId')} opens {', '.join(hits[:4]) or f'ports {lo}-{hi}'} to the internet",
                             S.HIGH, f"aws:{account}:{sg.get('GroupId')}", "Administrative/database ports reachable from anywhere get brute-forced within minutes.",
                             "Restrict the source to your VPN/office ranges, or use SSM Session Manager instead of SSH.", "CWE-284",
                             snippet=f"{sg.get('GroupName')}: {perm.get('IpProtocol')} {lo}-{hi} from 0.0.0.0/0"))

    step("RDS")
    for db in (_json(runner, base + ["rds", "describe-db-instances"], warnings, optional=True) or {}).get("DBInstances", []):
        dbid = db.get("DBInstanceIdentifier")
        if db.get("PubliclyAccessible"):
            out.append(F("AWS-RDS-PUBLIC", f"RDS instance '{dbid}' is publicly accessible", S.HIGH, f"aws:{account}:rds/{dbid}",
                         "The database has a public endpoint.", "Set PubliclyAccessible=false and use private subnets.", "CWE-284"))
        if not db.get("StorageEncrypted"):
            out.append(F("AWS-RDS-UNENCRYPTED", f"RDS instance '{dbid}' is not encrypted", S.MEDIUM, f"aws:{account}:rds/{dbid}",
                         "Data and snapshots are stored unencrypted.", "Restore from an encrypted snapshot copy.", "CWE-311"))

    step("EC2 metadata options")
    for res in (_json(runner, base + ["ec2", "describe-instances"], warnings, optional=True) or {}).get("Reservations", []):
        for inst in res.get("Instances", []):
            if (inst.get("MetadataOptions") or {}).get("HttpTokens") == "optional" and (inst.get("State") or {}).get("Name") == "running":
                iid = inst.get("InstanceId")
                out.append(F("AWS-IMDSV1", f"Instance {iid} allows IMDSv1", S.MEDIUM, f"aws:{account}:{iid}",
                             "IMDSv1 lets an SSRF bug steal the instance's credentials.", "Require IMDSv2 (HttpTokens=required).", "CWE-918"))

    step("CloudTrail")
    trails = (_json(runner, base + ["cloudtrail", "describe-trails"], warnings, optional=True) or {}).get("trailList")
    if trails is not None and not trails:
        out.append(F("AWS-NO-CLOUDTRAIL", "No CloudTrail trail configured", S.MEDIUM, f"aws:{account}",
                     "API activity isn't recorded, so an intrusion can't be investigated.", "Create a multi-region trail.", "CWE-778"))

    result.findings = out
    result.warnings = warnings
    result.files_scanned = len(buckets) + len(sgs)
    result.duration = time.time() - started
    return result


# ================================================================ GCP

def scan_gcp(project: Optional[str] = None, runner: Runner = run_cli, progress=None) -> ScanResult:
    if runner is run_cli:
        _require("gcloud", "Install the Google Cloud CLI and run `gcloud auth login`.")
    started = time.time()
    warnings: List[str] = []
    if not project:
        project = runner(["gcloud", "config", "get-value", "project"])[1].strip()
    if not project:
        raise ValueError("no GCP project: pass --project or `gcloud config set project …`")
    g = ["gcloud", "--project", project, "--format", "json", "--quiet"]
    result = ScanResult(root=f"gcp:{project}", scanners=["gcp"])
    out: List[Finding] = []
    step = (lambda s: progress.detail(s)) if progress else (lambda s: None)

    step("firewall rules")
    for rule in _json(runner, g + ["compute", "firewall-rules", "list"], warnings) or []:
        if rule.get("direction") != "INGRESS" or rule.get("disabled") or "0.0.0.0/0" not in (rule.get("sourceRanges") or []):
            continue
        ports = []
        for a in rule.get("allowed") or []:
            for p in a.get("ports") or (["0-65535"] if a.get("IPProtocol") in ("all", "tcp") else []):
                lo, _, hi = p.partition("-")
                ports.append((int(lo), int(hi or lo)))
        hits = [f"{p} ({n})" for p, n in SENSITIVE_PORTS.items() if any(lo <= p <= hi for lo, hi in ports)]
        if hits:
            out.append(F("GCP-FIREWALL-OPEN", f"Firewall rule '{rule['name']}' opens {', '.join(hits[:4])} to the internet", S.HIGH,
                         f"gcp:{project}:firewall/{rule['name']}", "Administrative/database ports reachable from anywhere.",
                         "Restrict sourceRanges, or use IAP TCP forwarding for admin access.", "CWE-284"))

    step("project IAM")
    policy = _json(runner, ["gcloud", "projects", "get-iam-policy", project, "--format", "json"], warnings) or {}
    for b in policy.get("bindings", []):
        for m in b.get("members", []):
            if m in ("allUsers", "allAuthenticatedUsers"):
                out.append(F("GCP-IAM-PUBLIC", f"{b['role']} granted to {m} on the project", S.CRITICAL, f"gcp:{project}:iam",
                             "Everyone on the internet holds this role.", "Remove the binding.", "CWE-284"))
            elif b.get("role") in ("roles/owner", "roles/editor") and m.startswith("serviceAccount:"):
                out.append(F("GCP-SA-PRIMITIVE-ROLE", f"Service account has {b['role']}: {m.split(':', 1)[1]}", S.MEDIUM, f"gcp:{project}:iam",
                             "Primitive roles grant broad access; a leaked key compromises the project.", "Use predefined, least-privilege roles.", "CWE-269"))

    step("storage buckets")
    buckets = _json(runner, g + ["storage", "buckets", "list"], warnings, optional=True) or []
    for bkt in buckets:
        name = bkt.get("name") or bkt.get("id", "").split("/")[-1]
        pol = _json(runner, ["gcloud", "storage", "buckets", "get-iam-policy", f"gs://{name}", "--format", "json"], warnings, optional=True) or {}
        for b in pol.get("bindings", []):
            pub = [m for m in b.get("members", []) if m in ("allUsers", "allAuthenticatedUsers")]
            if pub:
                out.append(F("GCP-BUCKET-PUBLIC", f"Bucket gs://{name} grants {b['role']} to {', '.join(pub)}", S.CRITICAL, f"gs://{name}",
                             "Objects are readable (or writable) by anyone.", "Remove the public binding; enable public access prevention.", "CWE-284"))

    step("Cloud SQL")
    for inst in _json(runner, g + ["sql", "instances", "list"], warnings, optional=True) or []:
        ipc = (inst.get("settings") or {}).get("ipConfiguration") or {}
        nets = [n.get("value") for n in ipc.get("authorizedNetworks") or []]
        if "0.0.0.0/0" in nets:
            out.append(F("GCP-SQL-PUBLIC", f"Cloud SQL '{inst.get('name')}' accepts connections from anywhere", S.HIGH,
                         f"gcp:{project}:sql/{inst.get('name')}", "The database is exposed to the internet.",
                         "Remove 0.0.0.0/0; use private IP or the Cloud SQL Auth Proxy.", "CWE-284"))
        if ipc.get("ipv4Enabled") and not ipc.get("requireSsl") and ipc.get("sslMode") not in ("ENCRYPTED_ONLY", "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"):
            out.append(F("GCP-SQL-NO-SSL", f"Cloud SQL '{inst.get('name')}' allows unencrypted connections", S.MEDIUM,
                         f"gcp:{project}:sql/{inst.get('name')}", "Credentials and data can travel in plain text.", "Require SSL.", "CWE-319"))

    result.findings = out
    result.warnings = warnings
    result.files_scanned = len(buckets)
    result.duration = time.time() - started
    return result


# ================================================================ Terraform plan JSON

def tfplan_findings(plan: dict, where: str) -> List[Finding]:
    out: List[Finding] = []
    for rc in plan.get("resource_changes") or []:
        after = (rc.get("change") or {}).get("after") or {}
        if not after or "delete" == (rc.get("change") or {}).get("actions", [""])[0]:
            continue
        typ, addr = rc.get("type", ""), rc.get("address", "")

        def add(rule, title, sev, desc, fix, cwe):
            out.append(Finding(rule, title, sev, "config", where, snippet=addr, description=desc, fix=fix, cwe=cwe,
                               extra={"resource": addr, "source": "terraform plan"}))

        if typ in ("aws_security_group", "aws_security_group_rule", "aws_vpc_security_group_ingress_rule"):
            rules = after.get("ingress") or ([after] if typ != "aws_security_group" else [])
            for r in rules:
                if typ == "aws_security_group_rule" and r.get("type") != "ingress":
                    continue
                cidrs = (r.get("cidr_blocks") or []) + ([r.get("cidr_ipv4")] if r.get("cidr_ipv4") else []) + (r.get("ipv6_cidr_blocks") or [])
                if not ({"0.0.0.0/0", "::/0"} & set(cidrs)):
                    continue
                lo, hi = r.get("from_port", 0) or 0, r.get("to_port", 65535) or 65535
                if str(r.get("protocol") or r.get("ip_protocol")) == "-1":
                    lo, hi = 0, 65535
                hits = [f"{p} ({n})" for p, n in SENSITIVE_PORTS.items() if lo <= p <= hi]
                add("TF-OPEN-INGRESS", f"{addr} opens {', '.join(hits[:3]) or f'{lo}-{hi}'} to the internet", S.HIGH if hits else S.MEDIUM,
                    "Ingress from 0.0.0.0/0 exposes the resource to the whole internet.", "Restrict source CIDRs.", "CWE-284")
        elif typ in ("aws_s3_bucket", "aws_s3_bucket_acl") and after.get("acl") in ("public-read", "public-read-write"):
            add("TF-PUBLIC-BUCKET", f"{addr} is public ({after['acl']})", S.HIGH, "The bucket will be publicly readable.", "Use private ACLs.", "CWE-284")
        elif typ == "aws_s3_bucket_public_access_block" and not all(after.get(k) for k in ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets")):
            add("TF-PUBLIC-BUCKET", f"{addr} disables S3 Block Public Access", S.MEDIUM, "Public ACLs/policies would take effect.", "Set all four flags to true.", "CWE-284")
        elif typ in ("aws_db_instance", "aws_rds_cluster_instance"):
            if after.get("publicly_accessible"):
                add("TF-PUBLIC-DB", f"{addr} is publicly accessible", S.HIGH, "The database gets a public endpoint.", "Set publicly_accessible = false.", "CWE-284")
            if after.get("storage_encrypted") is False:
                add("TF-UNENCRYPTED", f"{addr} storage is not encrypted", S.MEDIUM, "Data at rest is unencrypted.", "storage_encrypted = true.", "CWE-311")
        elif typ == "aws_ebs_volume" and after.get("encrypted") is False:
            add("TF-UNENCRYPTED", f"{addr} is not encrypted", S.MEDIUM, "Data at rest is unencrypted.", "encrypted = true.", "CWE-311")
        elif typ in ("aws_instance", "aws_launch_template"):
            mo = (after.get("metadata_options") or [{}])
            mo = mo[0] if isinstance(mo, list) and mo else mo if isinstance(mo, dict) else {}
            if mo.get("http_tokens") != "required":
                add("TF-IMDSV1", f"{addr} allows IMDSv1", S.MEDIUM, "SSRF can steal instance credentials via IMDSv1.",
                    "metadata_options { http_tokens = \"required\" }", "CWE-918")
        elif typ in ("aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"):
            try:
                doc = json.loads(after.get("policy") or "{}")
            except ValueError:
                doc = {}
            stmts = doc.get("Statement") or []
            stmts = stmts if isinstance(stmts, list) else [stmts]
            for st in stmts:
                acts = st.get("Action") if isinstance(st.get("Action"), list) else [st.get("Action")]
                res = st.get("Resource") if isinstance(st.get("Resource"), list) else [st.get("Resource")]
                if st.get("Effect") == "Allow" and "*" in acts and "*" in res:
                    add("TF-IAM-WILDCARD", f"{addr} allows * on *", S.HIGH, "Full administrative access.", "List specific actions and resources.", "CWE-269")
        elif typ == "aws_kms_key" and after.get("enable_key_rotation") is False:
            add("TF-KMS-NO-ROTATION", f"{addr} has key rotation disabled", S.LOW, "Keys never rotate.", "enable_key_rotation = true.", "CWE-320")
        elif typ == "google_compute_firewall" and "0.0.0.0/0" in (after.get("source_ranges") or []) and after.get("direction", "INGRESS") == "INGRESS":
            ports = [p for a in after.get("allow") or [] for p in a.get("ports") or ["0-65535"]]
            spans = [(int(p.split("-")[0]), int(p.split("-")[-1])) for p in ports if re.match(r"^\d+(-\d+)?$", p)]
            hits = [f"{p} ({n})" for p, n in SENSITIVE_PORTS.items() if any(lo <= p <= hi for lo, hi in spans)]
            if hits:
                add("TF-OPEN-INGRESS", f"{addr} opens {', '.join(hits[:3])} to the internet", S.HIGH, "Admin/database ports exposed.", "Restrict source_ranges.", "CWE-284")
        elif typ.startswith("google_storage_bucket_iam") and (after.get("member") in ("allUsers", "allAuthenticatedUsers")
                                                             or {"allUsers", "allAuthenticatedUsers"} & set(after.get("members") or [])):
            add("TF-PUBLIC-BUCKET", f"{addr} makes a bucket public", S.CRITICAL, "Objects become readable by anyone.", "Remove allUsers/allAuthenticatedUsers.", "CWE-284")
        elif typ == "azurerm_network_security_rule" and after.get("direction") == "Inbound" and after.get("access") == "Allow" \
                and after.get("source_address_prefix") in ("*", "0.0.0.0/0", "Internet"):
            add("TF-OPEN-INGRESS", f"{addr} allows inbound from the internet on {after.get('destination_port_range')}", S.HIGH,
                "The port is exposed to the internet.", "Restrict source_address_prefix.", "CWE-284")
    return out


def is_tfplan(text: str) -> bool:
    return '"resource_changes"' in text[:2_000_000] and '"terraform_version"' in text[:4096]
