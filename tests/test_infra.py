"""Container images (synthetic docker-save tarballs), Kubernetes/AWS/GCP (recorded CLI output), Terraform plans."""

import base64
import io
import json
import os
import tarfile
import tempfile
import unittest
import zipfile

from vulnfind import cloud, image
from vulnfind.engine import ScanOptions, scan

from helpers import TempProject


def _tar(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for path, data in files.items():
            info = tarfile.TarInfo(path)
            info.size = len(data)
            info.mode = 0o755 if path.startswith(("usr/local/bin/", "usr/local/apache2/bin/")) else 0o644
            t.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _jar():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as inner_zip:
        inner_zip.writestr("META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties",
                           "groupId=org.apache.logging.log4j\nartifactId=log4j-core\nversion=2.14.1\n")
    inner = buf.getvalue()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("META-INF/maven/com.example/app/pom.properties", "groupId=com.example\nartifactId=app\nversion=1.0\n")
        z.writestr("BOOT-INF/lib/log4j-core-2.14.1.jar", inner)
    return buf.getvalue()


GO_BIN = (b"\x7fELF" + b"\0" * 300_000 + b"\xff Go buildinf:\x08\x02go1.20.4\n"
          b"path\texample.com/app\nmod\texample.com/app\t(devel)\t\ndep\tgolang.org/x/net\tv0.7.0\th1:x=\n")
HTTPD = b"\x7fELF" + b"\0" * 300_000 + b"Server: Apache/2.4.49 (Unix)\0"


def make_image(path, user="", env=("PATH=/usr/bin", "DB_PASSWORD=hunter2")):
    layer1 = _tar({
        "etc/os-release": b'ID=debian\nVERSION_ID="10"\nPRETTY_NAME="Debian GNU/Linux 10 (buster)"\n',
        "var/lib/dpkg/status": (b"Package: libssl1.1\nStatus: install ok installed\nSource: openssl\nVersion: 1.1.1d-0+deb10u7\n\n"
                                b"Package: zlib1g\nStatus: install ok installed\nSource: zlib (1:1.2.11.dfsg-1)\nVersion: 1:1.2.11.dfsg-1+b1\n\n"
                                b"Package: removed\nStatus: deinstall ok config-files\nVersion: 1.0\n"),
        "app/node_modules/lodash/package.json": json.dumps({"name": "lodash", "version": "4.17.20"}).encode(),
        "app/node_modules/lodash/node_modules/x/README.md": b"x",
        "usr/lib/python3/dist-packages/PyYAML-5.3.dist-info/METADATA": b"Name: PyYAML\n",
        "app/app.jar": _jar(),
        "usr/local/bin/server": GO_BIN,
        "usr/local/apache2/bin/httpd": HTTPD,
        "app/.env": b"STRIPE=sk_live_" + b"51HfakeDEMOkeyA1b2C3d4E5f6G7h8\n",
        "app/secret-old.txt": b"x",
    })
    layer2 = _tar({"app/.wh.secret-old.txt": b"", "app/node_modules/.wh..wh..opq": b""})
    config = json.dumps({"config": {"User": user, "Env": list(env), "ExposedPorts": {"22/tcp": {}}},
                         "created": "2019-01-01T00:00:00Z"}).encode()
    with tarfile.open(path, "w") as t:
        for name, data in (("config.json", config), ("l1/layer.tar", layer1), ("l2/layer.tar", layer2),
                           ("manifest.json", json.dumps([{"Config": "config.json", "RepoTags": ["demo:1"],
                                                          "Layers": ["l1/layer.tar", "l2/layer.tar"]}]).encode())):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))


class ImageTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.path = os.path.join(cls.tmp.name, "img.tar")
        make_image(cls.path)
        cls.fs, cls.config, cls.tags = image.read_image(cls.path)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_layers_and_whiteouts(self):
        self.assertEqual(self.tags, ["demo:1"])
        self.assertNotIn("app/secret-old.txt", self.fs.files)  # removed by a whiteout in layer 2
        self.assertEqual(self.fs.node, {})  # opaque whiteout wiped node_modules
        self.assertIn("app/.env", self.fs.files)

    def test_package_extraction(self):
        dpkg = image.dpkg_packages(self.fs.files[image.DPKG].decode(), "/s", "Debian:10")
        self.assertEqual({(p.name, p.version) for p in dpkg}, {("openssl", "1.1.1d-0+deb10u7"), ("zlib", "1:1.2.11.dfsg-1")})
        self.assertEqual(set(self.fs.python.values()), {("PyYAML", "5.3")})
        self.assertEqual(sorted(self.fs.jars["app/app.jar"]), [("com.example:app", "1.0"), ("org.apache.logging.log4j:log4j-core", "2.14.1")])
        gover, mods = self.fs.gobins["usr/local/bin/server"]
        self.assertEqual((gover, mods), ("go1.20.4", [("golang.org/x/net", "v0.7.0")]))  # (devel) main module has no version
        self.assertEqual(self.fs.binaries["usr/local/apache2/bin/httpd"], ("apache", "2.4.49"))

    def test_os_detection(self):
        rel = image.os_release(self.fs)
        self.assertEqual(image.osv_ecosystem(rel), "Debian:10")
        self.assertTrue(image.os_eol(rel))
        self.assertEqual(image.osv_ecosystem({"ID": "ubuntu", "VERSION_ID": "22.04"}), "Ubuntu:22.04:LTS")
        self.assertEqual(image.osv_ecosystem({"ID": "alpine", "VERSION_ID": "3.19.1"}), "Alpine:v3.19")
        self.assertIsNone(image.os_eol({"ID": "debian", "VERSION_ID": "12"}))
        self.assertIsNone(image.os_eol({"ID": "ubuntu", "VERSION_ID": "24.04"}))

    def test_offline_scan_findings(self):
        r = image.scan_image(self.path, offline=True)
        ids = {f.rule_id for f in r.findings}
        self.assertTrue({"IMAGE-EOL-OS", "IMAGE-ROOT-USER", "IMAGE-SECRET-ENV", "IMAGE-SSH-EXPOSED", "IMAGE-STALE", "SECRET-STRIPE-LIVE"} <= ids, ids)
        names = {(p.ecosystem, p.name) for p in r.packages}
        self.assertTrue({("Debian:10", "openssl"), ("PyPI", "pyyaml"), ("Maven", "org.apache.logging.log4j:log4j-core"),
                         ("Go", "golang.org/x/net"), ("Go", "stdlib")} <= names)
        secret_env = next(f for f in r.findings if f.rule_id == "IMAGE-SECRET-ENV")
        self.assertNotIn("hunter2", secret_env.snippet)

    def test_non_root_image(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "i.tar")
            make_image(p, user="app", env=("PATH=/usr/bin",))
            ids = {f.rule_id for f in image.scan_image(p, offline=True).findings}
        self.assertFalse({"IMAGE-ROOT-USER", "IMAGE-SECRET-ENV"} & ids)


def fake_runner(responses):
    calls = []

    def run(cmd):
        calls.append(list(cmd))
        key = " ".join(cmd)
        for pattern, (rc, out) in responses.items():
            if pattern in key:
                return rc, out if isinstance(out, str) else json.dumps(out), ""
        return 1, "", "not recorded"
    run.calls = calls
    return run


POD_SPEC = {"hostNetwork": True, "volumes": [{"name": "d", "hostPath": {"path": "/var/run/docker.sock"}}],
            "containers": [{"name": "web", "image": "nginx:latest", "securityContext": {"privileged": True},
                            "env": [{"name": "DB_PASSWORD", "value": "hunter2"}, {"name": "LOG", "value": "info"}]}]}


class K8sTest(unittest.TestCase):
    def test_cluster_audit(self):
        run = fake_runner({
            "config current-context": (0, "prod\n"),
            "get deployments": (0, {"items": [
                {"kind": "Deployment", "metadata": {"name": "web", "namespace": "shop"}, "spec": {"template": {"spec": POD_SPEC}}},
                {"kind": "Pod", "metadata": {"name": "web-abc", "namespace": "shop", "ownerReferences": [{"kind": "ReplicaSet"}]}, "spec": POD_SPEC},
                {"kind": "Deployment", "metadata": {"name": "ok", "namespace": "shop"}, "spec": {"template": {"spec": {
                    "automountServiceAccountToken": False, "securityContext": {"runAsNonRoot": True},
                    "containers": [{"name": "c", "image": "app@sha256:abc", "resources": {"limits": {"cpu": "1"}},
                                    "securityContext": {"allowPrivilegeEscalation": False}}]}}}},
            ]}),
            "get clusterrolebindings": (0, {"items": [
                {"metadata": {"name": "ci-admin"}, "roleRef": {"name": "cluster-admin"},
                 "subjects": [{"kind": "ServiceAccount", "namespace": "ci", "name": "deployer"}]},
                {"metadata": {"name": "oops"}, "roleRef": {"name": "cluster-admin"}, "subjects": [{"kind": "Group", "name": "system:unauthenticated"}]},
                {"metadata": {"name": "system:kube"}, "roleRef": {"name": "cluster-admin"}, "subjects": [{"kind": "User", "name": "x"}]},
            ]}),
            "get ingresses": (0, {"items": [{"metadata": {"name": "i", "namespace": "shop"}, "spec": {"rules": [{"host": "shop.example.com"}]}}]}),
            "get networkpolicies": (0, {"items": []}),
            "get namespaces": (0, {"items": [{"metadata": {"name": "shop"}}, {"metadata": {"name": "kube-system"}}]}),
        })
        r = cloud.scan_k8s(runner=run)
        got = {(f.rule_id, f.file) for f in r.findings}
        for rule in ("K8S-PRIVILEGED", "K8S-HOST-NAMESPACE", "K8S-HOSTPATH", "K8S-SECRET-IN-ENV", "K8S-IMAGE-UNPINNED",
                     "K8S-SA-CLUSTER-ADMIN", "K8S-ANONYMOUS-ADMIN", "K8S-INGRESS-NO-TLS", "K8S-NO-NETWORKPOLICY"):
            self.assertIn(rule, {g[0] for g in got}, rule)
        self.assertFalse([g for g in got if "web-abc" in g[1]])  # controller-owned pod not double-reported
        self.assertFalse([g for g in got if "/ok" in g[1]])  # hardened deployment is clean
        self.assertEqual(r.root, "k8s:prod")

    def test_unreachable_cluster_is_an_error(self):
        with self.assertRaises(ValueError):
            cloud.scan_k8s(runner=fake_runner({"config current-context": (0, "prod")}))
        with self.assertRaises(ValueError):
            cloud.scan_k8s(runner=fake_runner({"config current-context": (1, "")}))


CRED_REPORT = base64.b64encode(
    b"user,arn,password_enabled,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_2_active,access_key_2_last_rotated\n"
    b"<root_account>,a,not_supported,false,false,N/A,false,N/A\n"
    b"alice,a,true,false,true,2020-01-01T00:00:00+00:00,false,N/A\n"
    b"bob,a,true,true,false,N/A,false,N/A\n").decode()


class AwsGcpTest(unittest.TestCase):
    def test_aws(self):
        run = fake_runner({
            "sts get-caller-identity": (0, {"Account": "123456789012"}),
            "iam get-account-summary": (0, {"SummaryMap": {"AccountMFAEnabled": 0, "AccountAccessKeysPresent": 1}}),
            "iam generate-credential-report": (0, {}),
            "iam get-credential-report": (0, {"Content": CRED_REPORT}),
            "s3api list-buckets": (0, {"Buckets": [{"Name": "public-data"}, {"Name": "private"}]}),
            "get-bucket-policy-status --bucket public-data": (0, {"PolicyStatus": {"IsPublic": True}}),
            "get-public-access-block --bucket private": (0, {"PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}}),
            "ec2 describe-security-groups": (0, {"SecurityGroups": [{"GroupId": "sg-1", "GroupName": "web", "IpPermissions": [
                {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}]}),
            "rds describe-db-instances": (0, {"DBInstances": [{"DBInstanceIdentifier": "db1", "PubliclyAccessible": True, "StorageEncrypted": True}]}),
            "ec2 describe-instances": (0, {"Reservations": [{"Instances": [{"InstanceId": "i-1", "State": {"Name": "running"},
                                                                             "MetadataOptions": {"HttpTokens": "optional"}}]}]}),
            "cloudtrail describe-trails": (0, {"trailList": []}),
        })
        ids = [f.rule_id for f in cloud.scan_aws(runner=run).findings]
        for rule in ("AWS-ROOT-NO-MFA", "AWS-ROOT-ACCESS-KEYS", "AWS-USER-NO-MFA", "AWS-OLD-ACCESS-KEY", "AWS-S3-PUBLIC",
                     "AWS-SG-OPEN", "AWS-RDS-PUBLIC", "AWS-IMDSV1", "AWS-NO-CLOUDTRAIL"):
            self.assertIn(rule, ids)
        self.assertEqual(ids.count("AWS-SG-OPEN"), 1)  # 443 open to the world is normal
        self.assertNotIn("bob", " ".join(f.title for f in cloud.scan_aws(runner=run).findings))
        self.assertTrue(all("--output" in c for c in run.calls if c[0] == "aws"))
        self.assertFalse([c for c in run.calls if any(w in " ".join(c) for w in (" put-", " delete-", " create-", " modify-", " update-"))])

    def test_aws_bad_credentials(self):
        with self.assertRaises(ValueError):
            cloud.scan_aws(runner=fake_runner({}))

    def test_gcp(self):
        run = fake_runner({
            "compute firewall-rules list": (0, [{"name": "allow-ssh", "direction": "INGRESS", "sourceRanges": ["0.0.0.0/0"],
                                                 "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}]},
                                                {"name": "web", "direction": "INGRESS", "sourceRanges": ["0.0.0.0/0"],
                                                 "allowed": [{"IPProtocol": "tcp", "ports": ["443"]}]}]),
            "projects get-iam-policy": (0, {"bindings": [{"role": "roles/viewer", "members": ["allUsers"]},
                                                         {"role": "roles/owner", "members": ["serviceAccount:ci@p.iam.gserviceaccount.com"]}]}),
            "storage buckets list": (0, [{"name": "assets"}]),
            "buckets get-iam-policy gs://assets": (0, {"bindings": [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}]}),
            "sql instances list": (0, [{"name": "db", "settings": {"ipConfiguration": {"ipv4Enabled": True,
                                                                                        "authorizedNetworks": [{"value": "0.0.0.0/0"}]}}}]),
        })
        ids = sorted(f.rule_id for f in cloud.scan_gcp("p", runner=run).findings)
        self.assertEqual(ids, ["GCP-BUCKET-PUBLIC", "GCP-FIREWALL-OPEN", "GCP-IAM-PUBLIC", "GCP-SA-PRIMITIVE-ROLE", "GCP-SQL-NO-SSL", "GCP-SQL-PUBLIC"])


PLAN = {"format_version": "1.2", "terraform_version": "1.9.0", "resource_changes": [
    {"address": "aws_security_group.ssh", "type": "aws_security_group", "change": {"actions": ["create"], "after": {
        "ingress": [{"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}]}}},
    {"address": "aws_s3_bucket.logs", "type": "aws_s3_bucket", "change": {"actions": ["create"], "after": {"acl": "public-read"}}},
    {"address": "aws_db_instance.main", "type": "aws_db_instance", "change": {"actions": ["update"], "after": {"publicly_accessible": True}}},
    {"address": "aws_iam_policy.admin", "type": "aws_iam_policy", "change": {"actions": ["create"], "after": {
        "policy": json.dumps({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})}}},
    {"address": "aws_instance.app", "type": "aws_instance", "change": {"actions": ["create"], "after": {"metadata_options": [{"http_tokens": "required"}]}}},
    {"address": "aws_s3_bucket.old", "type": "aws_s3_bucket", "change": {"actions": ["delete"], "after": None}},
]}


class TfPlanTest(unittest.TestCase):
    def test_plan_findings(self):
        got = sorted((f.rule_id, f.extra["resource"]) for f in cloud.tfplan_findings(PLAN, "plan.json"))
        self.assertEqual(got, [("TF-IAM-WILDCARD", "aws_iam_policy.admin"), ("TF-OPEN-INGRESS", "aws_security_group.ssh"),
                               ("TF-PUBLIC-BUCKET", "aws_s3_bucket.logs"), ("TF-PUBLIC-DB", "aws_db_instance.main")])

    def test_auto_detected_in_folder_scan(self):
        with TempProject({"infra/plan.json": json.dumps(PLAN)}) as root:
            ids = {f.rule_id for f in scan(root, ScanOptions(offline=True, scanners=["config"])).findings}
        self.assertIn("TF-IAM-WILDCARD", ids)


if __name__ == "__main__":
    unittest.main()
