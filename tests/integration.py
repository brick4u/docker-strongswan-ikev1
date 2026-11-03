#!/usr/bin/env python3
"""Opt-in, isolated Docker integration test. Python 3 standard library only.

Run: python3 tests/integration.py --execute --image strongswan-ikev1:test
No images are built/pulled and no host network configuration is changed.
"""
import argparse
import json
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time

LABEL = "org.strongswan-ikev1.integration"


class Harness:
    def __init__(self, image, evidence):
        self.image = image
        self.token = secrets.token_hex(8)
        self.psk = secrets.token_hex(32)
        self.network = "sswan-test-" + self.token
        self.containers = []
        self.network_created = False
        self.root = Path(tempfile.mkdtemp(prefix="sswan-integration-" )).resolve()
        self.evidence = evidence
        self.events = []

    def sanitize(self, text):
        return text.replace(self.psk, "[REDACTED]")

    def run(self, *args, check=True, timeout=60):
        p = subprocess.run(args, text=True, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=timeout)
        output = self.sanitize(p.stdout)
        self.events.append({"command": list(args), "returncode": p.returncode,
                            "output": output})
        if check and p.returncode:
            raise RuntimeError(f"Command failed ({p.returncode}): {' '.join(args)}\n{output}")
        return output

    def docker(self, *args, **kwargs):
        return self.run("docker", *args, **kwargs)

    def exec(self, name, *args, **kwargs):
        return self.docker("exec", name, *args, **kwargs)

    def swan(self, name, *args):
        return self.exec(name, "/usr/sbin/swanctl", *args)

    def wait(self, description, predicate, seconds=40):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            time.sleep(0.5)
        raise RuntimeError("Timed out: " + description)

    def setup(self):
        self.docker("image", "inspect", self.image)
        self.docker("network", "create", "--internal", "--driver", "bridge",
                    "--label", f"{LABEL}={self.token}", self.network)
        self.network_created = True

    def config(self, version, side, local, remote):
        other = "b" if side == "a" else "a"
        inner = {"a": "198.18.10.1", "b": "198.18.20.1"}
        return f"""connections {{
  tunnel {{
    version = {version}
    local_addrs = {local}
    remote_addrs = {remote}
    proposals = aes256-sha256-ecp384
    encap = yes
    rekey_time = 0
    reauth_time = 0
    local {{ auth = psk
      id = {side}.example
    }}
    remote {{ auth = psk
      id = {other}.example
    }}
    children {{
      protected {{
        local_ts = {inner[side]}/32
        remote_ts = {inner[other]}/32
        esp_proposals = aes256-sha256-ecp384
        start_action = none
        rekey_time = 0
        life_time = 3600
      }}
    }}
  }}
}}
secrets {{
  ike-test {{
    id-a = a.example
    id-b = b.example
    secret = {self.psk}
  }}
}}
"""

    def sas(self, name):
        return self.swan(name, "--list-sas", "--raw")

    @staticmethod
    def spis(text):
        return set(re.findall(r"spi-in=([0-9a-fA-F]+)", text))

    @staticmethod
    def counters(text):
        return tuple(sum(int(x) for x in re.findall(rf"\b{key}=(\d+)", text))
                     for key in ("bytes-in", "bytes-out", "packets-in", "packets-out"))

    def traffic(self, a, b):
        before = [self.counters(self.sas(n)) for n in (a, b)]
        for _ in range(2):
            self.exec(a, "ping", "-n", "-I", "198.18.10.1", "-c", "4", "-W", "2", "198.18.20.1")
            self.exec(b, "ping", "-n", "-I", "198.18.20.1", "-c", "4", "-W", "2", "198.18.10.1")
        after = [self.counters(self.sas(n)) for n in (a, b)]
        for old, new in zip(before, after):
            if not all(y > x for x, y in zip(old, new)):
                raise RuntimeError(f"Encrypted byte/packet counters did not increase: {old} -> {new}")

    def phase(self, version):
        names = [f"{self.network}-v{version}-{s}" for s in ("a", "b")]
        dirs = []
        for side, name in zip(("a", "b"), names):
            directory = self.root / f"v{version}-{side}"
            # Host parent stays 0700; mounted child must be traversable by
            # container UID 0 without CAP_DAC_OVERRIDE (host owner may differ).
            directory.mkdir(mode=0o755)
            dirs.append(directory)
            (directory / "strongswan.conf").write_text("""charon {
  # Retire superseded IKEv1 CHILD_SAs promptly for stable counter snapshots.
  delete_rekeyed = yes
  load_modular = yes
  plugins {
    include /etc/strongswan.d/charon/*.conf
  }
  filelog {
    stdout {
      default = 1
      flush_line = yes
      ike_name = yes
    }
  }
}
""")
            # Only the launcher is test-specific; charon remains foreground PID 1.
            self.docker("create", "--name", name, "--label", f"{LABEL}={self.token}",
                        "--network", self.network, "--cap-drop", "ALL",
                        "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW",
                        "--cap-add", "NET_BIND_SERVICE", "--mount",
                        f"type=bind,src={directory},dst=/test,readonly",
                        "--env", "STRONGSWAN_CONF=/test/strongswan.conf",
                        "--entrypoint", "/bin/sh", self.image, "-ec",
                        "while [ ! -f /test/ready ]; do sleep 0.1; done; exec /usr/libexec/ipsec/charon")
            self.containers.append(name)
            self.docker("start", name)
        addresses = []
        for name in names:
            info = json.loads(self.docker("inspect", name))[0]
            addresses.append(info["NetworkSettings"]["Networks"][self.network]["IPAddress"])
        for i, (name, directory) in enumerate(zip(names, dirs)):
            conf = directory / "swanctl.conf"
            conf.write_text(self.config(version, ("a", "b")[i], addresses[i], addresses[1-i]))
            conf.chmod(0o444)
            self.exec(name, "ip", "addr", "add", f"198.18.{10 if i == 0 else 20}.1/32", "dev", "lo")
            # Internal bridges have no default route. Supply a container-only
            # route so host-prefix traffic reaches the outbound XFRM policy.
            self.exec(name, "ip", "route", "add", f"198.18.{20 if i == 0 else 10}.1/32",
                      "via", addresses[1-i], "dev", "eth0")
            (directory / "ready").touch(mode=0o600)
            self.wait("VICI socket " + name, lambda n=name: "yes" in self.exec(
                n, "/bin/sh", "-c", "test -S /var/run/charon.vici && echo yes", check=False))
            self.swan(name, "--load-all", "--file", "/test/swanctl.conf")
        a, b = names
        self.swan(a, "--initiate", "--child", "protected", "--timeout", "30")
        for name in names:
            raw = self.sas(name)
            for pattern in (rf"version={version}\b", r"state=ESTABLISHED", r"state=INSTALLED",
                            r"encr-alg=AES_CBC", r"encr-keysize=256", r"integ-alg=HMAC_SHA2_256_128",
                            r"dh-group=ECP_384", r"encap=yes", r"local-port=4500", r"remote-port=4500"):
                if not re.search(pattern, raw):
                    raise RuntimeError(f"Missing negotiated property {pattern}: {raw}")
            state = self.exec(name, "ip", "xfrm", "state", "list", "nokeys")
            if "proto esp" not in state or "encap type espinudp" not in state:
                raise RuntimeError("Missing kernel ESP-in-UDP state")
        self.traffic(a, b)
        old = self.spis(self.sas(a))
        old_b = self.spis(self.sas(b))
        self.swan(a, "--rekey", "--child", "protected")
        self.wait("new CHILD_SA SPI", lambda: self.spis(self.sas(a)) - old)
        self.wait("retired CHILD_SA removed on A", lambda: not (self.spis(self.sas(a)) & old))
        self.wait("retired CHILD_SA removed on B", lambda: not (self.spis(self.sas(b)) & old_b))
        self.traffic(a, b)
        # IKEv1 replaces its IKE SA through reauthentication, not IKEv2 IKE rekey.
        old_raw = self.sas(a)
        old_ike = set(re.findall(r"initiator-spi=([0-9a-fA-F]+)", old_raw))
        if not old_ike:
            raise RuntimeError("Could not extract IKE SPI for lifecycle assertion")
        self.swan(a, "--rekey", "--ike", "tunnel", "--reauth")
        self.wait("reauthenticated IKE SA", lambda: (
            set(re.findall(r"initiator-spi=([0-9a-fA-F]+)", self.sas(a))) - old_ike))
        for name in names:
            self.wait("retired IKE SA removed " + name, lambda n=name: not (
                set(re.findall(r"initiator-spi=([0-9a-fA-F]+)", self.sas(n))) & old_ike))
            self.wait("CHILD after reauthentication " + name,
                      lambda n=name: "state=INSTALLED" in self.sas(n))
        self.traffic(a, b)
        print(f"PASS IKEv{version}: PSK, algorithms, bidirectional ESP, CHILD rekey, IKE reauthentication", flush=True)

    def startup_smoke(self):
        """Exercise image CMD and default start-scripts on a read-only rootfs."""
        directory = self.root / "startup"
        directory.mkdir(mode=0o755)
        conf = directory / "swanctl.conf"
        conf.write_text(self.config(1, "a", "%any", "192.0.2.2"))
        conf.chmod(0o444)
        name = self.network + "-startup"
        self.docker("create", "--name", name, "--label", f"{LABEL}={self.token}",
                    "--network", "none", "--read-only", "--tmpfs", "/run",
                    "--cap-drop", "ALL", "--cap-add", "NET_ADMIN",
                    "--cap-add", "NET_RAW", "--cap-add", "NET_BIND_SERVICE",
                    "--mount", f"type=bind,src={conf},dst=/etc/swanctl/swanctl.conf,readonly",
                    self.image)
        self.containers.append(name)
        self.docker("start", name)
        self.wait("default startup autoload", lambda: "tunnel" in self.exec(
            name, "/usr/sbin/swanctl", "--list-conns", "--raw", check=False))
        print("PASS default image CMD: read-only rootfs, /run tmpfs, automatic swanctl load", flush=True)

    def cleanup(self):
        failures = []
        for name in reversed(self.containers):
            try:
                self.docker("logs", name, check=False)
                info = json.loads(self.docker("inspect", name))[0]
                if info["Config"]["Labels"].get(LABEL) != self.token:
                    raise RuntimeError("Ownership label mismatch: " + name)
                self.docker("stop", "--time", "5", name, check=False)
                self.docker("rm", "--force", name)
            except Exception as exc:
                failures.append(str(exc))
        if self.network_created:
            try:
                info = json.loads(self.docker("network", "inspect", self.network))[0]
                if info["Labels"].get(LABEL) != self.token:
                    raise RuntimeError("Network ownership mismatch")
                self.docker("network", "rm", self.network)
            except Exception as exc:
                failures.append(str(exc))
        if self.evidence:
            evidence = self.evidence.resolve()
            evidence.mkdir(mode=0o700, parents=True, exist_ok=True)
            evidence.chmod(0o700)
            dest = evidence / f"integration-{self.token}.json"
            dest.write_text(self.sanitize(json.dumps(self.events, indent=2)))
            dest.chmod(0o600)
            print("Sanitized evidence:", dest)
        # Only remove the exact private directory created by this process.
        if self.root.parent == Path(tempfile.gettempdir()).resolve() and self.root.name.startswith("sswan-integration-") and not self.root.is_symlink():
            shutil.rmtree(self.root)
        else:
            failures.append("Refusing unexpected temporary directory cleanup")
        if failures:
            raise RuntimeError("Cleanup errors: " + "; ".join(failures))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true", help="Required opt-in to create Docker resources")
    parser.add_argument("--image", default="strongswan-ikev1:test", help="Existing local test image (never pulled)")
    parser.add_argument("--versions", nargs="+", type=int, choices=(1, 2), default=[1, 2])
    parser.add_argument("--evidence-dir", type=Path, help="Private directory for sanitized command output (no config secrets)")
    args = parser.parse_args()
    if not args.execute:
        parser.error("--execute is required; no Docker resources were created")
    harness = Harness(args.image, args.evidence_dir)
    try:
        harness.setup()
        harness.startup_smoke()
        for version in args.versions:
            harness.phase(version)
    finally:
        harness.cleanup()


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, subprocess.SubprocessError, OSError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
