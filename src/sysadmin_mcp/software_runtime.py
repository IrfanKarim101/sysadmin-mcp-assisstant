"""Standard-library-only installer copied verbatim into a reviewed remote job.

Fresh Rocky 9 native RPM installations only. No shell, repository creation,
configuration replacement, firewall changes, or automatic retry/rollback.
"""
import http.client
import json
import os
import platform
import shutil
import subprocess
import time
from pathlib import Path


def command(argv, *, check=True, timeout=20):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False,
                            env={**os.environ, "LC_ALL": "C", "SYSTEMD_PAGER": "cat"})
    if check and result.returncode:
        raise RuntimeError(f"Command failed ({result.returncode}): {argv!r}\n"
                           + result.stdout[-6000:] + result.stderr[-6000:])
    return result


def package_version(product):
    result = command(["/usr/bin/rpm", "-q", "--qf", "%{VERSION}", product], check=False)
    if result.returncode not in (0, 1):
        raise RuntimeError("Could not inspect RPM state")
    return result.stdout.strip() if result.returncode == 0 else None


def preflight(product):
    release = platform.freedesktop_os_release()
    if release.get("ID") != "rocky" or release.get("VERSION_ID", "").split(".")[0] != "9":
        raise RuntimeError("This installer requires Rocky Linux 9")
    if platform.machine() not in {"x86_64", "aarch64"}:
        raise RuntimeError("Unsupported architecture")
    for binary in ("/usr/bin/rpm", "/usr/bin/dnf", "/usr/bin/systemctl", "/usr/bin/sudo"):
        if not os.access(binary, os.X_OK):
            raise RuntimeError("Missing prerequisite: " + binary)
    if not Path("/run/systemd/system").is_dir():
        raise RuntimeError("A running systemd host is required")
    if package_version(product) is not None:
        raise RuntimeError("Already installed; fresh installation will not change an existing service")
    paths = [f"/etc/{product}", f"/var/lib/{product}", f"/var/log/{product}",
             f"/usr/share/{product}", f"/opt/{product}"]
    paths += [f"{root}/{product}.service" for root in
              ("/etc/systemd/system", "/run/systemd/system", "/usr/lib/systemd/system")]
    paths += [f"/etc/systemd/system/{product}.service.d", f"/run/systemd/system/{product}.service.d"]
    if product == "tomcat":
        paths += ["/etc/sysconfig/tomcat"]
        paths += [str(path) for path in Path("/opt").glob("*tomcat*")]
    for name in paths:
        path = Path(name)
        if path.exists() or path.is_symlink():
            raise RuntimeError("Existing application path must be reviewed separately: " + name)
    state = command(["/usr/bin/systemctl", "show", product + ".service",
                     "--property=LoadState", "--value"], check=False)
    if state.stdout.strip() != "not-found":
        raise RuntimeError("Existing or uninspectable systemd unit")
    for root in ("/", "/var", "/usr"):
        if shutil.disk_usage(root).free < 1024 ** 3:
            raise RuntimeError("At least 1 GiB free space is required on " + root)
    port = 80 if product == "nginx" else 8080
    # Inspect both address families without binding a privileged port.
    listeners = command(["/usr/sbin/ss", "-H", "-ltn", "sport = :" + str(port)])
    if listeners.stdout.strip():
        raise RuntimeError("Service port is already in use: " + str(port))


def install(product, version):
    preflight(product)
    # Only the VM administrator's existing Rocky repositories and trust keys.
    # Dependencies may be installed or updated as part of this approved operation.
    transaction = ["/usr/bin/dnf", "-y", "--disablerepo=*", "--enablerepo=baseos,appstream",
                   "--setopt=gpgcheck=1", "--setopt=*.gpgcheck=1",
                   "--setopt=sslverify=1", "--setopt=*.sslverify=1",
                   "--setopt=install_weak_deps=False", "install", product + "-" + version]
    activation = ["/usr/bin/systemctl", "enable", "--now", product + ".service"]
    syntax = ["/usr/sbin/nginx", "-t"] if product == "nginx" else None
    # nginx does not exist yet on a fresh machine, so sudo cannot resolve it
    # for a pre-install permission probe. Its syntax check still fails closed.
    for argv in [transaction, activation]:
        command(["/usr/bin/sudo", "-n", "-l", "--", *argv])
    print("Installing exact upstream version from baseos/appstream; dependency changes are included.", flush=True)
    result = command(["/usr/bin/sudo", "-n", "--", *transaction], timeout=720)
    print(result.stdout[-12000:], flush=True)
    if package_version(product) != version:
        raise RuntimeError("Installed version does not match the reviewed version; stopping before activation")
    if syntax:
        command(["/usr/bin/sudo", "-n", "--", *syntax])
    command(["/usr/bin/sudo", "-n", "--", *activation], timeout=60)
    print("Installation and activation finished; independent verification follows.", flush=True)


def http_ready(product):
    connection = http.client.HTTPConnection("127.0.0.1", 80 if product == "nginx" else 8080, timeout=2)
    try:
        connection.request("GET", "/")
        response = connection.getresponse()
        # A bare Tomcat has no ROOT application: 404 is expected and is not
        # evidence of a deployed application's health. No sample/manager apps added.
        return response.status in ({200} if product == "nginx" else {200, 404})
    except (OSError, http.client.HTTPException):
        return False
    finally:
        connection.close()


def verify(product, version):
    checks = []
    def add(name, passed):
        checks.append({"name": name, "passed": bool(passed)})
    add("Installed RPM upstream version equals " + version, package_version(product) == version)
    unit = product + ".service"
    add("Service is enabled at boot", command(["/usr/bin/systemctl", "is-enabled", unit], check=False).stdout.strip() == "enabled")
    if product == "nginx":
        add("Nginx configuration passes nginx -t", command(
            ["/usr/bin/sudo", "-n", "--", "/usr/sbin/nginx", "-t"], check=False).returncode == 0)
    deadline = time.monotonic() + 35
    ready = False
    while time.monotonic() < deadline:
        if http_ready(product):
            ready = True
            break
        time.sleep(1)
    add("Local HTTP responds" + (" (200 or bare-server 404; no application deployed)" if product == "tomcat" else " with 200"), ready)
    add("Service remains active", command(["/usr/bin/systemctl", "is-active", unit], check=False).stdout.strip() == "active")
    pid = command(["/usr/bin/systemctl", "show", unit, "--property=MainPID", "--value"]).stdout.strip()
    add("Service has a running main process", pid.isdecimal() and int(pid) > 0 and Path("/proc", pid).is_dir())
    print(json.dumps({"checks": checks}))
