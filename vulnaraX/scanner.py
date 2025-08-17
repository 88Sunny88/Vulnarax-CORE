import json
import os
import shutil
import subprocess
import tempfile

from .osv_client import query_osv


def _export_image_fs(image_name: str) -> str:
    """Create a container, export filesystem, return temp dir path"""
    temp_dir = tempfile.mkdtemp(prefix="vulnarax_")
    container_id = subprocess.check_output(
        ["docker", "create", image_name], text=True
    ).strip()
    export = subprocess.Popen(
        ["docker", "export", container_id],
        stdout=subprocess.PIPE
    )
    subprocess.check_call(["tar", "-C", temp_dir, "-xvf", "-"], stdin=export.stdout)
    subprocess.check_call(["docker", "rm", container_id], stdout=subprocess.DEVNULL)
    return temp_dir


def _detect_distro(rootfs: str):
    os_release = os.path.join(rootfs, "etc", "os-release")
    if os.path.exists(os_release):
        content = open(os_release).read().lower()
        if "alpine" in content:
            return "alpine"
        elif "debian" in content or "ubuntu" in content:
            return "debian"
    return None


def _parse_alpine_packages(rootfs: str):
    installed = os.path.join(rootfs, "lib", "apk", "db", "installed")
    packages = []
    current = {}
    for line in open(installed):
        line = line.strip()
        if line.startswith("P:"):
            current["package"] = line[2:]
        elif line.startswith("V:"):
            current["version"] = line[2:]
        elif line == "":
            if current:
                packages.append(current)
                current = {}
    if current:
        packages.append(current)
    return packages


def _parse_debian_packages(rootfs: str):
    status = os.path.join(rootfs, "var", "lib", "dpkg", "status")
    packages = []
    current = {}
    for line in open(status):
        line = line.strip()
        if line.startswith("Package:"):
            current["package"] = line.split(":")[1].strip()
        elif line.startswith("Version:"):
            current["version"] = line.split(":")[1].strip()
        elif line == "":
            if current:
                packages.append(current)
                current = {}
    if current:
        packages.append(current)
    return packages


def scan_image(image_name: str):
    rootfs = None
    try:
        print(f"[*] Exporting filesystem from Docker image: {image_name}")
        rootfs = _export_image_fs(image_name)
        distro = _detect_distro(rootfs)
        if not distro:
            return {"image": image_name, "error": "Unsupported distro"}
        print(f"[*] Detected distro: {distro}")

        if distro == "alpine":
            pkgs = _parse_alpine_packages(rootfs)
        else:
            pkgs = _parse_debian_packages(rootfs)

        vulnerabilities = []
        for pkg in pkgs:
            pkg_name = pkg["package"]
            pkg_version = pkg["version"]
            vulns = query_osv(pkg_name, pkg_version)
            for v in vulns:
                vuln_entry = {
                    "id": v.get("id"),
                    "package": pkg_name,
                    "version": pkg_version,
                    "severity": v.get("severity", "UNKNOWN"),
                    "description": v.get("summary", ""),
                    "fixed_version": v.get("fixed_version"),
                }
                if distro == "debian":
                    vuln_entry["instructions"] = f"apt-get install --only-upgrade {pkg_name}"
                else:
                    vuln_entry["instructions"] = f"apk upgrade {pkg_name}"

                vulnerabilities.append(vuln_entry)

        return {"image": image_name, "vulnerabilities": vulnerabilities}

    finally:
        if rootfs:
            shutil.rmtree(rootfs)