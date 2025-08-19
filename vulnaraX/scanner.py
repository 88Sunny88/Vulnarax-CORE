import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from cyclonedx.model.component import Component
from cyclonedx.model.bom import Bom
from cyclonedx.model.vulnerability import Vulnerability, VulnerabilityRating, VulnerabilitySeverity
from cyclonedx.output.json import JsonV1Dot5

from .osv_client import query_osv


def _export_image_fs(image_name: str) -> str:
    """Create container, export filesystem, return temp dir path"""
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


def _parse_python_dependencies(rootfs: str):
    deps = []
    for root, _, files in os.walk(rootfs):
        if "requirements.txt" in files:
            path = os.path.join(root, "requirements.txt")
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        if "==" in line:
                            name, version = line.split("==", 1)
                        else:
                            name, version = line, "latest"
                        deps.append({"package": name, "version": version})
        if "poetry.lock" in files:
            path = os.path.join(root, "poetry.lock")
            try:
                import toml
                lock_data = toml.load(path)
                for pkg in lock_data.get("package", []):
                    deps.append({"package": pkg["name"], "version": pkg["version"]})
            except Exception:
                pass
    return deps


def _parse_node_dependencies(rootfs: str):
    deps = []
    for root, _, files in os.walk(rootfs):
        if "package-lock.json" in files:
            path = os.path.join(root, "package-lock.json")
            try:
                with open(path) as f:
                    data = json.load(f)
                packages = data.get("packages", {})
                for pkg_path, pkg_info in packages.items():
                    if pkg_path == "":
                        continue  # root package
                    name = pkg_info.get("name") or Path(pkg_path).name
                    version = pkg_info.get("version", "latest")
                    deps.append({"package": name, "version": version})
            except Exception:
                pass
    return deps


def scan_image(image_name: str):
    rootfs = None
    try:
        print(f"[*] Exporting filesystem from Docker image: {image_name}")
        rootfs = _export_image_fs(image_name)
        distro = _detect_distro(rootfs)
        if not distro:
            return {"image": image_name, "error": "Unsupported distro"}
        print(f"[*] Detected distro: {distro}")

        # Parse OS packages
        if distro == "alpine":
            pkgs = _parse_alpine_packages(rootfs)
        else:
            pkgs = _parse_debian_packages(rootfs)

        # Parse language dependencies
        py_deps = _parse_python_dependencies(rootfs)
        node_deps = _parse_node_dependencies(rootfs)

        all_packages = pkgs + py_deps + node_deps

        vulnerabilities = []
        for pkg in all_packages:
            pkg_name = pkg["package"]
            pkg_version = pkg.get("version", "latest")
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
                if pkg in pkgs:  # system package
                    if distro == "debian":
                        vuln_entry["instructions"] = f"apt-get install --only-upgrade {pkg_name}"
                    else:
                        vuln_entry["instructions"] = f"apk upgrade {pkg_name}"
                else:  # language package
                    if pkg in py_deps:
                        vuln_entry["instructions"] = f"pip install --upgrade {pkg_name}"
                    else:
                        vuln_entry["instructions"] = f"npm install {pkg_name}@latest"
                vulnerabilities.append(vuln_entry)

        return {"image": image_name, "vulnerabilities": vulnerabilities}

    finally:
        if rootfs:
            shutil.rmtree(rootfs)

def generate_sbom(image_name: str, vulnerabilities: list, output_file: str):
    """
    Generate CycloneDX SBOM JSON for the scanned image and its vulnerabilities.
    """
    from cyclonedx.model.component import Component
    from cyclonedx.model.bom import Bom
    from cyclonedx.output.json import JsonV1Dot5
    from packageurl import PackageURL  # <-- Make sure this is imported
    
    # Just create components without linking vulnerabilities
    components = []
    seen_packages = set()
    
    for v in vulnerabilities:
        pkg_name = v['package']
        pkg_version = v['version']
        
        if (pkg_name, pkg_version) not in seen_packages:
            # Create a proper PackageURL object (not a string)
            purl = PackageURL(
                type='generic',
                name=pkg_name,
                version=pkg_version
            )
            
            component = Component(
                name=pkg_name,
                version=pkg_version,
                purl=purl  # Pass the actual PackageURL object
            )
            components.append(component)
            seen_packages.add((pkg_name, pkg_version))
    
    # Create BOM with just components
    bom = Bom(components=components)
    
    # Use the JSON serializer
    serializer = JsonV1Dot5(bom)
    json_output = serializer.output_as_string()
    
    # Write to file
    with open(output_file, 'w') as f:
        f.write(json_output)