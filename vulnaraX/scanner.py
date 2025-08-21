import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from cyclonedx.model.component import Component, ComponentType
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
                        continue
                    name = pkg_info.get("name") or Path(pkg_path).name
                    version = pkg_info.get("version", "latest")
                    deps.append({"package": name, "version": version})
            except Exception:
                pass
    return deps

def _parse_python_packages(rootfs: str):
    """
    Find and parse Python packages from requirements.txt, Pipfile.lock or site-packages
    """
    packages = []
    
    for req_file in ["requirements.txt", "app/requirements.txt", "src/requirements.txt"]:
        req_path = os.path.join(rootfs, req_file)
        if os.path.exists(req_path):
            with open(req_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if '==' in line:
                            pkg_name, version = line.split('==', 1)
                            packages.append({
                                "name": pkg_name.strip(),
                                "version": version.strip().split(';')[0].strip(),
                                "ecosystem": "PyPI"
                            })
    
    pipfile_lock = os.path.join(rootfs, "Pipfile.lock")
    if os.path.exists(pipfile_lock):
        try:
            with open(pipfile_lock, 'r') as f:
                lock_data = json.load(f)
                for pkg_type in ['default', 'develop']:
                    if pkg_type in lock_data:
                        for pkg_name, pkg_info in lock_data[pkg_type].items():
                            if 'version' in pkg_info:
                                version = pkg_info['version'].replace('==', '')
                                packages.append({
                                    "name": pkg_name,
                                    "version": version,
                                    "ecosystem": "PyPI"
                                })
        except (json.JSONDecodeError, KeyError):
            pass

    return packages

def _parse_nodejs_packages(rootfs: str):
    """
    Find and parse Node.js packages from package-lock.json or yarn.lock
    """
    packages = []
    
    pkg_lock = os.path.join(rootfs, "package-lock.json")
    if os.path.exists(pkg_lock):
        try:
            with open(pkg_lock, 'r') as f:
                lock_data = json.load(f)
                if 'dependencies' in lock_data:
                    for pkg_name, pkg_info in lock_data['dependencies'].items():
                        if 'version' in pkg_info:
                            packages.append({
                                "name": pkg_name,
                                "version": pkg_info['version'],
                                "ecosystem": "npm"
                            })
        except (json.JSONDecodeError, KeyError):
            pass
    
    node_modules = os.path.join(rootfs, "node_modules")
    if os.path.exists(node_modules) and os.path.isdir(node_modules):
        for pkg_dir in os.listdir(node_modules):
            if pkg_dir.startswith('.'):
                continue
                
            pkg_json = os.path.join(node_modules, pkg_dir, "package.json")
            if os.path.exists(pkg_json):
                try:
                    with open(pkg_json, 'r') as f:
                        pkg_data = json.load(f)
                        if 'name' in pkg_data and 'version' in pkg_data:
                            packages.append({
                                "name": pkg_data['name'],
                                "version": pkg_data['version'],
                                "ecosystem": "npm"
                            })
                except (json.JSONDecodeError, KeyError):
                    pass
                    
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

        # Parse OS packages
        if distro == "alpine":
            pkgs = _parse_alpine_packages(rootfs)
        else:
            pkgs = _parse_debian_packages(rootfs)

        py_deps = _parse_python_dependencies(rootfs)
        node_deps = _parse_node_dependencies(rootfs)
        py_packages = _parse_python_packages(rootfs)
        for pkg in py_packages:
            vulns = query_osv(pkg["name"], pkg.get("version", "PyPI"))
            for v in vulns:
                vuln_entry = {
                    "id": v.get("id"),
                    "package": pkg["name"],
                    "version": pkg["version"],
                    "_ecosystem": "PyPI",
                    "_display_severity": _get_severity_from_osv(v),
                    "fixed_version": v.get("fixed_version"),
                    "instructions": f"pip install --upgrade {pkg['name']}"
                }
                vulnerabilities.append(vuln_entry)

        node_packages = _parse_nodejs_packages(rootfs)
        for pkg in node_packages:
            vulns = query_osv(pkg["name"], pkg.get("version", "npm"))
            for v in vulns:
                vuln_entry = {
                    "id": v.get("id"),
                    "package": pkg["name"],
                    "version": pkg["version"],
                    "_ecosystem": "npm",
                    "_display_severity": _get_severity_from_osv(v),
                    "fixed_version": v.get("fixed_version"),
                    "instructions": f"npm install {pkg['name']}@latest"
                }
                vulnerabilities.append(vuln_entry)

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
    from packageurl import PackageURL
    
    components = []
    seen_packages = set()
    
    for v in vulnerabilities:
        pkg_name = v['package']
        pkg_version = v['version']
        pkg_ecosystem = v.get('_ecosystem', 'generic')
        
        if (pkg_name, pkg_version, pkg_ecosystem) not in seen_packages:
            if pkg_ecosystem == 'PyPI':
                purl_type = 'pypi'
            elif pkg_ecosystem == 'npm':
                purl_type = 'npm'
            else:
                purl_type = 'generic'

            purl = PackageURL(
                type=purl_type,
                name=pkg_name,
                version=pkg_version
            )
            
            component = Component(
                name=pkg_name,
                version=pkg_version,
                purl=purl,
                type=ComponentType.LIBRARY,
            )
            components.append(component)
            seen_packages.add((pkg_name, pkg_version, pkg_ecosystem))
    
    bom = Bom(components=components)
    
    serializer = JsonV1Dot5(bom)
    json_output = serializer.output_as_string()
    
    with open(output_file, 'w') as f:
        f.write(json_output)