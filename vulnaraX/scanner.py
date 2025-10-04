import json
import os
import shutil
import subprocess
import tempfile
import time
import logging
import asyncio
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.bom import Bom
from cyclonedx.model.vulnerability import Vulnerability, VulnerabilityRating, VulnerabilitySeverity
from cyclonedx.output.json import JsonV1Dot5

# Import vulnerability sources
from .sources.osv_client import query_osv_async, query_osv
from .sources.nvd_client import nvd_client, query_nvd

from vulnaraX.sources.nvd_client import query_nvd

from .sources.osv_client import query_osv

# Configuration
RATE_LIMIT_DELAY = float(os.getenv('VULNARAX_RATE_LIMIT_DELAY', '0.5'))
MAX_RETRIES = int(os.getenv('VULNARAX_MAX_RETRIES', '3'))
BATCH_SIZE = int(os.getenv('VULNARAX_BATCH_SIZE', '10'))
BATCH_DELAY = float(os.getenv('VULNARAX_BATCH_DELAY', '2.0'))

# Semaphore to limit concurrent vulnerability queries
VULNERABILITY_SEMAPHORE = asyncio.Semaphore(5)

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
    """Detect the Linux distribution"""
    os_release = os.path.join(rootfs, "etc", "os-release")
    if os.path.exists(os_release):
        content = open(os_release).read().lower()
        if "alpine" in content:
            return "alpine"
        elif "debian" in content or "ubuntu" in content:
            return "debian"
        elif "centos" in content or "rhel" in content or "fedora" in content:
            return "rhel"
    return "unknown"


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


def _normalize_severity(vuln_data):
    """Normalize severity across different vulnerability sources"""
    severity = vuln_data.get("severity", "UNKNOWN")
    
    if isinstance(severity, str):
        severity = severity.upper()
        
    # Map various severity formats to standard levels
    severity_map = {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH", 
        "MEDIUM": "MEDIUM",
        "MODERATE": "MEDIUM",
        "LOW": "LOW",
        "UNKNOWN": "UNKNOWN",
        "NONE": "LOW"
    }
    
    return severity_map.get(severity, "UNKNOWN")


async def scan_package_vulnerabilities_async(package_name: str, version: str) -> List[Dict]:
    """Scan a single package for vulnerabilities with concurrency control"""
    async with VULNERABILITY_SEMAPHORE:
        try:
            # Run OSV and NVD queries concurrently
            osv_task = query_osv_async(package_name, version)
            nvd_task = nvd_client.query_nvd_async(package_name, version)
            
            osv_result, nvd_result = await asyncio.gather(osv_task, nvd_task, return_exceptions=True)
            
            vulnerabilities = []
            
            # Process OSV results
            if isinstance(osv_result, list):
                vulnerabilities.extend(osv_result)
            elif isinstance(osv_result, Exception):
                print(f"OSV error for {package_name}: {osv_result}")
            
            # Process NVD results
            if isinstance(nvd_result, list):
                vulnerabilities.extend(nvd_result)
            elif isinstance(nvd_result, Exception):
                print(f"NVD error for {package_name}: {nvd_result}")
            
            return vulnerabilities
            
        except Exception as e:
            print(f"Error scanning {package_name} {version}: {e}")
            return []

async def scan_image_async(image_name: str) -> Dict[str, Any]:
    """Async version of scan_image with improved concurrency"""
    try:
        print(f"Starting async scan for {image_name}")
        
        # Extract packages (keep this synchronous as it involves Docker)
        packages = extract_packages_from_image(image_name)
        
        if not packages:
            return {
                "image": image_name,
                "vulnerabilities": [],
                "scan_timestamp": datetime.now().isoformat(),
                "vulnerability_count": 0,
                "error": "No packages found"
            }
        
        print(f"Found {len(packages)} packages, scanning vulnerabilities...")
        
        # Create tasks for vulnerability scanning (limit to first 100 packages for performance)
        tasks = []
        for package in packages[:100]:
            package_name = package.get('name', 'unknown')
            version = package.get('version', 'unknown')
            
            if package_name != 'unknown' and version != 'unknown':
                task = scan_package_vulnerabilities_async(package_name, version)
                tasks.append(task)
        
        # Execute all vulnerability scans with controlled concurrency
        print(f"Executing {len(tasks)} vulnerability scan tasks...")
        vulnerability_lists = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Flatten and deduplicate vulnerabilities
        all_vulnerabilities = []
        seen_vulns = set()
        
        for vuln_list in vulnerability_lists:
            if isinstance(vuln_list, list):
                for vuln in vuln_list:
                    if isinstance(vuln, dict):
                        vuln_key = f"{vuln.get('id', '')}:{vuln.get('package', '')}"
                        if vuln_key not in seen_vulns:
                            seen_vulns.add(vuln_key)
                            all_vulnerabilities.append(vuln)
        
        print(f"Scan completed for {image_name}. Found {len(all_vulnerabilities)} vulnerabilities")
        
        return {
            "image": image_name,
            "vulnerabilities": all_vulnerabilities,
            "scan_timestamp": datetime.now().isoformat(),
            "vulnerability_count": len(all_vulnerabilities)
        }
        
    except Exception as e:
        print(f"Error scanning image {image_name}: {e}")
        return {
            "image": image_name,
            "vulnerabilities": [],
            "scan_timestamp": datetime.now().isoformat(),
            "vulnerability_count": 0,
            "error": str(e)
        }
    finally:
        # Clean up sessions
        try:
            await nvd_client.close_session()
        except:
            pass

def _extract_packages_debian(rootfs: str):
    """Extract packages from Debian-based systems"""
    packages = []
    dpkg_status = os.path.join(rootfs, "var", "lib", "dpkg", "status")
    
    if not os.path.exists(dpkg_status):
        return packages
    
    with open(dpkg_status, 'r') as f:
        current_package = {}
        for line in f:
            line = line.strip()
            if line.startswith("Package:"):
                if current_package and current_package.get("name") and current_package.get("version"):
                    packages.append(current_package)
                current_package = {"name": line.split(":", 1)[1].strip()}
            elif line.startswith("Version:"):
                current_package["version"] = line.split(":", 1)[1].strip()
            elif line.startswith("Status:") and "install ok installed" not in line:
                current_package = {}  # Skip non-installed packages
        
        # Add the last package
        if current_package and current_package.get("name") and current_package.get("version"):
            packages.append(current_package)
    
    return packages

def _extract_packages_alpine(rootfs: str):
    """Extract packages from Alpine Linux"""
    packages = []
    apk_installed = os.path.join(rootfs, "lib", "apk", "db", "installed")
    
    if not os.path.exists(apk_installed):
        return packages
    
    try:
        with open(apk_installed, 'r') as f:
            content = f.read()
            
        package_blocks = content.split('\n\n')
        for block in package_blocks:
            if not block.strip():
                continue
            
            name = None
            version = None
            
            for line in block.split('\n'):
                if line.startswith('P:'):
                    name = line[2:]
                elif line.startswith('V:'):
                    version = line[2:]
            
            if name and version:
                packages.append({"name": name, "version": version})
    
    except Exception as e:
        logging.warning(f"Failed to parse Alpine packages: {e}")
    
    return packages

def _extract_packages_rhel(rootfs: str):
    """Extract packages from RHEL-based systems"""
    packages = []
    rpm_db_path = os.path.join(rootfs, "var", "lib", "rpm")
    
    if not os.path.exists(rpm_db_path):
        return packages
    
    try:
        # This is a simplified version - in reality you'd need to parse RPM database
        # For now, return empty list
        logging.info("RHEL package extraction not fully implemented")
    except Exception as e:
        logging.warning(f"Failed to parse RHEL packages: {e}")
    
    return packages

def extract_packages_from_image(image_name: str):
    """Extract packages from Docker image"""
    rootfs = None
    packages = []
    
    try:
        print(f"[*] Extracting packages from {image_name}")
        rootfs = _export_image_fs(image_name)
        distro = _detect_distro(rootfs)
        print(f"[*] Detected distro: {distro}")

        # Extract packages based on distro
        if distro == "debian":
            packages.extend(_extract_packages_debian(rootfs))
        elif distro == "alpine":
            packages.extend(_extract_packages_alpine(rootfs))
        elif distro == "rhel":
            packages.extend(_extract_packages_rhel(rootfs))
        else:
            print(f"[!] Unsupported distro: {distro}")

        # Also extract Python and Node.js packages
        try:
            py_packages = _parse_python_packages(rootfs)
            packages.extend(py_packages)
        except Exception as e:
            logging.warning(f"Failed to extract Python packages: {e}")

        try:
            node_packages = _parse_nodejs_packages(rootfs)
            packages.extend(node_packages)
        except Exception as e:
            logging.warning(f"Failed to extract Node.js packages: {e}")

    except Exception as e:
        print(f"[!] Error extracting packages from {image_name}: {e}")
        return []
    finally:
        if rootfs and os.path.exists(rootfs):
            shutil.rmtree(rootfs)
    
    return packages
    """
    Scan Docker image for vulnerabilities with improved rate limiting and error handling
    """
    vulnerabilities = []
    rootfs = None
    
    try:
        print(f"[*] Starting scan for {image_name}")
        rootfs = _export_image_fs(image_name)
        distro = _detect_distro(rootfs)
        print(f"[*] Detected distro: {distro}")

        # Extract packages based on distro
        if distro == "debian":
            pkgs = _extract_packages_debian(rootfs)
        elif distro == "alpine":
            pkgs = _extract_packages_alpine(rootfs)
        elif distro == "rhel":
            pkgs = _extract_packages_rhel(rootfs)
        else:
            print(f"[!] Unsupported distro: {distro}")
            pkgs = []

        # Extract Python dependencies
        py_deps = []
        try:
            py_packages = _parse_python_packages(rootfs)
            for pkg in py_packages:
                try:
                    vulns = query_osv(pkg["name"], pkg.get("version", ""))
                    for v in vulns:
                        vulnerabilities.append({
                            "id": v.get("id"),
                            "package": pkg["name"],
                            "version": pkg["version"],
                            "_ecosystem": "PyPI",
                            "severity": _normalize_severity(v),
                            "fixed_version": v.get("fixed_version"),
                            "instructions": f"pip install {pkg['name']}=={v.get('fixed_version', 'latest')}"
                        })
                    time.sleep(RATE_LIMIT_DELAY)  # Rate limiting
                except Exception as e:
                    logging.warning(f"Failed to scan Python package {pkg['name']}: {e}")
        except Exception as e:
            logging.warning(f"Failed to extract Python packages: {e}")

        # Extract Node.js dependencies
        node_deps = []
        try:
            node_packages = _parse_nodejs_packages(rootfs)
            for pkg in node_packages:
                try:
                    vulns = query_osv(pkg["name"], pkg.get("version", "npm"))
                    for v in vulns:
                        vulnerabilities.append({
                            "id": v.get("id"),
                            "package": pkg["name"],
                            "version": pkg["version"],
                            "_ecosystem": "npm",
                            "severity": _normalize_severity(v),
                            "fixed_version": v.get("fixed_version"),
                            "instructions": f"npm install {pkg['name']}@latest"
                        })
                    time.sleep(RATE_LIMIT_DELAY)  # Rate limiting
                except Exception as e:
                    logging.warning(f"Failed to scan Node.js package {pkg['name']}: {e}")
        except Exception as e:
            logging.warning(f"Failed to extract Node.js packages: {e}")

        # Process system packages in batches
        print(f"[*] Processing {len(pkgs)} system packages in batches of {BATCH_SIZE}")
        
        for i in range(0, len(pkgs), BATCH_SIZE):
            batch = pkgs[i:i + BATCH_SIZE]
            batch_num = (i // BATCH_SIZE) + 1
            total_batches = (len(pkgs) + BATCH_SIZE - 1) // BATCH_SIZE
            
            print(f"[*] Processing batch {batch_num}/{total_batches} ({len(batch)} packages)")
            
            for pkg in batch:
                pkg_name = pkg.get("name", "unknown")
                pkg_version = pkg.get("version", "unknown")
                
                if pkg_name == "unknown" or pkg_version == "unknown":
                    continue
                
                # Query OSV with error handling and retries
                osv_results = []
                for attempt in range(MAX_RETRIES):
                    try:
                        time.sleep(RATE_LIMIT_DELAY)
                        osv_results = query_osv(pkg_name, pkg_version)
                        break  # Success, exit retry loop
                    except Exception as e:
                        if attempt < MAX_RETRIES - 1:
                            wait_time = (attempt + 1) * 2  # Exponential backoff
                            logging.warning(f"OSV query failed for {pkg_name} {pkg_version} (attempt {attempt + 1}/{MAX_RETRIES}): {e}. Retrying in {wait_time}s...")
                            time.sleep(wait_time)
                        else:
                            logging.error(f"OSV query failed for {pkg_name} {pkg_version} after {MAX_RETRIES} attempts: {e}")
                            osv_results = []

                # Query NVD with error handling and retries
                nvd_results = []
                for attempt in range(MAX_RETRIES):
                    try:
                        time.sleep(RATE_LIMIT_DELAY)
                        nvd_results = query_nvd(pkg_name, pkg_version)
                        break  # Success, exit retry loop
                    except Exception as e:
                        if attempt < MAX_RETRIES - 1:
                            wait_time = (attempt + 1) * 2  # Exponential backoff
                            logging.warning(f"NVD query failed for {pkg_name} {pkg_version} (attempt {attempt + 1}/{MAX_RETRIES}): {e}. Retrying in {wait_time}s...")
                            time.sleep(wait_time)
                        else:
                            logging.error(f"NVD query failed for {pkg_name} {pkg_version} after {MAX_RETRIES} attempts: {e}")
                            nvd_results = []

                # Process results with error handling
                try:
                    for v in osv_results + nvd_results:
                        if not v or not v.get("id"):
                            continue  # Skip invalid vulnerability entries
                        
                        vuln_entry = {
                            "id": v.get("id"),
                            "package": pkg_name,
                            "version": pkg_version,
                            "severity": _normalize_severity(v),
                            "description": v.get("summary", v.get("description", ""))[:200],
                            "fixed_version": v.get("fixed_version"),
                            "instructions": f"apt-get install --only-upgrade {pkg_name}"
                        }
                        vulnerabilities.append(vuln_entry)
                except Exception as e:
                    logging.error(f"Error processing vulnerabilities for {pkg_name} {pkg_version}: {e}")

            # Delay between batches (except for the last batch)
            if i + BATCH_SIZE < len(pkgs):
                print(f"[*] Waiting {BATCH_DELAY}s before next batch...")
                time.sleep(BATCH_DELAY)

        print(f"[*] Scan completed for {image_name}. Found {len(vulnerabilities)} vulnerabilities")
        
        return {
            "image": image_name,
            "vulnerabilities": vulnerabilities,
            "scan_timestamp": datetime.now().isoformat(),
            "vulnerability_count": len(vulnerabilities)
        }

    except Exception as e:
        logging.error(f"Critical error during scan of {image_name}: {e}")
        return {
            "image": image_name,
            "vulnerabilities": [],
            "scan_timestamp": datetime.now().isoformat(),
            "vulnerability_count": 0,
            "error": str(e)
        }
    finally:
        if rootfs and os.path.exists(rootfs):
            try:
                shutil.rmtree(rootfs)
            except Exception as e:
                logging.warning(f"Failed to cleanup temporary directory {rootfs}: {e}")

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


class VulnerabilityScanner:
    """Vulnerability scanner with async support and persistent caching"""
    
    def __init__(self, rate_limit_delay: float = 0.5, max_concurrent: int = 5):
        self.rate_limit_delay = rate_limit_delay
        self.max_concurrent = max_concurrent
        
    def scan_packages(self, packages: List[Dict[str, str]]) -> List[Dict]:
        """Synchronous package vulnerability scanning"""
        vulnerabilities = []
        
        for package in packages:
            name = package.get('name', '')
            version = package.get('version', '')
            
            if not name:
                continue
                
            try:
                # Query OSV
                osv_vulns = query_osv(name, version)
                vulnerabilities.extend(osv_vulns)
                
                # Query NVD
                nvd_vulns = query_nvd(name, version)
                vulnerabilities.extend(nvd_vulns)
                
                time.sleep(self.rate_limit_delay)
                
            except Exception as e:
                logging.warning(f"Failed to scan package {name}:{version}: {e}")
        
        return vulnerabilities
    
    async def scan_packages_async(self, packages: List[Dict[str, str]]) -> List[Dict]:
        """Asynchronous package vulnerability scanning with rate limiting"""
        semaphore = asyncio.Semaphore(self.max_concurrent)
        tasks = []
        
        for package in packages:
            name = package.get('name', '')
            version = package.get('version', '')
            
            if name:
                task = self._scan_single_package_async(semaphore, name, version)
                tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        vulnerabilities = []
        for result in results:
            if isinstance(result, list):
                vulnerabilities.extend(result)
            elif isinstance(result, Exception):
                logging.warning(f"Task failed with exception: {result}")
        
        return vulnerabilities
    
    async def _scan_single_package_async(self, semaphore: asyncio.Semaphore, name: str, version: str) -> List[Dict]:
        """Scan a single package asynchronously"""
        async with semaphore:
            try:
                # Query both sources concurrently
                osv_task = query_osv_async(name, version)
                nvd_task = nvd_client.query_nvd_async(name, version)
                
                osv_vulns, nvd_vulns = await asyncio.gather(osv_task, nvd_task, return_exceptions=True)
                
                result = []
                if isinstance(osv_vulns, list):
                    result.extend(osv_vulns)
                if isinstance(nvd_vulns, list):
                    result.extend(nvd_vulns)
                
                # Rate limiting
                await asyncio.sleep(self.rate_limit_delay)
                
                return result
                
            except Exception as e:
                logging.warning(f"Failed to scan package {name}:{version}: {e}")
                return []
    
    def scan_docker_image(self, image_name: str) -> Dict:
        """Scan Docker image for vulnerabilities"""
        try:
            packages = extract_packages_from_image(image_name)
            vulnerabilities = self.scan_packages(packages)
            
            return {
                "image": image_name,
                "vulnerabilities": vulnerabilities,
                "scan_timestamp": datetime.now().isoformat(),
                "package_count": len(packages),
                "vulnerability_count": len(vulnerabilities)
            }
        except Exception as e:
            logging.error(f"Failed to scan Docker image {image_name}: {e}")
            return {
                "image": image_name,
                "vulnerabilities": [],
                "scan_timestamp": datetime.now().isoformat(),
                "error": str(e)
            }
    
    async def scan_docker_image_async(self, image_name: str) -> Dict:
        """Asynchronously scan Docker image for vulnerabilities"""
        try:
            packages = extract_packages_from_image(image_name)
            vulnerabilities = await self.scan_packages_async(packages)
            
            return {
                "image": image_name,
                "vulnerabilities": vulnerabilities,
                "scan_timestamp": datetime.now().isoformat(),
                "package_count": len(packages),
                "vulnerability_count": len(vulnerabilities)
            }
        except Exception as e:
            logging.error(f"Failed to scan Docker image {image_name}: {e}")
            return {
                "image": image_name,
                "vulnerabilities": [],
                "scan_timestamp": datetime.now().isoformat(),
                "error": str(e)
            }