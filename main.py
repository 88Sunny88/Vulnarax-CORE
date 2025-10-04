from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import logging
import json
import os
import tempfile
from datetime import datetime
import time

# Import cache system
from vulnaraX.cache import get_cache, VulnerabilityCache
from vulnaraX.metrics import get_metrics

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="VulnaraX Core API",
    description="Vulnerability scanning and SBOM generation service",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic models
class ScanRequest(BaseModel):
    image_name: str

class PackageScanRequest(BaseModel):
    packages: List[Dict[str, str]]

class JavaProjectScanRequest(BaseModel):
    project_path: str

class GoProjectScanRequest(BaseModel):
    project_path: str

class SBOMRequest(BaseModel):
    image_name: str
    vulnerabilities: List[Dict[str, Any]]

class SBOMGenerationRequest(BaseModel):
    project_path: str
    project_name: str
    ecosystem: str
    format: Optional[str] = "spdx"  # spdx or cyclonedx

class SBOMFromPackagesRequest(BaseModel):
    packages: List[Dict[str, Any]]
    project_name: str
    ecosystem: str
    format: Optional[str] = "spdx"

class ScanResponse(BaseModel):
    image: str
    vulnerabilities: List[Dict[str, Any]]
    scan_timestamp: str
    vulnerability_count: int

class PackageScanResponse(BaseModel):
    packages: List[Dict[str, str]]
    vulnerabilities: List[Dict[str, Any]]
    scan_timestamp: str
    vulnerability_count: int
    package_count: int
    vulnerability_count: int

class SBOMResponse(BaseModel):
    sbom_path: str
    image_name: str
    generated_at: str

class SBOMGenerationResponse(BaseModel):
    sbom: Dict[str, Any]
    format: str
    project_name: str
    generated_at: str
    package_count: int
    vulnerability_count: int

class HealthResponse(BaseModel):
    status: str
    timestamp: str
    service: str

class CacheStatsResponse(BaseModel):
    total_entries: int
    valid_entries: int
    expired_entries: int
    by_source: Dict[str, int]

@app.post("/scan", response_model=ScanResponse)
async def scan_endpoint(request: ScanRequest):
    """Async scan endpoint for production use"""
    metrics_instance = get_metrics()
    start_time = time.time()
    
    # Increment active scans
    metrics_instance.set_active_scans(metrics_instance.active_scans + 1)
    
    try:
        # Import here to avoid circular imports
        from vulnaraX.scanner import scan_image_async
        
        logger.info(f"Starting async scan for image: {request.image_name}")
        metrics_instance.increment_scan_requests("docker_image", "started")
        
        scan_results = await scan_image_async(request.image_name)
        
        if not scan_results:
            metrics_instance.increment_errors("scan_failed", "scanner")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Scan failed to produce results"
            )
        
        # Record vulnerabilities found
        vulnerabilities = scan_results.get("vulnerabilities", [])
        for vuln in vulnerabilities:
            ecosystem = vuln.get("_ecosystem", "unknown")
            severity = vuln.get("severity", "unknown")
            metrics_instance.increment_vulnerabilities_found(ecosystem, severity)
        
        response = ScanResponse(
            image=scan_results.get("image", request.image_name),
            vulnerabilities=vulnerabilities,
            scan_timestamp=scan_results.get("scan_timestamp", datetime.now().isoformat()),
            vulnerability_count=scan_results.get("vulnerability_count", 0)
        )
        
        # Record successful scan
        scan_duration = time.time() - start_time
        metrics_instance.record_scan_duration(scan_duration, "docker_image")
        metrics_instance.increment_scan_requests("docker_image", "success")
        
        logger.info(f"Scan completed for {request.image_name}. Found {response.vulnerability_count} vulnerabilities")
        return response
        
    except Exception as e:
        scan_duration = time.time() - start_time
        metrics_instance.record_scan_duration(scan_duration, "docker_image")
        metrics_instance.increment_scan_requests("docker_image", "error")
        metrics_instance.increment_errors("exception", "scan_endpoint")
        
        logger.error(f"Scan failed for {request.image_name}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scan failed: {str(e)}"
        )
    finally:
        # Decrement active scans
        metrics_instance.set_active_scans(max(0, metrics_instance.active_scans - 1))

@app.post("/scan-sync", response_model=ScanResponse)
async def scan_sync_endpoint(request: ScanRequest):
    """Synchronous scan endpoint for backward compatibility"""
    try:
        # Import here to avoid circular imports
        from vulnaraX.scanner import scan_image
        
        logger.info(f"Starting sync scan for image: {request.image_name}")
        
        scan_results = scan_image(request.image_name)
        
        if not scan_results:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Scan failed to produce results"
            )
        
        response = ScanResponse(
            image=scan_results.get("image", request.image_name),
            vulnerabilities=scan_results.get("vulnerabilities", []),
            scan_timestamp=datetime.now().isoformat(),
            vulnerability_count=len(scan_results.get("vulnerabilities", []))
        )
        
        logger.info(f"Sync scan completed for {request.image_name}. Found {response.vulnerability_count} vulnerabilities")
        return response
        
    except Exception as e:
        logger.error(f"Sync scan failed for {request.image_name}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Sync scan failed: {str(e)}"
        )

@app.post("/scan/packages", response_model=PackageScanResponse)
async def scan_packages_endpoint(request: PackageScanRequest):
    """Async package vulnerability scanning with batch processing"""
    try:
        from vulnaraX.scanner import VulnerabilityScanner
        
        logger.info(f"Starting async package scan for {len(request.packages)} packages")
        
        scanner = VulnerabilityScanner(rate_limit_delay=0.5, max_concurrent=5)
        vulnerabilities = await scanner.scan_packages_async(request.packages)
        
        response = PackageScanResponse(
            packages=request.packages,
            vulnerabilities=vulnerabilities,
            scan_timestamp=datetime.now().isoformat(),
            vulnerability_count=len(vulnerabilities),
            package_count=len(request.packages)
        )
        
        logger.info(f"Package scan completed. Found {response.vulnerability_count} vulnerabilities across {response.package_count} packages")
        return response
        
    except Exception as e:
        logger.error(f"Package scan failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Package scan failed: {str(e)}"
        )

@app.post("/scan/packages/sync", response_model=PackageScanResponse)
async def scan_packages_sync_endpoint(request: PackageScanRequest):
    """Synchronous package vulnerability scanning"""
    try:
        from vulnaraX.scanner import VulnerabilityScanner
        
        logger.info(f"Starting sync package scan for {len(request.packages)} packages")
        
        scanner = VulnerabilityScanner(rate_limit_delay=0.5)
        vulnerabilities = scanner.scan_packages(request.packages)
        
        response = PackageScanResponse(
            packages=request.packages,
            vulnerabilities=vulnerabilities,
            scan_timestamp=datetime.now().isoformat(),
            vulnerability_count=len(vulnerabilities),
            package_count=len(request.packages)
        )
        
        logger.info(f"Sync package scan completed. Found {response.vulnerability_count} vulnerabilities across {response.package_count} packages")
        return response
        
    except Exception as e:
        logger.error(f"Sync package scan failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Sync package scan failed: {str(e)}"
        )

@app.post("/scan/java", response_model=PackageScanResponse)
async def scan_java_project_endpoint(request: JavaProjectScanRequest):
    """Scan Java project (Maven/Gradle) for vulnerabilities"""
    try:
        from vulnaraX.parsers.java_parser import parse_java_dependencies
        from vulnaraX.scanner import VulnerabilityScanner
        
        logger.info(f"Starting Java project scan for: {request.project_path}")
        
        # Extract Java dependencies
        java_packages = parse_java_dependencies(request.project_path)
        
        if not java_packages:
            return PackageScanResponse(
                packages=[],
                vulnerabilities=[],
                scan_timestamp=datetime.now().isoformat(),
                vulnerability_count=0,
                package_count=0
            )
        
        # Clean package data for API response (remove non-standard fields)
        clean_packages = []
        for pkg in java_packages:
            clean_pkg = {
                'name': pkg['name'],
                'version': pkg['version'],
                'ecosystem': pkg['ecosystem']
            }
            clean_packages.append(clean_pkg)
        
        # Scan for vulnerabilities
        scanner = VulnerabilityScanner(rate_limit_delay=0.5, max_concurrent=5)
        vulnerabilities = await scanner.scan_packages_async(java_packages)
        
        response = PackageScanResponse(
            packages=clean_packages,
            vulnerabilities=vulnerabilities,
            scan_timestamp=datetime.now().isoformat(),
            vulnerability_count=len(vulnerabilities),
            package_count=len(java_packages)
        )
        
        logger.info(f"Java project scan completed. Found {response.vulnerability_count} vulnerabilities across {response.package_count} Java packages")
        return response
        
    except Exception as e:
        logger.error(f"Java project scan failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Java project scan failed: {str(e)}"
        )

@app.post("/scan/go", response_model=PackageScanResponse)
async def scan_go_project_endpoint(request: GoProjectScanRequest):
    """Scan Go project (go.mod/go.sum) for vulnerabilities"""
    try:
        from vulnaraX.parsers.go_parser import parse_go_dependencies
        from vulnaraX.scanner import VulnerabilityScanner
        
        logger.info(f"Starting Go project scan for: {request.project_path}")
        
        # Extract Go dependencies
        go_packages = parse_go_dependencies(request.project_path)
        
        if not go_packages:
            return PackageScanResponse(
                packages=[],
                vulnerabilities=[],
                scan_timestamp=datetime.now().isoformat(),
                vulnerability_count=0,
                package_count=0
            )
        
        # Clean package data for API response (remove non-string fields)
        clean_packages = []
        for pkg in go_packages:
            clean_pkg = {
                'name': pkg['name'],
                'version': pkg['version'],
                'ecosystem': pkg['ecosystem']
            }
            clean_packages.append(clean_pkg)
        
        # Scan for vulnerabilities
        scanner = VulnerabilityScanner(rate_limit_delay=0.5, max_concurrent=5)
        vulnerabilities = await scanner.scan_packages_async(go_packages)
        
        response = PackageScanResponse(
            packages=clean_packages,
            vulnerabilities=vulnerabilities,
            scan_timestamp=datetime.now().isoformat(),
            vulnerability_count=len(vulnerabilities),
            package_count=len(go_packages)
        )
        
        logger.info(f"Go project scan completed. Found {response.vulnerability_count} vulnerabilities across {response.package_count} Go packages")
        return response
        
    except Exception as e:
        logger.error(f"Go project scan failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Go project scan failed: {str(e)}"
        )

@app.post("/sbom", response_model=SBOMResponse)
async def sbom_endpoint(request: SBOMRequest):
    """Generate SBOM for a scanned image"""
    try:
        # Import here to avoid circular imports
        from vulnaraX.scanner import generate_sbom
        
        logger.info(f"Generating SBOM for image: {request.image_name}")
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
            output_file = temp_file.name
        
        generate_sbom(request.image_name, request.vulnerabilities, output_file)
        
        if not os.path.exists(output_file):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="SBOM generation failed - output file not created"
            )
        
        response = SBOMResponse(
            sbom_path=output_file,
            image_name=request.image_name,
            generated_at=datetime.now().isoformat()
        )
        
        logger.info(f"SBOM generated for {request.image_name} at {output_file}")
        return response
        
    except Exception as e:
        logger.error(f"SBOM generation failed for {request.image_name}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"SBOM generation failed: {str(e)}"
        )

@app.get("/health", response_model=HealthResponse)
def health_check():
    """Health check endpoint"""
    return HealthResponse(
        status="healthy",
        timestamp=datetime.now().isoformat(),
        service="VulnaraX Scanner"
    )

@app.get("/cache/stats", response_model=CacheStatsResponse)
async def get_cache_stats():
    """Get cache statistics"""
    cache = VulnerabilityCache()
    stats = cache.get_cache_stats()
    return CacheStatsResponse(**stats)

@app.post("/cache/cleanup")
async def cleanup_cache():
    """Clean up expired cache entries"""
    cache = VulnerabilityCache()
    cleaned = cache.cleanup_expired()
    return {"cleaned_entries": cleaned, "message": f"Cleaned {cleaned} expired entries"}

@app.delete("/cache/clear")
async def clear_cache():
    """Clear all cache entries"""
    cache = VulnerabilityCache()
    cleared = cache.clear_all()
    return {"cleared_entries": cleared, "message": f"Cleared {cleared} cache entries"}

@app.get("/metrics", response_class=PlainTextResponse)
async def get_prometheus_metrics():
    """Prometheus metrics endpoint"""
    metrics_instance = get_metrics()
    
    # Update cache size metric
    cache = VulnerabilityCache()
    stats = cache.get_cache_stats()
    metrics_instance.set_cache_size(stats.get("total_entries", 0))
    
    return metrics_instance.get_metrics_text()

@app.get("/metrics/summary")
async def get_metrics_summary():
    """Human-readable metrics summary"""
    metrics_instance = get_metrics()
    
    # Update cache metrics
    cache = VulnerabilityCache()
    stats = cache.get_cache_stats()
    metrics_instance.set_cache_size(stats.get("total_entries", 0))
    
    return metrics_instance.get_summary_stats()

# SBOM Generation Endpoints
@app.post("/sbom/generate", response_model=SBOMGenerationResponse)
async def generate_sbom_from_scan(request: SBOMGenerationRequest):
    """Generate enhanced SBOM from project scan"""
    metrics_instance = get_metrics()
    start_time = time.time()
    
    try:
        from vulnaraX.sbom_generator import generate_enhanced_sbom
        from vulnaraX.scanner import VulnerabilityScanner
        
        logger.info(f"Generating SBOM for {request.ecosystem} project: {request.project_name}")
        
        # Initialize scanner
        scanner = VulnerabilityScanner()
        
        # First scan the project to get packages and vulnerabilities
        packages = []
        if request.ecosystem.lower() == 'java':
            from vulnaraX.parsers.java_parser import JavaParser
            
            parser = JavaParser()
            packages = parser.extract_java_dependencies_from_directory(request.project_path)
            
            # Scan for vulnerabilities
            scan_result = await scanner.scan_packages_async(packages)
            packages = scan_result
            
        elif request.ecosystem.lower() == 'go':
            from vulnaraX.parsers.go_parser import GoParser
            
            parser = GoParser()
            packages = parser.extract_go_dependencies_from_directory(request.project_path)
            
            # Scan for vulnerabilities  
            scan_result = await scanner.scan_packages_async(packages)
            packages = scan_result
            
        elif request.ecosystem.lower() == 'python':
            from vulnaraX.parsers.pip_parser import PipParser
            
            parser = PipParser()
            packages = parser.parse_requirements(request.project_path)
            
            # Scan for vulnerabilities
            scan_result = await scanner.scan_packages_async(packages)
            packages = scan_result
        
        # Generate enhanced SBOM
        sbom = generate_enhanced_sbom(
            packages=packages,
            ecosystem=request.ecosystem,
            project_name=request.project_name,
            format=request.format,
            project_path=request.project_path
        )
        
        # Count vulnerabilities
        vulnerability_count = sum(len(pkg.get('vulnerabilities', [])) for pkg in packages)
        
        metrics_instance.record_scan_duration(time.time() - start_time)
        
        return SBOMGenerationResponse(
            sbom=sbom,
            format=request.format,
            project_name=request.project_name,
            generated_at=datetime.now().isoformat(),
            package_count=len(packages),
            vulnerability_count=vulnerability_count
        )
        
    except Exception as e:
        logger.error(f"SBOM generation failed: {str(e)}")
        metrics_instance.increment_errors("sbom_generation", "sbom")
        raise HTTPException(status_code=500, detail=f"SBOM generation failed: {str(e)}")

@app.post("/sbom/from-packages", response_model=SBOMGenerationResponse)
async def generate_sbom_from_packages(request: SBOMFromPackagesRequest):
    """Generate enhanced SBOM from package list"""
    metrics_instance = get_metrics()
    start_time = time.time()
    
    try:
        from vulnaraX.sbom_generator import generate_enhanced_sbom
        
        logger.info(f"Generating SBOM from {len(request.packages)} packages for project: {request.project_name}")
        
        # Generate enhanced SBOM
        sbom = generate_enhanced_sbom(
            packages=request.packages,
            ecosystem=request.ecosystem,
            project_name=request.project_name,
            format=request.format
        )
        
        # Count vulnerabilities
        vulnerability_count = sum(len(pkg.get('vulnerabilities', [])) for pkg in request.packages)
        
        metrics_instance.record_scan_duration(time.time() - start_time)
        
        return SBOMGenerationResponse(
            sbom=sbom,
            format=request.format,
            project_name=request.project_name,
            generated_at=datetime.now().isoformat(),
            package_count=len(request.packages),
            vulnerability_count=vulnerability_count
        )
        
    except Exception as e:
        logger.error(f"SBOM generation from packages failed: {str(e)}")
        metrics_instance.increment_errors("sbom_generation", "sbom")
        raise HTTPException(status_code=500, detail=f"SBOM generation failed: {str(e)}")

@app.get("/")
def root():
    """Root endpoint with API information"""
    return {
        "service": "VulnaraX Vulnerability Scanner",
        "version": "2.0.0",
        "endpoints": {
            "scan": "POST /scan - Async Docker image scanning",
            "scan_sync": "POST /scan-sync - Sync Docker image scanning",
            "scan_packages": "POST /scan/packages - Async package scanning",
            "scan_java": "POST /scan/java - Java project scanning",
            "scan_go": "POST /scan/go - Go project scanning",
            "sbom_generate": "POST /sbom/generate - Generate SBOM from project",
            "sbom_from_packages": "POST /sbom/from-packages - Generate SBOM from packages",
            "sbom": "POST /sbom - Generate SBOM (legacy)",
            "health": "GET /health - Health check",
            "cache_stats": "GET /cache/stats - Cache statistics",
            "cache_cleanup": "POST /cache/cleanup - Cache cleanup",
            "cache_clear": "DELETE /cache/clear - Clear cache",
            "metrics": "GET /metrics - Prometheus metrics",
            "metrics_summary": "GET /metrics/summary - Metrics summary"
        },
        "features": [
            "Multi-ecosystem vulnerability scanning (Docker, Java, Go, Python)",
            "Enhanced SBOM generation (SPDX & CycloneDX)",
            "License detection and compliance",
            "Dependency relationship mapping",
            "Persistent SQLite caching with metrics",
            "Prometheus monitoring",
            "Supply chain security analysis"
        ]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8002,
        reload=True,
        log_level="info"
    )