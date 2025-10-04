from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import logging
import json
import os
import tempfile
from datetime import datetime

# Import cache system
from vulnaraX.cache import get_cache, VulnerabilityCache

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

class SBOMRequest(BaseModel):
    image_name: str
    vulnerabilities: List[Dict[str, Any]]

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
    try:
        # Import here to avoid circular imports
        from vulnaraX.scanner import scan_image_async
        
        logger.info(f"Starting async scan for image: {request.image_name}")
        
        scan_results = await scan_image_async(request.image_name)
        
        if not scan_results:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Scan failed to produce results"
            )
        
        response = ScanResponse(
            image=scan_results.get("image", request.image_name),
            vulnerabilities=scan_results.get("vulnerabilities", []),
            scan_timestamp=scan_results.get("scan_timestamp", datetime.now().isoformat()),
            vulnerability_count=scan_results.get("vulnerability_count", 0)
        )
        
        logger.info(f"Scan completed for {request.image_name}. Found {response.vulnerability_count} vulnerabilities")
        return response
        
    except Exception as e:
        logger.error(f"Scan failed for {request.image_name}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scan failed: {str(e)}"
        )

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

@app.get("/")
async def root():
    """Root endpoint with service information"""
    return {
        "service": "VulnaraX Core API",
        "version": "1.0.0",
        "endpoints": {
            "scan": "POST /scan (async production endpoint)",
            "scan-sync": "POST /scan-sync (sync compatibility endpoint)",
            "sbom": "POST /sbom", 
            "health": "GET /health"
        },
        "production_features": {
            "async_scanning": True,
            "rate_limiting": True,
            "concurrent_support": "30-40 simultaneous scans"
        }
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