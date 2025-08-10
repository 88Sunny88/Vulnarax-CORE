# VulnaraX CORE

## Workflow: Vulnerability Scan

To perform a vulnerability scan on your Docker image, use the following command:

```bash
vulnaraX scan my-docker-image:latest --output report.json
```

This will scan the `my-docker-image:latest` Docker image and save the results in `report.json`.
### Detailed Workflow

2. CLI pulls image metadata from Docker or tar file.  
3. Detects packages (OS + language-specific).  
4. Queries OSV API for vulnerabilities.  
5. Outputs:  
    - JSON (machine-readable)  
    - Table summary (human-readable)  
    - Optional CycloneDX SBOM as well  