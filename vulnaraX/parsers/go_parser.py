"""
Go modules parser for go.mod and go.sum files
"""

import re
import os
from typing import List, Dict, Any, Optional
from pathlib import Path


class GoParser:
    """Parser for Go module files"""
    
    def __init__(self):
        pass
        
    def parse_go_mod(self, file_path: str) -> List[Dict[str, str]]:
        """Parse go.mod file for dependencies"""
        dependencies = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Remove comments
            content = re.sub(r'//.*$', '', content, flags=re.MULTILINE)
            
            # Find require blocks
            require_blocks = re.findall(r'require\s*\((.*?)\)', content, re.DOTALL)
            
            # Process require blocks
            for block in require_blocks:
                lines = block.strip().split('\n')
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith('//'):
                        dependency = self._parse_go_require_line(line)
                        if dependency:
                            dependencies.append(dependency)
            
            # Find single line requires
            single_requires = re.findall(r'require\s+([^\s]+)\s+([^\s]+)', content)
            for module, version in single_requires:
                dependencies.append({
                    'name': module.strip(),
                    'version': version.strip(),
                    'ecosystem': 'Go',
                    'indirect': False
                })
            
            # Find replace directives (important for security)
            replaces = re.findall(r'replace\s+([^\s]+)\s+=>\s+([^\s]+)(?:\s+([^\s]+))?', content)
            replace_map = {}
            for original, replacement, version in replaces:
                replace_map[original.strip()] = {
                    'replacement': replacement.strip(),
                    'version': version.strip() if version else None
                }
            
            # Apply replacements
            for dep in dependencies:
                if dep['name'] in replace_map:
                    replace_info = replace_map[dep['name']]
                    dep['replaced_by'] = replace_info['replacement']
                    if replace_info['version']:
                        dep['version'] = replace_info['version']
                        
        except Exception as e:
            print(f"[!] Error parsing go.mod: {e}")
        
        return dependencies
    
    def parse_go_sum(self, file_path: str) -> Dict[str, List[str]]:
        """Parse go.sum file for integrity information"""
        checksums = {}
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        parts = line.split(' ')
                        if len(parts) >= 3:
                            module_version = parts[0]
                            checksum_type = parts[1]
                            checksum = parts[2]
                            
                            # Extract module name and version
                            if '/go.mod' in module_version:
                                # Skip go.mod entries, we only want actual modules
                                continue
                            elif ' v' in module_version:
                                module, version = module_version.rsplit(' v', 1)
                            elif '@v' in module_version:
                                module, version = module_version.split('@v', 1)
                            else:
                                continue
                            
                            if module not in checksums:
                                checksums[module] = []
                            
                            checksums[module].append({
                                'version': version,
                                'checksum_type': checksum_type,
                                'checksum': checksum
                            })
                            
        except Exception as e:
            print(f"[!] Error parsing go.sum: {e}")
        
        return checksums
    
    def extract_go_dependencies_from_directory(self, directory: str) -> List[Dict[str, str]]:
        """Extract all Go dependencies from a directory"""
        all_dependencies = []
        
        # Find and parse go.mod files
        for go_mod_file in Path(directory).rglob('go.mod'):
            print(f"[*] Found go.mod: {go_mod_file}")
            deps = self.parse_go_mod(str(go_mod_file))
            
            # Check for corresponding go.sum
            go_sum_file = go_mod_file.parent / 'go.sum'
            if go_sum_file.exists():
                print(f"[*] Found go.sum: {go_sum_file}")
                checksums = self.parse_go_sum(str(go_sum_file))
                
                # Add checksum information to dependencies
                for dep in deps:
                    module_name = dep['name']
                    if module_name in checksums:
                        dep['checksums'] = checksums[module_name]
                        dep['verified'] = True
                    else:
                        dep['verified'] = False
            
            all_dependencies.extend(deps)
        
        # Deduplicate dependencies
        seen = set()
        unique_dependencies = []
        for dep in all_dependencies:
            dep_key = (dep['name'], dep['version'])
            if dep_key not in seen:
                seen.add(dep_key)
                unique_dependencies.append(dep)
        
        return unique_dependencies
    
    def _parse_go_require_line(self, line: str) -> Optional[Dict[str, str]]:
        """Parse a single require line from go.mod"""
        # Handle different formats:
        # module version
        # module version // indirect
        
        line = line.strip()
        if not line:
            return None
        
        # Check for indirect comment
        indirect = '// indirect' in line
        if indirect:
            line = line.replace('// indirect', '').strip()
        
        parts = line.split()
        if len(parts) >= 2:
            module = parts[0]
            version = parts[1]
            
            return {
                'name': module,
                'version': version,
                'ecosystem': 'Go',
                'indirect': indirect
            }
        
        return None
    
    def get_go_vulnerability_format(self, dependency: Dict[str, str]) -> str:
        """Convert Go dependency to format expected by vulnerability APIs"""
        # OSV expects Go modules in the format: module@version
        return f"{dependency['name']}@{dependency['version']}"


# Global instance
go_parser = GoParser()

def parse_go_dependencies(directory: str) -> List[Dict[str, str]]:
    """Parse Go dependencies from a directory"""
    return go_parser.extract_go_dependencies_from_directory(directory)