"""
Java ecosystem parser for Maven (pom.xml) and Gradle (build.gradle) dependencies
"""

import xml.etree.ElementTree as ET
import re
import json
import os
from typing import List, Dict, Any, Optional
from pathlib import Path


class JavaParser:
    """Parser for Java dependency management files"""
    
    def __init__(self):
        self.maven_namespace = {'maven': 'http://maven.apache.org/POM/4.0.0'}
        
    def parse_maven_pom(self, file_path: str) -> List[Dict[str, str]]:
        """Parse Maven pom.xml file for dependencies"""
        dependencies = []
        
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Handle namespace or no namespace
            namespace = ''
            if root.tag.startswith('{'):
                namespace = root.tag[root.tag.find('{')+1:root.tag.find('}')]
                ns = {'': namespace}
            else:
                ns = {}
            
            # Find dependencies sections
            if namespace:
                deps_xpath = './/dependencies/dependency'
            else:
                deps_xpath = './/dependencies/dependency'
            
            for dependency in root.findall(deps_xpath, ns):
                group_id = self._get_text_safe(dependency.find('groupId', ns) if namespace else dependency.find('groupId'))
                artifact_id = self._get_text_safe(dependency.find('artifactId', ns) if namespace else dependency.find('artifactId'))
                version = self._get_text_safe(dependency.find('version', ns) if namespace else dependency.find('version'))
                scope = self._get_text_safe(dependency.find('scope', ns) if namespace else dependency.find('scope'))
                
                if group_id and artifact_id:
                    # Handle version variables like ${spring.version}
                    if version and version.startswith('${') and version.endswith('}'):
                        version = self._resolve_property(root, version[2:-1], ns, namespace)
                    
                    dep_name = f"{group_id}:{artifact_id}"
                    dependencies.append({
                        'name': dep_name,
                        'version': version or 'unknown',
                        'ecosystem': 'Maven',
                        'scope': scope or 'compile',
                        'group_id': group_id,
                        'artifact_id': artifact_id
                    })
            
            # Also check for dependency management section
            dep_mgmt_xpath = './/dependencyManagement/dependencies/dependency'
            for dependency in root.findall(dep_mgmt_xpath, ns):
                group_id = self._get_text_safe(dependency.find('groupId', ns) if namespace else dependency.find('groupId'))
                artifact_id = self._get_text_safe(dependency.find('artifactId', ns) if namespace else dependency.find('artifactId'))
                version = self._get_text_safe(dependency.find('version', ns) if namespace else dependency.find('version'))
                
                if group_id and artifact_id:
                    if version and version.startswith('${') and version.endswith('}'):
                        version = self._resolve_property(root, version[2:-1], ns, namespace)
                    
                    dep_name = f"{group_id}:{artifact_id}"
                    dependencies.append({
                        'name': dep_name,
                        'version': version or 'unknown',
                        'ecosystem': 'Maven',
                        'scope': 'managed',
                        'group_id': group_id,
                        'artifact_id': artifact_id
                    })
                        
        except ET.ParseError as e:
            print(f"[!] Error parsing Maven pom.xml: {e}")
        except Exception as e:
            print(f"[!] Error processing Maven pom.xml: {e}")
        
        return dependencies
    
    def parse_gradle_build(self, file_path: str) -> List[Dict[str, str]]:
        """Parse Gradle build.gradle file for dependencies"""
        dependencies = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Remove comments and strings to avoid false matches
            content = self._clean_gradle_content(content)
            
            # Patterns for different dependency declaration styles
            patterns = [
                # implementation 'group:artifact:version'
                r"(?:implementation|compile|api|testImplementation|testCompile|runtimeOnly|compileOnly)\s+['\"]([^:]+):([^:]+):([^'\"]+)['\"]",
                # implementation group: 'group', name: 'artifact', version: 'version'
                r"(?:implementation|compile|api|testImplementation|testCompile|runtimeOnly|compileOnly)\s+group:\s*['\"]([^'\"]+)['\"]\s*,\s*name:\s*['\"]([^'\"]+)['\"]\s*,\s*version:\s*['\"]([^'\"]+)['\"]",
                # Kotlin DSL style
                r"(?:implementation|compile|api|testImplementation|testCompile|runtimeOnly|compileOnly)\s*\(\s*['\"]([^:]+):([^:]+):([^'\"]+)['\"]\s*\)",
            ]
            
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE)
                for match in matches:
                    group_id = match.group(1).strip()
                    artifact_id = match.group(2).strip()
                    version = match.group(3).strip()
                    
                    dep_name = f"{group_id}:{artifact_id}"
                    dependencies.append({
                        'name': dep_name,
                        'version': version,
                        'ecosystem': 'Maven',  # Gradle uses Maven repository format
                        'scope': 'implementation',
                        'group_id': group_id,
                        'artifact_id': artifact_id
                    })
            
            # Handle version variables
            dependencies = self._resolve_gradle_versions(content, dependencies)
                        
        except Exception as e:
            print(f"[!] Error parsing Gradle build.gradle: {e}")
        
        return dependencies
    
    def parse_gradle_kotlin_build(self, file_path: str) -> List[Dict[str, str]]:
        """Parse Gradle build.gradle.kts (Kotlin DSL) file for dependencies"""
        dependencies = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Clean content
            content = self._clean_gradle_content(content)
            
            # Kotlin DSL specific patterns
            patterns = [
                # implementation("group:artifact:version")
                r"(?:implementation|compile|api|testImplementation|testCompile|runtimeOnly|compileOnly)\s*\(\s*\"([^:]+):([^:]+):([^\"]+)\"\s*\)",
                # implementation("group", "artifact", "version")
                r"(?:implementation|compile|api|testImplementation|testCompile|runtimeOnly|compileOnly)\s*\(\s*\"([^\"]+)\"\s*,\s*\"([^\"]+)\"\s*,\s*\"([^\"]+)\"\s*\)",
            ]
            
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE)
                for match in matches:
                    group_id = match.group(1).strip()
                    artifact_id = match.group(2).strip()
                    version = match.group(3).strip()
                    
                    dep_name = f"{group_id}:{artifact_id}"
                    dependencies.append({
                        'name': dep_name,
                        'version': version,
                        'ecosystem': 'Maven',
                        'scope': 'implementation',
                        'group_id': group_id,
                        'artifact_id': artifact_id
                    })
            
            # Handle version variables
            dependencies = self._resolve_gradle_versions(content, dependencies)
                        
        except Exception as e:
            print(f"[!] Error parsing Gradle build.gradle.kts: {e}")
        
        return dependencies
    
    def extract_java_dependencies_from_directory(self, directory: str) -> List[Dict[str, str]]:
        """Extract all Java dependencies from a directory"""
        all_dependencies = []
        
        # Find and parse Maven pom.xml files
        for pom_file in Path(directory).rglob('pom.xml'):
            print(f"[*] Found Maven pom.xml: {pom_file}")
            deps = self.parse_maven_pom(str(pom_file))
            all_dependencies.extend(deps)
        
        # Find and parse Gradle build files
        for build_file in Path(directory).rglob('build.gradle'):
            print(f"[*] Found Gradle build.gradle: {build_file}")
            deps = self.parse_gradle_build(str(build_file))
            all_dependencies.extend(deps)
        
        # Find and parse Gradle Kotlin DSL files
        for build_file in Path(directory).rglob('build.gradle.kts'):
            print(f"[*] Found Gradle build.gradle.kts: {build_file}")
            deps = self.parse_gradle_kotlin_build(str(build_file))
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
    
    def _get_text_safe(self, element) -> Optional[str]:
        """Safely get text from XML element"""
        return element.text.strip() if element is not None and element.text else None
    
    def _resolve_property(self, root, property_name: str, ns: dict, namespace: str) -> Optional[str]:
        """Resolve Maven property variables"""
        try:
            # Look in properties section
            if namespace:
                props_element = root.find('.//properties', ns)
            else:
                props_element = root.find('.//properties')
            
            if props_element is not None:
                if namespace:
                    prop_element = props_element.find(property_name, ns)
                else:
                    prop_element = props_element.find(property_name)
                
                if prop_element is not None:
                    return prop_element.text.strip()
            
            # Handle common built-in properties
            if property_name == 'project.version':
                version_elem = root.find('.//version', ns) if namespace else root.find('.//version')
                if version_elem is not None:
                    return version_elem.text.strip()
            
        except Exception:
            pass
        
        return None
    
    def _clean_gradle_content(self, content: str) -> str:
        """Remove comments and strings from Gradle content to avoid false matches"""
        # Remove single line comments
        content = re.sub(r'//.*$', '', content, flags=re.MULTILINE)
        
        # Remove multi-line comments
        content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
        
        return content
    
    def _resolve_gradle_versions(self, content: str, dependencies: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """Resolve Gradle version variables"""
        # Extract version variables
        version_vars = {}
        
        # Look for version definitions
        var_patterns = [
            r"val\s+(\w+)\s*=\s*['\"]([^'\"]+)['\"]",  # Kotlin DSL
            r"def\s+(\w+)\s*=\s*['\"]([^'\"]+)['\"]",  # Groovy
            r"(\w+)\s*=\s*['\"]([^'\"]+)['\"]",        # Simple assignment
        ]
        
        for pattern in var_patterns:
            matches = re.finditer(pattern, content, re.MULTILINE)
            for match in matches:
                var_name = match.group(1)
                var_value = match.group(2)
                version_vars[var_name] = var_value
        
        # Resolve variables in dependencies
        for dep in dependencies:
            version = dep['version']
            if version.startswith('$'):
                # Handle ${varName} or $varName
                var_name = version.replace('${', '').replace('}', '').replace('$', '')
                if var_name in version_vars:
                    dep['version'] = version_vars[var_name]
        
        return dependencies


# Global instance
java_parser = JavaParser()

def parse_java_dependencies(directory: str) -> List[Dict[str, str]]:
    """Parse Java dependencies from a directory"""
    return java_parser.extract_java_dependencies_from_directory(directory)