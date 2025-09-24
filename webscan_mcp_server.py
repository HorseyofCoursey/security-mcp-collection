#!/usr/bin/env python3
"""
WebScan MCP Server - Model Context Protocol server for web vulnerability scanning
Integrates Nikto, HTTPX, Nuclei, ffuf with intelligent wordlist management and nuclei template management
"""

import asyncio
import json
import logging
import subprocess
import tempfile
import os
import sys
import re
import requests
import hashlib
import zipfile
import tarfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union
from datetime import datetime, timedelta
import threading
import time
from urllib.parse import urljoin, urlparse

try:
    from mcp.server.models import InitializationOptions
    from mcp.server import NotificationOptions, Server
    from mcp.server.stdio import stdio_server
    from mcp.types import Tool, TextContent
except ImportError as e:
    print(f"MCP import error: {e}", file=sys.stderr)
    print("Please install the MCP library: pip install mcp>=1.12.4", file=sys.stderr)
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stderr)]
)
logger = logging.getLogger("webscan-mcp-server")

class WordlistManager:
    """Intelligent wordlist downloader and manager"""
    
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir / "wordlists"
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.seclists_dir = self.base_dir / "SecLists"
        self.miessler_dir = self.base_dir / "Miessler"
        self.custom_dir = self.base_dir / "custom"
        self.custom_dir.mkdir(parents=True, exist_ok=True)
        
        # Wordlist sources
        self.sources = {
            "seclists": {
                "url": "https://github.com/danielmiessler/SecLists.git",
                "dir": self.seclists_dir,
                "type": "git"
            },
            "miessler": {
                "url": "https://github.com/danielmiessler/RobotsDisallowed.git", 
                "dir": self.miessler_dir,
                "type": "git"
            }
        }
        
        # Common wordlist categories and their paths
        self.wordlist_catalog = {
            "directories": {
                "common": "Discovery/Web-Content/common.txt",
                "big": "Discovery/Web-Content/big.txt", 
                "directory-list-2.3-medium": "Discovery/Web-Content/directory-list-2.3-medium.txt",
                "directory-list-2.3-small": "Discovery/Web-Content/directory-list-2.3-small.txt",
                "raft-medium-directories": "Discovery/Web-Content/raft-medium-directories.txt",
                "raft-small-directories": "Discovery/Web-Content/raft-small-directories.txt",
                "quickhits": "Discovery/Web-Content/quickhits.txt"
            },
            "files": {
                "common": "Discovery/Web-Content/common.txt",
                "raft-medium-files": "Discovery/Web-Content/raft-medium-files.txt",
                "raft-small-files": "Discovery/Web-Content/raft-small-files.txt",
                "common-extensions": "Discovery/Web-Content/web-extensions.txt"
            },
            "subdomains": {
                "subdomains-top1million-5000": "Discovery/DNS/subdomains-top1million-5000.txt",
                "subdomains-top1million-20000": "Discovery/DNS/subdomains-top1million-20000.txt",
                "fierce-hostlist": "Discovery/DNS/fierce-hostlist.txt"
            },
            "parameters": {
                "burp-parameter-names": "Discovery/Web-Content/burp-parameter-names.txt",
                "common-parameters": "Discovery/Web-Content/common-parameters.txt"
            },
            "usernames": {
                "common-usernames": "Usernames/xato-net-10-million-usernames.txt",
                "top-usernames-shortlist": "Usernames/top-usernames-shortlist.txt"
            },
            "passwords": {
                "rockyou": "Passwords/Leaked-Databases/rockyou.txt",
                "common-passwords": "Passwords/Common-Credentials/10-million-password-list-top-1000000.txt",
                "darkweb2017-top10000": "Passwords/Leaked-Databases/darkweb2017-top10000.txt"
            }
        }

    async def check_wordlist_availability(self) -> Dict[str, Any]:
        """Check which wordlists are available locally and which can be downloaded"""
        available = {}
        missing = {}
        
        for category, wordlists in self.wordlist_catalog.items():
            available[category] = {}
            missing[category] = {}
            
            for name, path in wordlists.items():
                full_path = self.seclists_dir / path
                if full_path.exists():
                    size = full_path.stat().st_size
                    available[category][name] = {
                        "path": str(full_path),
                        "size": size,
                        "size_mb": round(size / 1024 / 1024, 2)
                    }
                else:
                    missing[category][name] = {
                        "path": str(full_path),
                        "relative_path": path
                    }
        
        return {
            "available": available,
            "missing": missing,
            "seclists_installed": self.seclists_dir.exists(),
            "total_available": sum(len(cat.keys()) for cat in available.values()),
            "total_missing": sum(len(cat.keys()) for cat in missing.values())
        }

    async def install_seclists(self) -> Dict[str, Any]:
        """Download and install SecLists repository"""
        try:
            logger.info("Installing SecLists repository...")
            
            # Check if git is available
            git_check = await asyncio.create_subprocess_exec(
                'git', '--version',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await git_check.wait()
            
            if git_check.returncode != 0:
                return {
                    "success": False,
                    "error": "Git is not installed. Please install git first."
                }
            
            # Clone SecLists repository
            if self.seclists_dir.exists():
                # Update existing repository
                process = await asyncio.create_subprocess_exec(
                    'git', 'pull',
                    cwd=self.seclists_dir,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
            else:
                # Clone new repository
                process = await asyncio.create_subprocess_exec(
                    'git', 'clone', '--depth', '1', 
                    'https://github.com/danielmiessler/SecLists.git',
                    str(self.seclists_dir),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                # Create quick access symlinks for common wordlists
                await self.create_quick_access_links()
                
                return {
                    "success": True,
                    "message": "SecLists installed successfully",
                    "path": str(self.seclists_dir),
                    "stdout": stdout.decode(),
                    "stderr": stderr.decode()
                }
            else:
                return {
                    "success": False,
                    "error": f"Git operation failed: {stderr.decode()}",
                    "stdout": stdout.decode()
                }
                
        except Exception as e:
            logger.error(f"Error installing SecLists: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    async def create_quick_access_links(self):
        """Create symlinks for commonly used wordlists"""
        try:
            quick_dir = self.base_dir / "quick"
            quick_dir.mkdir(exist_ok=True)
            
            # Common quick access wordlists
            quick_links = {
                "common-dirs.txt": "Discovery/Web-Content/common.txt",
                "big-dirs.txt": "Discovery/Web-Content/big.txt",
                "medium-dirs.txt": "Discovery/Web-Content/directory-list-2.3-medium.txt",
                "small-dirs.txt": "Discovery/Web-Content/directory-list-2.3-small.txt",
                "subdomains-5k.txt": "Discovery/DNS/subdomains-top1million-5000.txt",
                "subdomains-20k.txt": "Discovery/DNS/subdomains-top1million-20000.txt",
                "common-files.txt": "Discovery/Web-Content/raft-medium-files.txt",
                "common-params.txt": "Discovery/Web-Content/burp-parameter-names.txt"
            }
            
            for link_name, target_path in quick_links.items():
                link_path = quick_dir / link_name
                target_full_path = self.seclists_dir / target_path
                
                if target_full_path.exists() and not link_path.exists():
                    try:
                        link_path.symlink_to(target_full_path)
                        logger.info(f"Created quick access link: {link_name}")
                    except Exception as e:
                        logger.warning(f"Could not create symlink {link_name}: {e}")
                        
        except Exception as e:
            logger.warning(f"Error creating quick access links: {e}")

    async def download_custom_wordlist(self, url: str, name: str) -> Dict[str, Any]:
        """Download a custom wordlist from URL"""
        try:
            logger.info(f"Downloading custom wordlist: {name}")
            
            response = requests.get(url, stream=True, timeout=30)
            response.raise_for_status()
            
            file_path = self.custom_dir / f"{name}.txt"
            
            with open(file_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            size = file_path.stat().st_size
            
            return {
                "success": True,
                "message": f"Downloaded {name} successfully",
                "path": str(file_path),
                "size": size,
                "size_mb": round(size / 1024 / 1024, 2)
            }
            
        except Exception as e:
            logger.error(f"Error downloading custom wordlist: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def get_wordlist_path(self, category: str, name: str) -> Optional[str]:
        """Get the full path to a wordlist"""
        if category in self.wordlist_catalog and name in self.wordlist_catalog[category]:
            path = self.seclists_dir / self.wordlist_catalog[category][name]
            if path.exists():
                return str(path)
        
        # Check in quick access directory
        quick_path = self.base_dir / "quick" / f"{name}.txt"
        if quick_path.exists():
            return str(quick_path)
        
        # Check in custom directory
        custom_path = self.custom_dir / f"{name}.txt"
        if custom_path.exists():
            return str(custom_path)
        
        return None

    async def suggest_wordlist(self, scan_type: str, target_size: str = "medium") -> Dict[str, Any]:
        """Suggest appropriate wordlist based on scan type and target size"""
        suggestions = {
            "directory": {
                "small": {"category": "directories", "name": "directory-list-2.3-small"},
                "medium": {"category": "directories", "name": "directory-list-2.3-medium"},
                "large": {"category": "directories", "name": "big"}
            },
            "file": {
                "small": {"category": "files", "name": "raft-small-files"},
                "medium": {"category": "files", "name": "raft-medium-files"},
                "large": {"category": "files", "name": "common"}
            },
            "subdomain": {
                "small": {"category": "subdomains", "name": "fierce-hostlist"},
                "medium": {"category": "subdomains", "name": "subdomains-top1million-5000"},
                "large": {"category": "subdomains", "name": "subdomains-top1million-20000"}
            },
            "parameter": {
                "small": {"category": "parameters", "name": "common-parameters"},
                "medium": {"category": "parameters", "name": "burp-parameter-names"},
                "large": {"category": "parameters", "name": "burp-parameter-names"}
            }
        }
        
        if scan_type in suggestions and target_size in suggestions[scan_type]:
            suggestion = suggestions[scan_type][target_size]
            path = self.get_wordlist_path(suggestion["category"], suggestion["name"])
            
            return {
                "success": True,
                "suggestion": suggestion,
                "path": path,
                "available": path is not None
            }
        
        return {
            "success": False,
            "error": f"No suggestion available for {scan_type} scan with {target_size} target"
        }

class NucleiManager:
    """Nuclei template manager for keeping templates up-to-date"""
    
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir / "nuclei"
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.templates_dir = self.base_dir / "templates"
        self.custom_templates_dir = self.base_dir / "custom-templates"
        self.custom_templates_dir.mkdir(parents=True, exist_ok=True)
        
        # Template sources
        self.template_sources = {
            "official": "https://github.com/projectdiscovery/nuclei-templates.git",
            "community": "https://github.com/geeknik/nuclei-templates-community.git",
            "fuzzing": "https://github.com/projectdiscovery/fuzzing-templates.git"
        }
        
        # Template categories for easy selection
        self.template_categories = {
            "web": ["cves", "vulnerabilities", "misconfiguration", "default-logins"],
            "network": ["network", "dns", "ssl"],
            "cloud": ["cloud", "aws", "azure", "gcp"],
            "technologies": ["tech", "detections"],
            "exposures": ["exposures", "files", "panels"],
            "all": ["*"]
        }

    async def check_nuclei_installation(self) -> Dict[str, Any]:
        """Check nuclei installation and template status"""
        try:
            # Check nuclei binary
            version_result = await asyncio.create_subprocess_exec(
                'nuclei', '-version',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await version_result.communicate()
            
            nuclei_info = {
                "nuclei_installed": version_result.returncode == 0,
                "version": stdout.decode().strip() if version_result.returncode == 0 else None
            }
            
            # Check template status
            template_info = await self.get_template_info()
            nuclei_info.update(template_info)
            
            return nuclei_info
            
        except Exception as e:
            logger.error(f"Error checking nuclei installation: {e}")
            return {
                "nuclei_installed": False,
                "error": str(e)
            }

    async def get_template_info(self) -> Dict[str, Any]:
        """Get information about current templates"""
        try:
            # Run nuclei template list to get current stats
            list_result = await asyncio.create_subprocess_exec(
                'nuclei', '-tl',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await list_result.communicate()
            
            if list_result.returncode == 0:
                output = stdout.decode()
                
                # Count templates by type
                template_counts = {}
                total_templates = 0
                
                for line in output.split('\n'):
                    if '.yaml' in line or '.yml' in line:
                        total_templates += 1
                        # Extract category from path
                        if '/' in line:
                            category = line.split('/')[0].strip()
                            template_counts[category] = template_counts.get(category, 0) + 1
                
                # Get last update time from templates directory
                templates_path = Path.home() / "nuclei-templates"
                last_update = None
                if templates_path.exists():
                    stat = templates_path.stat()
                    last_update = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                
                return {
                    "templates_available": True,
                    "total_templates": total_templates,
                    "template_counts": template_counts,
                    "last_update": last_update,
                    "templates_path": str(templates_path)
                }
            else:
                return {
                    "templates_available": False,
                    "error": "Could not list templates"
                }
                
        except Exception as e:
            logger.error(f"Error getting template info: {e}")
            return {
                "templates_available": False,
                "error": str(e)
            }

    async def update_nuclei_templates(self, force_update: bool = False) -> Dict[str, Any]:
        """Update nuclei templates to latest version"""
        try:
            logger.info("Updating nuclei templates...")
            
            # Use nuclei's built-in template update
            cmd = ['nuclei', '-update-templates']
            if force_update:
                cmd.append('-update-template-dir')
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            stdout_text = stdout.decode('utf-8', errors='replace')
            stderr_text = stderr.decode('utf-8', errors='replace')
            
            if process.returncode == 0:
                # Get updated template info
                template_info = await self.get_template_info()
                
                return {
                    "success": True,
                    "message": "Templates updated successfully",
                    "stdout": stdout_text,
                    "stderr": stderr_text,
                    "template_info": template_info
                }
            else:
                return {
                    "success": False,
                    "error": f"Template update failed: {stderr_text}",
                    "stdout": stdout_text
                }
                
        except Exception as e:
            logger.error(f"Error updating nuclei templates: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    async def download_custom_templates(self, repo_url: str, name: str) -> Dict[str, Any]:
        """Download custom nuclei templates from a git repository"""
        try:
            custom_dir = self.custom_templates_dir / name
            
            if custom_dir.exists():
                # Update existing repository
                process = await asyncio.create_subprocess_exec(
                    'git', 'pull',
                    cwd=custom_dir,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
            else:
                # Clone new repository
                process = await asyncio.create_subprocess_exec(
                    'git', 'clone', repo_url, str(custom_dir),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                # Count templates in the custom directory
                template_count = len(list(custom_dir.rglob("*.yaml"))) + len(list(custom_dir.rglob("*.yml")))
                
                return {
                    "success": True,
                    "message": f"Custom templates downloaded: {name}",
                    "path": str(custom_dir),
                    "template_count": template_count,
                    "stdout": stdout.decode(),
                    "stderr": stderr.decode()
                }
            else:
                return {
                    "success": False,
                    "error": f"Git operation failed: {stderr.decode()}",
                    "stdout": stdout.decode()
                }
                
        except Exception as e:
            logger.error(f"Error downloading custom templates: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def get_template_suggestions(self, scan_type: str, severity: str = "medium") -> Dict[str, Any]:
        """Suggest appropriate nuclei templates based on scan type"""
        suggestions = {
            "web_app": {
                "tags": ["xss", "sqli", "rce", "lfi", "ssrf"],
                "paths": ["vulnerabilities/", "cves/", "default-logins/"],
                "severity": ["medium", "high", "critical"]
            },
            "infrastructure": {
                "tags": ["network", "dns", "ssl", "misconfig"],
                "paths": ["network/", "dns/", "ssl/", "misconfiguration/"],
                "severity": ["low", "medium", "high", "critical"]
            },
            "cloud": {
                "tags": ["aws", "azure", "gcp", "cloud"],
                "paths": ["cloud/", "aws/", "azure/", "gcp/"],
                "severity": ["medium", "high", "critical"]
            },
            "api": {
                "tags": ["api", "graphql", "rest"],
                "paths": ["vulnerabilities/", "misconfiguration/"],
                "severity": ["medium", "high", "critical"]
            },
            "iot": {
                "tags": ["iot", "router", "camera"],
                "paths": ["iot/", "default-logins/"],
                "severity": ["medium", "high", "critical"]
            }
        }
        
        if scan_type in suggestions:
            suggestion = suggestions[scan_type]
            
            # Filter by severity
            severity_levels = {
                "low": ["info", "low", "medium", "high", "critical"],
                "medium": ["medium", "high", "critical"],
                "high": ["high", "critical"],
                "critical": ["critical"]
            }
            
            suggested_severity = severity_levels.get(severity, ["medium", "high", "critical"])
            
            return {
                "success": True,
                "scan_type": scan_type,
                "suggested_tags": suggestion["tags"],
                "suggested_paths": suggestion["paths"],
                "suggested_severity": suggested_severity,
                "template_args": {
                    "tags": suggestion["tags"][:3],  # Limit to 3 tags
                    "severity": suggested_severity
                }
            }
        
        return {
            "success": False,
            "error": f"No suggestions available for scan type: {scan_type}"
        }

    async def validate_templates(self, template_paths: List[str] = None) -> Dict[str, Any]:
        """Validate nuclei templates for syntax errors"""
        try:
            cmd = ['nuclei', '-validate']
            if template_paths:
                for path in template_paths:
                    cmd.extend(['-t', path])
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            stdout_text = stdout.decode('utf-8', errors='replace')
            stderr_text = stderr.decode('utf-8', errors='replace')
            
            return {
                "success": process.returncode == 0,
                "validation_output": stdout_text,
                "errors": stderr_text,
                "return_code": process.returncode
            }
            
        except Exception as e:
            logger.error(f"Error validating templates: {e}")
            return {
                "success": False,
                "error": str(e)
            }

class WebScanMCPServer:
    """MCP Server for web vulnerability scanning tools"""
    
    def __init__(self):
        self.server = Server("webscan-mcp-server")
        self.output_dir = Path.home() / ".webscan_mcp" / "output"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize managers
        self.wordlist_manager = WordlistManager(Path.home() / ".webscan_mcp")
        self.nuclei_manager = NucleiManager(Path.home() / ".webscan_mcp")
        
        # Detect available tools
        self.tools = self.detect_available_tools()
        self.setup_handlers()
        
    def detect_available_tools(self) -> Dict[str, Dict[str, Any]]:
        """Detect which web scanning tools are available"""
        tools = {}
        
        # Check for ffuf
        try:
            result = subprocess.run(['ffuf', '-V'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                which_result = subprocess.run(['which', 'ffuf'], capture_output=True, text=True)
                tools['ffuf'] = {
                    'path': which_result.stdout.strip(),
                    'version': result.stdout.strip(),
                    'available': True
                }
                logger.info(f"Found ffuf: {tools['ffuf']['path']}")
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
            tools['ffuf'] = {'available': False}
        
        # Check for httpx
        try:
            result = subprocess.run(['httpx', '-version'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                which_result = subprocess.run(['which', 'httpx'], capture_output=True, text=True)
                tools['httpx'] = {
                    'path': which_result.stdout.strip(),
                    'version': result.stderr.strip() if result.stderr else result.stdout.strip(),
                    'available': True
                }
                logger.info(f"Found httpx: {tools['httpx']['path']}")
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
            tools['httpx'] = {'available': False}
        
        # Check for nuclei
        try:
            result = subprocess.run(['nuclei', '-version'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                which_result = subprocess.run(['which', 'nuclei'], capture_output=True, text=True)
                tools['nuclei'] = {
                    'path': which_result.stdout.strip(),
                    'version': result.stdout.strip(),
                    'available': True
                }
                logger.info(f"Found nuclei: {tools['nuclei']['path']}")
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
            tools['nuclei'] = {'available': False}
        
        # Check for nikto
        try:
            result = subprocess.run(['nikto', '-Version'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0 or 'Nikto' in result.stdout:
                which_result = subprocess.run(['which', 'nikto'], capture_output=True, text=True)
                tools['nikto'] = {
                    'path': which_result.stdout.strip(),
                    'version': result.stdout.split('\n')[0] if result.stdout else 'Available',
                    'available': True
                }
                logger.info(f"Found nikto: {tools['nikto']['path']}")
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
            tools['nikto'] = {'available': False}
        
        # Check for gobuster
        try:
            result = subprocess.run(['gobuster', 'version'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                which_result = subprocess.run(['which', 'gobuster'], capture_output=True, text=True)
                tools['gobuster'] = {
                    'path': which_result.stdout.strip(),
                    'version': result.stdout.strip(),
                    'available': True
                }
                logger.info(f"Found gobuster: {tools['gobuster']['path']}")
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
            tools['gobuster'] = {'available': False}
        
        available_tools = [name for name, info in tools.items() if info.get('available')]
        logger.info(f"Available web scanning tools: {available_tools}")
        
        return tools

    async def run_ffuf_scan(self, url: str, wordlist: str, mode: str = "dir", 
                           extensions: List[str] = None, filters: Dict[str, Any] = None,
                           threads: int = 40, timeout: int = 300) -> Dict[str, Any]:
        """Run ffuf directory/file fuzzing"""
        try:
            scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.output_dir / f"ffuf_{scan_id}.json"
            
            # Build ffuf command
            cmd = ['ffuf', '-u', url, '-w', wordlist, '-o', str(output_file), '-of', 'json', '-t', str(threads)]
            
            # Add mode-specific options
            if mode == "dir":
                if not url.endswith('/'):
                    url += '/'
                cmd[cmd.index('-u') + 1] = url + 'FUZZ'
            elif mode == "file":
                if extensions:
                    cmd.extend(['-e', ','.join(extensions)])
                if '.' not in url.split('/')[-1]:
                    cmd[cmd.index('-u') + 1] = url + '/FUZZ'
                else:
                    cmd[cmd.index('-u') + 1] = url.replace(url.split('/')[-1], 'FUZZ')
            elif mode == "subdomain":
                cmd[cmd.index('-u') + 1] = url.replace('://', '://FUZZ.')
            elif mode == "parameter":
                cmd[cmd.index('-u') + 1] = url + '?FUZZ=test'
                cmd.extend(['-X', 'GET,POST'])
            
            # Add filters
            if filters:
                for filter_type, value in filters.items():
                    if filter_type == "status":
                        cmd.extend(['-mc', str(value)])
                    elif filter_type == "size":
                        cmd.extend(['-fs', str(value)])
                    elif filter_type == "words":
                        cmd.extend(['-fw', str(value)])
                    elif filter_type == "lines":
                        cmd.extend(['-fl', str(value)])
            else:
                # Default filters to reduce noise
                cmd.extend(['-mc', '200,204,301,302,307,401,403,405,500'])
            
            logger.info(f"Running ffuf: {' '.join(cmd[:8])}...")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), 
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                return {
                    'success': False,
                    'error': f'ffuf scan timed out after {timeout} seconds'
                }
            
            stdout_text = stdout.decode('utf-8', errors='replace')
            stderr_text = stderr.decode('utf-8', errors='replace')
            
            # Parse JSON output
            results = []
            if output_file.exists():
                try:
                    with open(output_file, 'r') as f:
                        json_data = json.load(f)
                        results = json_data.get('results', [])
                except Exception as e:
                    logger.error(f"Error parsing ffuf JSON output: {e}")
            
            return {
                'success': process.returncode == 0,
                'stdout': stdout_text,
                'stderr': stderr_text,
                'results': results,
                'results_count': len(results),
                'return_code': process.returncode,
                'scan_id': scan_id,
                'output_file': str(output_file),
                'mode': mode,
                'target': url,
                'wordlist': wordlist
            }
            
        except Exception as e:
            logger.error(f"Error running ffuf: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    async def run_httpx_scan(self, targets: List[str], options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Run httpx for HTTP probing and discovery"""
        try:
            scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.output_dir / f"httpx_{scan_id}.json"
            
            # Create temporary input file
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as tmp:
                for target in targets:
                    tmp.write(f"{target}\n")
                input_file = tmp.name
            
            # Build httpx command
            cmd = ['httpx', '-l', input_file, '-o', str(output_file), '-json']
            
            # Add options
            if options:
                if options.get('follow_redirects'):
                    cmd.append('-fr')
                if options.get('status_code'):
                    cmd.extend(['-sc'])
                if options.get('content_length'):
                    cmd.extend(['-cl'])
                if options.get('title'):
                    cmd.extend(['-title'])
                if options.get('tech_detect'):
                    cmd.extend(['-tech-detect'])
                if options.get('ports'):
                    cmd.extend(['-ports', ','.join(map(str, options['ports']))])
                if options.get('threads'):
                    cmd.extend(['-threads', str(options['threads'])])
                else:
                    cmd.extend(['-threads', '50'])
            else:
                # Default options
                cmd.extend(['-sc', '-cl', '-title', '-tech-detect', '-threads', '50'])
            
            logger.info(f"Running httpx on {len(targets)} targets...")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            # Clean up temporary file
            os.unlink(input_file)
            
            stdout_text = stdout.decode('utf-8', errors='replace')
            stderr_text = stderr.decode('utf-8', errors='replace')
            
            # Parse JSON output
            results = []
            if output_file.exists():
                try:
                    with open(output_file, 'r') as f:
                        for line in f:
                            if line.strip():
                                results.append(json.loads(line.strip()))
                except Exception as e:
                    logger.error(f"Error parsing httpx JSON output: {e}")
            
            return {
                'success': process.returncode == 0,
                'stdout': stdout_text,
                'stderr': stderr_text,
                'results': results,
                'results_count': len(results),
                'return_code': process.returncode,
                'scan_id': scan_id,
                'output_file': str(output_file),
                'targets': targets
            }
            
        except Exception as e:
            logger.error(f"Error running httpx: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    async def run_nuclei_scan(self, targets: List[str], templates: List[str] = None, 
                             severity: List[str] = None, tags: List[str] = None,
                             auto_update: bool = True) -> Dict[str, Any]:
        """Run nuclei vulnerability scanning with optional auto-update"""
        try:
            # Auto-update templates if requested and they're older than 7 days
            if auto_update:
                status = await self.nuclei_manager.check_nuclei_installation()
                if status.get('last_update'):
                    try:
                        last_update = datetime.strptime(status['last_update'], "%Y-%m-%d %H:%M:%S")
                        if (datetime.now() - last_update).days > 7:
                            logger.info("Templates are older than 7 days, updating...")
                            update_result = await self.nuclei_manager.update_nuclei_templates()
                            if not update_result['success']:
                                logger.warning(f"Template update failed: {update_result['error']}")
                    except Exception as e:
                        logger.warning(f"Could not check template age: {e}")
            
            scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.output_dir / f"nuclei_{scan_id}.json"
            
            # Create temporary input file
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as tmp:
                for target in targets:
                    tmp.write(f"{target}\n")
                input_file = tmp.name
            
            # Build nuclei command
            cmd = ['nuclei', '-l', input_file, '-o', str(output_file), '-json']
            
            # Add template options
            if templates:
                cmd.extend(['-t', ','.join(templates)])
            
            # Add severity filter
            if severity:
                cmd.extend(['-severity', ','.join(severity)])
            else:
                cmd.extend(['-severity', 'low,medium,high,critical'])
            
            # Add tag filter
            if tags:
                cmd.extend(['-tags', ','.join(tags)])
            
            # Performance options
            cmd.extend(['-c', '50', '-timeout', '10'])
            
            logger.info(f"Running nuclei on {len(targets)} targets...")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            # Clean up temporary file
            os.unlink(input_file)
            
            stdout_text = stdout.decode('utf-8', errors='replace')
            stderr_text = stderr.decode('utf-8', errors='replace')
            
            # Parse JSON output
            results = []
            if output_file.exists():
                try:
                    with open(output_file, 'r') as f:
                        for line in f:
                            if line.strip():
                                results.append(json.loads(line.strip()))
                except Exception as e:
                    logger.error(f"Error parsing nuclei JSON output: {e}")
            
            return {
                'success': process.returncode == 0,
                'stdout': stdout_text,
                'stderr': stderr_text,
                'results': results,
                'results_count': len(results),
                'return_code': process.returncode,
                'scan_id': scan_id,
                'output_file': str(output_file),
                'targets': targets
            }
            
        except Exception as e:
            logger.error(f"Error running nuclei: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    async def run_nikto_scan(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Run nikto web vulnerability scan"""
        try:
            scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.output_dir / f"nikto_{scan_id}.txt"
            
            # Build nikto command
            cmd = ['nikto', '-h', target, '-output', str(output_file)]
            
            # Add options
            if options:
                if options.get('ssl'):
                    cmd.append('-ssl')
                if options.get('port'):
                    cmd.extend(['-port', str(options['port'])])
                if options.get('plugins'):
                    cmd.extend(['-Plugins', options['plugins']])
            
            logger.info(f"Running nikto on {target}...")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            stdout_text = stdout.decode('utf-8', errors='replace')
            stderr_text = stderr.decode('utf-8', errors='replace')
            
            # Read output file
            output_content = ""
            if output_file.exists():
                try:
                    with open(output_file, 'r') as f:
                        output_content = f.read()
                except Exception as e:
                    logger.error(f"Error reading nikto output: {e}")
            
            return {
                'success': process.returncode == 0,
                'stdout': stdout_text,
                'stderr': stderr_text,
                'output_content': output_content,
                'return_code': process.returncode,
                'scan_id': scan_id,
                'output_file': str(output_file),
                'target': target
            }
            
        except Exception as e:
            logger.error(f"Error running nikto: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    def setup_handlers(self):
        """Setup MCP server handlers"""
        
        @self.server.list_tools()
        async def handle_list_tools() -> List[Tool]:
            """List available web scanning tools"""
            return [
                Tool(
                    name="ffuf_directory_scan",
                    description="Fuzz directories and files using ffuf with intelligent wordlist selection",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "url": {
                                "type": "string",
                                "description": "Target URL to scan"
                            },
                            "wordlist": {
                                "type": "string",
                                "description": "Wordlist name or 'auto' for automatic selection"
                            },
                            "mode": {
                                "type": "string",
                                "enum": ["dir", "file", "subdomain", "parameter"],
                                "description": "Fuzzing mode",
                                "default": "dir"
                            },
                            "extensions": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "File extensions to fuzz (for file mode)"
                            },
                            "size": {
                                "type": "string",
                                "enum": ["small", "medium", "large"],
                                "description": "Wordlist size preference",
                                "default": "medium"
                            },
                            "threads": {
                                "type": "integer",
                                "description": "Number of threads",
                                "default": 40
                            }
                        },
                        "required": ["url"]
                    }
                ),
                Tool(
                    name="httpx_discovery",
                    description="Probe URLs with httpx for HTTP discovery and reconnaissance",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "targets": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "List of target URLs/domains"
                            },
                            "ports": {
                                "type": "array", 
                                "items": {"type": "integer"},
                                "description": "Ports to probe"
                            },
                            "follow_redirects": {
                                "type": "boolean",
                                "description": "Follow redirects",
                                "default": True
                            },
                            "tech_detect": {
                                "type": "boolean",
                                "description": "Detect technologies",
                                "default": True
                            }
                        },
                        "required": ["targets"]
                    }
                ),
                Tool(
                    name="nuclei_vulnerability_scan",
                    description="Run nuclei vulnerability scans with template selection and auto-updates",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "targets": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "List of target URLs"
                            },
                            "severity": {
                                "type": "array",
                                "items": {
                                    "type": "string",
                                    "enum": ["info", "low", "medium", "high", "critical"]
                                },
                                "description": "Severity levels to scan for"
                            },
                            "tags": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Template tags to include"
                            },
                            "auto_update": {
                                "type": "boolean",
                                "description": "Auto-update templates if older than 7 days",
                                "default": True
                            }
                        },
                        "required": ["targets"]
                    }
                ),
                Tool(
                    name="nikto_web_scan",
                    description="Run comprehensive nikto web vulnerability scan",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "target": {
                                "type": "string",
                                "description": "Target URL to scan"
                            },
                            "ssl": {
                                "type": "boolean",
                                "description": "Use SSL/HTTPS",
                                "default": False
                            },
                            "port": {
                                "type": "integer",
                                "description": "Target port"
                            }
                        },
                        "required": ["target"]
                    }
                ),
                Tool(
                    name="comprehensive_web_scan",
                    description="Run comprehensive web scan combining multiple tools",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "target": {
                                "type": "string", 
                                "description": "Target URL or domain"
                            },
                            "include_vuln_scan": {
                                "type": "boolean",
                                "description": "Include vulnerability scanning",
                                "default": True
                            },
                            "include_directory_scan": {
                                "type": "boolean",
                                "description": "Include directory fuzzing",
                                "default": True
                            },
                            "scan_intensity": {
                                "type": "string",
                                "enum": ["light", "normal", "aggressive"],
                                "description": "Scan intensity level",
                                "default": "normal"
                            }
                        },
                        "required": ["target"]
                    }
                ),
                Tool(
                    name="manage_wordlists",
                    description="Manage wordlists: check availability, install, download custom",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "action": {
                                "type": "string",
                                "enum": ["check", "install", "download", "suggest"],
                                "description": "Action to perform"
                            },
                            "url": {
                                "type": "string",
                                "description": "URL for custom wordlist download"
                            },
                            "name": {
                                "type": "string",
                                "description": "Name for custom wordlist"
                            },
                            "scan_type": {
                                "type": "string",
                                "enum": ["directory", "file", "subdomain", "parameter"],
                                "description": "Scan type for wordlist suggestion"
                            },
                            "size": {
                                "type": "string",
                                "enum": ["small", "medium", "large"],
                                "description": "Preferred wordlist size"
                            }
                        },
                        "required": ["action"]
                    }
                ),
                Tool(
                    name="manage_nuclei_templates",
                    description="Manage nuclei templates: check status, update, download custom",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "action": {
                                "type": "string",
                                "enum": ["check", "update", "download", "suggest", "validate"],
                                "description": "Action to perform"
                            },
                            "repo_url": {
                                "type": "string",
                                "description": "Git repository URL for custom templates"
                            },
                            "name": {
                                "type": "string",
                                "description": "Name for custom template collection"
                            },
                            "scan_type": {
                                "type": "string",
                                "enum": ["web_app", "infrastructure", "cloud", "api", "iot"],
                                "description": "Type of scan for template suggestions"
                            },
                            "severity": {
                                "type": "string",
                                "enum": ["low", "medium", "high", "critical"],
                                "description": "Minimum severity level for suggestions"
                            },
                            "force_update": {
                                "type": "boolean",
                                "description": "Force template directory update",
                                "default": False
                            }
                        },
                        "required": ["action"]
                    }
                ),
                Tool(
                    name="check_webscan_tools",
                    description="Check which web scanning tools are available",
                    inputSchema={
                        "type": "object",
                        "properties": {}
                    }
                )
            ]

        @self.server.call_tool()
        async def handle_call_tool(name: str, arguments: dict) -> List[Any]:
            """Handle tool calls"""
            try:
                if name == "check_webscan_tools":
                    return await self.format_tools_status()
                
                elif name == "manage_wordlists":
                    return await self.handle_wordlist_management(arguments)
                
                elif name == "manage_nuclei_templates":
                    return await self.handle_nuclei_management(arguments)
                
                elif name == "ffuf_directory_scan":
                    return await self.handle_ffuf_scan(arguments)
                
                elif name == "httpx_discovery":
                    return await self.handle_httpx_scan(arguments)
                
                elif name == "nuclei_vulnerability_scan":
                    return await self.handle_nuclei_scan(arguments)
                
                elif name == "nikto_web_scan":
                    return await self.handle_nikto_scan(arguments)
                
                elif name == "comprehensive_web_scan":
                    return await self.handle_comprehensive_scan(arguments)
                
                else:
                    raise ValueError(f"Unknown tool: {name}")
                    
            except Exception as e:
                logger.error(f"Error in tool call {name}: {e}")
                return [TextContent(type="text", text=f"Error: {str(e)}")]

    async def format_tools_status(self) -> List[TextContent]:
        """Format web scanning tools status"""
        response = "🌐 Web Scanning Tools Status:\n\n"
        
        for tool_name, tool_info in self.tools.items():
            if tool_info.get('available'):
                status = "✅"
                details = f"{tool_info['path']}"
                if 'version' in tool_info:
                    details += f"\n    Version: {tool_info['version']}"
            else:
                status = "❌"
                details = "Not installed"
            
            response += f"{status} {tool_name}: {details}\n"
        
        response += "\n📝 Installation Notes:\n"
        response += "• ffuf: go install github.com/ffuf/ffuf@latest\n"
        response += "• httpx: go install github.com/projectdiscovery/httpx/cmd/httpx@latest\n"
        response += "• nuclei: go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest\n"
        response += "• nikto: apt install nikto\n"
        response += "• gobuster: apt install gobuster\n"
        
        return [TextContent(type="text", text=response)]

    async def handle_wordlist_management(self, arguments: dict) -> List[TextContent]:
        """Handle wordlist management operations"""
        action = arguments.get("action")
        
        if action == "check":
            status = await self.wordlist_manager.check_wordlist_availability()
            response = "📚 Wordlist Status:\n\n"
            response += f"SecLists installed: {'✅' if status['seclists_installed'] else '❌'}\n"
            response += f"Available wordlists: {status['total_available']}\n"
            response += f"Missing wordlists: {status['total_missing']}\n\n"
            
            if status['total_available'] > 0:
                response += "📋 Available by category:\n"
                for category, lists in status['available'].items():
                    if lists:
                        response += f"• {category}: {len(lists)} lists\n"
            
            if status['total_missing'] > 0:
                response += "\n❓ Missing categories:\n"
                for category, lists in status['missing'].items():
                    if lists:
                        response += f"• {category}: {len(lists)} lists\n"
                response += "\nRun 'install' action to download SecLists.\n"
        
        elif action == "install":
            result = await self.wordlist_manager.install_seclists()
            if result['success']:
                response = f"✅ {result['message']}\n"
                response += f"📁 Installed to: {result['path']}\n"
                # Check status after installation
                status = await self.wordlist_manager.check_wordlist_availability()
                response += f"📚 Now available: {status['total_available']} wordlists\n"
            else:
                response = f"❌ Installation failed: {result['error']}\n"
        
        elif action == "download":
            url = arguments.get("url")
            name = arguments.get("name")
            if not url or not name:
                response = "❌ Both 'url' and 'name' are required for custom download\n"
            else:
                result = await self.wordlist_manager.download_custom_wordlist(url, name)
                if result['success']:
                    response = f"✅ {result['message']}\n"
                    response += f"📁 Saved to: {result['path']}\n"
                    response += f"📊 Size: {result['size_mb']} MB\n"
                else:
                    response = f"❌ Download failed: {result['error']}\n"
        
        elif action == "suggest":
            scan_type = arguments.get("scan_type", "directory")
            size = arguments.get("size", "medium")
            result = await self.wordlist_manager.suggest_wordlist(scan_type, size)
            if result['success']:
                suggestion = result['suggestion']
                response = f"💡 Suggested wordlist for {scan_type} scan ({size}):\n"
                response += f"📋 Category: {suggestion['category']}\n"
                response += f"📝 Name: {suggestion['name']}\n"
                response += f"📁 Available: {'✅' if result['available'] else '❌'}\n"
                if result['path']:
                    response += f"🗂️ Path: {result['path']}\n"
                else:
                    response += "⚠️ Wordlist not found. Run 'install' action first.\n"
            else:
                response = f"❌ {result['error']}\n"
        
        else:
            response = "❌ Unknown action. Use: check, install, download, or suggest\n"
        
        return [TextContent(type="text", text=response)]

    async def handle_nuclei_management(self, arguments: dict) -> List[TextContent]:
        """Handle nuclei template management operations"""
        action = arguments.get("action")
        
        if action == "check":
            status = await self.nuclei_manager.check_nuclei_installation()
            response = "🔍 Nuclei Template Status:\n\n"
            
            if status.get("nuclei_installed"):
                response += f"✅ Nuclei installed: {status.get('version', 'Unknown version')}\n"
                
                if status.get("templates_available"):
                    response += f"📚 Templates available: {status.get('total_templates', 0)}\n"
                    response += f"📁 Templates path: {status.get('templates_path', 'Unknown')}\n"
                    response += f"🕒 Last update: {status.get('last_update', 'Unknown')}\n\n"
                    
                    template_counts = status.get('template_counts', {})
                    if template_counts:
                        response += "📊 Templates by category:\n"
                        for category, count in sorted(template_counts.items()):
                            response += f"  • {category}: {count}\n"
                else:
                    response += "❌ Templates not available - run 'update' action\n"
            else:
                response += "❌ Nuclei not installed\n"
        
        elif action == "update":
            force_update = arguments.get("force_update", False)
            result = await self.nuclei_manager.update_nuclei_templates(force_update)
            
            if result['success']:
                response = f"✅ {result['message']}\n"
                template_info = result.get('template_info', {})
                if template_info.get('total_templates'):
                    response += f"📚 Total templates: {template_info['total_templates']}\n"
                response += "\n🔄 Templates are now up-to-date with the latest releases!\n"
            else:
                response = f"❌ Template update failed: {result['error']}\n"
        
        elif action == "download":
            repo_url = arguments.get("repo_url")
            name = arguments.get("name")
            if not repo_url or not name:
                response = "❌ Both 'repo_url' and 'name' are required for custom template download\n"
            else:
                result = await self.nuclei_manager.download_custom_templates(repo_url, name)
                if result['success']:
                    response = f"✅ {result['message']}\n"
                    response += f"📁 Saved to: {result['path']}\n"
                    response += f"📊 Templates: {result['template_count']}\n"
                else:
                    response = f"❌ Download failed: {result['error']}\n"
        
        elif action == "suggest":
            scan_type = arguments.get("scan_type", "web_app")
            severity = arguments.get("severity", "medium")
            result = self.nuclei_manager.get_template_suggestions(scan_type, severity)
            
            if result['success']:
                response = f"💡 Template suggestions for {scan_type} scan:\n\n"
                response += f"🏷️ Recommended tags: {', '.join(result['suggested_tags'])}\n"
                response += f"📁 Recommended paths: {', '.join(result['suggested_paths'])}\n"
                response += f"⚠️ Severity levels: {', '.join(result['suggested_severity'])}\n\n"
                response += "🚀 Use these in nuclei_vulnerability_scan:\n"
                response += f"  Tags: {result['template_args']['tags']}\n"
                response += f"  Severity: {result['template_args']['severity']}\n"
            else:
                response = f"❌ {result['error']}\n"
        
        elif action == "validate":
            result = await self.nuclei_manager.validate_templates()
            if result['success']:
                response = "✅ Template validation completed successfully\n"
                if result['validation_output']:
                    response += f"\n📋 Validation output:\n{result['validation_output']}\n"
            else:
                response = f"❌ Template validation failed: {result.get('error', 'Unknown error')}\n"
                if result.get('errors'):
                    response += f"\n📋 Errors:\n{result['errors']}\n"
        
        else:
            response = "❌ Unknown action. Use: check, update, download, suggest, or validate\n"
        
        return [TextContent(type="text", text=response)]

    async def handle_ffuf_scan(self, arguments: dict) -> List[TextContent]:
        """Handle ffuf scanning"""
        if not self.tools['ffuf']['available']:
            return [TextContent(type="text", text="❌ ffuf is not available. Please install it first.")]
        
        url = arguments.get("url")
        wordlist = arguments.get("wordlist", "auto")
        mode = arguments.get("mode", "dir")
        size = arguments.get("size", "medium")
        extensions = arguments.get("extensions", [])
        threads = arguments.get("threads", 40)
        
        # Handle automatic wordlist selection
        if wordlist == "auto":
            suggestion = await self.wordlist_manager.suggest_wordlist(mode, size)
            if suggestion['success'] and suggestion['available']:
                wordlist = suggestion['path']
            else:
                # Try to install SecLists
                install_result = await self.wordlist_manager.install_seclists()
                if install_result['success']:
                    suggestion = await self.wordlist_manager.suggest_wordlist(mode, size)
                    if suggestion['success'] and suggestion['available']:
                        wordlist = suggestion['path']
                    else:
                        return [TextContent(type="text", text="❌ Could not find appropriate wordlist even after installing SecLists")]
                else:
                    return [TextContent(type="text", text=f"❌ No wordlist available and installation failed: {install_result['error']}")]
        else:
            # Try to resolve wordlist name to path
            wordlist_path = self.wordlist_manager.get_wordlist_path("directories", wordlist)
            if wordlist_path:
                wordlist = wordlist_path
            elif not os.path.exists(wordlist):
                return [TextContent(type="text", text=f"❌ Wordlist not found: {wordlist}")]
        
        result = await self.run_ffuf_scan(url, wordlist, mode, extensions, threads=threads)
        
        if result['success']:
            response = f"🔍 ffuf {mode.title()} Scan Results\n"
            response += "=" * 40 + "\n\n"
            response += f"🎯 Target: {url}\n"
            response += f"📋 Mode: {mode}\n"
            response += f"📚 Wordlist: {os.path.basename(wordlist)}\n"
            response += f"🔍 Results found: {result['results_count']}\n\n"
            
            if result['results']:
                response += "📊 Discovered endpoints:\n"
                for res in result['results'][:50]:  # Limit to 50 results
                    status = res.get('status', 'N/A')
                    url_found = res.get('url', 'N/A') 
                    size = res.get('length', 'N/A')
                    words = res.get('words', 'N/A')
                    response += f"  [{status}] {url_found} (Size: {size}, Words: {words})\n"
                
                if result['results_count'] > 50:
                    response += f"  ... and {result['results_count'] - 50} more results\n"
                
                response += f"\n💾 Full results saved to: {result['output_file']}\n"
            else:
                response += "No results found.\n"
        else:
            response = f"❌ ffuf scan failed: {result.get('error', 'Unknown error')}\n"
        
        return [TextContent(type="text", text=response)]

    async def handle_httpx_scan(self, arguments: dict) -> List[TextContent]:
        """Handle httpx scanning"""
        if not self.tools['httpx']['available']:
            return [TextContent(type="text", text="❌ httpx is not available. Please install it first.")]
        
        targets = arguments.get("targets", [])
        ports = arguments.get("ports", [])
        follow_redirects = arguments.get("follow_redirects", True)
        tech_detect = arguments.get("tech_detect", True)
        
        options = {
            "follow_redirects": follow_redirects,
            "tech_detect": tech_detect,
            "status_code": True,
            "content_length": True,
            "title": True
        }
        
        if ports:
            options["ports"] = ports
        
        result = await self.run_httpx_scan(targets, options)
        
        if result['success']:
            response = f"🌐 httpx Discovery Results\n"
            response += "=" * 30 + "\n\n"
            response += f"🎯 Targets scanned: {len(targets)}\n"
            response += f"✅ Alive hosts: {result['results_count']}\n\n"
            
            if result['results']:
                response += "📊 Discovered services:\n"
                for res in result['results']:
                    url = res.get('url', 'N/A')
                    status = res.get('status_code', 'N/A')
                    title = res.get('title', '')
                    length = res.get('content_length', 'N/A')
                    tech = res.get('tech', [])
                    
                    response += f"  [{status}] {url}"
                    if title:
                        response += f" - {title[:50]}"
                    response += f" (Length: {length})\n"
                    if tech:
                        response += f"      Technologies: {', '.join(tech[:3])}\n"
                
                response += f"\n💾 Full results saved to: {result['output_file']}\n"
            else:
                response += "No alive hosts found.\n"
        else:
            response = f"❌ httpx scan failed: {result.get('error', 'Unknown error')}\n"
        
        return [TextContent(type="text", text=response)]

    async def handle_nuclei_scan(self, arguments: dict) -> List[TextContent]:
        """Handle nuclei vulnerability scanning"""
        if not self.tools['nuclei']['available']:
            return [TextContent(type="text", text="❌ nuclei is not available. Please install it first.")]
        
        targets = arguments.get("targets", [])
        severity = arguments.get("severity", ["low", "medium", "high", "critical"])
        tags = arguments.get("tags", [])
        auto_update = arguments.get("auto_update", True)
        
        result = await self.run_nuclei_scan(targets, severity=severity, tags=tags, auto_update=auto_update)
        
        if result['success']:
            response = f"🔍 nuclei Vulnerability Scan Results\n"
            response += "=" * 40 + "\n\n"
            response += f"🎯 Targets scanned: {len(targets)}\n"
            response += f"⚠️ Vulnerabilities found: {result['results_count']}\n\n"
            
            if result['results']:
                # Group by severity
                severity_groups = {}
                for res in result['results']:
                    sev = res.get('info', {}).get('severity', 'unknown')
                    if sev not in severity_groups:
                        severity_groups[sev] = []
                    severity_groups[sev].append(res)
                
                # Display by severity (critical first)
                severity_order = ['critical', 'high', 'medium', 'low', 'info', 'unknown']
                for sev in severity_order:
                    if sev in severity_groups:
                        vulns = severity_groups[sev]
                        response += f"🚨 {sev.upper()} ({len(vulns)} findings):\n"
                        for vuln in vulns[:10]:  # Limit per severity
                            name = vuln.get('info', {}).get('name', 'Unknown')
                            target = vuln.get('matched-at', 'Unknown')
                            response += f"  • {name} - {target}\n"
                        
                        if len(vulns) > 10:
                            response += f"    ... and {len(vulns) - 10} more\n"
                        response += "\n"
                
                response += f"💾 Full results saved to: {result['output_file']}\n"
            else:
                response += "No vulnerabilities found.\n"
        else:
            response = f"❌ nuclei scan failed: {result.get('error', 'Unknown error')}\n"
        
        return [TextContent(type="text", text=response)]

    async def handle_nikto_scan(self, arguments: dict) -> List[TextContent]:
        """Handle nikto web vulnerability scanning"""
        if not self.tools['nikto']['available']:
            return [TextContent(type="text", text="❌ nikto is not available. Please install it first.")]
        
        target = arguments.get("target")
        ssl = arguments.get("ssl", False)
        port = arguments.get("port")
        
        options = {"ssl": ssl}
        if port:
            options["port"] = port
        
        result = await self.run_nikto_scan(target, options)
        
        if result['success']:
            response = f"🔍 nikto Web Vulnerability Scan\n"
            response += "=" * 35 + "\n\n"
            response += f"🎯 Target: {target}\n\n"
            
            if result['output_content']:
                # Parse nikto output for key findings
                lines = result['output_content'].split('\n')
                findings = []
                for line in lines:
                    if '+ ' in line and any(keyword in line.lower() for keyword in 
                                         ['vulnerability', 'exposed', 'accessible', 'found', 'detected']):
                        findings.append(line.strip())
                
                if findings:
                    response += f"⚠️ Key findings ({len(findings)}):\n"
                    for finding in findings[:20]:  # Limit findings
                        response += f"  {finding}\n"
                    
                    if len(findings) > 20:
                        response += f"  ... and {len(findings) - 20} more findings\n"
                else:
                    response += "No significant vulnerabilities detected.\n"
                
                response += f"\n💾 Full report saved to: {result['output_file']}\n"
            else:
                response += "Scan completed but no detailed output available.\n"
        else:
            response = f"❌ nikto scan failed: {result.get('error', 'Unknown error')}\n"
        
        return [TextContent(type="text", text=response)]

    async def handle_comprehensive_scan(self, arguments: dict) -> List[TextContent]:
        """Handle comprehensive multi-tool web scanning"""
        target = arguments.get("target")
        include_vuln = arguments.get("include_vuln_scan", True)
        include_dir = arguments.get("include_directory_scan", True)
        intensity = arguments.get("scan_intensity", "normal")
        
        response = f"🚀 Comprehensive Web Scan\n"
        response += "=" * 30 + "\n\n"
        response += f"🎯 Target: {target}\n"
        response += f"📊 Intensity: {intensity}\n"
        response += f"🔍 Include vulnerability scan: {'✅' if include_vuln else '❌'}\n"
        response += f"📁 Include directory scan: {'✅' if include_dir else '❌'}\n\n"
        
        # Phase 1: HTTP Discovery
        if self.tools['httpx']['available']:
            response += "📡 Phase 1: HTTP Discovery (httpx)\n"
            httpx_result = await self.run_httpx_scan([target])
            if httpx_result['success'] and httpx_result['results']:
                alive_urls = [res.get('url') for res in httpx_result['results']]
                response += f"✅ Found {len(alive_urls)} alive service(s)\n\n"
            else:
                alive_urls = [target]
                response += "⚠️ httpx discovery failed, proceeding with original target\n\n"
        else:
            alive_urls = [target]
            response += "⚠️ httpx not available, skipping discovery phase\n\n"
        
        # Phase 2: Directory/File Discovery
        if include_dir and self.tools['ffuf']['available']:
            response += "📁 Phase 2: Directory Discovery (ffuf)\n"
            
            # Determine wordlist size based on intensity
            size_map = {"light": "small", "normal": "medium", "aggressive": "large"}
            wordlist_size = size_map.get(intensity, "medium")
            
            for url in alive_urls[:3]:  # Limit to 3 URLs
                ffuf_args = {
                    "url": url,
                    "wordlist": "auto",
                    "mode": "dir",
                    "size": wordlist_size,
                    "threads": 30 if intensity == "light" else 50
                }
                ffuf_result = await self.handle_ffuf_scan(ffuf_args)
                response += f"  Target: {url}\n"
                # Extract just the summary
                ffuf_text = ffuf_result[0].text
                if "Results found:" in ffuf_text:
                    summary_line = [line for line in ffuf_text.split('\n') if "Results found:" in line][0]
                    response += f"  {summary_line}\n"
            response += "\n"
        
        # Phase 3: Vulnerability Scanning
        if include_vuln:
            vuln_tools_run = []
            
            # Run nuclei if available
            if self.tools['nuclei']['available']:
                response += "🔍 Phase 3a: Vulnerability Scan (nuclei)\n"
                severity_map = {
                    "light": ["high", "critical"],
                    "normal": ["medium", "high", "critical"], 
                    "aggressive": ["low", "medium", "high", "critical"]
                }
                nuclei_args = {
                    "targets": alive_urls,
                    "severity": severity_map.get(intensity, ["medium", "high", "critical"]),
                    "auto_update": True
                }
                nuclei_result = await self.handle_nuclei_scan(nuclei_args)
                nuclei_text = nuclei_result[0].text
                if "Vulnerabilities found:" in nuclei_text:
                    summary_line = [line for line in nuclei_text.split('\n') if "Vulnerabilities found:" in line][0]
                    response += f"  {summary_line}\n"
                vuln_tools_run.append("nuclei")
                response += "\n"
            
            # Run nikto if available and intensity is normal/aggressive
            if self.tools['nikto']['available'] and intensity in ["normal", "aggressive"]:
                response += "🔍 Phase 3b: Web Vulnerability Scan (nikto)\n"
                for url in alive_urls[:2]:  # Limit nikto to 2 URLs
                    nikto_args = {"target": url}
                    nikto_result = await self.handle_nikto_scan(nikto_args)
                    response += f"  Scanned: {url}\n"
                vuln_tools_run.append("nikto")
                response += "\n"
        
        # Summary
        response += "📋 Scan Summary:\n"
        response += f"  • Discovery: {'httpx' if self.tools['httpx']['available'] else 'skipped'}\n"
        response += f"  • Directory fuzzing: {'ffuf' if include_dir and self.tools['ffuf']['available'] else 'skipped'}\n" 
        response += f"  • Vulnerability scanning: {', '.join(vuln_tools_run) if vuln_tools_run else 'skipped'}\n"
        response += f"  • Scan intensity: {intensity}\n"
        response += f"\n💾 All results saved to: {self.output_dir}\n"
        
        return [TextContent(type="text", text=response)]

async def main():
    """Main entry point"""
    try:
        server = WebScanMCPServer()
        logger.info("Starting WebScan MCP Server...")
        
        async with stdio_server() as (read_stream, write_stream):
            await server.server.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="webscan-mcp-server",
                    server_version="1.0.0",
                    capabilities=server.server.get_capabilities(
                        notification_options=NotificationOptions(),
                        experimental_capabilities={}
                    )
                )
            )
    except Exception as e:
        logger.error(f"Server failed to start: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
