#!/usr/bin/env python3
"""
SubHunter MCP Server - Model Context Protocol server for subdomain enumeration
Integrates multiple subdomain discovery tools: subfinder, assetfinder, findomain, etc.
"""

import asyncio
import json
import logging
import subprocess
import tempfile
import os
import sys
import re
import socket
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from datetime import datetime
from urllib.parse import urlparse

try:
    from mcp.server.models import InitializationOptions
    from mcp.server import NotificationOptions, Server
    from mcp.server.stdio import stdio_server
    from mcp.types import Tool, TextContent, Resource
except ImportError as e:
    print(f"MCP import error: {e}", file=sys.stderr)
    print("Please install the MCP library: pip install mcp>=1.12.4", file=sys.stderr)
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stderr)]
)
logger = logging.getLogger("subhunter-mcp-server")

class SubHunterMCPServer:
    """MCP Server for comprehensive subdomain enumeration"""
    
    def __init__(self):
        self.server = Server("subhunter-mcp-server")
        self.tools = self.detect_available_tools()
        self.output_dir = Path.home() / ".subhunter_mcp" / "output"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.setup_handlers()
        
    def detect_available_tools(self) -> Dict[str, str]:
        """Detect which subdomain enumeration tools are available"""
        tools = {}
        
        # List of subdomain enumeration tools to check
        tool_checks = {
            'subfinder': ['subfinder', '--version'],
            'assetfinder': ['assetfinder', '--help'],
            'findomain': ['findomain', '--version'],
            'sublist3r': ['sublist3r', '--help'],
            'amass': ['amass', 'enum', '--help'],
            'knockpy': ['knockpy', '--help'],
            'subbrute': ['subbrute', '--help'],
            'massdns': ['massdns', '--help'],
            'dnsrecon': ['dnsrecon', '--help'],
            'fierce': ['fierce', '--help'],
            'gobuster': ['gobuster', 'dns', '--help'],
            'dnsx': ['dnsx', '--help'],
            'httpx': ['httpx', '--help'],
            'dig': ['dig', '-v'],
            'nslookup': ['nslookup', '-version']
        }
        
        for tool_name, check_cmd in tool_checks.items():
            try:
                result = subprocess.run(check_cmd, capture_output=True, text=True, timeout=10)
                if result.returncode == 0 or tool_name in result.stdout.lower() or tool_name in result.stderr.lower():
                    # Find the tool path
                    which_result = subprocess.run(['which', tool_name], capture_output=True, text=True)
                    if which_result.returncode == 0:
                        tools[tool_name] = which_result.stdout.strip()
                        logger.info(f"Found {tool_name} at: {tools[tool_name]}")
                    else:
                        tools[tool_name] = tool_name  # Assume it's in PATH
                        logger.info(f"Found {tool_name} in PATH")
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
                continue
        
        logger.info(f"Available subdomain tools: {list(tools.keys())}")
        return tools

    async def run_tool_command(self, tool: str, args: List[str], timeout: int = 300) -> Dict[str, Any]:
        """Execute a subdomain enumeration tool with given arguments"""
        try:
            if tool not in self.tools:
                return {
                    'success': False,
                    'error': f'{tool} not available. Please install it first.'
                }
            
            cmd = [self.tools[tool]] + args
            logger.info(f"Running {tool}: {' '.join(cmd)}")
            
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
                    'error': f'{tool} command timed out after {timeout} seconds'
                }
            
            stdout_text = stdout.decode('utf-8', errors='replace')
            stderr_text = stderr.decode('utf-8', errors='replace')
            
            return {
                'success': process.returncode == 0,
                'stdout': stdout_text,
                'stderr': stderr_text,
                'return_code': process.returncode,
                'tool': tool
            }
            
        except Exception as e:
            logger.error(f"Error running {tool}: {e}")
            return {
                'success': False,
                'error': str(e),
                'tool': tool
            }

    def parse_subdomains(self, output: str, tool: str) -> Set[str]:
        """Parse subdomain results from tool output"""
        subdomains = set()
        
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            
            # Skip empty lines and common non-subdomain lines
            if not line or line.startswith('#') or line.startswith('[') or 'error' in line.lower():
                continue
            
            # Different parsing strategies based on tool
            if tool in ['subfinder', 'assetfinder', 'findomain']:
                # These tools typically output one subdomain per line
                if '.' in line and not line.startswith('http'):
                    # Clean up the line
                    subdomain = re.sub(r'^https?://', '', line)
                    subdomain = subdomain.split('/')[0]  # Remove path
                    subdomain = subdomain.split(':')[0]  # Remove port
                    if self.is_valid_domain(subdomain):
                        subdomains.add(subdomain.lower())
            
            elif tool == 'sublist3r':
                # Sublist3r has a specific output format
                if line and '.' in line and not any(x in line for x in ['Starting', 'Enumerating', 'Total']):
                    subdomain = line.strip()
                    if self.is_valid_domain(subdomain):
                        subdomains.add(subdomain.lower())
            
            elif tool == 'amass':
                # Amass enum output format
                if '.' in line and not any(x in line for x in ['OWASP', 'Average', 'ASN']):
                    subdomain = line.strip()
                    if self.is_valid_domain(subdomain):
                        subdomains.add(subdomain.lower())
            
            elif tool == 'gobuster':
                # Gobuster dns mode output
                if 'Found:' in line:
                    subdomain = line.split('Found:')[1].strip()
                    if self.is_valid_domain(subdomain):
                        subdomains.add(subdomain.lower())
            
            else:
                # Generic parsing for other tools
                domain_match = re.search(r'([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}', line)
                if domain_match:
                    subdomain = domain_match.group(0)
                    if self.is_valid_domain(subdomain):
                        subdomains.add(subdomain.lower())
        
        return subdomains

    def is_valid_domain(self, domain: str) -> bool:
        """Check if a string is a valid domain name"""
        if not domain or len(domain) > 255:
            return False
        
        # Basic domain validation
        pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        )
        
        return bool(pattern.match(domain))

    async def resolve_subdomains(self, subdomains: Set[str]) -> Dict[str, Dict[str, Any]]:
        """Resolve subdomains to IP addresses and check if they're alive"""
        results = {}
        
        for subdomain in subdomains:
            try:
                # Try to resolve the domain
                ip_addresses = socket.gethostbyname_ex(subdomain)[2]
                results[subdomain] = {
                    'resolved': True,
                    'ips': ip_addresses,
                    'alive': True
                }
            except socket.gaierror:
                results[subdomain] = {
                    'resolved': False,
                    'ips': [],
                    'alive': False
                }
            except Exception as e:
                results[subdomain] = {
                    'resolved': False,
                    'ips': [],
                    'alive': False,
                    'error': str(e)
                }
        
        return results

    async def check_http_status(self, subdomains: Set[str]) -> Dict[str, Dict[str, Any]]:
        """Check HTTP status of subdomains using httpx if available"""
        if 'httpx' not in self.tools:
            return {}
        
        # Create temporary file with subdomains
        temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
        for subdomain in subdomains:
            temp_file.write(f"{subdomain}\n")
        temp_file.close()
        
        try:
            # Run httpx
            args = ['-l', temp_file.name, '-json', '-silent', '-timeout', '10']
            result = await self.run_tool_command('httpx', args, timeout=120)
            
            http_results = {}
            if result['success'] and result['stdout']:
                for line in result['stdout'].split('\n'):
                    if line.strip():
                        try:
                            data = json.loads(line)
                            url = data.get('url', '')
                            domain = urlparse(url).netloc
                            if domain:
                                http_results[domain] = {
                                    'url': url,
                                    'status_code': data.get('status_code'),
                                    'content_length': data.get('content_length'),
                                    'title': data.get('title', ''),
                                    'tech': data.get('tech', []),
                                    'server': data.get('server', '')
                                }
                        except json.JSONDecodeError:
                            continue
            
            return http_results
            
        finally:
            # Clean up temp file
            try:
                os.unlink(temp_file.name)
            except:
                pass

    def setup_handlers(self):
        """Setup MCP server handlers"""
        
        @self.server.list_tools()
        async def handle_list_tools() -> List[Tool]:
            """List available subdomain enumeration tools"""
            tools = [
                Tool(
                    name="subhunt_comprehensive",
                    description="Run comprehensive subdomain enumeration using all available tools",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "domain": {
                                "type": "string",
                                "description": "Target domain to enumerate subdomains for"
                            },
                            "resolve_dns": {
                                "type": "boolean",
                                "description": "Resolve subdomains to IP addresses",
                                "default": True
                            },
                            "check_http": {
                                "type": "boolean", 
                                "description": "Check HTTP status of discovered subdomains",
                                "default": True
                            },
                            "timeout": {
                                "type": "integer",
                                "description": "Timeout per tool in seconds",
                                "default": 300
                            },
                            "max_results": {
                                "type": "integer",
                                "description": "Maximum number of subdomains to return",
                                "default": 500
                            }
                        },
                        "required": ["domain"]
                    }
                ),
                Tool(
                    name="subhunter_passive",
                    description="Passive subdomain enumeration using public sources",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "domain": {"type": "string"},
                            "tools": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Specific tools to use (subfinder, assetfinder, findomain, etc.)"
                            },
                            "timeout": {"type": "integer", "default": 180}
                        },
                        "required": ["domain"]
                    }
                ),
                Tool(
                    name="subhunter_bruteforce",
                    description="Brute force subdomain enumeration",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "domain": {"type": "string"},
                            "wordlist": {
                                "type": "string",
                                "description": "Path to wordlist file (optional)"
                            },
                            "threads": {"type": "integer", "default": 25},
                            "timeout": {"type": "integer", "default": 300}
                        },
                        "required": ["domain"]
                    }
                ),
                Tool(
                    name="subhunter_resolver",
                    description="Resolve list of subdomains to IP addresses",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "subdomains": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "List of subdomains to resolve"
                            },
                            "check_http": {"type": "boolean", "default": False}
                        },
                        "required": ["subdomains"]
                    }
                ),
                Tool(
                    name="subhunter_single_tool",
                    description="Run a specific subdomain enumeration tool",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "tool": {
                                "type": "string",
                                "enum": list(self.tools.keys()),
                                "description": "Specific tool to use"
                            },
                            "domain": {"type": "string"},
                            "additional_args": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Additional arguments for the tool"
                            },
                            "timeout": {"type": "integer", "default": 180}
                        },
                        "required": ["tool", "domain"]
                    }
                ),
                Tool(
                    name="check_subhunter_tools",
                    description="Check which subdomain enumeration tools are available",
                    inputSchema={
                        "type": "object",
                        "properties": {}
                    }
                )
            ]
            
            return tools

        @self.server.call_tool()
        async def handle_call_tool(name: str, arguments: dict) -> List[Any]:
            """Handle tool calls"""
            try:
                if name == "check_sub_tools":
                    response = "🔧 Available Subdomain Enumeration Tools:\n\n"
                    if self.tools:
                        for tool, path in self.tools.items():
                            response += f"✅ {tool}: {path}\n"
                    else:
                        response += "❌ No subdomain enumeration tools found!\n"
                        response += "\nRecommended tools to install:\n"
                        response += "• subfinder: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest\n"
                        response += "• assetfinder: go install github.com/tomnomnom/assetfinder@latest\n"
                        response += "• findomain: https://github.com/findomain/findomain\n"
                        response += "• httpx: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest\n"
                    
                    return [TextContent(type="text", text=response)]

                elif name == "subhunter_comprehensive":
                    domain = arguments.get("domain")
                    resolve_dns = arguments.get("resolve_dns", True)
                    check_http = arguments.get("check_http", True)
                    timeout = arguments.get("timeout", 300)
                    max_results = arguments.get("max_results", 500)
                    
                    return await self.run_comprehensive_scan(domain, resolve_dns, check_http, timeout, max_results)

                elif name == "subhunter_passive":
                    domain = arguments.get("domain")
                    requested_tools = arguments.get("tools", [])
                    timeout = arguments.get("timeout", 180)
                    
                    # Use requested tools or default passive tools
                    passive_tools = ['subfinder', 'assetfinder', 'findomain', 'sublist3r']
                    tools_to_use = [t for t in (requested_tools or passive_tools) if t in self.tools]
                    
                    return await self.run_passive_scan(domain, tools_to_use, timeout)

                elif name == "subhunter_bruteforce":
                    domain = arguments.get("domain")
                    wordlist = arguments.get("wordlist")
                    threads = arguments.get("threads", 25)
                    timeout = arguments.get("timeout", 300)
                    
                    return await self.run_bruteforce_scan(domain, wordlist, threads, timeout)

                elif name == "subhunter_resolver":
                    subdomains = arguments.get("subdomains", [])
                    check_http = arguments.get("check_http", False)
                    
                    return await self.run_resolver_scan(subdomains, check_http)

                elif name == "subhunter_single_tool":
                    tool = arguments.get("tool")
                    domain = arguments.get("domain")
                    additional_args = arguments.get("additional_args", [])
                    timeout = arguments.get("timeout", 180)
                    
                    return await self.run_single_tool_scan(tool, domain, additional_args, timeout)

                else:
                    raise ValueError(f"Unknown tool: {name}")
                    
            except Exception as e:
                logger.error(f"Error in tool call {name}: {e}")
                return [TextContent(type="text", text=f"Error: {str(e)}")]

    async def run_comprehensive_scan(self, domain: str, resolve_dns: bool, check_http: bool, timeout: int, max_results: int) -> List[TextContent]:
        """Run comprehensive subdomain enumeration"""
        scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        logger.info(f"Starting comprehensive scan for {domain} (ID: {scan_id})")
        
        all_subdomains = set()
        tool_results = {}
        
        # Run passive enumeration tools
        passive_tools = ['subfinder', 'assetfinder', 'findomain', 'sublist3r', 'amass']
        for tool in passive_tools:
            if tool in self.tools:
                logger.info(f"Running {tool}...")
                if tool == 'subfinder':
                    args = ['-d', domain, '-silent']
                elif tool == 'assetfinder':
                    args = [domain]
                elif tool == 'findomain':
                    args = ['-t', domain, '-q']
                elif tool == 'sublist3r':
                    args = ['-d', domain]
                elif tool == 'amass':
                    args = ['enum', '-passive', '-d', domain]
                else:
                    continue
                
                result = await self.run_tool_command(tool, args, timeout=120)
                if result['success']:
                    subdomains = self.parse_subdomains(result['stdout'], tool)
                    all_subdomains.update(subdomains)
                    tool_results[tool] = {
                        'subdomains_found': len(subdomains),
                        'success': True
                    }
                else:
                    tool_results[tool] = {
                        'subdomains_found': 0,
                        'success': False,
                        'error': result.get('error', 'Unknown error')
                    }
        
        # Run brute force if gobuster is available
        if 'gobuster' in self.tools and len(all_subdomains) < max_results:
            logger.info("Running gobuster DNS brute force...")
            args = ['dns', '-d', domain, '-w', '/usr/share/wordlists/dirb/common.txt', '-q']
            result = await self.run_tool_command('gobuster', args, timeout=180)
            if result['success']:
                subdomains = self.parse_subdomains(result['stdout'], 'gobuster')
                all_subdomains.update(subdomains)
                tool_results['gobuster'] = {
                    'subdomains_found': len(subdomains),
                    'success': True
                }
        
        # Limit results
        if len(all_subdomains) > max_results:
            all_subdomains = set(list(all_subdomains)[:max_results])
        
        # Resolve subdomains if requested
        resolved_results = {}
        if resolve_dns and all_subdomains:
            logger.info("Resolving subdomains...")
            resolved_results = await self.resolve_subdomains(all_subdomains)
        
        # Check HTTP status if requested
        http_results = {}
        if check_http and all_subdomains:
            logger.info("Checking HTTP status...")
            http_results = await self.check_http_status(all_subdomains)
        
        # Format response
        response = f"🎯 SubHunter Comprehensive Scan Results for {domain}\n"
        response += "=" * 60 + "\n\n"
        response += f"📊 Scan ID: {scan_id}\n"
        response += f"🔍 Total subdomains found: {len(all_subdomains)}\n\n"
        
        # Tool summary
        response += "🔧 Tool Results:\n"
        for tool, result in tool_results.items():
            status = "✅" if result['success'] else "❌"
            response += f"{status} {tool}: {result['subdomains_found']} subdomains"
            if not result['success']:
                response += f" (Error: {result.get('error', 'Unknown')})"
            response += "\n"
        response += "\n"
        
        # Subdomain list with details
        if all_subdomains:
            response += "📋 Discovered Subdomains:\n"
            for i, subdomain in enumerate(sorted(all_subdomains), 1):
                response += f"{i:3d}. {subdomain}"
                
                # Add resolution info
                if subdomain in resolved_results:
                    res = resolved_results[subdomain]
                    if res['resolved']:
                        response += f" → {', '.join(res['ips'])}"
                    else:
                        response += " → [No DNS]"
                
                # Add HTTP info
                if subdomain in http_results:
                    http = http_results[subdomain]
                    response += f" [{http.get('status_code', 'N/A')}]"
                    if http.get('title'):
                        response += f" '{http['title'][:30]}...'"
                
                response += "\n"
                
                # Limit display
                if i >= 100:
                    response += f"... and {len(all_subdomains) - 100} more\n"
                    break
        
        return [TextContent(type="text", text=response)]

    async def run_passive_scan(self, domain: str, tools_to_use: List[str], timeout: int) -> List[TextContent]:
        """Run passive subdomain enumeration"""
        all_subdomains = set()
        tool_results = {}
        
        for tool in tools_to_use:
            if tool == 'subfinder':
                args = ['-d', domain, '-silent']
            elif tool == 'assetfinder':
                args = [domain]
            elif tool == 'findomain':
                args = ['-t', domain, '-q']
            elif tool == 'sublist3r':
                args = ['-d', domain]
            else:
                continue
            
            result = await self.run_tool_command(tool, args, timeout)
            if result['success']:
                subdomains = self.parse_subdomains(result['stdout'], tool)
                all_subdomains.update(subdomains)
                tool_results[tool] = len(subdomains)
        
        response = f"🔍 Passive Subdomain Enumeration for {domain}\n"
        response += "=" * 50 + "\n\n"
        response += f"Tools used: {', '.join(tools_to_use)}\n"
        response += f"Total unique subdomains: {len(all_subdomains)}\n\n"
        
        for tool, count in tool_results.items():
            response += f"• {tool}: {count} subdomains\n"
        
        if all_subdomains:
            response += "\n📋 Subdomains:\n"
            for subdomain in sorted(all_subdomains):
                response += f"  {subdomain}\n"
        
        return [TextContent(type="text", text=response)]

    async def run_bruteforce_scan(self, domain: str, wordlist: str, threads: int, timeout: int) -> List[TextContent]:
        """Run brute force subdomain enumeration"""
        if 'gobuster' not in self.tools:
            return [TextContent(type="text", text="❌ Gobuster not available for brute force scanning")]
        
        # Use default wordlist if none provided
        if not wordlist:
            wordlist = '/usr/share/wordlists/dirb/common.txt'
        
        args = ['dns', '-d', domain, '-w', wordlist, '-t', str(threads), '-q']
        result = await self.run_tool_command('gobuster', args, timeout)
        
        if result['success']:
            subdomains = self.parse_subdomains(result['stdout'], 'gobuster')
            response = f"🔨 Brute Force Scan Results for {domain}\n"
            response += "=" * 40 + "\n\n"
            response += f"Wordlist: {wordlist}\n"
            response += f"Threads: {threads}\n"
            response += f"Subdomains found: {len(subdomains)}\n\n"
            
            if subdomains:
                response += "📋 Discovered Subdomains:\n"
                for subdomain in sorted(subdomains):
                    response += f"  {subdomain}\n"
            
            return [TextContent(type="text", text=response)]
        else:
            return [TextContent(type="text", text=f"❌ Brute force scan failed: {result.get('error', 'Unknown error')}")]

    async def run_resolver_scan(self, subdomains: List[str], check_http: bool) -> List[TextContent]:
        """Resolve subdomains to IP addresses"""
        subdomain_set = set(subdomains)
        resolved_results = await self.resolve_subdomains(subdomain_set)
        
        response = "🔍 Subdomain Resolution Results\n"
        response += "=" * 40 + "\n\n"
        
        alive_count = sum(1 for r in resolved_results.values() if r['resolved'])
        response += f"Total subdomains: {len(subdomains)}\n"
        response += f"Resolved: {alive_count}\n"
        response += f"Failed: {len(subdomains) - alive_count}\n\n"
        
        # Get HTTP info if requested
        http_results = {}
        if check_http:
            http_results = await self.check_http_status(subdomain_set)
        
        response += "📋 Resolution Details:\n"
        for subdomain in sorted(subdomains):
            if subdomain in resolved_results:
                res = resolved_results[subdomain]
                if res['resolved']:
                    response += f"✅ {subdomain} → {', '.join(res['ips'])}"
                    if subdomain in http_results:
                        http = http_results[subdomain]
                        response += f" [{http.get('status_code', 'N/A')}]"
                    response += "\n"
                else:
                    response += f"❌ {subdomain} → No DNS resolution\n"
        
        return [TextContent(type="text", text=response)]

    async def run_single_tool_scan(self, tool: str, domain: str, additional_args: List[str], timeout: int) -> List[TextContent]:
        """Run a specific subdomain enumeration tool"""
        if tool not in self.tools:
            return [TextContent(type="text", text=f"❌ Tool {tool} not available")]
        
        # Build arguments based on tool
        if tool == 'subfinder':
            args = ['-d', domain] + additional_args
        elif tool == 'assetfinder':
            args = [domain] + additional_args
        elif tool == 'findomain':
            args = ['-t', domain] + additional_args
        else:
            args = [domain] + additional_args
        
        result = await self.run_tool_command(tool, args, timeout)
        
        if result['success']:
            subdomains = self.parse_subdomains(result['stdout'], tool)
            response = f"🔧 {tool.capitalize()} Results for {domain}\n"
            response += "=" * 40 + "\n\n"
            response += f"Subdomains found: {len(subdomains)}\n\n"
            
            if subdomains:
                response += "📋 Subdomains:\n"
                for subdomain in sorted(subdomains):
                    response += f"  {subdomain}\n"
            
            # Include raw output if verbose
            if result['stdout']:
                response += f"\n📄 Raw Output:\n{result['stdout'][:1000]}"
                if len(result['stdout']) > 1000:
                    response += "... (truncated)"
            
            return [TextContent(type="text", text=response)]
        else:
            return [TextContent(type="text", text=f"❌ {tool} failed: {result.get('error', 'Unknown error')}")]

async def main():
    """Main entry point"""
    try:
        server = SubHunterMCPServer()
        
        logger.info("Starting SubHunter MCP Server...")
        
        async with stdio_server() as (read_stream, write_stream):
            await server.server.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="subhunter-mcp-server",
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
    server = SubHunterMCPServer()
    asyncio.run(main())
