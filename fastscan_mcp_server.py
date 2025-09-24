#!/usr/bin/env python3
"""
FastScan MCP Server - Model Context Protocol server for high-speed port scanning
Integrates Masscan and Rustscan for rapid network reconnaissance
"""

import asyncio
import json
import logging
import subprocess
import tempfile
import os
import sys
import re
import ipaddress
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union
from datetime import datetime

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
logger = logging.getLogger("fastscan-mcp-server")

class FastScanMCPServer:
    """MCP Server for high-speed port scanning using Masscan and Rustscan"""
    
    def __init__(self):
        self.server = Server("fastscan-mcp-server")
        self.tools = self.detect_available_tools()
        self.output_dir = Path.home() / ".fastscan_mcp" / "output"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.setup_handlers()
        
    def detect_available_tools(self) -> Dict[str, Dict[str, Any]]:
        """Detect which fast scanning tools are available"""
        tools = {}
        
        # Check for Masscan
        try:
            result = subprocess.run(['masscan', '--version'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                which_result = subprocess.run(['which', 'masscan'], capture_output=True, text=True)
                tools['masscan'] = {
                    'path': which_result.stdout.strip(),
                    'version': result.stdout.strip(),
                    'available': True,
                    'requires_root': True
                }
                logger.info(f"Found Masscan: {tools['masscan']['path']}")
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
            tools['masscan'] = {'available': False}
        
        # Check for Rustscan
        try:
            result = subprocess.run(['rustscan', '--version'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                which_result = subprocess.run(['which', 'rustscan'], capture_output=True, text=True)
                tools['rustscan'] = {
                    'path': which_result.stdout.strip(),
                    'version': result.stdout.strip(),
                    'available': True,
                    'requires_root': False
                }
                logger.info(f"Found Rustscan: {tools['rustscan']['path']}")
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
            tools['rustscan'] = {'available': False}
        
        # Check for Zmap as bonus
        try:
            result = subprocess.run(['zmap', '--version'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                which_result = subprocess.run(['which', 'zmap'], capture_output=True, text=True)
                tools['zmap'] = {
                    'path': which_result.stdout.strip(),
                    'version': result.stdout.strip(),
                    'available': True,
                    'requires_root': True
                }
                logger.info(f"Found Zmap: {tools['zmap']['path']}")
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
            tools['zmap'] = {'available': False}
        
        available_tools = [name for name, info in tools.items() if info.get('available')]
        logger.info(f"Available fast scanning tools: {available_tools}")
        
        return tools

    def validate_targets(self, targets: Union[str, List[str]]) -> List[str]:
        """Validate and normalize target specifications"""
        if isinstance(targets, str):
            targets = [targets]
        
        valid_targets = []
        for target in targets:
            target = target.strip()
            
            # Check if it's a valid IP, CIDR, or hostname
            try:
                # Try parsing as IP network (handles both single IPs and CIDR)
                ipaddress.ip_network(target, strict=False)
                valid_targets.append(target)
            except ValueError:
                # Not an IP/CIDR, check if it's a valid hostname
                if re.match(r'^[a-zA-Z0-9.-]+$', target) and '.' in target:
                    valid_targets.append(target)
                else:
                    logger.warning(f"Invalid target format: {target}")
        
        return valid_targets

    def parse_port_range(self, port_range: str) -> str:
        """Parse and validate port range specification"""
        if not port_range:
            return "1-65535"
        
        # Common port ranges
        if port_range.lower() == "common":
            return "80,443,22,21,23,25,53,110,111,135,139,143,993,995,1723,3306,3389,5432,5900,6379"
        elif port_range.lower() == "top1000":
            return "1-1000"
        elif port_range.lower() == "web":
            return "80,443,8080,8443,8000,8888,9000,9443"
        
        # Validate port range format
        if re.match(r'^(\d+(-\d+)?)(,\d+(-\d+)?)*$', port_range):
            return port_range
        
        logger.warning(f"Invalid port range format: {port_range}, using default")
        return "1-65535"

    async def run_masscan(self, targets: List[str], ports: str, rate: int, timeout: int, 
                         additional_args: List[str] = None) -> Dict[str, Any]:
        """Run Masscan scan"""
        if not self.tools['masscan']['available']:
            return {'success': False, 'error': 'Masscan not available'}
        
        # Check if running as root
        if os.geteuid() != 0:
            return {
                'success': False, 
                'error': 'Masscan requires root privileges. Run with sudo or as root.'
            }
        
        try:
            # Create temporary output file
            scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.output_dir / f"masscan_{scan_id}.json"
            
            # Build command
            cmd = [
                'masscan',
                '-p', ports,
                '--rate', str(rate),
                '--output-format', 'json',
                '--output-filename', str(output_file),
                '--open-only'
            ]
            
            # Add targets
            cmd.extend(targets)
            
            # Add additional arguments
            if additional_args:
                cmd.extend(additional_args)
            
            logger.info(f"Running Masscan: {' '.join(cmd[:8])}...")
            
            # Run Masscan
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
                    'error': f'Masscan timed out after {timeout} seconds'
                }
            
            stdout_text = stdout.decode('utf-8', errors='replace')
            stderr_text = stderr.decode('utf-8', errors='replace')
            
            # Parse results from JSON output file
            results = []
            if output_file.exists():
                try:
                    with open(output_file, 'r') as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                try:
                                    result = json.loads(line)
                                    results.append(result)
                                except json.JSONDecodeError:
                                    continue
                except Exception as e:
                    logger.error(f"Error reading Masscan output: {e}")
            
            return {
                'success': process.returncode == 0,
                'stdout': stdout_text,
                'stderr': stderr_text,
                'return_code': process.returncode,
                'tool': 'masscan',
                'scan_id': scan_id,
                'output_file': str(output_file),
                'results': results,
                'targets_scanned': targets,
                'ports_scanned': ports
            }
            
        except Exception as e:
            logger.error(f"Error running Masscan: {e}")
            return {
                'success': False,
                'error': str(e),
                'tool': 'masscan'
            }

    async def run_rustscan(self, targets: List[str], ports: str, timeout: int, 
                          batch_size: int = 1000, additional_args: List[str] = None) -> Dict[str, Any]:
        """Run Rustscan scan"""
        if not self.tools['rustscan']['available']:
            return {'success': False, 'error': 'Rustscan not available'}
        
        try:
            scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Build command
            cmd = ['rustscan']
            
            # Add targets
            for target in targets:
                cmd.extend(['-a', target])
            
            # Add port specification
            if ports and ports != "1-65535":
                cmd.extend(['-p', ports])
            
            # Add batch size
            cmd.extend(['-b', str(batch_size)])
            
            # Add timeout
            cmd.extend(['-t', str(timeout * 1000)])  # Rustscan uses milliseconds
            
            # JSON output
            cmd.append('--output')
            cmd.append('json')
            
            # Add additional arguments
            if additional_args:
                cmd.extend(additional_args)
            
            logger.info(f"Running Rustscan: {' '.join(cmd[:10])}...")
            
            # Run Rustscan
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), 
                    timeout=timeout + 60  # Extra buffer for rustscan
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                return {
                    'success': False,
                    'error': f'Rustscan timed out after {timeout + 60} seconds'
                }
            
            stdout_text = stdout.decode('utf-8', errors='replace')
            stderr_text = stderr.decode('utf-8', errors='replace')
            
            # Parse results
            results = self.parse_rustscan_output(stdout_text)
            
            return {
                'success': process.returncode == 0,
                'stdout': stdout_text,
                'stderr': stderr_text,
                'return_code': process.returncode,
                'tool': 'rustscan',
                'scan_id': scan_id,
                'results': results,
                'targets_scanned': targets,
                'ports_scanned': ports
            }
            
        except Exception as e:
            logger.error(f"Error running Rustscan: {e}")
            return {
                'success': False,
                'error': str(e),
                'tool': 'rustscan'
            }

    def parse_rustscan_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse Rustscan output to extract open ports"""
        results = []
        
        lines = output.split('\n')
        current_host = None
        
        for line in lines:
            line = line.strip()
            
            # Look for host information
            if 'Open' in line and '/' in line:
                # Parse lines like "Open 192.168.1.1:22"
                match = re.search(r'Open\s+([^:]+):(\d+)', line)
                if match:
                    host = match.group(1)
                    port = int(match.group(2))
                    
                    results.append({
                        'ip': host,
                        'port': port,
                        'proto': 'tcp',
                        'status': 'open'
                    })
            
            # Also try to parse JSON if present
            if line.startswith('{') and line.endswith('}'):
                try:
                    json_data = json.loads(line)
                    if 'ips' in json_data:
                        for ip_data in json_data['ips']:
                            ip = ip_data.get('Ip', '')
                            for port in ip_data.get('ports', []):
                                results.append({
                                    'ip': ip,
                                    'port': port,
                                    'proto': 'tcp',
                                    'status': 'open'
                                })
                except json.JSONDecodeError:
                    continue
        
        return results

    async def run_zmap(self, targets: List[str], port: int, rate: int, timeout: int) -> Dict[str, Any]:
        """Run Zmap scan (single port across many hosts)"""
        if not self.tools['zmap']['available']:
            return {'success': False, 'error': 'Zmap not available'}
        
        # Zmap requires root
        if os.geteuid() != 0:
            return {
                'success': False, 
                'error': 'Zmap requires root privileges. Run with sudo or as root.'
            }
        
        try:
            scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.output_dir / f"zmap_{scan_id}.txt"
            
            # Build command
            cmd = [
                'zmap',
                '-p', str(port),
                '-r', str(rate),
                '-o', str(output_file)
            ]
            
            # Add targets (Zmap expects CIDR notation)
            cmd.extend(targets)
            
            logger.info(f"Running Zmap: {' '.join(cmd)}")
            
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
                    'error': f'Zmap timed out after {timeout} seconds'
                }
            
            stdout_text = stdout.decode('utf-8', errors='replace')
            stderr_text = stderr.decode('utf-8', errors='replace')
            
            # Parse results
            results = []
            if output_file.exists():
                try:
                    with open(output_file, 'r') as f:
                        for line in f:
                            ip = line.strip()
                            if ip and not ip.startswith('#'):
                                results.append({
                                    'ip': ip,
                                    'port': port,
                                    'proto': 'tcp',
                                    'status': 'open'
                                })
                except Exception as e:
                    logger.error(f"Error reading Zmap output: {e}")
            
            return {
                'success': process.returncode == 0,
                'stdout': stdout_text,
                'stderr': stderr_text,
                'return_code': process.returncode,
                'tool': 'zmap',
                'scan_id': scan_id,
                'output_file': str(output_file),
                'results': results,
                'targets_scanned': targets,
                'port_scanned': port
            }
            
        except Exception as e:
            logger.error(f"Error running Zmap: {e}")
            return {
                'success': False,
                'error': str(e),
                'tool': 'zmap'
            }

    def setup_handlers(self):
        """Setup MCP server handlers"""
        
        @self.server.list_tools()
        async def handle_list_tools() -> List[Tool]:
            """List available fast scanning tools"""
            return [
                Tool(
                    name="fastscan_auto",
                    description="Automatically choose best available fast scanner and run comprehensive scan",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "targets": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Target IPs, hostnames, or CIDR ranges"
                            },
                            "ports": {
                                "type": "string",
                                "description": "Port range (e.g., '80,443', '1-1000', 'common', 'web')",
                                "default": "common"
                            },
                            "rate": {
                                "type": "integer",
                                "description": "Scan rate (packets/second)",
                                "default": 1000
                            },
                            "timeout": {
                                "type": "integer",
                                "description": "Timeout in seconds",
                                "default": 300
                            }
                        },
                        "required": ["targets"]
                    }
                ),
                Tool(
                    name="fastscan_masscan",
                    description="Use Masscan for high-speed port scanning",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "targets": {
                                "type": "array",
                                "items": {"type": "string"}
                            },
                            "ports": {"type": "string", "default": "common"},
                            "rate": {"type": "integer", "default": 1000},
                            "timeout": {"type": "integer", "default": 300},
                            "additional_args": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Additional Masscan arguments"
                            }
                        },
                        "required": ["targets"]
                    }
                ),
                Tool(
                    name="fastscan_rustscan",
                    description="Use Rustscan for fast port scanning",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "targets": {
                                "type": "array",
                                "items": {"type": "string"}
                            },
                            "ports": {"type": "string", "default": "1-65535"},
                            "batch_size": {"type": "integer", "default": 1000},
                            "timeout": {"type": "integer", "default": 300},
                            "additional_args": {
                                "type": "array",
                                "items": {"type": "string"}
                            }
                        },
                        "required": ["targets"]
                    }
                ),
                Tool(
                    name="fastscan_zmap",
                    description="Use Zmap for Internet-wide single port scanning",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "targets": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "CIDR ranges for scanning"
                            },
                            "port": {"type": "integer", "description": "Single port to scan"},
                            "rate": {"type": "integer", "default": 10000},
                            "timeout": {"type": "integer", "default": 600}
                        },
                        "required": ["targets", "port"]
                    }
                ),
                Tool(
                    name="fastscan_compare",
                    description="Compare results between Masscan and Rustscan",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "targets": {
                                "type": "array",
                                "items": {"type": "string"}
                            },
                            "ports": {"type": "string", "default": "common"},
                            "timeout": {"type": "integer", "default": 300}
                        },
                        "required": ["targets"]
                    }
                ),
                Tool(
                    name="check_fastscan_tools",
                    description="Check which fast scanning tools are available",
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
                if name == "check_fastscan_tools":
                    response = "🚀 FastScan Tools Status:\n\n"
                    
                    for tool_name, tool_info in self.tools.items():
                        if tool_info.get('available'):
                            status = "✅"
                            details = f"{tool_info['path']}"
                            if tool_info.get('requires_root'):
                                details += " (requires root)"
                            if 'version' in tool_info:
                                details += f"\n    Version: {tool_info['version']}"
                        else:
                            status = "❌"
                            details = "Not installed"
                        
                        response += f"{status} {tool_name.capitalize()}: {details}\n"
                    
                    response += "\n📝 Installation Notes:\n"
                    response += "• Masscan: apt install masscan (requires root)\n"
                    response += "• Rustscan: cargo install rustscan (no root required)\n"
                    response += "• Zmap: apt install zmap (requires root)\n"
                    
                    return [TextContent(type="text", text=response)]

                elif name == "fastscan_auto":
                    targets = arguments.get("targets", [])
                    ports = arguments.get("ports", "common")
                    rate = arguments.get("rate", 1000)
                    timeout = arguments.get("timeout", 300)
                    
                    return await self.run_auto_scan(targets, ports, rate, timeout)

                elif name == "fastscan_masscan":
                    targets = arguments.get("targets", [])
                    ports = arguments.get("ports", "common")
                    rate = arguments.get("rate", 1000)
                    timeout = arguments.get("timeout", 300)
                    additional_args = arguments.get("additional_args", [])
                    
                    return await self.run_masscan_scan(targets, ports, rate, timeout, additional_args)

                elif name == "fastscan_rustscan":
                    targets = arguments.get("targets", [])
                    ports = arguments.get("ports", "1-65535")
                    batch_size = arguments.get("batch_size", 1000)
                    timeout = arguments.get("timeout", 300)
                    additional_args = arguments.get("additional_args", [])
                    
                    return await self.run_rustscan_scan(targets, ports, batch_size, timeout, additional_args)

                elif name == "fastscan_zmap":
                    targets = arguments.get("targets", [])
                    port = arguments.get("port")
                    rate = arguments.get("rate", 10000)
                    timeout = arguments.get("timeout", 600)
                    
                    return await self.run_zmap_scan(targets, port, rate, timeout)

                elif name == "fastscan_compare":
                    targets = arguments.get("targets", [])
                    ports = arguments.get("ports", "common")
                    timeout = arguments.get("timeout", 300)
                    
                    return await self.run_comparison_scan(targets, ports, timeout)

                else:
                    raise ValueError(f"Unknown tool: {name}")
                    
            except Exception as e:
                logger.error(f"Error in tool call {name}: {e}")
                return [TextContent(type="text", text=f"Error: {str(e)}")]

    async def run_auto_scan(self, targets: List[str], ports: str, rate: int, timeout: int) -> List[TextContent]:
        """Automatically choose and run the best available scanner"""
        valid_targets = self.validate_targets(targets)
        if not valid_targets:
            return [TextContent(type="text", text="❌ No valid targets provided")]
        
        parsed_ports = self.parse_port_range(ports)
        
        # Choose best available tool
        if self.tools['rustscan']['available']:
            tool = 'rustscan'
            result = await self.run_rustscan(valid_targets, parsed_ports, timeout)
        elif self.tools['masscan']['available']:
            tool = 'masscan' 
            result = await self.run_masscan(valid_targets, parsed_ports, rate, timeout)
        else:
            return [TextContent(type="text", text="❌ No fast scanning tools available")]
        
        return await self.format_scan_response(result, f"Auto-selected {tool}")

    async def run_masscan_scan(self, targets: List[str], ports: str, rate: int, timeout: int, additional_args: List[str]) -> List[TextContent]:
        """Run Masscan scan"""
        valid_targets = self.validate_targets(targets)
        if not valid_targets:
            return [TextContent(type="text", text="❌ No valid targets provided")]
        
        parsed_ports = self.parse_port_range(ports)
        result = await self.run_masscan(valid_targets, parsed_ports, rate, timeout, additional_args)
        
        return await self.format_scan_response(result, "Masscan")

    async def run_rustscan_scan(self, targets: List[str], ports: str, batch_size: int, timeout: int, additional_args: List[str]) -> List[TextContent]:
        """Run Rustscan scan"""
        valid_targets = self.validate_targets(targets)
        if not valid_targets:
            return [TextContent(type="text", text="❌ No valid targets provided")]
        
        parsed_ports = self.parse_port_range(ports) if ports != "1-65535" else ""
        result = await self.run_rustscan(valid_targets, parsed_ports, timeout, batch_size, additional_args)
        
        return await self.format_scan_response(result, "Rustscan")

    async def run_zmap_scan(self, targets: List[str], port: int, rate: int, timeout: int) -> List[TextContent]:
        """Run Zmap scan"""
        valid_targets = self.validate_targets(targets)
        if not valid_targets:
            return [TextContent(type="text", text="❌ No valid targets provided")]
        
        result = await self.run_zmap(valid_targets, port, rate, timeout)
        
        return await self.format_scan_response(result, "Zmap")

    async def run_comparison_scan(self, targets: List[str], ports: str, timeout: int) -> List[TextContent]:
        """Compare results between available scanners"""
        valid_targets = self.validate_targets(targets)
        if not valid_targets:
            return [TextContent(type="text", text="❌ No valid targets provided")]
        
        parsed_ports = self.parse_port_range(ports)
        results = {}
        
        # Run available scanners
        if self.tools['masscan']['available']:
            results['masscan'] = await self.run_masscan(valid_targets, parsed_ports, 1000, timeout//2)
        
        if self.tools['rustscan']['available']:
            results['rustscan'] = await self.run_rustscan(valid_targets, parsed_ports, timeout//2)
        
        return await self.format_comparison_response(results, valid_targets, parsed_ports)

    async def format_scan_response(self, result: Dict[str, Any], tool_name: str) -> List[TextContent]:
        """Format scan response for display"""
        if not result['success']:
            return [TextContent(type="text", text=f"❌ {tool_name} scan failed: {result.get('error', 'Unknown error')}")]
        
        response = f"🚀 {tool_name} Fast Scan Results\n"
        response += "=" * 50 + "\n\n"
        
        if 'scan_id' in result:
            response += f"📊 Scan ID: {result['scan_id']}\n"
        
        response += f"🎯 Targets: {', '.join(result.get('targets_scanned', []))}\n"
        response += f"🔍 Ports: {result.get('ports_scanned', 'N/A')}\n"
        
        # Results summary
        results = result.get('results', [])
        if results:
            response += f"✅ Open ports found: {len(results)}\n\n"
            
            # Group by host
            hosts = {}
            for res in results:
                ip = res.get('ip', 'unknown')
                port = res.get('port', 'unknown')
                if ip not in hosts:
                    hosts[ip] = []
                hosts[ip].append(port)
            
            response += "📋 Open Ports by Host:\n"
            for ip, ports in sorted(hosts.items()):
                ports_str = ', '.join(map(str, sorted(ports)))
                response += f"  {ip}: {ports_str}\n"
            
            # Show detailed results for first few hosts
            if len(results) <= 50:
                response += "\n📝 Detailed Results:\n"
                for res in sorted(results, key=lambda x: (x.get('ip', ''), x.get('port', 0))):
                    response += f"  {res.get('ip', 'unknown')}:{res.get('port', 'unknown')} ({res.get('proto', 'tcp')}) - {res.get('status', 'open')}\n"
            elif len(results) > 50:
                response += f"\n... showing summary view ({len(results)} total results)\n"
        else:
            response += "❌ No open ports found\n"
        
        # Add performance info from stderr if available
        stderr = result.get('stderr', '')
        if stderr:
            # Extract interesting performance metrics
            if 'rate' in stderr.lower():
                response += f"\n📈 Performance Info:\n{stderr[:200]}...\n"
        
        return [TextContent(type="text", text=response)]

    async def format_comparison_response(self, results: Dict[str, Dict[str, Any]], targets: List[str], ports: str) -> List[TextContent]:
        """Format comparison response between multiple scanners"""
        response = f"🔄 FastScan Tool Comparison\n"
        response += "=" * 40 + "\n\n"
        response += f"🎯 Targets: {', '.join(targets)}\n"
        response += f"🔍 Ports: {ports}\n\n"
        
        # Summary of each tool
        all_results = {}
        for tool, result in results.items():
            if result['success']:
                ports_found = len(result.get('results', []))
                response += f"✅ {tool.capitalize()}: {ports_found} open ports\n"
                
                # Collect results for comparison
                for res in result.get('results', []):
                    key = f"{res.get('ip')}:{res.get('port')}"
                    if key not in all_results:
                        all_results[key] = {'found_by': []}
                    all_results[key]['found_by'].append(tool)
                    all_results[key]['ip'] = res.get('ip')
                    all_results[key]['port'] = res.get('port')
            else:
                response += f"❌ {tool.capitalize()}: Failed - {result.get('error', 'Unknown error')}\n"
        
        if all_results:
            response += "\n📊 Comparison Analysis:\n"
            
            # Find consensus and unique findings
            consensus = []
            unique = {}
            
            for key, data in all_results.items():
                if len(data['found_by']) > 1:
                    consensus.append(key)
                else:
                    tool = data['found_by'][0]
                    if tool not in unique:
                        unique[tool] = []
                    unique[tool].append(key)
            
            if consensus:
                response += f"🤝 Consensus findings ({len(consensus)}): Found by multiple tools\n"
                for key in sorted(consensus):
                    response += f"  {key}\n"
            
            if unique:
                response += f"\n🔍 Unique findings:\n"
                for tool, findings in unique.items():
                    response += f"  {tool.capitalize()} only ({len(findings)}): {', '.join(findings[:5])}"
                    if len(findings) > 5:
                        response += f" ... and {len(findings) - 5} more"
                    response += "\n"
            
            response += f"\n📈 Total unique ports: {len(all_results)}\n"
        
        return [TextContent(type="text", text=response)]

async def main():
    """Main entry point"""
    try:
        server = FastScanMCPServer()
        
        logger.info("Starting FastScan MCP Server...")
        
        async with stdio_server() as (read_stream, write_stream):
            await server.server.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="fastscan-mcp-server",
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
