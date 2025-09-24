#!/usr/bin/env python3
"""
Network Analysis MCP Server - Model Context Protocol server for network monitoring and analysis
Integrates Wireshark (tshark), tcpdump, netstat, ss, iftop, and other network tools
"""

import asyncio
import json
import logging
import subprocess
import tempfile
import os
import sys
import re
import signal
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union
from datetime import datetime
import threading
import time

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
logger = logging.getLogger("netanalysis-mcp-server")

class NetworkAnalysisMCPServer:
    """MCP Server for network analysis and monitoring tools"""
    
    def __init__(self):
        self.server = Server("netanalysis-mcp-server")
        self.tools = self.detect_available_tools()
        self.output_dir = Path.home() / ".netanalysis_mcp" / "output"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.active_captures = {}  # Track active packet captures
        self.setup_handlers()
        
    def detect_available_tools(self) -> Dict[str, Dict[str, Any]]:
        """Detect which network analysis tools are available"""
        tools = {}
        
        # Check for tshark (Wireshark CLI)
        try:
            result = subprocess.run(['tshark', '--version'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                which_result = subprocess.run(['which', 'tshark'], capture_output=True, text=True)
                tools['tshark'] = {
                    'path': which_result.stdout.strip(),
                    'version': result.stdout.split('\n')[0],
                    'available': True,
                    'requires_root': True
                }
                logger.info(f"Found tshark: {tools['tshark']['path']}")
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
            tools['tshark'] = {'available': False}
        
        # Check for tcpdump
        try:
            result = subprocess.run(['tcpdump', '--version'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0 or 'tcpdump version' in result.stderr:
                which_result = subprocess.run(['which', 'tcpdump'], capture_output=True, text=True)
                tools['tcpdump'] = {
                    'path': which_result.stdout.strip(),
                    'version': result.stderr.split('\n')[0] if result.stderr else 'Available',
                    'available': True,
                    'requires_root': True
                }
                logger.info(f"Found tcpdump: {tools['tcpdump']['path']}")
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
            tools['tcpdump'] = {'available': False}
        
        # Check for netstat
        try:
            result = subprocess.run(['netstat', '--version'], capture_output=True, text=True, timeout=10)
            which_result = subprocess.run(['which', 'netstat'], capture_output=True, text=True)
            if which_result.returncode == 0:
                tools['netstat'] = {
                    'path': which_result.stdout.strip(),
                    'version': 'Available',
                    'available': True,
                    'requires_root': False
                }
                logger.info(f"Found netstat: {tools['netstat']['path']}")
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
            tools['netstat'] = {'available': False}
        
        # Check for ss (modern netstat replacement)
        try:
            result = subprocess.run(['ss', '--version'], capture_output=True, text=True, timeout=10)
            which_result = subprocess.run(['which', 'ss'], capture_output=True, text=True)
            if which_result.returncode == 0:
                tools['ss'] = {
                    'path': which_result.stdout.strip(),
                    'version': result.stdout.strip() if result.stdout else 'Available',
                    'available': True,
                    'requires_root': False
                }
                logger.info(f"Found ss: {tools['ss']['path']}")
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
            tools['ss'] = {'available': False}
        
        # Check for iftop
        try:
            result = subprocess.run(['iftop', '-h'], capture_output=True, text=True, timeout=10)
            which_result = subprocess.run(['which', 'iftop'], capture_output=True, text=True)
            if which_result.returncode == 0:
                tools['iftop'] = {
                    'path': which_result.stdout.strip(),
                    'version': 'Available',
                    'available': True,
                    'requires_root': True
                }
                logger.info(f"Found iftop: {tools['iftop']['path']}")
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
            tools['iftop'] = {'available': False}
        
        # Check for nethogs
        try:
            result = subprocess.run(['nethogs', '-V'], capture_output=True, text=True, timeout=10)
            which_result = subprocess.run(['which', 'nethogs'], capture_output=True, text=True)
            if which_result.returncode == 0:
                tools['nethogs'] = {
                    'path': which_result.stdout.strip(),
                    'version': 'Available',
                    'available': True,
                    'requires_root': True
                }
                logger.info(f"Found nethogs: {tools['nethogs']['path']}")
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
            tools['nethogs'] = {'available': False}
        
        # Check for lsof
        try:
            which_result = subprocess.run(['which', 'lsof'], capture_output=True, text=True)
            if which_result.returncode == 0:
                tools['lsof'] = {
                    'path': which_result.stdout.strip(),
                    'version': 'Available',
                    'available': True,
                    'requires_root': False
                }
                logger.info(f"Found lsof: {tools['lsof']['path']}")
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
            tools['lsof'] = {'available': False}
        
        available_tools = [name for name, info in tools.items() if info.get('available')]
        logger.info(f"Available network analysis tools: {available_tools}")
        
        return tools

    def get_network_interfaces(self) -> List[str]:
        """Get list of available network interfaces"""
        try:
            result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                interfaces = []
                for line in result.stdout.split('\n'):
                    match = re.search(r'^\d+:\s+(\w+):', line)
                    if match and match.group(1) not in ['lo']:
                        interfaces.append(match.group(1))
                return interfaces
        except:
            pass
        
        # Fallback method
        try:
            result = subprocess.run(['ls', '/sys/class/net/'], capture_output=True, text=True)
            if result.returncode == 0:
                return [iface for iface in result.stdout.split() if iface != 'lo']
        except:
            pass
        
        return ['eth0', 'wlan0']  # Common defaults

    async def run_packet_capture(self, tool: str, interface: str, duration: int, 
                                filter_expr: str = "", output_format: str = "text") -> Dict[str, Any]:
        """Run packet capture using tshark or tcpdump"""
        try:
            capture_id = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            if tool == "tshark" and self.tools['tshark']['available']:
                output_file = self.output_dir / f"tshark_{capture_id}.pcap"
                
                cmd = ['tshark', '-i', interface, '-a', f'duration:{duration}']
                if filter_expr:
                    cmd.extend(['-f', filter_expr])
                if output_format == "pcap":
                    cmd.extend(['-w', str(output_file)])
                else:
                    cmd.extend(['-T', 'text'])
                
            elif tool == "tcpdump" and self.tools['tcpdump']['available']:
                output_file = self.output_dir / f"tcpdump_{capture_id}.pcap"
                
                cmd = ['tcpdump', '-i', interface, '-G', str(duration), '-W', '1']
                if filter_expr:
                    cmd.append(filter_expr)
                if output_format == "pcap":
                    cmd.extend(['-w', str(output_file)])
                else:
                    cmd.extend(['-v'])
                    
            else:
                return {'success': False, 'error': f'{tool} not available'}
            
            logger.info(f"Starting packet capture: {' '.join(cmd[:6])}...")
            
            # Start the capture process
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Store active capture for potential cancellation
            self.active_captures[capture_id] = process
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), 
                    timeout=duration + 30  # Extra buffer
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                return {
                    'success': False,
                    'error': f'Packet capture timed out after {duration + 30} seconds'
                }
            finally:
                # Remove from active captures
                if capture_id in self.active_captures:
                    del self.active_captures[capture_id]
            
            stdout_text = stdout.decode('utf-8', errors='replace')
            stderr_text = stderr.decode('utf-8', errors='replace')
            
            return {
                'success': process.returncode == 0,
                'stdout': stdout_text,
                'stderr': stderr_text,
                'return_code': process.returncode,
                'tool': tool,
                'capture_id': capture_id,
                'output_file': str(output_file) if output_format == "pcap" else None,
                'interface': interface,
                'duration': duration,
                'filter': filter_expr
            }
            
        except Exception as e:
            logger.error(f"Error running packet capture: {e}")
            return {
                'success': False,
                'error': str(e),
                'tool': tool
            }

    async def analyze_network_connections(self, tool: str = "ss") -> Dict[str, Any]:
        """Analyze current network connections"""
        try:
            if tool == "ss" and self.tools['ss']['available']:
                cmd = ['ss', '-tuln', '--processes']
            elif tool == "netstat" and self.tools['netstat']['available']:
                cmd = ['netstat', '-tuln', '--processes']
            else:
                return {'success': False, 'error': f'{tool} not available'}
            
            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await result.communicate()
            stdout_text = stdout.decode('utf-8', errors='replace')
            stderr_text = stderr.decode('utf-8', errors='replace')
            
            # Parse connection information
            connections = self.parse_connections(stdout_text, tool)
            
            return {
                'success': result.returncode == 0,
                'stdout': stdout_text,
                'stderr': stderr_text,
                'tool': tool,
                'connections': connections,
                'connection_count': len(connections)
            }
            
        except Exception as e:
            logger.error(f"Error analyzing connections: {e}")
            return {'success': False, 'error': str(e)}

    def parse_connections(self, output: str, tool: str) -> List[Dict[str, Any]]:
        """Parse network connections from ss/netstat output"""
        connections = []
        lines = output.split('\n')[1:]  # Skip header
        
        for line in lines:
            if not line.strip():
                continue
                
            parts = line.split()
            if len(parts) >= 4:
                connection = {
                    'protocol': parts[0] if parts[0] else 'unknown',
                    'state': parts[1] if tool == 'ss' and len(parts) > 1 else 'unknown',
                    'local_address': parts[3] if len(parts) > 3 else 'unknown',
                    'remote_address': parts[4] if len(parts) > 4 else 'unknown'
                }
                
                # Extract process info if available
                if len(parts) > 5:
                    process_info = ' '.join(parts[5:])
                    connection['process'] = process_info
                
                connections.append(connection)
        
        return connections

    async def monitor_bandwidth(self, interface: str, duration: int = 10) -> Dict[str, Any]:
        """Monitor bandwidth usage using iftop or similar tools"""
        try:
            if self.tools['iftop']['available']:
                cmd = ['iftop', '-i', interface, '-t', '-s', str(duration)]
                tool = 'iftop'
            else:
                # Fallback to basic interface statistics
                return await self.get_interface_stats(interface)
            
            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    result.communicate(), 
                    timeout=duration + 10
                )
            except asyncio.TimeoutError:
                result.kill()
                await result.wait()
                return {'success': False, 'error': 'Bandwidth monitoring timed out'}
            
            stdout_text = stdout.decode('utf-8', errors='replace')
            stderr_text = stderr.decode('utf-8', errors='replace')
            
            return {
                'success': result.returncode == 0,
                'stdout': stdout_text,
                'stderr': stderr_text,
                'tool': tool,
                'interface': interface,
                'duration': duration
            }
            
        except Exception as e:
            logger.error(f"Error monitoring bandwidth: {e}")
            return {'success': False, 'error': str(e)}

    async def get_interface_stats(self, interface: str) -> Dict[str, Any]:
        """Get basic interface statistics"""
        try:
            # Read interface statistics from /proc/net/dev
            stats_file = f'/proc/net/dev'
            
            with open(stats_file, 'r') as f:
                content = f.read()
            
            stats = {}
            for line in content.split('\n'):
                if interface in line:
                    parts = line.split()
                    if len(parts) >= 16:
                        stats = {
                            'interface': interface,
                            'rx_bytes': int(parts[1]),
                            'rx_packets': int(parts[2]),
                            'rx_errors': int(parts[3]),
                            'tx_bytes': int(parts[9]),
                            'tx_packets': int(parts[10]),
                            'tx_errors': int(parts[11])
                        }
                    break
            
            return {
                'success': True,
                'tool': 'proc_net_dev',
                'interface_stats': stats
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}

    async def analyze_open_ports(self) -> Dict[str, Any]:
        """Analyze open ports and listening services"""
        try:
            results = {}
            
            # Use lsof if available
            if self.tools['lsof']['available']:
                result = await asyncio.create_subprocess_exec(
                    'lsof', '-i', '-P', '-n',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await result.communicate()
                results['lsof'] = {
                    'stdout': stdout.decode('utf-8', errors='replace'),
                    'stderr': stderr.decode('utf-8', errors='replace'),
                    'success': result.returncode == 0
                }
            
            # Use ss for listening ports
            if self.tools['ss']['available']:
                result = await asyncio.create_subprocess_exec(
                    'ss', '-tuln',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await result.communicate()
                results['ss_listening'] = {
                    'stdout': stdout.decode('utf-8', errors='replace'),
                    'stderr': stderr.decode('utf-8', errors='replace'),
                    'success': result.returncode == 0
                }
            
            return {
                'success': True,
                'results': results
            }
            
        except Exception as e:
            logger.error(f"Error analyzing open ports: {e}")
            return {'success': False, 'error': str(e)}

    def setup_handlers(self):
        """Setup MCP server handlers"""
        
        @self.server.list_tools()
        async def handle_list_tools() -> List[Tool]:
            """List available network analysis tools"""
            return [
                Tool(
                    name="packet_capture",
                    description="Capture network packets using tshark or tcpdump",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "tool": {
                                "type": "string",
                                "enum": ["tshark", "tcpdump", "auto"],
                                "description": "Packet capture tool to use",
                                "default": "auto"
                            },
                            "interface": {
                                "type": "string",
                                "description": "Network interface to capture from",
                                "default": "any"
                            },
                            "duration": {
                                "type": "integer",
                                "description": "Capture duration in seconds",
                                "default": 30
                            },
                            "filter": {
                                "type": "string",
                                "description": "Packet filter expression (BPF syntax)",
                                "default": ""
                            },
                            "output_format": {
                                "type": "string",
                                "enum": ["text", "pcap"],
                                "description": "Output format",
                                "default": "text"
                            }
                        }
                    }
                ),
                Tool(
                    name="analyze_connections",
                    description="Analyze current network connections",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "tool": {
                                "type": "string",
                                "enum": ["ss", "netstat", "auto"],
                                "description": "Tool to use for connection analysis",
                                "default": "auto"
                            }
                        }
                    }
                ),
                Tool(
                    name="monitor_bandwidth",
                    description="Monitor network bandwidth usage",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "interface": {
                                "type": "string",
                                "description": "Network interface to monitor"
                            },
                            "duration": {
                                "type": "integer",
                                "description": "Monitoring duration in seconds",
                                "default": 10
                            }
                        },
                        "required": ["interface"]
                    }
                ),
                Tool(
                    name="analyze_open_ports",
                    description="Analyze open ports and listening services",
                    inputSchema={
                        "type": "object",
                        "properties": {}
                    }
                ),
                Tool(
                    name="get_network_interfaces",
                    description="List available network interfaces",
                    inputSchema={
                        "type": "object",
                        "properties": {}
                    }
                ),
                Tool(
                    name="check_netanalysis_tools",
                    description="Check which network analysis tools are available",
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
                if name == "check_netanalysis_tools":
                    response = "🔍 Network Analysis Tools Status:\n\n"
                    
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
                        
                        response += f"{status} {tool_name}: {details}\n"
                    
                    response += "\n📝 Installation Notes:\n"
                    response += "• tshark: apt install tshark (Wireshark CLI)\n"
                    response += "• tcpdump: apt install tcpdump\n"
                    response += "• iftop: apt install iftop\n"
                    response += "• nethogs: apt install nethogs\n"
                    response += "• ss/netstat: Usually pre-installed\n"
                    
                    return [TextContent(type="text", text=response)]

                elif name == "get_network_interfaces":
                    interfaces = self.get_network_interfaces()
                    response = "🌐 Available Network Interfaces:\n\n"
                    for iface in interfaces:
                        response += f"• {iface}\n"
                    
                    return [TextContent(type="text", text=response)]

                elif name == "packet_capture":
                    tool = arguments.get("tool", "auto")
                    interface = arguments.get("interface", "any")
                    duration = arguments.get("duration", 30)
                    filter_expr = arguments.get("filter", "")
                    output_format = arguments.get("output_format", "text")
                    
                    # Auto-select tool
                    if tool == "auto":
                        if self.tools['tshark']['available']:
                            tool = "tshark"
                        elif self.tools['tcpdump']['available']:
                            tool = "tcpdump"
                        else:
                            return [TextContent(type="text", text="❌ No packet capture tools available")]
                    
                    # Check root permissions for packet capture
                    if os.geteuid() != 0:
                        return [TextContent(type="text", text="❌ Packet capture requires root privileges. Run with sudo.")]
                    
                    result = await self.run_packet_capture(tool, interface, duration, filter_expr, output_format)
                    
                    return await self.format_capture_response(result)

                elif name == "analyze_connections":
                    tool = arguments.get("tool", "auto")
                    
                    # Auto-select tool
                    if tool == "auto":
                        if self.tools['ss']['available']:
                            tool = "ss"
                        elif self.tools['netstat']['available']:
                            tool = "netstat"
                        else:
                            return [TextContent(type="text", text="❌ No connection analysis tools available")]
                    
                    result = await self.analyze_network_connections(tool)
                    
                    return await self.format_connections_response(result)

                elif name == "monitor_bandwidth":
                    interface = arguments.get("interface")
                    duration = arguments.get("duration", 10)
                    
                    result = await self.monitor_bandwidth(interface, duration)
                    
                    return await self.format_bandwidth_response(result)

                elif name == "analyze_open_ports":
                    result = await self.analyze_open_ports()
                    
                    return await self.format_ports_response(result)

                else:
                    raise ValueError(f"Unknown tool: {name}")
                    
            except Exception as e:
                logger.error(f"Error in tool call {name}: {e}")
                return [TextContent(type="text", text=f"Error: {str(e)}")]

    async def format_capture_response(self, result: Dict[str, Any]) -> List[TextContent]:
        """Format packet capture response"""
        if not result['success']:
            return [TextContent(type="text", text=f"❌ Packet capture failed: {result.get('error', 'Unknown error')}")]
        
        response = f"📡 Packet Capture Results ({result['tool']})\n"
        response += "=" * 50 + "\n\n"
        response += f"🎯 Interface: {result['interface']}\n"
        response += f"⏱️ Duration: {result['duration']} seconds\n"
        response += f"🔍 Filter: {result.get('filter', 'None')}\n"
        
        if result.get('capture_id'):
            response += f"📊 Capture ID: {result['capture_id']}\n"
        
        if result.get('output_file'):
            response += f"💾 Output file: {result['output_file']}\n"
        
        response += "\n📋 Capture Output:\n"
        if result['stdout']:
            # Limit output to prevent overwhelming the response
            stdout_lines = result['stdout'].split('\n')
            if len(stdout_lines) > 100:
                response += '\n'.join(stdout_lines[:50])
                response += f"\n... ({len(stdout_lines) - 100} more lines) ...\n"
                response += '\n'.join(stdout_lines[-50:])
            else:
                response += result['stdout']
        
        return [TextContent(type="text", text=response)]

    async def format_connections_response(self, result: Dict[str, Any]) -> List[TextContent]:
        """Format network connections response"""
        if not result['success']:
            return [TextContent(type="text", text=f"❌ Connection analysis failed: {result.get('error', 'Unknown error')}")]
        
        response = f"🌐 Network Connections Analysis ({result['tool']})\n"
        response += "=" * 50 + "\n\n"
        response += f"📊 Total connections: {result.get('connection_count', 0)}\n\n"
        
        connections = result.get('connections', [])
        if connections:
            # Group by protocol
            protocols = {}
            for conn in connections:
                proto = conn.get('protocol', 'unknown')
                if proto not in protocols:
                    protocols[proto] = []
                protocols[proto].append(conn)
            
            for proto, conns in protocols.items():
                response += f"📋 {proto.upper()} Connections ({len(conns)}):\n"
                for conn in conns[:20]:  # Limit to 20 per protocol
                    local = conn.get('local_address', 'unknown')
                    remote = conn.get('remote_address', 'unknown')
                    state = conn.get('state', 'unknown')
                    response += f"  {local} → {remote} ({state})\n"
                
                if len(conns) > 20:
                    response += f"  ... and {len(conns) - 20} more\n"
                response += "\n"
        else:
            response += "No active connections found.\n"
        
        return [TextContent(type="text", text=response)]

    async def format_bandwidth_response(self, result: Dict[str, Any]) -> List[TextContent]:
        """Format bandwidth monitoring response"""
        if not result['success']:
            return [TextContent(type="text", text=f"❌ Bandwidth monitoring failed: {result.get('error', 'Unknown error')}")]
        
        response = f"📊 Bandwidth Monitoring Results\n"
        response += "=" * 40 + "\n\n"
        response += f"🌐 Interface: {result['interface']}\n"
        response += f"⏱️ Duration: {result['duration']} seconds\n\n"
        
        if result.get('interface_stats'):
            stats = result['interface_stats']
            response += "📈 Interface Statistics:\n"
            response += f"  RX: {stats.get('rx_bytes', 0):,} bytes, {stats.get('rx_packets', 0):,} packets\n"
            response += f"  TX: {stats.get('tx_bytes', 0):,} bytes, {stats.get('tx_packets', 0):,} packets\n"
            response += f"  Errors: RX {stats.get('rx_errors', 0)}, TX {stats.get('tx_errors', 0)}\n"
        
        if result.get('stdout'):
            response += "\n📋 Monitoring Output:\n"
            response += result['stdout'][:2000]  # Limit output
        
        return [TextContent(type="text", text=response)]

    async def format_ports_response(self, result: Dict[str, Any]) -> List[TextContent]:
        """Format open ports analysis response"""
        if not result['success']:
            return [TextContent(type="text", text=f"❌ Port analysis failed: {result.get('error', 'Unknown error')}")]
        
        response = f"🔍 Open Ports Analysis\n"
        response += "=" * 30 + "\n\n"
        
        results = result.get('results', {})
        
        if 'lsof' in results and results['lsof']['success']:
            response += "📋 Open Network Files (lsof):\n"
            lsof_output = results['lsof']['stdout']
            lines = lsof_output.split('\n')[1:]  # Skip header
            
            listening_ports = []
            for line in lines[:50]:  # Limit output
                if 'LISTEN' in line:
                    listening_ports.append(line.strip())
            
            if listening_ports:
                response += f"🔊 Listening services ({len(listening_ports)}):\n"
                for port in listening_ports:
                    response += f"  {port}\n"
            response += "\n"
        
        if 'ss_listening' in results and results['ss_listening']['success']:
            response += "📋 Listening Ports (ss):\n"
            ss_output = results['ss_listening']['stdout']
            lines = ss_output.split('\n')[1:]  # Skip header
            
            for line in lines[:30]:  # Limit output
                if line.strip():
                    response += f"  {line.strip()}\n"
        
        return [TextContent(type="text", text=response)]

async def main():
    """Main entry point"""
    try:
        server = NetworkAnalysisMCPServer()
        logger.info("Starting Network Analysis MCP Server...")
        
        async with stdio_server() as (read_stream, write_stream):
            await server.server.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="netanalysis-mcp-server",
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
