"""
Security MCP Server - Network scanning and threat intelligence
"""

import asyncio
import json
import logging
import os
import subprocess
from typing import Any, Optional

import nmap
import requests
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("security-mcp-server")

# Initialize MCP server
app = Server("security-mcp-server")

# VirusTotal API key from environment
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")


@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available security tools."""
    return [
        Tool(
            name="network_scan",
            description="Scan a subnet for open systems and services using nmap. "
                        "Use CIDR notation (e.g., 192.168.1.0/24). "
                        "IMPORTANT: Only use on networks you own or have authorization to scan.",
            inputSchema={
                "type": "object",
                "properties": {
                    "subnet": {
                        "type": "string",
                        "description": "Target subnet in CIDR notation (e.g., 192.168.1.0/24)"
                    },
                    "scan_type": {
                        "type": "string",
                        "enum": ["quick", "standard", "detailed"],
                        "description": "Scan intensity: quick (-sn ping), standard (-sV version), detailed (-A aggressive)",
                        "default": "standard"
                    }
                },
                "required": ["subnet"]
            }
        ),
        Tool(
            name="virustotal_lookup",
            description="Look up threat intelligence for a file hash, IP address, or domain using VirusTotal API. "
                        "Requires VIRUSTOTAL_API_KEY environment variable.",
            inputSchema={
                "type": "object",
                "properties": {
                    "indicator": {
                        "type": "string",
                        "description": "The indicator to look up (MD5/SHA1/SHA256 hash, IP address, or domain)"
                    },
                    "indicator_type": {
                        "type": "string",
                        "enum": ["hash", "ip", "domain"],
                        "description": "Type of indicator being queried"
                    }
                },
                "required": ["indicator", "indicator_type"]
            }
        )
    ]


@app.call_tool()
async def call_tool(name: str, arguments: Any) -> list[TextContent]:
    """Handle tool execution."""

    if name == "network_scan":
        return await network_scan(arguments)
    elif name == "virustotal_lookup":
        return await virustotal_lookup(arguments)
    else:
        raise ValueError(f"Unknown tool: {name}")


async def network_scan(args: dict) -> list[TextContent]:
    """
    Perform network scan using nmap.

    Args:
        args: Dictionary containing 'subnet' and optional 'scan_type'
    """
    subnet = args.get("subnet")
    scan_type = args.get("scan_type", "standard")

    if not subnet:
        return [TextContent(
            type="text",
            text="Error: subnet parameter is required"
        )]

    try:
        # Initialize nmap scanner
        nm = nmap.PortScanner()

        # Determine scan arguments based on type
        scan_args_map = {
            "quick": "-sn",  # Ping scan only
            "standard": "-sV -T4",  # Version detection, faster timing
            "detailed": "-A -T4"  # Aggressive scan (OS, version, scripts)
        }

        scan_args = scan_args_map.get(scan_type, "-sV -T4")

        logger.info(f"Starting {scan_type} scan of {subnet}")

        # Perform the scan
        nm.scan(hosts=subnet, arguments=scan_args)

        # Build results
        results = {
            "scan_type": scan_type,
            "subnet": subnet,
            "hosts_scanned": len(nm.all_hosts()),
            "hosts": []
        }

        for host in nm.all_hosts():
            host_info = {
                "ip": host,
                "hostname": nm[host].hostname() if nm[host].hostname() else "N/A",
                "state": nm[host].state(),
                "protocols": {}
            }

            # Add protocol and port information
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                host_info["protocols"][proto] = []

                for port in ports:
                    port_info = {
                        "port": port,
                        "state": nm[host][proto][port]["state"]
                    }

                    # Add service info if available
                    if "name" in nm[host][proto][port]:
                        port_info["service"] = nm[host][proto][port]["name"]
                    if "product" in nm[host][proto][port]:
                        port_info["product"] = nm[host][proto][port]["product"]
                    if "version" in nm[host][proto][port]:
                        port_info["version"] = nm[host][proto][port]["version"]

                    host_info["protocols"][proto].append(port_info)

            results["hosts"].append(host_info)

        # Format output
        output = f"Network Scan Results for {subnet}\n"
        output += f"{'=' * 50}\n"
        output += f"Scan Type: {scan_type}\n"
        output += f"Hosts Found: {results['hosts_scanned']}\n\n"

        for host in results["hosts"]:
            output += f"Host: {host['ip']}\n"
            output += f"  Hostname: {host['hostname']}\n"
            output += f"  State: {host['state']}\n"

            for proto, ports in host["protocols"].items():
                output += f"  Protocol: {proto.upper()}\n"
                for port_info in ports:
                    output += f"    Port {port_info['port']}: {port_info['state']}"
                    if "service" in port_info:
                        output += f" - {port_info['service']}"
                    if "product" in port_info:
                        output += f" ({port_info['product']}"
                        if "version" in port_info:
                            output += f" {port_info['version']}"
                        output += ")"
                    output += "\n"
            output += "\n"

        return [TextContent(
            type="text",
            text=output
        )]

    except Exception as e:
        logger.error(f"Network scan error: {str(e)}")
        return [TextContent(
            type="text",
            text=f"Error performing network scan: {str(e)}\n"
                 f"Make sure nmap is installed and you have appropriate permissions."
        )]


async def virustotal_lookup(args: dict) -> list[TextContent]:
    """
    Look up threat intelligence using VirusTotal API.

    Args:
        args: Dictionary containing 'indicator' and 'indicator_type'
    """
    indicator = args.get("indicator")
    indicator_type = args.get("indicator_type")

    if not indicator or not indicator_type:
        return [TextContent(
            type="text",
            text="Error: Both 'indicator' and 'indicator_type' parameters are required"
        )]

    if not VT_API_KEY:
        return [TextContent(
            type="text",
            text="Error: VIRUSTOTAL_API_KEY environment variable is not set.\n"
                 "Get your API key from https://www.virustotal.com/"
        )]

    try:
        # Build API endpoint based on indicator type
        api_endpoints = {
            "hash": f"https://www.virustotal.com/api/v3/files/{indicator}",
            "ip": f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}",
            "domain": f"https://www.virustotal.com/api/v3/domains/{indicator}"
        }

        url = api_endpoints.get(indicator_type)
        if not url:
            return [TextContent(
                type="text",
                text=f"Error: Invalid indicator_type '{indicator_type}'"
            )]

        headers = {
            "x-apikey": VT_API_KEY
        }

        logger.info(f"Querying VirusTotal for {indicator_type}: {indicator}")

        # Make API request
        response = requests.get(url, headers=headers, timeout=30)

        if response.status_code == 404:
            return [TextContent(
                type="text",
                text=f"No results found for {indicator_type}: {indicator}"
            )]

        response.raise_for_status()
        data = response.json()

        # Parse results
        attributes = data.get("data", {}).get("attributes", {})

        output = f"VirusTotal Threat Intelligence Report\n"
        output += f"{'=' * 50}\n"
        output += f"Indicator: {indicator}\n"
        output += f"Type: {indicator_type}\n\n"

        # Handle different indicator types
        if indicator_type == "hash":
            stats = attributes.get("last_analysis_stats", {})
            output += f"Last Analysis Stats:\n"
            output += f"  Malicious: {stats.get('malicious', 0)}\n"
            output += f"  Suspicious: {stats.get('suspicious', 0)}\n"
            output += f"  Undetected: {stats.get('undetected', 0)}\n"
            output += f"  Harmless: {stats.get('harmless', 0)}\n\n"

            if stats.get('malicious', 0) > 0:
                output += f"⚠️  WARNING: This file is flagged as malicious by {stats['malicious']} vendors!\n\n"

            # File names
            names = attributes.get("names", [])
            if names:
                output += f"File Names: {', '.join(names[:5])}\n"

            # File type
            file_type = attributes.get("type_description")
            if file_type:
                output += f"File Type: {file_type}\n"

        elif indicator_type == "ip":
            stats = attributes.get("last_analysis_stats", {})
            output += f"Last Analysis Stats:\n"
            output += f"  Malicious: {stats.get('malicious', 0)}\n"
            output += f"  Suspicious: {stats.get('suspicious', 0)}\n"
            output += f"  Undetected: {stats.get('undetected', 0)}\n"
            output += f"  Harmless: {stats.get('harmless', 0)}\n\n"

            if stats.get('malicious', 0) > 0:
                output += f"⚠️  WARNING: This IP is flagged as malicious by {stats['malicious']} vendors!\n\n"

            # ASN and country
            asn = attributes.get("asn")
            country = attributes.get("country")
            if asn:
                output += f"ASN: {asn}\n"
            if country:
                output += f"Country: {country}\n"

        elif indicator_type == "domain":
            stats = attributes.get("last_analysis_stats", {})
            output += f"Last Analysis Stats:\n"
            output += f"  Malicious: {stats.get('malicious', 0)}\n"
            output += f"  Suspicious: {stats.get('suspicious', 0)}\n"
            output += f"  Undetected: {stats.get('undetected', 0)}\n"
            output += f"  Harmless: {stats.get('harmless', 0)}\n\n"

            if stats.get('malicious', 0) > 0:
                output += f"⚠️  WARNING: This domain is flagged as malicious by {stats['malicious']} vendors!\n\n"

            # Categories
            categories = attributes.get("categories", {})
            if categories:
                output += f"Categories: {', '.join(categories.values())}\n"

            asn = attributes.get("asn")
            country = attributes.get("country")
            if asn:
                output += f"ASN: {asn}\n"
            if country:
                output += f"Country: {country}\n"

        elif indicator_type == "domain":
            stats = attributes.get("last_analysis_stats", {})
            output += f"Last Analysis Stats:\n"
            output += f"  Malicious: {stats.get('malicious', 0)}\n"
            output += f"  Suspicious: {stats.get('suspicious', 0)}\n"
            output += f"  Undetected: {stats.get('undetected', 0)}\n"
            output += f"  Harmless: {stats.get('harmless', 0)}\n\n"

            if stats.get('malicious', 0) > 0:
                output += f"⚠️  WARNING: This domain is flagged as malicious by {stats['malicious']} vendors!\n\n"

            # Categories
            categories = attributes.get("categories", {})
            if categories:
                output += f"Categories: {', '.join(categories.values())}\n"
            asn = attributes.get("asn")
            country = attributes.get("country")
            if asn:
                output += f"ASN: {asn}\n"
            if country:
                output += f"Country: {country}\n"

        elif indicator_type == "domain":
            stats = attributes.get("last_analysis_stats", {})
            output += f"Last Analysis Stats:\n"
            output += f"  Malicious: {stats.get('malicious', 0)}\n"
            output += f"  Suspicious: {stats.get('suspicious', 0)}\n"
            output += f"  Undetected: {stats.get('undetected', 0)}\n"
            output += f"  Harmless: {stats.get('harmless', 0)}\n\n"

            if stats.get('malicious', 0) > 0:
                output += f"⚠️  WARNING: This domain is flagged as malicious by {stats['malicious']} vendors!\n\n"

            # Categories
            categories = attributes.get("categories", {})
            if categories:
                output += f"Categories: {', '.join(categories.values())}\n"

        # Reputation score (if available)
        reputation = attributes.get("reputation")
        if reputation is not None:
            output += f"Reputation Score: {reputation}\n"

        return [TextContent(
            type="text",
            text=output
        )]

    except requests.exceptions.HTTPError as e:
        logger.error(f"VirusTotal API error: {str(e)}")
        return [TextContent(
            type="text",
            text=f"Error querying VirusTotal API: {e.response.status_code}\n"
                 f"Message: {e.response.text}"
        )]
    except Exception as e:
        logger.error(f"VirusTotal lookup error: {str(e)}")
        return [TextContent(
            type="text",
            text=f"Error performing VirusTotal lookup: {str(e)}"
        )]


async def main():
    """Run the MCP server."""
    logger.info("Starting Security MCP Server")
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
