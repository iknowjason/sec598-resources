"""
Security MCP Server - Network scanning, threat intelligence, and red team planning
"""

import asyncio
import json
import logging
import os
import subprocess
import tempfile
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

# API keys from environment
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
HYBRID_ANALYSIS_API_KEY = os.getenv("HYBRID_ANALYSIS_API_KEY", "")
SERPER_API_KEY = os.getenv("SERPER_API_KEY", "")


@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available security tools."""
    tools = [
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
        ),
        Tool(
            name="analyze_email",
            description="Analyze an email file (EML or MSG format) for phishing indicators, brand impersonation, "
                        "lookalike domains, and other security threats using Sublime Security. "
                        "Provide the full path to the email file.",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Full path to the EML or MSG email file to analyze"
                    }
                },
                "required": ["file_path"]
            }
        ),
        Tool(
            name="red_team_planner",
            description="Perform passive OSINT reconnaissance on a target company and generate MITRE ATT&CK "
                        "Initial Access attack plans. Returns 5 phishing/credential harvesting pretexts based on "
                        "publicly available information. Uses Serper API for web research. "
                        "IMPORTANT: Only use for authorized penetration testing engagements.",
            inputSchema={
                "type": "object",
                "properties": {
                    "company_name": {
                        "type": "string",
                        "description": "Target company name for OSINT reconnaissance"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Target company's primary domain (e.g., acme.com)"
                    }
                },
                "required": ["company_name", "domain"]
            }
        )
    ]

    # Only add analyze_file tool if Hybrid Analysis API key is configured
    if HYBRID_ANALYSIS_API_KEY:
        tools.append(
            Tool(
                name="analyze_file",
                description="Submit a file to Hybrid Analysis (Falcon Sandbox) for malware analysis. "
                            "Returns threat scores, detected malware families, and behavioral indicators. "
                            "Requires HYBRID_ANALYSIS_API_KEY environment variable.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Full path to the file to analyze for malware"
                        },
                        "environment": {
                            "type": "string",
                            "enum": ["windows10_64", "windows7_32", "windows7_64", "linux_64"],
                            "description": "Sandbox environment for analysis",
                            "default": "windows10_64"
                        }
                    },
                    "required": ["file_path"]
                }
            )
        )

    return tools


@app.call_tool()
async def call_tool(name: str, arguments: Any) -> list[TextContent]:
    """Handle tool execution."""

    if name == "network_scan":
        return await network_scan(arguments)
    elif name == "virustotal_lookup":
        return await virustotal_lookup(arguments)
    elif name == "analyze_email":
        return await analyze_email(arguments)
    elif name == "analyze_file":
        return await analyze_file(arguments)
    elif name == "red_team_planner":
        return await red_team_planner(arguments)
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
                output += f"WARNING: This file is flagged as malicious by {stats['malicious']} vendors!\n\n"

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
                output += f"WARNING: This IP is flagged as malicious by {stats['malicious']} vendors!\n\n"

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
                output += f"WARNING: This domain is flagged as malicious by {stats['malicious']} vendors!\n\n"

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


async def analyze_email(args: dict) -> list[TextContent]:
    """
    Analyze an email file using Sublime Security CLI.

    Args:
        args: Dictionary containing 'file_path' to EML or MSG file
    """
    file_path = args.get("file_path")

    if not file_path:
        return [TextContent(
            type="text",
            text="Error: file_path parameter is required"
        )]

    # Validate file exists
    if not os.path.exists(file_path):
        return [TextContent(
            type="text",
            text=f"Error: File not found: {file_path}"
        )]

    # Validate file extension
    valid_extensions = ['.eml', '.msg', '.mbox']
    file_ext = os.path.splitext(file_path)[1].lower()
    if file_ext not in valid_extensions:
        return [TextContent(
            type="text",
            text=f"Error: Invalid file type '{file_ext}'. Supported formats: EML, MSG, MBOX"
        )]

    try:
        # Try using sublime Python module first
        try:
            import sublime

            sublime_client = sublime.Sublime()

            # Load the email file
            if file_ext == '.eml':
                raw_message = sublime.util.load_eml(file_path)
            elif file_ext == '.msg':
                raw_message = sublime.util.load_msg(file_path)
            else:
                raw_message = sublime.util.load_mbox(file_path)

            # Load detection rules from default location or sublime-rules
            rules_paths = [
                os.path.expanduser("~/sublime-rules/detection-rules/"),
                "/opt/sublime-rules/detection-rules/",
                os.path.join(os.path.dirname(__file__), "sublime-rules/detection-rules/")
            ]

            rules = []
            queries = []
            for rules_path in rules_paths:
                if os.path.exists(rules_path):
                    rules, queries = sublime.util.load_yml_path(rules_path)
                    break

            if not rules:
                # Analyze without custom rules - will use built-in analysis
                response = sublime_client.analyze_raw_message(raw_message)
            else:
                response = sublime_client.analyze_raw_message(raw_message, rules, queries)

            # Format output
            output = f"Sublime Security Email Analysis\n"
            output += f"{'=' * 50}\n"
            output += f"File: {os.path.basename(file_path)}\n\n"

            # Parse response
            if hasattr(response, 'flagged_rules') and response.flagged_rules:
                output += f"THREATS DETECTED!\n"
                output += f"{'-' * 30}\n"
                for rule in response.flagged_rules:
                    output += f"  - {rule.name}: {rule.description}\n"
                    if hasattr(rule, 'severity'):
                        output += f"    Severity: {rule.severity}\n"
                output += "\n"
            else:
                output += "No threats detected by detection rules.\n\n"

            # Add message metadata if available
            if hasattr(response, 'message'):
                msg = response.message
                if hasattr(msg, 'sender'):
                    output += f"Sender: {msg.sender}\n"
                if hasattr(msg, 'subject'):
                    output += f"Subject: {msg.subject}\n"
                if hasattr(msg, 'recipients'):
                    output += f"Recipients: {', '.join(msg.recipients[:5])}\n"

            return [TextContent(type="text", text=output)]

        except ImportError:
            # Fall back to CLI if module not available
            logger.info("Sublime Python module not found, falling back to CLI")

            # Check for sublime-rules directory
            rules_paths = [
                os.path.expanduser("~/sublime-rules/detection-rules/"),
                "/opt/sublime-rules/detection-rules/",
            ]

            rules_path = None
            for path in rules_paths:
                if os.path.exists(path):
                    rules_path = path
                    break

            # Build CLI command
            cmd = ["sublime", "analyze", "-i", file_path]
            if rules_path:
                cmd.extend(["-r", rules_path])

            # Run sublime CLI
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )

            output = f"Sublime Security Email Analysis\n"
            output += f"{'=' * 50}\n"
            output += f"File: {os.path.basename(file_path)}\n\n"

            if result.returncode == 0:
                output += result.stdout
            else:
                output += f"Analysis completed with warnings:\n{result.stderr}\n"
                output += result.stdout

            return [TextContent(type="text", text=output)]

    except subprocess.TimeoutExpired:
        return [TextContent(
            type="text",
            text="Error: Email analysis timed out after 120 seconds"
        )]
    except FileNotFoundError:
        return [TextContent(
            type="text",
            text="Error: Sublime CLI not found. Install with: pip install sublime-cli\n"
                 "Also clone rules: git clone https://github.com/sublime-security/sublime-rules.git ~/sublime-rules"
        )]
    except Exception as e:
        logger.error(f"Email analysis error: {str(e)}")
        return [TextContent(
            type="text",
            text=f"Error analyzing email: {str(e)}"
        )]


async def analyze_file(args: dict) -> list[TextContent]:
    """
    Submit a file to Hybrid Analysis for malware analysis.

    Args:
        args: Dictionary containing 'file_path' and optional 'environment'
    """
    file_path = args.get("file_path")
    environment = args.get("environment", "windows10_64")

    if not file_path:
        return [TextContent(
            type="text",
            text="Error: file_path parameter is required"
        )]

    if not HYBRID_ANALYSIS_API_KEY:
        return [TextContent(
            type="text",
            text="Error: HYBRID_ANALYSIS_API_KEY environment variable is not set.\n"
                 "Get your API key from https://hybrid-analysis.com/my-account?tab=%23api-key-tab"
        )]

    # Validate file exists
    if not os.path.exists(file_path):
        return [TextContent(
            type="text",
            text=f"Error: File not found: {file_path}"
        )]

    # Environment ID mapping
    env_map = {
        "windows10_64": 160,
        "windows7_32": 100,
        "windows7_64": 120,
        "linux_64": 300
    }

    env_id = env_map.get(environment, 160)

    try:
        # First, check if file hash already exists in database
        import hashlib
        with open(file_path, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()

        headers = {
            "api-key": HYBRID_ANALYSIS_API_KEY,
            "User-Agent": "Falcon Sandbox"
        }

        # Check for existing analysis
        logger.info(f"Checking Hybrid Analysis for existing report: {file_hash}")
        overview_url = f"https://hybrid-analysis.com/api/v2/overview/{file_hash}"
        overview_response = requests.get(overview_url, headers=headers, timeout=30)

        if overview_response.status_code == 200:
            data = overview_response.json()
            return format_hybrid_analysis_result(data, file_path, file_hash, from_cache=True)

        # Submit new file for analysis
        logger.info(f"Submitting file to Hybrid Analysis: {file_path}")
        submit_url = "https://hybrid-analysis.com/api/v2/submit/file"

        with open(file_path, 'rb') as f:
            files = {'file': (os.path.basename(file_path), f)}
            data = {'environment_id': env_id}

            submit_response = requests.post(
                submit_url,
                headers=headers,
                files=files,
                data=data,
                timeout=60
            )

        if submit_response.status_code == 201:
            result = submit_response.json()
            job_id = result.get('job_id')
            sha256 = result.get('sha256')

            output = f"Hybrid Analysis - File Submitted\n"
            output += f"{'=' * 50}\n"
            output += f"File: {os.path.basename(file_path)}\n"
            output += f"SHA256: {sha256}\n"
            output += f"Job ID: {job_id}\n"
            output += f"Environment: {environment}\n\n"
            output += f"Analysis is in progress. Check results at:\n"
            output += f"https://hybrid-analysis.com/sample/{sha256}\n\n"
            output += f"Note: Full analysis typically takes 2-5 minutes.\n"
            output += f"Use virustotal_lookup with the hash to check additional sources."

            return [TextContent(type="text", text=output)]

        elif submit_response.status_code == 429:
            return [TextContent(
                type="text",
                text="Error: API rate limit exceeded. Please wait before submitting more files."
            )]
        else:
            return [TextContent(
                type="text",
                text=f"Error submitting file: {submit_response.status_code}\n{submit_response.text}"
            )]

    except Exception as e:
        logger.error(f"Hybrid Analysis error: {str(e)}")
        return [TextContent(
            type="text",
            text=f"Error analyzing file with Hybrid Analysis: {str(e)}"
        )]


def format_hybrid_analysis_result(data: dict, file_path: str, file_hash: str, from_cache: bool = False) -> list[TextContent]:
    """Format Hybrid Analysis API response into readable output."""
    output = f"Hybrid Analysis - Malware Report\n"
    output += f"{'=' * 50}\n"
    output += f"File: {os.path.basename(file_path)}\n"
    output += f"SHA256: {file_hash}\n"
    if from_cache:
        output += f"(Retrieved from existing analysis)\n"
    output += "\n"

    # Threat score
    threat_score = data.get('threat_score')
    verdict = data.get('verdict')
    if threat_score is not None:
        output += f"Threat Score: {threat_score}/100\n"
    if verdict:
        output += f"Verdict: {verdict.upper()}\n"
        if verdict.lower() == 'malicious':
            output += f"WARNING: This file is classified as MALICIOUS!\n"
    output += "\n"

    # Malware family
    families = data.get('malware_family') or data.get('vx_family')
    if families:
        output += f"Malware Family: {families}\n\n"

    # Tags
    tags = data.get('tags')
    if tags:
        output += f"Tags: {', '.join(tags)}\n\n"

    # AV detections
    av_detect = data.get('av_detect')
    if av_detect:
        output += f"AV Detection Rate: {av_detect}%\n\n"

    # MITRE ATT&CK techniques
    mitre = data.get('mitre_attcks')
    if mitre:
        output += f"MITRE ATT&CK Techniques:\n"
        for technique in mitre[:10]:
            tactic = technique.get('tactic', 'Unknown')
            tech_id = technique.get('technique', 'Unknown')
            name = technique.get('attck_id_wiki', tech_id)
            output += f"  - [{tactic}] {name}\n"
        output += "\n"

    # Signatures
    signatures = data.get('signatures')
    if signatures:
        output += f"Behavioral Signatures:\n"
        for sig in signatures[:10]:
            if isinstance(sig, dict):
                output += f"  - {sig.get('name', 'Unknown')}: {sig.get('description', '')}\n"
            else:
                output += f"  - {sig}\n"
        output += "\n"

    # Link to full report
    output += f"Full Report: https://hybrid-analysis.com/sample/{file_hash}\n"

    return [TextContent(type="text", text=output)]


async def red_team_planner(args: dict) -> list[TextContent]:
    """
    Perform OSINT reconnaissance and generate MITRE ATT&CK Initial Access attack plans.

    Args:
        args: Dictionary containing 'company_name' and 'domain'
    """
    company_name = args.get("company_name")
    domain = args.get("domain")

    if not company_name or not domain:
        return [TextContent(
            type="text",
            text="Error: Both 'company_name' and 'domain' parameters are required"
        )]

    if not SERPER_API_KEY:
        return [TextContent(
            type="text",
            text="Error: SERPER_API_KEY environment variable is not set.\n"
                 "Get your API key from https://serper.dev/"
        )]

    try:
        logger.info(f"Starting OSINT reconnaissance for {company_name} ({domain})")

        # Perform multiple OSINT searches
        osint_data = await gather_osint(company_name, domain)

        # Generate attack plans based on OSINT
        attack_plans = generate_attack_plans(company_name, domain, osint_data)

        # Format output
        output = f"Red Team Intelligence Report\n"
        output += f"{'=' * 60}\n"
        output += f"Target: {company_name}\n"
        output += f"Domain: {domain}\n"
        output += f"{'=' * 60}\n\n"

        # OSINT Summary
        output += f"OSINT RECONNAISSANCE SUMMARY\n"
        output += f"{'-' * 40}\n"

        if osint_data.get('company_info'):
            output += f"\nCompany Profile:\n{osint_data['company_info']}\n"

        if osint_data.get('executives'):
            output += f"\nKey Personnel Identified:\n"
            for exec in osint_data['executives'][:5]:
                output += f"  - {exec}\n"

        if osint_data.get('technologies'):
            output += f"\nTechnology Stack:\n"
            for tech in osint_data['technologies'][:10]:
                output += f"  - {tech}\n"

        if osint_data.get('recent_news'):
            output += f"\nRecent News/Events:\n"
            for news in osint_data['recent_news'][:5]:
                output += f"  - {news}\n"

        if osint_data.get('job_postings'):
            output += f"\nJob Postings (reveals internal tech):\n"
            for job in osint_data['job_postings'][:5]:
                output += f"  - {job}\n"

        output += f"\n{'=' * 60}\n"
        output += f"MITRE ATT&CK INITIAL ACCESS CAMPAIGN PLANS\n"
        output += f"{'=' * 60}\n\n"

        # Output each attack plan
        for i, plan in enumerate(attack_plans, 1):
            output += f"CAMPAIGN {i}: {plan['name']}\n"
            output += f"{'-' * 40}\n"
            output += f"MITRE Technique: {plan['mitre_id']} - {plan['mitre_name']}\n"
            output += f"Sub-technique: {plan.get('sub_technique', 'N/A')}\n\n"

            output += f"Sender Persona:\n"
            output += f"  Name: {plan['sender_persona']['name']}\n"
            output += f"  Role: {plan['sender_persona']['role']}\n"
            output += f"  Email: {plan['sender_persona']['email']}\n\n"

            output += f"Email Subject: {plan['subject']}\n\n"

            output += f"Pretext Narrative:\n{plan['pretext']}\n\n"

            output += f"Payload Suggestion: {plan['payload']}\n\n"

            output += f"Success Indicators:\n"
            for indicator in plan['success_indicators']:
                output += f"  - {indicator}\n"

            output += f"\n{'=' * 60}\n\n"

        output += f"DISCLAIMER: This information is for authorized penetration testing only.\n"
        output += f"Ensure you have written authorization before conducting any attacks.\n"

        return [TextContent(type="text", text=output)]

    except Exception as e:
        logger.error(f"Red team planner error: {str(e)}")
        return [TextContent(
            type="text",
            text=f"Error performing reconnaissance: {str(e)}"
        )]


async def gather_osint(company_name: str, domain: str) -> dict:
    """Gather OSINT data using Serper API searches."""
    osint_data = {
        'company_info': '',
        'executives': [],
        'technologies': [],
        'recent_news': [],
        'job_postings': []
    }

    headers = {
        "X-API-KEY": SERPER_API_KEY,
        "Content-Type": "application/json"
    }

    searches = [
        {"query": f"{company_name} company about", "type": "company_info"},
        {"query": f"{company_name} CEO CTO CFO executives leadership team", "type": "executives"},
        {"query": f"site:linkedin.com {company_name} employees", "type": "executives"},
        {"query": f"{domain} technology stack software tools", "type": "technologies"},
        {"query": f"site:builtwith.com {domain}", "type": "technologies"},
        {"query": f"{company_name} news announcement 2024 2025", "type": "recent_news"},
        {"query": f"site:linkedin.com/jobs {company_name}", "type": "job_postings"},
        {"query": f"{company_name} careers hiring engineer developer", "type": "job_postings"},
    ]

    for search in searches:
        try:
            response = requests.post(
                "https://google.serper.dev/search",
                headers=headers,
                json={"q": search["query"], "num": 10},
                timeout=15
            )

            if response.status_code == 200:
                data = response.json()
                results = data.get('organic', [])

                for result in results[:5]:
                    title = result.get('title', '')
                    snippet = result.get('snippet', '')
                    combined = f"{title}: {snippet}"

                    if search["type"] == "company_info" and not osint_data['company_info']:
                        osint_data['company_info'] = snippet[:500]
                    elif search["type"] == "executives":
                        osint_data['executives'].append(combined[:200])
                    elif search["type"] == "technologies":
                        osint_data['technologies'].append(combined[:200])
                    elif search["type"] == "recent_news":
                        osint_data['recent_news'].append(combined[:200])
                    elif search["type"] == "job_postings":
                        osint_data['job_postings'].append(combined[:200])

        except Exception as e:
            logger.warning(f"Search failed for '{search['query']}': {str(e)}")
            continue

    # Deduplicate
    osint_data['executives'] = list(set(osint_data['executives']))[:10]
    osint_data['technologies'] = list(set(osint_data['technologies']))[:10]
    osint_data['recent_news'] = list(set(osint_data['recent_news']))[:5]
    osint_data['job_postings'] = list(set(osint_data['job_postings']))[:5]

    return osint_data


def generate_attack_plans(company_name: str, domain: str, osint_data: dict) -> list[dict]:
    """Generate 5 phishing/credential harvesting attack plans based on OSINT."""

    # Extract useful context
    has_executives = len(osint_data.get('executives', [])) > 0
    has_tech = len(osint_data.get('technologies', [])) > 0
    has_news = len(osint_data.get('recent_news', [])) > 0
    has_jobs = len(osint_data.get('job_postings', [])) > 0

    plans = [
        # Plan 1: Executive Impersonation (T1566.001 - Spearphishing Attachment)
        {
            "name": "Executive Communication - Urgent Document Review",
            "mitre_id": "T1566.001",
            "mitre_name": "Phishing: Spearphishing Attachment",
            "sub_technique": "Malicious Office Document",
            "sender_persona": {
                "name": f"Office of the CEO",
                "role": "Executive Assistant",
                "email": f"executive-office@{domain.replace('.', '-')}-corp.com"
            },
            "subject": f"[URGENT] {company_name} Q4 Strategic Initiative - Review Required",
            "pretext": f"""Dear Team Member,

On behalf of the executive leadership team at {company_name}, I am sharing the attached confidential document regarding our upcoming strategic initiatives for the next quarter.

This document contains sensitive information about organizational changes and requires your immediate review and acknowledgment. Please open the attached document and follow the instructions to confirm receipt.

Your prompt attention to this matter is appreciated. If you have any questions, please reach out to your direct supervisor.

Best regards,
Executive Office
{company_name}""",
            "payload": "Macro-enabled Word document (.docm) with embedded PowerShell downloader",
            "success_indicators": [
                "Document opened and macros enabled",
                "Outbound connection to C2 infrastructure",
                "Credential prompt interaction"
            ]
        },

        # Plan 2: IT Support (T1566.002 - Spearphishing Link)
        {
            "name": "IT Security Alert - Password Reset Required",
            "mitre_id": "T1566.002",
            "mitre_name": "Phishing: Spearphishing Link",
            "sub_technique": "Credential Harvesting Page",
            "sender_persona": {
                "name": "IT Security Team",
                "role": "Security Operations",
                "email": f"security-alerts@{domain.replace('.', '-')}-it.com"
            },
            "subject": f"[Action Required] {company_name} Security Update - Password Reset",
            "pretext": f"""SECURITY NOTICE

Our security monitoring systems have detected unusual activity associated with your {company_name} account. As a precautionary measure, we require all employees to verify their credentials.

Please click the secure link below to verify your identity and reset your password within the next 24 hours:

[VERIFY ACCOUNT NOW]

Failure to complete this verification may result in temporary account suspension.

If you did not request this reset, please contact the IT Help Desk immediately.

{company_name} IT Security Team
This is an automated security notification.""",
            "payload": "Cloned SSO/Okta login page hosted on lookalike domain",
            "success_indicators": [
                "Click-through to credential harvesting page",
                "Credential submission captured",
                "MFA token interception (if using real-time phishing proxy)"
            ]
        },

        # Plan 3: HR/Benefits (T1566.001 - Spearphishing Attachment)
        {
            "name": "HR Benefits Update - Open Enrollment",
            "mitre_id": "T1566.001",
            "mitre_name": "Phishing: Spearphishing Attachment",
            "sub_technique": "Malicious PDF with embedded JavaScript",
            "sender_persona": {
                "name": "Human Resources",
                "role": "Benefits Administration",
                "email": f"hr-benefits@{domain.replace('.', '-')}-hr.com"
            },
            "subject": f"{company_name} Open Enrollment 2025 - Action Required by Friday",
            "pretext": f"""Dear {company_name} Team Member,

Open Enrollment for the 2025 benefits year is now open! This is your opportunity to review and update your healthcare, dental, vision, and retirement benefits.

KEY DATES:
- Enrollment Period: Now through Friday
- Changes Effective: January 1, 2025

Please review the attached Benefits Summary document for complete details on plan changes and new offerings this year.

IMPORTANT: You must acknowledge receipt of this document by opening the attachment and completing the verification form.

Questions? Contact HR Benefits at extension 4500.

Best regards,
{company_name} Human Resources""",
            "payload": "PDF with embedded JavaScript or link to malicious HTA file",
            "success_indicators": [
                "PDF opened in vulnerable reader",
                "JavaScript execution",
                "HTA file download and execution"
            ]
        },

        # Plan 4: Vendor/Partner (T1566.002 - Spearphishing Link)
        {
            "name": "Vendor Portal Access - Invoice Review",
            "mitre_id": "T1566.002",
            "mitre_name": "Phishing: Spearphishing Link",
            "sub_technique": "Business Email Compromise (BEC)",
            "sender_persona": {
                "name": "Accounts Payable",
                "role": "Finance Department",
                "email": f"ap-invoices@{domain.replace('.', '-')}-finance.com"
            },
            "subject": f"Invoice #INV-2025-{domain[:3].upper()}-4892 - Payment Confirmation Required",
            "pretext": f"""Hello,

We are processing payment for the attached invoice and require your verification before releasing funds.

Invoice Details:
- Invoice #: INV-2025-{domain[:3].upper()}-4892
- Amount: $47,892.00
- Due Date: This Week

Please log in to our vendor portal to review and confirm this invoice:

[ACCESS VENDOR PORTAL]

If you do not recognize this invoice or have questions, please contact our accounts payable team immediately at ap@{domain}.

Thank you for your prompt attention.

{company_name} Accounts Payable""",
            "payload": "Credential harvesting page mimicking vendor/finance portal",
            "success_indicators": [
                "Portal link clicked",
                "Credentials entered on fake portal",
                "Session token captured"
            ]
        },

        # Plan 5: Software/SaaS Update (T1566.003 - Spearphishing via Service)
        {
            "name": "Collaboration Platform Security Update",
            "mitre_id": "T1566.003",
            "mitre_name": "Phishing: Spearphishing via Service",
            "sub_technique": "OAuth Token Theft via Malicious App",
            "sender_persona": {
                "name": "Microsoft 365 Admin",
                "role": "IT Administration",
                "email": "no-reply@microsoft-365-admin.com"
            },
            "subject": f"[{company_name}] Microsoft 365 Security Update - Authorization Required",
            "pretext": f"""Microsoft 365 Security Notification

Your organization ({company_name}) has enabled enhanced security features that require re-authorization of your Microsoft 365 applications.

To ensure uninterrupted access to:
- Outlook and Email
- Microsoft Teams
- SharePoint and OneDrive
- Office Applications

Please authorize the security update by clicking below:

[AUTHORIZE NOW]

This authorization is required within 48 hours. Failure to complete may result in restricted access to Microsoft 365 services.

This notification was sent to all {company_name} Microsoft 365 users.

Microsoft 365 Administration
This is an automated message from your organization's Microsoft 365 tenant.""",
            "payload": "Malicious OAuth application requesting mail.read, files.read permissions",
            "success_indicators": [
                "OAuth consent flow initiated",
                "Permissions granted to malicious app",
                "Access token obtained for mailbox/files access"
            ]
        }
    ]

    return plans


async def main():
    """Run the MCP server."""
    logger.info("Starting Security MCP Server")
    logger.info(f"VirusTotal API: {'configured' if VT_API_KEY else 'not configured'}")
    logger.info(f"Hybrid Analysis API: {'configured' if HYBRID_ANALYSIS_API_KEY else 'not configured'}")
    logger.info(f"Serper API: {'configured' if SERPER_API_KEY else 'not configured'}")

    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
