from mcp.server.fastmcp import FastMCP
import boto3
import json
import time
import uuid
import os
from urllib.parse import urlsplit, parse_qsl

mcp = FastMCP("Security Testing Adversary")

S3_BUCKET = "bedrock-security-scanner-config"
S3_INSTANCE_DATA_KEY = "ec2-resources/output.json"

@mcp.tool()
def get_methodology() -> str:
    """Provide the security testing methodology for automated penetration testing."""
    return (
        "Security Testing Methodology:\n"
        "1. Port Scanning: Identify open ports and services and perform service identification where possible.\n"
        "2. Vulnerability Assessment: Detect potential vulnerabilities using vulnerability scanning tools.  This can be network services vulnerability scanning as well as web application active scanning.\n"
        "3. Exploitation: Attempt to exploit identified vulnerabilities.  Exploitation should be comprised of building the payload, preapring the target system, and running the exploit.\n"
        "4. Post-Exploitation: Assess the impact of successful exploitation.\n"
    )

@mcp.tool()
def check_access() -> str:
    """
    Check access to EC2 instance using SSM by running 'whoami' command.

    Returns:
        The result of the check_access operation
    """

    try:
        # Initialize boto3 clients
        s3_client = boto3.client('s3')
        ssm_client = boto3.client('ssm')

        # Get the EC2 instance ID from S3
        instance_data = get_instance_data_from_s3(s3_client)

        if not instance_data or 'instance_id' not in instance_data:
            return "Error: EC2 instance data not found in S3. Please ensure the instance has been created."

        instance_id = instance_data['instance_id']

        # Create a unique document name
        document_name = f"CheckAccessSSM-{str(uuid.uuid4())[:8]}"

        # Define the command to run (basic identity check)
        command = "whoami && id"

        # Create and run the SSM document
        result = run_command_with_ssm(ssm_client, instance_id, document_name, "check_access", command)

        # Format the response
        formatted_result = json.dumps(result, indent=2)
        return f"Access check completed on instance {instance_id}:\n{formatted_result}"

    except Exception as e:
        return f"Error checking access: {str(e)}"


@mcp.tool()
def run_masscan_scan(target: str, ports: str = "--top-ports 100") -> str:
    """
    Run a fast Masscan scan against a target to identify open ports.

    Args:
        target: The IP address or CIDR range to scan (e.g., 192.168.1.1 or 192.168.1.0/24)
        ports: The ports to scan, default is all ports (1-65535)
              Use "top100" for top 100 ports only

    Returns:
        The scan results and analysis
    """

    try:

        s3_client = boto3.client('s3')
        ssm_client = boto3.client('ssm')

        instance_data = get_instance_data_from_s3(s3_client)

        if not instance_data or 'instance_id' not in instance_data:
            return "Error: EC2 instance data not found in S3. Please ensure the instance has been created."

        instance_id = instance_data['instance_id']

        scan_id = str(uuid.uuid4())[:8]
        document_name = f"MasscanScan-{scan_id}"
        output_file = f"/tmp/masscan-results-{scan_id}.json"
        s3_key = f"scan-results/masscan-{scan_id}.json"

        port_arg = ""
        if ports.lower() == "top100":
            # Include the top 100 ports
            port_arg = "--top-ports 100 -p6443"
        else:
            port_arg = f"-p {ports}"

        command = f"""
        mkdir -p /tmp/scans
        sudo masscan {target} {port_arg} --rate=500 -oJ {output_file}

        # Upload results to S3
        aws s3 cp {output_file} s3://{S3_BUCKET}/{s3_key}

        # Basic analysis of results
        echo "Analyzing scan results..."
        jq -c '.[] | select(.ports != null) | {{ip: .ip, ports: [.ports[].port]}}' {output_file} || echo "No open ports found"

        echo "Scan complete. Results saved to S3 at s3://{S3_BUCKET}/{s3_key}"
        """

        # Create and run the SSM document
        result = run_command_with_ssm(ssm_client, instance_id, document_name, "masscan", command)

        # Check if scan completed successfully
        if result["status"] != "Success":
            return f"Masscan scan failed:\n{json.dumps(result, indent=2)}"

        try:
            s3_response = s3_client.get_object(Bucket=S3_BUCKET, Key=s3_key)
            scan_results = s3_response['Body'].read().decode('utf-8')

            parsed_results = json.loads(scan_results)

            # Extract open ports
            open_ports = []
            for entry in parsed_results:
                if 'ports' in entry and entry['ports']:
                    for port_info in entry['ports']:
                        if 'port' in port_info:
                            open_ports.append(port_info['port'])

            if open_ports:
                open_ports_str = ", ".join(map(str, sorted(open_ports)))
                analysis = f"Masscan found {len(open_ports)} open ports: {open_ports_str}"
            else:
                analysis = "Masscan did not find any open ports."

            return f"""
            Masscan scan completed successfully against {target}

            Analysis:
            {analysis}

            Raw Command Output:
            {result['stdout']}

            Scan results saved to S3 at: s3://{S3_BUCKET}/{s3_key}
            """
        except Exception as e:
            return f"""
            Masscan scan completed, but there was an error analyzing results: {str(e)}

            Raw Command Output:
            {result['stdout']}

            Scan results saved to S3 at: s3://{S3_BUCKET}/{s3_key}
            """

    except Exception as e:
        return f"Error running Masscan scan: {str(e)}"


@mcp.tool()
def run_nmap_scan(target: str, ports: str = None, scan_type: str = "full") -> str:
    """
    Run an Nmap scan against a target for service identification and detailed port analysis.

    Args:
        target: The IP address or CIDR range to scan (e.g., 192.168.1.1 or 192.168.1.0/24)
        ports: Specific ports to scan (i.e., 80,443,8080) or None to use latest masscan results
        scan_type: The type of scan to perform:
                  - Use the -sV option for service detection
                  - Use -Pn to skip host discovery
                  - Use sudo so that Syn scan can be performed
                  - Always use -n -vvv flags

    Returns:
        The scan results and analysis.  Returns the nmap full command line of the nmap command that was run.
    """

    try:
        s3_client = boto3.client('s3')
        ssm_client = boto3.client('ssm')

        instance_data = get_instance_data_from_s3(s3_client)

        if not instance_data or 'instance_id' not in instance_data:
            return "Error: EC2 instance data not found in S3. Please ensure the instance has been created."

        instance_id = instance_data['instance_id']

        scan_id = str(uuid.uuid4())[:8]
        document_name = f"NmapScan-{scan_id}"
        output_file = f"/tmp/nmap-results-{scan_id}.xml"
        s3_key = f"scan-results/nmap-{scan_id}.xml"

        # If no ports specified, try to get the latest masscan results
        port_command = ""
        if not ports:
            port_command = """
            # Find the latest masscan result
            LATEST_MASSCAN=$(aws s3 ls s3://{S3_BUCKET}/scan-results/masscan- | sort | tail -n 1 | awk '{{print $4}}')
            if [ -n "$LATEST_MASSCAN" ]; then
                echo "Found latest masscan result: $LATEST_MASSCAN"
                aws s3 cp s3://{S3_BUCKET}/scan-results/$LATEST_MASSCAN /tmp/latest-masscan.json

                # Extract open ports from masscan result
                OPEN_PORTS=$(jq -r '.[] | select(.ports != null) | .ports[].port' /tmp/latest-masscan.json | tr '\\n' ',' | sed 's/,$//')
                if [ -n "$OPEN_PORTS" ]; then
                    echo "Using open ports from masscan: $OPEN_PORTS"
                    NMAP_PORT_ARGS="-p $OPEN_PORTS"
                else
                    echo "No open ports found in masscan results. Scanning common ports."
                    NMAP_PORT_ARGS="--top-ports 100"
                fi
            else
                echo "No masscan results found. Scanning common ports."
                NMAP_PORT_ARGS="--top-ports 100"
            fi
            """.format(S3_BUCKET=S3_BUCKET)
        else:
            port_command = f"""
            # Using specified ports: {ports}
            NMAP_PORT_ARGS="-p {ports}"
            """

        # Determine scan options based on scan_type
        scan_options = ""
        if scan_type.lower() == "full":
            scan_options = "-sV -n -vvv -Pn"
        elif scan_type.lower() == "quick":
            scan_options = "-sV --version-intensity 2"  # Service detection with lower intensity
        elif scan_type.lower() == "stealth":
            scan_options = "-sS"  # Stealth SYN scan
        else:
            scan_options = "-sV -n -vvv -Pn"  # Default to service detection

        # Create the nmap command
        command = f"""
        mkdir -p /tmp/scans

        {port_command}

        # Run nmap with appropriate options
        sudo nmap $NMAP_PORT_ARGS {scan_options} -oX {output_file} {target}

        # Convert XML to readable format for analysis
        sudo nmap $NMAP_PORT_ARGS {scan_options} -oN /tmp/nmap-results-{scan_id}.txt {target}

        # Upload results to S3
        aws s3 cp {output_file} s3://{S3_BUCKET}/{s3_key}
        aws s3 cp /tmp/nmap-results-{scan_id}.txt s3://{S3_BUCKET}/scan-results/nmap-{scan_id}.txt

        echo "Scan complete. Results saved to S3 at s3://{S3_BUCKET}/{s3_key}"

        # Display summary of results
        cat /tmp/nmap-results-{scan_id}.txt
        """

        # Create and run the SSM document
        result = run_command_with_ssm(ssm_client, instance_id, document_name, "nmap", command)

        # Check if scan completed successfully
        if result["status"] != "Success":
            return f"Nmap scan failed:\n{json.dumps(result, indent=2)}"

        # Analyze the output directly
        scan_output = result["stdout"]

        # Extract key information from scan output
        open_ports_section = ""
        if "PORT" in scan_output and "STATE" in scan_output:
            lines = scan_output.split('\n')
            port_lines = []
            capture = False

            for line in lines:
                if "PORT" in line and "STATE" in line and "SERVICE" in line:
                    capture = True
                    port_lines.append(line)
                    continue

                if capture and line.strip() and not line.startswith("Nmap") and not line.startswith("Host is"):
                    if "/tcp" in line or "/udp" in line:
                        port_lines.append(line)
                    else:
                        capture = False

            if port_lines:
                open_ports_section = "\n".join(port_lines)

        return f"""
        Nmap scan completed successfully against {target}

        Open Ports and Services:
        {open_ports_section if open_ports_section else "No detailed port information found in the output."}

        Scan Type: {scan_type}

        Raw Scan Output:
        {scan_output}

        Scan results saved to S3 at: s3://{S3_BUCKET}/{s3_key}
        """

    except Exception as e:
        return f"Error running Nmap scan: {str(e)}"

@mcp.tool()
def create_and_run_ssm_document(instance_id: str, document_name: str, command: str) -> str:
    """
    Create and run an SSM document with the specified command.

    Args:
        instance_id: EC2 instance ID
        document_name: Name for the SSM document
        command: Shell command to run

    Returns:
        The result of the SSM command execution
    """

    try:
        # Initialize boto3 client
        ssm_client = boto3.client('ssm')

        # Run the command using SSM
        result = run_command_with_ssm(ssm_client, instance_id, document_name, document_name, command)

        # Format the response
        formatted_result = json.dumps(result, indent=2)
        return f"SSM command execution completed:\n{formatted_result}"

    except Exception as e:
        return f"Error executing SSM command: {str(e)}"


def get_instance_data_from_s3(s3_client):
    """Get EC2 instance data from S3"""
    try:
        # Get the EC2 instance data from S3
        response = s3_client.get_object(
            Bucket=S3_BUCKET,
            Key=S3_INSTANCE_DATA_KEY
        )

        # Parse the JSON content
        content = response['Body'].read().decode('utf-8')
        instance_data = json.loads(content)
        return instance_data
    except s3_client.exceptions.NoSuchKey:
        # File doesn't exist, instance hasn't been created yet
        return None
    except Exception as e:
        raise Exception(f"Failed to get instance data from S3: {str(e)}")


def run_command_with_ssm(ssm_client, instance_id, document_name, tool_name, command):
    """Create and run an SSM document with the specified command"""
    try:
        # Create SSM document for this tool
        ssm_document = {
            "schemaVersion": "2.2",
            "description": f"Run {tool_name} command",
            "parameters": {},
            "mainSteps": [
                {
                    "action": "aws:runShellScript",
                    "name": f"run{tool_name.capitalize()}Command",
                    "inputs": {
                        "runCommand": [
                            command
                        ]
                    }
                }
            ]
        }

        ssm_client.create_document(
            Content=json.dumps(ssm_document),
            Name=document_name,
            DocumentType='Command',
            DocumentFormat='JSON'
        )

        # Run the command
        response = ssm_client.send_command(
            InstanceIds=[instance_id],
            DocumentName=document_name,
            Comment=f"Run command: {tool_name}"
        )

        command_id = response['Command']['CommandId']

        # Wait for command completion
        return wait_for_command_completion(ssm_client, command_id, instance_id, tool_name)

    except Exception as e:
        return {
            "status": "Error",
            "message": str(e),
            "stdout": "",
            "stderr": f"Failed to execute {tool_name}: {str(e)}"
        }
    finally:
        # Clean up the document after execution
        try:
            ssm_client.delete_document(Name=document_name)
        except Exception:
            pass  # Ignore cleanup errors


def wait_for_command_completion(ssm_client, command_id, instance_id, tool_name):
    """Wait for an SSM command to complete and retrieve the results"""
    # Note that this is 60 seconds on retries times time.sleep of 5 - 600 seconds or 10 minutes
    max_retries = 120
    retries = 0

    while retries < max_retries:
        time.sleep(5)  # Wait before checking

        try:
            result = ssm_client.get_command_invocation(
                CommandId=command_id,
                InstanceId=instance_id
            )

            status = result['Status']

            if status in ['Success', 'Failed', 'Cancelled', 'TimedOut']:
                return {
                    "tool": tool_name,
                    "status": status,
                    "stdout": result.get('StandardOutputContent', ''),
                    "stderr": result.get('StandardErrorContent', ''),
                    "execution_time": {
                        "start": result.get('ExecutionStartDateTime', ''),
                        "end": result.get('ExecutionEndDateTime', '')
                    }
                }

        except Exception as e:
            return {
                "tool": tool_name,
                "status": "Error",
                "message": str(e),
                "stdout": "",
                "stderr": f"Error checking command status: {str(e)}"
            }

        retries += 1

    return {
        "tool": tool_name,
        "status": "Timeout",
        "message": "Command execution check timed out",
        "stdout": "",
        "stderr": "Timed out waiting for command to complete"
    }

@mcp.tool()
def run_nuclei_scan(target: str, ports: str = None, custom_templates: str = None) -> str:
    """
    Run comprehensive Nuclei vulnerability scans against a target.

    Args:
        target: The IP address or hostname to scan (e.g., 192.168.1.1 or example.com)
        ports: Specific ports to scan (e.g., "80,443,8080") or None to use latest masscan/nmap results
        custom_templates: Path to custom Nuclei templates on the instance (e.g., "/home/ubuntu/custom")

    Returns:
        The vulnerability scan results and analysis with potential exploitation targets
    """
    try:
        # Initialize boto3 clients
        s3_client = boto3.client('s3')
        ssm_client = boto3.client('ssm')

        # Get the EC2 instance ID from S3
        instance_data = get_instance_data_from_s3(s3_client)

        if not instance_data or 'instance_id' not in instance_data:
            return "Error: EC2 instance data not found in S3. Please ensure the instance has been created."

        instance_id = instance_data['instance_id']

        # Create a unique scan ID
        scan_id = str(uuid.uuid4())[:8]
        document_name = f"NucleiScan-{scan_id}"

        # Prepare port data - Fixed syntax
        port_command = """
        # Try to find open ports from previous scan results
        LATEST_MASSCAN=$(aws s3 ls s3://{S3_BUCKET}/scan-results/masscan- | sort | tail -n 1 | awk '{{print $4}}')
        if [ -n "$LATEST_MASSCAN" ]; then
            echo "Found latest masscan result: $LATEST_MASSCAN"
            aws s3 cp s3://{S3_BUCKET}/scan-results/$LATEST_MASSCAN /tmp/latest-masscan.json

            # Extract open ports from masscan result
            OPEN_PORTS=$(jq -r '.[] | select(.ports != null) | .ports[].port' /tmp/latest-masscan.json | tr '\\n' ',' | sed 's/,$//')
            if [ -n "$OPEN_PORTS" ]; then
                echo "Using open ports from masscan: $OPEN_PORTS"
            else
                echo "No open ports found in masscan results. Using default web ports."
                OPEN_PORTS="80,443,8080,8443"
            fi
        else
            # Try to find nmap results
            LATEST_NMAP=$(aws s3 ls s3://{S3_BUCKET}/scan-results/nmap- | grep txt | sort | tail -n 1 | awk '{{print $4}}')
            if [ -n "$LATEST_NMAP" ]; then
                echo "Found latest nmap result: $LATEST_NMAP"
                aws s3 cp s3://{S3_BUCKET}/scan-results/$LATEST_NMAP /tmp/latest-nmap.txt

                # Extract open ports from nmap result
                OPEN_PORTS=$(grep "^[0-9]" /tmp/latest-nmap.txt | grep "open" | cut -d'/' -f1 | tr '\\n' ',' | sed 's/,$//')
                if [ -n "$OPEN_PORTS" ]; then
                    echo "Using open ports from nmap: $OPEN_PORTS"
                else
                    echo "No open ports found in nmap results. Using default web ports."
                    OPEN_PORTS="80,443,8080,8443"
                fi
            else
                echo "No scan results found. Using default web ports."
                OPEN_PORTS="80,443,8080,8443"
            fi
        fi
        """.format(S3_BUCKET=S3_BUCKET)

        # If ports are specified, override the auto-detection
        if ports:
            port_command += f"""
            # Override with specified ports: {ports}
            OPEN_PORTS="{ports}"
            """

        # Common setup commands - Fix HOME environment variable
        setup_command = f"""
        # Fix HOME directory issue
        export HOME="/home/ubuntu"

        # Find all project discovery tools
        PDTM_PATH="/home/ubuntu/.pdtm/go/bin"
        
        # Ensure Project Discovery tools path is set
        export PATH=$PATH:$PDTM_PATH:/root/go/bin:/usr/local/go/bin:/root/.pdtm/go/bin:/home/ubuntu/.pdtm/go/bin
        
        # Create working directories
        mkdir -p /home/ubuntu/scans/{scan_id}
        cd /home/ubuntu/scans/{scan_id}

        # Save target information
        echo "{target}" > target.txt

        # Create exploitable vulnerabilities file to collect findings
        echo "# EXPLOITABLE VULNERABILITIES" > exploitable.txt
        echo "Target: {target}" >> exploitable.txt
        echo "Scan ID: {scan_id}" >> exploitable.txt
        echo "Date: $(date)" >> exploitable.txt
        echo "" >> exploitable.txt
        """

        # Basic scan implementation - Fixed syntax
        basic_scan_command = """
        echo "===== STARTING BASIC VULNERABILITY SCAN ====="
        echo "Running basic port-based Nuclei scan..."

        # Initialize counters to avoid shell errors
        BASIC_CRITICAL_COUNT=0
        BASIC_HIGH_COUNT=0
        BASIC_MEDIUM_COUNT=0

        # Run Naabu for port scanning and pipe to Nuclei with proper error handling
        echo "{target}" | naabu -p $OPEN_PORTS | nuclei -severity critical,high,medium -o basic-scan.txt || touch basic-scan.txt

        # Upload scan results to S3
        aws s3 cp basic-scan.txt s3://{S3_BUCKET}/scan-results/nuclei-basic-{scan_id}.txt

        # Analyze results for critical and high vulnerabilities - Fixed grep counting
        BASIC_CRITICAL_COUNT=$(grep -c "\\[critical\\]" basic-scan.txt | tr -d '\n' || echo "0")
        BASIC_HIGH_COUNT=$(grep -c "\\[high\\]" basic-scan.txt | tr -d '\n' || echo "0")
        BASIC_MEDIUM_COUNT=$(grep -c "\\[medium\\]" basic-scan.txt | tr -d '\n' || echo "0")

        echo "Basic scan completed with $BASIC_CRITICAL_COUNT critical, $BASIC_HIGH_COUNT high, and $BASIC_MEDIUM_COUNT medium vulnerabilities."

        # Add exploitable vulnerabilities to the collection file
        if [ "$(echo $BASIC_CRITICAL_COUNT | tr -d '\n')" -gt 0 ] || [ "$(echo $BASIC_HIGH_COUNT | tr -d '\n')" -gt 0 ]; then
            echo "## Basic Scan Exploitable Vulnerabilities" >> exploitable.txt
            echo "" >> exploitable.txt
            grep -E "\\[critical\\]|\\[high\\]" basic-scan.txt >> exploitable.txt || echo "None found" >> exploitable.txt
            echo "" >> exploitable.txt
        fi
        """.format(target=target, S3_BUCKET=S3_BUCKET, scan_id=scan_id)

        if not custom_templates:
            custom_templates = "/home/ubuntu/custom"

        advanced_scan_command = """
        echo "===== STARTING ADVANCED VULNERABILITY SCAN ====="

        # Initialize URL count and counters
        URL_COUNT=0
        ADV_CRITICAL_COUNT=0
        ADV_HIGH_COUNT=0
        ADV_MEDIUM_COUNT=0

        # Step 1: Find API endpoints and URLs using Katana
        echo "Starting Katana web crawler to find API endpoints and URLs..."

        # Ensure directory exists
        mkdir -p /home/ubuntu/scans/{scan_id}/urls
        
        echo "Crawling HTTP on port 80"
        katana -u http://{target}:80 -jc -jsl -o /home/ubuntu/scans/{scan_id}/urls/urls-80.txt 

        echo "Crawling HTTPS on port 443"
        katana -u https://{target}:443 -jc -jsl -o /home/ubuntu/scans/{scan_id}/urls/urls-443.txt

        # Combine URL lists
        cat /home/ubuntu/scans/{scan_id}/urls/urls-80.txt /home/ubuntu/scans/{scan_id}/urls/urls-443.txt | sort -u > urls.txt

        # Count discovered URLs
        URL_COUNT=$(wc -l < urls.txt || echo "0")
        echo "Discovered $URL_COUNT URLs/endpoints."

        # Step 2: Run Nuclei DAST scan with custom templates
        echo "Starting advanced Nuclei scan with DAST and custom templates"

        # Check if custom templates exist
        if [ -d "{custom_templates}" ]; then
            echo "Using custom templates from {custom_templates}"
            TEMPLATE_ARG="-t {custom_templates}"
        else
            echo "Custom templates directory not found. Using default templates."
            TEMPLATE_ARG=""
        fi

        # Run Nuclei with DAST mode on discovered URLs only if URLs were found
        if [ "$URL_COUNT" -gt 0 ]; then
            nuclei -l urls.txt $TEMPLATE_ARG -dast -severity critical,high,medium -o advanced-scan.txt || touch advanced-scan.txt

            # Upload scan results to S3
            aws s3 cp urls.txt s3://{S3_BUCKET}/scan-results/nuclei-urls-{scan_id}.txt
            aws s3 cp advanced-scan.txt s3://{S3_BUCKET}/scan-results/nuclei-advanced-{scan_id}.txt

            # Analyze results for critical and high vulnerabilities
            ADV_CRITICAL_COUNT=$(grep -c "\\[critical\\]" advanced-scan.txt | tr -d '\n' || echo "0")
            ADV_HIGH_COUNT=$(grep -c "\\[high\\]" advanced-scan.txt | tr -d '\n' || echo "0")
            ADV_MEDIUM_COUNT=$(grep -c "\\[medium\\]" advanced-scan.txt | tr -d '\n' || echo "0")

            echo "Advanced scan completed with $ADV_CRITICAL_COUNT critical, $ADV_HIGH_COUNT high, and $ADV_MEDIUM_COUNT medium vulnerabilities."

            # Add exploitable vulnerabilities to the collection file
            if [ "$ADV_CRITICAL_COUNT" -gt 0 ] || [ "$ADV_HIGH_COUNT" -gt 0 ]; then
                echo "## Advanced Scan Exploitable Vulnerabilities" >> exploitable.txt
                echo "" >> exploitable.txt
                grep -E "\\[critical\\]|\\[high\\]" advanced-scan.txt >> exploitable.txt || echo "None found" >> exploitable.txt

                echo "" >> exploitable.txt
                echo "## Potential Exploitation Targets (URLs)" >> exploitable.txt
                echo "" >> exploitable.txt
                grep -E "\\[critical\\]|\\[high\\]" advanced-scan.txt | grep -o "http[s]\\?://[^[:space:]]*" | sort -u >> exploitable.txt || echo "None found" >> exploitable.txt
            fi
        else
            echo "No URLs discovered. Skipping advanced scan."
            touch advanced-scan.txt
        fi
        """.format(target=target, S3_BUCKET=S3_BUCKET, scan_id=scan_id, custom_templates=custom_templates)

        # Summary and analysis command - Fixed syntax for arithmetic
        summary_command = """
        # Create comprehensive summary combining both scans
        # Use explicit arithmetic to avoid shell issues
        TOTAL_CRITICAL=$((BASIC_CRITICAL_COUNT + ADV_CRITICAL_COUNT))
        TOTAL_HIGH=$((BASIC_HIGH_COUNT + ADV_HIGH_COUNT))
        TOTAL_MEDIUM=$((BASIC_MEDIUM_COUNT + ADV_MEDIUM_COUNT))

        echo "===== VULNERABILITY SCAN SUMMARY =====" > summary.txt
        echo "Target: {target}" >> summary.txt
        echo "Ports: $OPEN_PORTS" >> summary.txt
        echo "Scan ID: {scan_id}" >> summary.txt
        echo "Time: $(date)" >> summary.txt
        echo "" >> summary.txt

        echo "## Combined Findings" >> summary.txt
        echo "- Critical vulnerabilities: $TOTAL_CRITICAL" >> summary.txt
        echo "- High vulnerabilities: $TOTAL_HIGH" >> summary.txt
        echo "- Medium vulnerabilities: $TOTAL_MEDIUM" >> summary.txt
        echo "" >> summary.txt

        echo "## Basic Scan Results" >> summary.txt
        echo "- Critical: $BASIC_CRITICAL_COUNT" >> summary.txt
        echo "- High: $BASIC_HIGH_COUNT" >> summary.txt
        echo "- Medium: $BASIC_MEDIUM_COUNT" >> summary.txt
        echo "" >> summary.txt

        echo "## Advanced Scan Results" >> summary.txt
        echo "- URLs discovered: $URL_COUNT" >> summary.txt
        echo "- Critical: $ADV_CRITICAL_COUNT" >> summary.txt
        echo "- High: $ADV_HIGH_COUNT" >> summary.txt
        echo "- Medium: $ADV_MEDIUM_COUNT" >> summary.txt
        echo "" >> summary.txt

        # Check if any exploitable vulnerabilities were found
        EXPLOITABLE_COUNT=$((TOTAL_CRITICAL + TOTAL_HIGH))
        if [ "$EXPLOITABLE_COUNT" -gt 0 ]; then
            echo "## RECOMMENDATION" >> summary.txt
            echo "Found $EXPLOITABLE_COUNT critical/high vulnerabilities that could be exploitable." >> summary.txt
            echo "Proceed to exploitation phase targeting these vulnerabilities." >> summary.txt
            echo "See exploitable.txt for detailed targets." >> summary.txt

            # Copy exploitable.txt content to summary
            echo "" >> summary.txt
            echo "## EXPLOITABLE VULNERABILITIES DETAILS" >> summary.txt
            cat exploitable.txt >> summary.txt
        else
            echo "## RECOMMENDATION" >> summary.txt
            echo "No critical or high vulnerabilities found that could be easily exploited." >> summary.txt
            echo "Consider additional scanning techniques or verify medium vulnerabilities." >> summary.txt
        fi

        # Upload final reports to S3
        aws s3 cp summary.txt s3://{S3_BUCKET}/scan-results/nuclei-summary-{scan_id}.txt
        aws s3 cp exploitable.txt s3://{S3_BUCKET}/scan-results/nuclei-exploitable-{scan_id}.txt

        # Output the summary for return value
        cat summary.txt

        # Also return the count of exploitable vulnerabilities for easy parsing
        echo ""
        echo "SCAN_RESULTS_EXPLOITABLE_COUNT=$EXPLOITABLE_COUNT"
        """.format(target=target, S3_BUCKET=S3_BUCKET, scan_id=scan_id)

        # Combine all command sections
        full_command = setup_command + port_command + basic_scan_command + advanced_scan_command + summary_command

        # Create and run the SSM document with extended timeout
        result = run_command_with_ssm(ssm_client, instance_id, document_name, "nuclei", full_command)

        # Check if scan completed successfully
        if result["status"] != "Success":
            return f"Nuclei scan failed:\n{json.dumps(result, indent=2)}"

        # Extract scan results data
        scan_output = result["stdout"]

        # Extract the exploitable vulnerability count
        exploitable_count = 0
        for line in scan_output.split('\n'):
            if line.startswith("SCAN_RESULTS_EXPLOITABLE_COUNT="):
                try:
                    exploitable_count = int(line.split('=')[1].strip())
                except ValueError:
                    pass

        # Format output with proper highlighting for exploitation phase
        if exploitable_count > 0:
            # Extract the exploitable vulnerabilities section for highlighting
            exploitable_section = ""
            capture = False
            for line in scan_output.split('\n'):
                if "EXPLOITABLE VULNERABILITIES DETAILS" in line:
                    capture = True
                    exploitable_section += line + "\n"
                elif capture and line.strip():
                    exploitable_section += line + "\n"

            recommendation = f"""
            CRITICAL FINDING: {exploitable_count} exploitable vulnerabilities detected!

            NEXT STEPS FOR EXPLOITATION PHASE:
            1. Review the detailed vulnerability findings below
            2. Select the most promising vulnerability for exploitation
            3. Develop a targeted exploit based on the vulnerability details
            4. Execute the exploit to achieve the security testing objectives

            {exploitable_section}
            """
        else:
            recommendation = """
            No critical or high vulnerabilities were found that could be easily exploited.

            NEXT STEPS:
            1. Consider running more specialized security tools or custom scans
            2. Verify medium vulnerabilities for potential exploitation vectors
            3. Try different scanning techniques or approaches
            """

        # Construct the final response
        formatted_results = f"""
        COMPREHENSIVE VULNERABILITY SCAN RESULTS

        Target: {target}
        Scan ID: {scan_id}

        Both basic and advanced Nuclei scans have been completed.

        {recommendation}

        Scan details saved to S3 at:
        - s3://{S3_BUCKET}/scan-results/nuclei-basic-{scan_id}.txt
        - s3://{S3_BUCKET}/scan-results/nuclei-advanced-{scan_id}.txt
        - s3://{S3_BUCKET}/scan-results/nuclei-summary-{scan_id}.txt
        - s3://{S3_BUCKET}/scan-results/nuclei-exploitable-{scan_id}.txt
        """

        return formatted_results

    except Exception as e:
        return f"Error running Nuclei scan: {str(e)}"

@mcp.tool()
def open_c2_port(port: int = 9998) -> str:
    """
    Open a port in the AWS Security Group for command and control connections.

    Args:
        port: The TCP port to open (default: 9998)

    Returns:
        Status of the security group rule addition
    """
    try:
        # Initialize boto3 clients
        s3_client = boto3.client('s3')
        ec2_client = boto3.client('ec2')
        ssm_client = boto3.client('ssm')

        # Get the EC2 instance ID from S3
        instance_data = get_instance_data_from_s3(s3_client)

        if not instance_data or 'instance_id' not in instance_data:
            return "Error: EC2 instance data not found in S3. Please ensure the instance has been created."

        instance_id = instance_data['instance_id']

        # Create a unique operation ID
        operation_id = str(uuid.uuid4())[:8]
        document_name = f"OpenC2Port-{operation_id}"

        # Set up command to open the port
        command = f"""
        # Fix HOME directory issue
        export HOME="/home/ubuntu"

        # Create log file
        mkdir -p /home/ubuntu/c2-config
        cd /home/ubuntu/c2-config

        echo "# C2 Port Configuration Log" > c2-port-log.txt
        echo "Port: {port}" >> c2-port-log.txt
        echo "Timestamp: $(date)" >> c2-port-log.txt
        echo "" >> c2-port-log.txt

        # Get instance ID and security groups using AWS metadata
        INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
        echo "Instance ID: $INSTANCE_ID" >> c2-port-log.txt

        # Get security groups for the instance using AWS CLI
        echo "Retrieving security groups..." >> c2-port-log.txt
        SECURITY_GROUPS=$(aws ec2 describe-instances --instance-ids $INSTANCE_ID --query 'Reservations[*].Instances[*].SecurityGroups[*].[GroupId]' --output text)

        if [ -z "$SECURITY_GROUPS" ]; then
            echo "Error: Could not retrieve security groups for instance $INSTANCE_ID" >> c2-port-log.txt
            exit 1
        fi

        echo "Security Groups: $SECURITY_GROUPS" >> c2-port-log.txt

        # Use the first security group
        SG_ID=$(echo $SECURITY_GROUPS | awk '{{print $1}}')
        echo "Using Security Group: $SG_ID" >> c2-port-log.txt

        # Check if port is already open
        echo "Checking if port {port} is already open..." >> c2-port-log.txt
        PORT_CHECK=$(aws ec2 describe-security-groups --group-ids $SG_ID --query 'SecurityGroups[*].IpPermissions[?ToPort==`{port}`]' --output text)

        if [ -n "$PORT_CHECK" ]; then
            echo "Port {port} is already open in security group $SG_ID" >> c2-port-log.txt
        else
            echo "Opening port {port} in security group $SG_ID..." >> c2-port-log.txt

            # Add rule to allow inbound traffic on the specified port
            aws ec2 authorize-security-group-ingress \\
                --group-id $SG_ID \\
                --protocol tcp \\
                --port {port} \\
                --cidr 0.0.0.0/0

            if [ $? -eq 0 ]; then
                echo "Successfully opened port {port} for inbound TCP traffic from any source (0.0.0.0/0)" >> c2-port-log.txt
            else
                echo "Failed to open port {port}. Check AWS CLI output for details." >> c2-port-log.txt
                exit 1
            fi
        fi

        # Save port to S3 for other tools to use
        echo "{port}" > c2-port.txt
        aws s3 cp c2-port.txt s3://{S3_BUCKET}/config/c2-port.txt

        # Save log to S3
        aws s3 cp c2-port-log.txt s3://{S3_BUCKET}/config/c2-port-log-${operation_id}.txt

        # Return results
        cat c2-port-log.txt
        """

        # Run the command
        result = run_command_with_ssm(ssm_client, instance_id, document_name, "open_c2_port", command)

        # Check if command completed successfully
        if result["status"] != "Success":
            return f"Failed to open C2 port:\n{json.dumps(result, indent=2)}"

        # Format the response
        port_output = result["stdout"]

        response = f"""
        C2 PORT CONFIGURATION COMPLETE

        Port: {port}
        Operation ID: {operation_id}

        {port_output}

        The C2 port has been configured in the AWS Security Group.
        This port will be used for reverse shell connections during exploitation.
        """

        return response

    except Exception as e:
        return f"Error opening C2 port: {str(e)}"


@mcp.tool()
def run_exploit(target: str, vuln_info: str, payload_id: str = None) -> str:
    """
    Execute an exploit against the target system using the vulnerability information.  Use ssm to run the exploit command.

    Args:
        target: The IP address or FQDN of the system to exploit
        vuln_info: The payload injected, as returned by build_payload
        payload_id: Optional specific payload ID to use for tracking

    Returns:
        The results of the exploitation attempt
    """
    try:
        return f"The results of the exploitation from ssm command: {target} {vuln_info} {payload_id}"

    except Exception as e:
        return f"Error running payload: {str(e)}"

@mcp.tool()
def build_payload(vuln_information: str, attacker_port: int) -> str:
    """Generate an exploit payload based on the vulnerability information.

    This tool takes the vulnerability information and builds an exploit payload.

    Args:
        vuln_information: The vulnerability information that should be used to build a payload.
        attacker_port: The port number of the attacker's listener.

    Returns:
        A string representing the exploit payload.
    """

    try:
        # generate prompt to build the payload and then return it
        return f"SSM command to build payload: {vuln_information}"

    except Exception as e:
        return f"Error building payload: {str(e)}"

@mcp.tool()
def prepare_target(prepare_commands: str) -> str:
    """Run commmands on the target system to prepare it for the exploit payload.

    This tool runs pre-requisite commands on the target system to prepare it for the exploit payload.

    Args:
        prepare_commands: The commands that should run on the target system to prepare it for the exploit payload.

    Returns:
        A string representing the output.
    """
    try:
        # generate prompt to build the payload and then return it
        return f"SSM command to prepare target: {prepare_commands}"

    except Exception as e:
        return f"Error preparing target: {str(e)}"

if __name__ == "__main__":
    mcp.run()