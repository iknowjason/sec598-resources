#!/bin/bash

# Set variables
HOSTS_FILE="/home/ubuntu/hosts.txt"
MASSCAN_OUTPUT="/home/ubuntu/new_masscan_scan.json"
HOSTS_PORTS_FILE="/home/ubuntu/new_hosts-ports.txt"
NUCLEI_OUTPUT="/home/ubuntu/new_nuclei-output.json"
NEW_VULN_BASELINE="/home/ubuntu/new-output-vuln.txt"
BASELINE_VULN_FILE="/home/ubuntu/output-vuln-baseline.txt"
LOG_FILE="/home/ubuntu/vuln_scan.log"
RESULT_FILE="/home/ubuntu/vuln-result.txt"

# Ensure log directory exists
mkdir -p "$(dirname $LOG_FILE)"

# Log start of scan with timestamp
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting weekly vulnerability scan" >> $LOG_FILE
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting weekly vulnerability scan"

# Step 1: Run masscan port scan to create a JSON file and sweep top ports - adjust as necessary
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Running masscan" >> $LOG_FILE
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Running masscan"
sudo masscan --top-ports 10000 -iL $HOSTS_FILE -oJ $MASSCAN_OUTPUT

# Step 2: Convert masscan JSON to hosts-ports format
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Converting masscan output to hosts-ports format" >> $LOG_FILE
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Converting masscan output to hosts-ports format"
jq -r '.[] | "\(.ip):\(.ports[].port)"' $MASSCAN_OUTPUT | sort -u > $HOSTS_PORTS_FILE

# Step 3: Run nuclei vulnerability scan with hosts-ports file as input, output nuclei to json
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Running nuclei vulnerability scan" >> $LOG_FILE
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Running nuclei vulnerability scan"
cat $HOSTS_PORTS_FILE | httpx | nuclei -json-export $NUCLEI_OUTPUT

# Step 4: Convert nuclei findings to a text file with each issue on a separate line as template:host format
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Converting nuclei output to text format" >> $LOG_FILE
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Converting nuclei output to text format"
jq -r '.[] | "\(.["template-id"]):\(.host)"' $NUCLEI_OUTPUT | sort -u > $NEW_VULN_BASELINE

# Step 5: Compare the new scan with the baseline to find new vulnerabilities
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Comparing new scan with baseline" >> $LOG_FILE
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Comparing new scan with baseline"

# Check if baseline file exists
if [ ! -f "$BASELINE_VULN_FILE" ]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Warning: Baseline file not found. Creating a new baseline." >> $LOG_FILE
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Warning: Baseline file not found. Creating a new baseline."
    cp $NEW_VULN_BASELINE $BASELINE_VULN_FILE
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Initial baseline created. No comparison performed for first run." >> $LOG_FILE
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Initial baseline created. No comparison performed for first run."
    exit 0
fi

# Detect any new vulnerabilities against baseline
NEW_VULNS=$(comm -23 $NEW_VULN_BASELINE $BASELINE_VULN_FILE)

if [ -z "$NEW_VULNS" ]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] No new vulnerabilities found." >> $LOG_FILE
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] No new vulnerabilities found."
else
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] New vulnerabilities found:" >> $LOG_FILE
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] New vulnerabilities found:"
    
    # Clear the result file
    > $RESULT_FILE
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] New Vulnerabilities Detected" >> $RESULT_FILE
    echo "------------------------------------------------" >> $RESULT_FILE
    
    # Process each new vulnerability
    while IFS=':' read -r template host remainder; do
        if [ -n "$remainder" ]; then
            # If there's more than one colon, reconstruct the host part
            host="$host:$remainder"
        fi
        
        echo "New vulnerability based on template found: $template on host: $host" >> $LOG_FILE
        echo "New vulnerability based on template found: $template on host: $host"
        echo "Template: $template" >> $RESULT_FILE
        echo "Host: $host" >> $RESULT_FILE
        echo "------------------------------------------------" >> $RESULT_FILE
    done <<< "$NEW_VULNS"
    
    # Send notification
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Sending notification for new vulnerabilities" >> $LOG_FILE
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Sending notification for new vulnerabilities"
    notify -data $RESULT_FILE -provider-config provider.yaml -bulk
    
    # Update the baseline
    cp $NEW_VULN_BASELINE $BASELINE_VULN_FILE
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Baseline updated with new findings." >> $LOG_FILE
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Baseline updated with new findings."
fi

# Clean up temporary files
rm -f $MASSCAN_OUTPUT $HOSTS_PORTS_FILE $NUCLEI_OUTPUT $NEW_VULN_BASELINE

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Weekly vulnerability scan completed" >> $LOG_FILE
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Weekly vulnerability scan completed"
echo "------------------------------------------------" >> $LOG_FILE
