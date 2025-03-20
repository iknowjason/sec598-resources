#!/bin/bash

# Set variables
RANGES_FILE="/home/ubuntu/ranges.txt"
BASELINE_JSON="/home/ubuntu/network_baseline.json"
TEMP_JSON="/home/ubuntu/network_scan_tmp.json"
BASELINE_TXT="/home/ubuntu/network_baseline.txt"
TEMP_TXT="/home/ubuntu/network_scan_tmp.txt"
LOG_FILE="/home/ubuntu/network_scan.log"
RESULT_FILE="/home/ubuntu/network_result.txt"

# Ensure log directory exists
mkdir -p "$(dirname $LOG_FILE)"

# Log start of scan with timestamp
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting network scan for ranges in $RANGES_FILE" >> $LOG_FILE

# Step 1: Run masscan to create a temporary JSON file
sudo masscan --top-ports 10000 -iL $RANGES_FILE -oJ $TEMP_JSON

# Step 2: Convert baseline JSON to list of IP:port
jq -r '.[] | "\(.ip):\(.ports[].port)"' $BASELINE_JSON | sort -u > $BASELINE_TXT

# Step 3: Convert new temp JSON to list of IP:port
jq -r '.[] | "\(.ip):\(.ports[].port)"' $TEMP_JSON | sort -u > $TEMP_TXT

# Step 4: Find new hosts/ports by comparing the two files
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Comparing results with baseline" >> $LOG_FILE

NEW_ENTRIES=$(comm -23 $TEMP_TXT $BASELINE_TXT)

if [ -z "$NEW_ENTRIES" ]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] No new hosts/ports found." >> $LOG_FILE
else
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] New hosts/ports found:" >> $LOG_FILE
    echo "$NEW_ENTRIES" >> $LOG_FILE
    
    # Create the result file for notification
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] New hosts/ports found:" > $RESULT_FILE
    echo "$NEW_ENTRIES" >> $RESULT_FILE
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Network scan completed" >> $RESULT_FILE
    echo "------------------------------------------------" >> $RESULT_FILE
    
    # Send the result to notification channel only when new findings exist
    notify -data $RESULT_FILE -provider-config provider.yaml -bulk
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Notification sent" >> $LOG_FILE
    
    # Update the baseline files with new results
    cp $TEMP_JSON $BASELINE_JSON
    cp $TEMP_TXT $BASELINE_TXT
    
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Baseline updated with new findings." >> $LOG_FILE
fi

# Clean up temporary files
rm -f $TEMP_JSON $TEMP_TXT

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Network scan completed" >> $LOG_FILE
echo "------------------------------------------------" >> $LOG_FILE
