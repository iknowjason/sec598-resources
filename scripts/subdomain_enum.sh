#!/bin/bash

TARGET="tesla.com"
BASELINE_JSON="/home/ubuntu/subdomain_enum_baseline.json"
TEMP_JSON="/home/ubuntu/temp_subdomain_enum_baseline.json"
BASELINE_TXT="/home/ubuntu/baseline.txt"
TEMP_TXT="/home/ubuntu/temp_baseline.txt"
LOG_FILE="/home/ubuntu/subdomain_enum.log"
NOTIFICATION_REPORT="/home/ubuntu/subdomain_result.txt"

# Check if logfile exists
mkdir -p "$(dirname $LOG_FILE)"

# Log start of scan with timestamp
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting subdomain enumeration scan for $TARGET" >> $LOG_FILE

# Step 1: Run subfinder to create a temporary JSON file
echo $TARGET | subfinder -silent -json -o $TEMP_JSON

# Step 2: Convert baseline JSON to list of hosts (We do need the baseline json to exist)
cat $BASELINE_JSON | jq -r '.host' | sort -u > $BASELINE_TXT

# Step 3: Convert new temp JSON to list of hosts
cat $TEMP_JSON | jq -r '.host' | sort -u > $TEMP_TXT

# Step 4: Find any new hosts by comparing the two files
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Comparing results with baseline" >> $LOG_FILE

NEW_HOSTS=$(comm -23 $TEMP_TXT $BASELINE_TXT)

if [ -z "$NEW_HOSTS" ]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] No new subdomains found." >> $LOG_FILE
else
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] New subdomains found:" >> $LOG_FILE
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] New subdomains found:" > $NOTIFICATION_REPORT
    echo "$NEW_HOSTS" >> $LOG_FILE
    echo "$NEW_HOSTS" > $NOTIFICATION_REPORT
    # Sent notification to channel defined by notify
    notify -data $NOTIFICATION_REPORT -provider-config provider.yaml -bulk
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Notification sent" >> $LOG_FILE
    
    # Update the baseline files with new results
    cp $TEMP_JSON $BASELINE_JSON
    cp $TEMP_TXT $BASELINE_TXT
    
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Baseline updated with new findings." >> $LOG_FILE
fi

# Clean up temporary files
rm $TEMP_JSON $TEMP_TXT

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Subdomain enumeration scan completed" >> $LOG_FILE
echo "------------------------------------------------" >> $LOG_FILE
