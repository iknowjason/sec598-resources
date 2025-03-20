#!/bin/bash

INPUT_FILE="products.txt"
TEMP_FILE="processed_products.txt"

if [ ! -f "$INPUT_FILE" ]; then
    echo "Error: Input file $INPUT_FILE not found."
    exit 1
fi

cat "$INPUT_FILE" | tr '[:upper:]' '[:lower:]' | sed 's/, */,/g' | tr ',' '\n' | sed 's/^ *//g' | sed 's/ *$//g' > "$TEMP_FILE"

echo "Products that will be processed:"
cat "$TEMP_FILE"
echo ""

LOG_FILE="cvemap_run.log"
RESULT_FILE="/home/ubuntu/cve_result.txt"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting CVE mapping for products in $INPUT_FILE" > "$LOG_FILE"

TOTAL_PRODUCTS=$(wc -l < "$TEMP_FILE")
CURRENT=0

NEW_VULNS_FOUND=false

mapfile -t products < "$TEMP_FILE"

> "$RESULT_FILE"

for product in "${products[@]}"; do
    if [ -z "$product" ]; then
        continue
    fi
    
    CURRENT=$((CURRENT + 1))
    
    safe_filename=$(echo "$product" | tr ' ' '_')
    output_file="output_${safe_filename}.json"
    
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Processing $CURRENT/$TOTAL_PRODUCTS: '$product'"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Processing $CURRENT/$TOTAL_PRODUCTS: '$product'" >> "$LOG_FILE"
    
    # Run cvemap command with explicit shell to avoid potential issues
    bash -c "cvemap -p \"$product\" -j > \"$output_file\""
    
    # Check if command succeeded
    if [ $? -eq 0 ]; then
        echo "  ✓ Successfully generated $output_file"
        echo "  ✓ Successfully generated $output_file" >> "$LOG_FILE"
        
        # Check for vulnerabilities discovered in the last x number of days 
        #new_vulns=$(jq -r '.[] | select(.age_in_days < 1) | {cve_id, cve_description, cvss_score, severity}' "$output_file")
        new_vulns=$(jq -r '.[] | select(.age_in_days < 180) | {cve_id, cve_description, cvss_score, severity}' "$output_file")
        
        if [ -n "$new_vulns" ]; then
            echo "  ! New vulnerabilities discovered in '$product'"
            echo "  ! New vulnerabilities discovered in '$product'" >> "$LOG_FILE"
            
            echo "=== New vulnerability discovered in $product ===" >> "$RESULT_FILE"
            echo "$new_vulns" >> "$RESULT_FILE"
            echo "" >> "$RESULT_FILE"
            
            NEW_VULNS_FOUND=true
        else
            echo "  - No new vulnerabilities found for '$product'"
            echo "  - No new vulnerabilities found for '$product'" >> "$LOG_FILE"
        fi
    else
        echo "  ✗ Error running cvemap for '$product'"
        echo "  ✗ Error running cvemap for '$product'" >> "$LOG_FILE"
    fi
    
    sleep 1
done

echo "[$(date '+%Y-%m-%d %H:%M:%S')] All products processed. Check $LOG_FILE for details."
echo "[$(date '+%Y-%m-%d %H:%M:%S')] All products processed." >> "$LOG_FILE"

if [ "$NEW_VULNS_FOUND" = true ]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Sending notification for new vulnerabilities"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Sending notification for new vulnerabilities" >> "$LOG_FILE"
    
    notify -data "$RESULT_FILE" -provider-config provider.yaml -bulk
    
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Notification sent"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Notification sent" >> "$LOG_FILE"
else
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] No new vulnerabilities found, notification not sent"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] No new vulnerabilities found, notification not sent" >> "$LOG_FILE"
fi

rm "$TEMP_FILE"
