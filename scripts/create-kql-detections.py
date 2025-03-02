import logging
import sys
import os
import json
import uuid
from llama_index.core import SummaryIndex
from llama_index.readers.web import SimpleWebPageReader
import yaml
import traceback

def validate_customdetails(yaml_content):
    """Ensure that only CommandLine is in the customDetails section."""
    lines = yaml_content.split('\n')
    in_customdetails = False
    customdetails_lines = []

    for line in lines:
        if line.strip() == 'customDetails:':
            in_customdetails = True
            continue
        elif in_customdetails:
            if not line.startswith(' '):
                in_customdetails = False
            else:
                customdetails_lines.append(line.strip())

    # Check if there's anything other than CommandLine
    valid_customdetails = ['CommandLine: CommandLine']
    invalid_fields = [line for line in customdetails_lines if line not in valid_customdetails]

    if invalid_fields:
        print(f"[!] Warning: Invalid customDetails fields found: {invalid_fields}")
        print("[!] Fixing customDetails to only include CommandLine...")

        # Fix the YAML content
        fixed_content = []
        in_customdetails = False
        skip_until_next_top_level = False

        for line in lines:
            if line.strip() == 'customDetails:':
                fixed_content.append('customDetails:')
                fixed_content.append('  CommandLine: CommandLine')
                in_customdetails = True
                skip_until_next_top_level = True
                continue

            if skip_until_next_top_level:
                if not line.startswith(' ') and line.strip():
                    skip_until_next_top_level = False
                    in_customdetails = False
                    fixed_content.append(line)
            elif not in_customdetails:
                fixed_content.append(line)

        return '\n'.join(fixed_content)

    return yaml_content

def main():
    # Configure logging
    logging.basicConfig(stream=sys.stdout, level=logging.INFO)
    logging.getLogger().addHandler(logging.StreamHandler(stream=sys.stdout))

    # Set the url for the analysis target
    url = "https://medium.com/@0xHossam/powershell-exploits-modern-apts-and-their-malicious-scripting-tactics-7f98b0e8090c"
    
    print("\n[+] Analyzing URL for consumption of intelligence:", url)
    
    # Load the data from webpage
    documents = SimpleWebPageReader(html_to_text=True).load_data([url])
    
    # Index the page
    index = SummaryIndex.from_documents(documents)
    
    # Set the query engine to the index
    query_engine = index.as_query_engine()
    
    # Call to OpenAI to summarize with prompt
    print("\n[+] Generating threat intelligence summary and detection options")

    text_summary = query_engine.query('''
    You are a Cyber Security expert with vast knowledge of detection engineering. I am an SOC Analyst and I need help writing a Detection.
    
    First, I want you to consume some threat intelligence from the following blog URL I will share with you.
    I want you to briefly summarize the blog in 5 sentences or less.
    
    Then I want you to output five options for creating Detections of adversary behavior. The Detections will use Sysmon with CommandLine data.
    The Detections will use KQL as Azure sentinel analytics rules.
    
    Format the output as JSON with this structure:
    {
        "summary": "Your 5-sentence summary here",
        "detections": [
            {"id": 1, "name": "Detection name 1", "description": "Description of detection 1"},
            {"id": 2, "name": "Detection name 2", "description": "Description of detection 2"},
            {"id": 3, "name": "Detection name 3", "description": "Description of detection 3"},
            {"id": 4, "name": "Detection name 4", "description": "Description of detection 4"},
            {"id": 5, "name": "Detection name 5", "description": "Description of detection 5"}
        ]
    }
    
    Only respond with the JSON structure, no additional text.
    ''')
    
    # Show summary 
    print("\n===== Blog Summary and Detection Options =====\n")
    try:
        result = json.loads(str(text_summary))
        summary = result["summary"]
        detections = result["detections"]
        
        print("SUMMARY:")
        print(summary)
        print("\nDETECTION OPTIONS:")
        for detection in detections:
            print(f"{detection['id']}. {detection['name']}: {detection['description']}")
        
        # Create a file with summary and options
        with open("summary.txt", "w") as file:
            file.write(f"SUMMARY:\n{summary}\n\nDETECTION OPTIONS:\n")
            for detection in detections:
                file.write(f"{detection['id']}. {detection['name']}: {detection['description']}\n")
        
        print("\n[+] Summary and detection options saved to summary.txt")
        
        # User input 
        selected_detection = None
        while selected_detection not in range(1, 6):
            try:
                selected_detection = int(input("\nSelect a detection option (1-5): "))
                if selected_detection not in range(1, 6):
                    print("Please enter a valid option between 1 and 5.")
            except ValueError:
                print("Please enter a valid number between 1 and 5.")
        
        # Get selected detection details
        selected = next((d for d in detections if d["id"] == selected_detection), None)
        print(f"\n[+] You selected: {selected['name']}")
        
        # Load Sysmon KQL parser
        sysmon_parser = load_sysmon_parser()
        
        # Load YAML templates from example files
        yaml_templates = load_yaml_templates()
        
        # Print out which example we'll be using
        print(f"\n[+] Using template from example1.yaml as base for new detection")
        
        # Make a second query to OpenAI to generate the KQL detection logic
        print(f"\n[+] Generating KQL detection logic for: {selected['name']}")
        kql_detection = generate_kql_detection(selected, query_engine, url)
        print("\n[+] KQL detection logic generated successfully")
        
        # Create YAML file with the detection
        print("\n[+] Creating YAML file with detection rule...")
        try:
            yaml_content = create_yaml_detection(yaml_templates, selected, sysmon_parser, kql_detection)
            print("[+] YAML content created successfully")

            # Validate customDetails
            yaml_content = validate_customdetails(yaml_content)

        except Exception as e:
            print(f"[!] Error creating YAML content: {e}")
            traceback.print_exc()
            sys.exit(1)
        
        # Save YAML file
        detection_filename = f"detection_{selected_detection}_{selected['name'].lower().replace(' ', '_')}.yaml"
        with open(detection_filename, "w") as file:
            file.write(yaml_content)
        
        print(f"\n[+] Detection rule saved to {detection_filename}")
        print(f"[+] Success! The detection is ready for deployment to Azure Sentinel.")
        
    except json.JSONDecodeError:
        print("Error: Could not parse the response as JSON. Here's the raw response:")
        print(text_summary)
        with open("error_response.txt", "w") as file:
            file.write(str(text_summary))
        print("[+] Raw response saved to error_response.txt")


def load_sysmon_parser():
    """Load the Sysmon parser KQL code."""
    # Sysmon-AllVersions_Parser.txt
    # https://github.com/Azure/Azure-Sentinel/blob/master/Parsers/Sysmon/Sysmon-AllVersions_Parser.txt 
    sysmon_parser = """Event
| where Source == "Microsoft-Windows-Sysmon"
| extend RenderedDescription = tostring(split(RenderedDescription, ":")[0])
| extend EventData = parse_xml(EventData).DataItem.EventData.Data
| mv-expand bagexpansion=array EventData
| evaluate bag_unpack(EventData)
| extend Key = tostring(column_ifexists('@Name', "")), Value = tostring(column_ifexists('#text', ""))
| evaluate pivot(Key, any(Value), TimeGenerated, Source, EventLog, Computer, EventLevel, EventLevelName, EventID, UserName, RenderedDescription, MG, ManagementGroupName, _ResourceId)
| extend TimeGenerated = column_ifexists("TimeGenerated", ""), Source = column_ifexists("Source", ""), EventLog = column_ifexists("EventLog", ""), Computer = column_ifexists("Computer", ""), EventLevel = column_ifexists("EventLevel", ""), EventLevelName = column_ifexists("EventLevelName", ""), EventID = column_ifexists("EventID", ""), UserName = column_ifexists("UserName", ""), RenderedDescription = column_ifexists("RenderedDescription", ""), MG = column_ifexists("MG", ""), ManagementGroupName = column_ifexists("ManagementGroupName", ""), _ResourceId = column_ifexists("_ResourceId", ""), UtcTime = column_ifexists("UtcTime", ""), ID = column_ifexists("ID", ""), Description = column_ifexists("Description", ""), RuleName = column_ifexists("RuleName", ""), ProcessGuid = column_ifexists("ProcessGuid", ""), ProcessId = column_ifexists("ProcessId", ""), Image = column_ifexists("Image", ""), FileVersion = column_ifexists("FileVersion", ""), Product = column_ifexists("Product", ""), Company = column_ifexists("Company", ""), OriginalFileName = column_ifexists("OriginalFileName", ""), CommandLine = column_ifexists("CommandLine", ""), CurrentDirectory = column_ifexists("CurrentDirectory", ""), User = column_ifexists("User", ""), LogonGuid = column_ifexists("LogonGuid", ""), LogonId = column_ifexists("LogonId", ""), TerminalSessionId = column_ifexists("TerminalSessionId", ""), IntegrityLevel = column_ifexists("IntegrityLevel", ""), Hashes = column_ifexists("Hashes", ""), ParentProcessGuid = column_ifexists("ParentProcessGuid", ""), ParentProcessId = column_ifexists("ParentProcessId", ""), ParentImage = column_ifexists("ParentImage", ""), ParentCommandLine = column_ifexists("ParentCommandLine", ""), ParentUser = column_ifexists("ParentUser", ""), TargetFilename = column_ifexists("TargetFilename", ""), CreationUtcTime = column_ifexists("CreationUtcTime", ""), PreviousCreationUtcTime = column_ifexists("PreviousCreationUtcTime", ""), Protocol = column_ifexists("Protocol", ""), Initiated = column_ifexists("Initiated", ""), SourceIsIpv6 = column_ifexists("SourceIsIpv6", ""), SourceIp = column_ifexists("SourceIp", ""), SourceHostname = column_ifexists("SourceHostname", ""), SourcePort = column_ifexists("SourcePort", ""), SourcePortName = column_ifexists("SourcePortName", ""), DestinationIsIpv6 = column_ifexists("DestinationIsIpv6", ""), DestinationIp = column_ifexists("DestinationIp", ""), DestinationHostname = column_ifexists("DestinationHostname", ""), DestinationPort = column_ifexists("DestinationPort", ""), DestinationPortName = column_ifexists("DestinationPortName", ""), State = column_ifexists("State", ""), Version = column_ifexists("Version", ""), SchemaVersion = column_ifexists("SchemaVersion", ""), ImageLoaded = column_ifexists("ImageLoaded", ""), Signed = column_ifexists("Signed", ""), Signature = column_ifexists("Signature", ""), SignatureStatus = column_ifexists("SignatureStatus", ""), SourceProcessGuid = column_ifexists("SourceProcessGuid", ""), SourceProcessId = column_ifexists("SourceProcessId", ""), SourceImage = column_ifexists("SourceImage", ""), TargetProcessGuid = column_ifexists("TargetProcessGuid", ""), TargetProcessId = column_ifexists("TargetProcessId", ""), TargetImage = column_ifexists("TargetImage", ""), NewThreadId = column_ifexists("NewThreadId", ""), StartAddress = column_ifexists("StartAddress", ""), StartModule = column_ifexists("StartModule", ""), StartFunction = column_ifexists("StartFunction", ""), SourceUser = column_ifexists("SourceUser", ""), TargetUser = column_ifexists("TargetUser", ""), Device = column_ifexists("Device", ""), SourceProcessGUID = column_ifexists("SourceProcessGUID", ""), SourceThreadId = column_ifexists("SourceThreadId", ""), TargetProcessGUID = column_ifexists("TargetProcessGUID", ""), GrantedAccess = column_ifexists("GrantedAccess", ""), CallTrace = column_ifexists("CallTrace", ""), EventType = column_ifexists("EventType", ""), TargetObject = column_ifexists("TargetObject", ""), Details = column_ifexists("Details", ""), NewName = column_ifexists("NewName", ""), Hash = column_ifexists("Hash", ""), Contents = column_ifexists("Contents", ""), Configuration = column_ifexists("Configuration", ""), ConfigurationFileHash = column_ifexists("ConfigurationFileHash", ""), PipeName = column_ifexists("PipeName", ""), Operation = column_ifexists("Operation", ""), EventNamespace = column_ifexists("EventNamespace", ""), Name = column_ifexists("Name", ""), Query = column_ifexists("Query", ""), Type = column_ifexists("Type", ""), Destination = column_ifexists("Destination", ""), Consumer = column_ifexists("Consumer", ""), Filter = column_ifexists("Filter", ""), QueryName = column_ifexists("QueryName", ""), QueryStatus = column_ifexists("QueryStatus", ""), QueryResults = column_ifexists("QueryResults", ""), IsExecutable = column_ifexists("IsExecutable", ""), Archived = column_ifexists("Archived", ""), Session = column_ifexists("Session", ""), ClientInfo = column_ifexists("ClientInfo", "")
// Fix for wrong casing in EventID10
| extend SourceProcessGuid=iff(isnotempty(SourceProcessGUID),SourceProcessGUID,SourceProcessGuid), TargetProcessGuid=iff(isnotempty(TargetProcessGUID),TargetProcessGUID,TargetProcessGuid)
| project-away SourceProcessGUID, TargetProcessGUID  
// end fix
| parse RuleName with * 'technique_id=' TechniqueId ',' * 'technique_name=' TechniqueName
| parse Hashes with * 'SHA1=' SHA1 ',' * 'MD5=' MD5 ',' * 'SHA256=' SHA256 ',' * 'IMPHASH=' IMPHASH"""
    
    return sysmon_parser


def load_yaml_templates():
    """Load YAML templates from example files."""
    # Check for the required example YAML files
    required_files = ["example1.yaml", "example2.yaml", "example3.yaml"]
    missing_files = [f for f in required_files if not os.path.exists(f)]
    
    if missing_files:
        print(f"[!] Error: The following required YAML template files are missing: {', '.join(missing_files)}")
        print("[!] Please ensure example1.yaml, example2.yaml, and example3.yaml are in the working directory.")
        sys.exit(1)
    
    templates = []
    for file_path in required_files:
        try:
            with open(file_path, 'r') as file:
                content = file.read()                
                templates.append(content)
            print(f"[+] Loaded template from {file_path}")
        except Exception as e:
            print(f"[!] Error loading {file_path}: {e}")
            sys.exit(1)
    
    return templates


def generate_kql_detection(detection, query_engine, blog_url):
    """Generate KQL detection logic with a second call to OpenAI."""
    
    # Make a second API call to generate the specific KQL for the selected detection
    kql_prompt = f"""
    You are a Cyber Security expert with vast knowledge of detection engineering and Kusto Query Language (KQL).
    
    I've analyzed a blog post at {blog_url} about PowerShell exploitation techniques used by APTs.
    
    I need to create a KQL query for an Azure Sentinel detection rule for the following detection:
    Name: {detection['name']}
    Description: {detection['description']}
   
    IMPORTANT REQUIREMENTS:
    1. Create a KQL query that ONLY focuses on the CommandLine field in Sysmon EventID 1 (process creation) events.
    2. DO NOT use any other fields like UserName, as they may not be available in our dataset.
    3. The customDetails section in the YAML must ONLY include the CommandLine field, no other fields.
    
    Your query should start with filtering for Sysmon EventID 1, like:
    | where EventID == 1
    
    Then focus exclusively on patterns in the CommandLine field to detect PowerShell malicious activity.
    Include comments in the query to explain your detection logic.
    
    The KQL detection should focus on analyzing patterns in the CommandLine field that indicate malicious PowerShell usage,
    such as encoded commands, obfuscation techniques, suspicious parameters, etc.
    
    Only return the KQL query without any explanation or additional text.
    """
    
    kql_response = query_engine.query(kql_prompt)
    
    # Clean up the response to get just the KQL
    kql_text = str(kql_response).strip()
    
    # Safety check - verify that no UserName field is being referenced
    problematic_fields = ["UserName", "Username", "User Name", "user_name"]
    for field in problematic_fields:
        if field in kql_text:
            print(f"[!] Warning: Generated KQL contains potentially problematic field: {field}")
            print("[!] Attempting to modify the query to focus only on CommandLine field...")
            kql_text = kql_text.replace(field, "// WARNING: Removed reference to " + field)
    
    # Also check and fix EventID if needed
    if "EventID == 4" in kql_text:
        print("[!] Warning: Generated KQL is using EventID 4 instead of EventID 1 for Sysmon process creation")
        print("[!] Automatically fixing EventID in the query...")
        kql_text = kql_text.replace("EventID == 4", "EventID == 1")
    
    return kql_text


def create_yaml_detection(yaml_templates, detection, sysmon_parser, kql_detection):
    """Create the YAML detection rule using templates and generated KQL."""
    import uuid
    
    # Generate a unique ID for the rule
    rule_id = str(uuid.uuid4())
    
    # DON'T use YAML parser - use direct string manipulation instead
    # This ensures we maintain the exact format and indentation of the template
    
    # Choose the first template
    template_yaml_str = yaml_templates[0]
    
    # Process the template line by line
    lines = template_yaml_str.split('\n')
    result_lines = []
    
    # Track our position in the YAML file
    in_description = False
    in_query = False
    skip_until_next_top_level = False
    
    for i, line in enumerate(lines):
        # Check if we've found a top-level field
        if line and not line.startswith(' ') and ':' in line:
            # Reset state variables when we hit a new top-level field
            in_description = False
            in_query = False
        
        # Check if we need to replace any ID/name/description fields
        if line.startswith('id:'):
            result_lines.append(f'id: {rule_id}')
        elif line.startswith('name:'):
            result_lines.append(f'name: {detection["name"]}')
        elif line.startswith('description:'):
            result_lines.append('description: |')
            in_description = True
            
            # Add description content with proper indentation
            for desc_line in detection['description'].split('\n'):
                result_lines.append(f'  {desc_line}')
            
            # Skip the template's description lines
            skip_until_next_top_level = True
        elif line.startswith('query:'):
            result_lines.append('query: |')
            in_query = True
            
            # Combine Sysmon parser and the detection KQL
            full_query = f"{sysmon_parser}\n{kql_detection}"
            
            # Add query content with proper indentation
            for q_line in full_query.split('\n'):
                # Skip empty lines
                if not q_line.strip():
                    continue
                result_lines.append(f'  {q_line}')
            
            # Skip the template's query lines
            skip_until_next_top_level = True
        elif skip_until_next_top_level:
            # Skip lines until we reach another top-level field
            if line and not line.startswith(' ') and ':' in line:
                skip_until_next_top_level = False
                result_lines.append(line)
        else:
            # Add the line as-is
            result_lines.append(line)
    
    # Join lines back into a single string
    yaml_content = '\n'.join(result_lines)
    
    # Save a debug copy
    with open('debug_direct_yaml.txt', 'w') as f:
        f.write(yaml_content)
    
    return yaml_content


if __name__ == "__main__":
    main()
