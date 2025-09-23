# Workflow Setup for Alert Enrichment Automation with OpenAI 

1. Upload the workflow: ```alert-enrichment.yaml```
2. Add the following API Keys:
   - Secret Name: ```openai```; Secret keys:  ```OPENAI_API_KEY```
   - Secret Name: ```sublime```; Secret keys:  ```SUBLIME_API_KEY```
   - Secret Name: ```urlscan```; Secret keys:  ```URLSCAN_API_KEY```
   - Secret Name: ```virustotal```; Secret keys:  ```VIRUSTOTAL_API_KEY```
    
4. Go into your Default Workspace settings as shown in the image.  You will then allow file extensions and mime types.
5. Add a file extension such as ```.docm```
6. Add Allowed MIME types such as ```application/vnd.ms-word.document.macroenabled.12```
7. Toggle off the ```Validate file content```
8. Click ```Upldate workspace settings```

![workspace-settings](workspace-settings.png "workspace-settings")
