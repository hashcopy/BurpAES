from burp import IBurpExtender, IHttpListener, IScannerCheck, IScanIssue
from java.io import PrintWriter
import re

class BurpExtender(IBurpExtender, IHttpListener, IScannerCheck):
    
    def registerExtenderCallbacks(self, callbacks):
        # Set up extension name and helpers
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("JS Key/IV Finder")
        
        # Register listeners
        callbacks.registerHttpListener(self)
        callbacks.registerScannerCheck(self)
        
        # Output handlers
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)
        
        # Print initialization message
        self._stdout.println("JS Key/IV Finder Extension Loaded")
        
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Only process responses
        if not messageIsRequest:
            response = messageInfo.getResponse()
            analyzed_response = self._helpers.analyzeResponse(response)
            headers = analyzed_response.getHeaders()
            body_offset = analyzed_response.getBodyOffset()
            body = response[body_offset:].tostring()  # Get response body
            
            # Check if the response is a JavaScript file
            content_type = [header for header in headers if header.lower().startswith("content-type:")]

            if content_type and "javascript" in content_type[0].lower():
                # Search for key and IV in the JavaScript file
                iv_pattern = r'["\']([a-zA-Z0-9+/=]{16,32})["\']'
                key_pattern = r'["\']([a-zA-Z0-9+/=]{32,64})["\']'
                
                iv_matches = list(re.finditer(iv_pattern, body))
                key_matches = list(re.finditer(key_pattern, body))
                
                if iv_matches or key_matches:
                    self.highlightAndLogIssue(messageInfo, body_offset, body, iv_matches, key_matches)

    def highlightAndLogIssue(self, messageInfo, body_offset, body, iv_matches, key_matches):
        markers = []
        
        # Collect byte offsets for each match (IV and Key)
        for match in iv_matches + key_matches:
            start = body_offset + match.start()
            end = body_offset + match.end()
            markers.append([start, end])  # Add start and end positions of each match
        
        # Create a list of highlighted markers for the response
        response_highlight = markers

        # Log issue with the highlighted matches in the response
        url = self._helpers.analyzeRequest(messageInfo).getUrl()
        issue = CustomScanIssue(
            messageInfo.getHttpService(),
            url,
            [self._callbacks.applyMarkers(messageInfo, None, response_highlight)],  # Highlight response
            "Potential Key/IV Found",
            "Found potential IV and Key in JavaScript file.",
            "Information"
        )
        self._callbacks.addScanIssue(issue)

# Custom class for scan issues
class CustomScanIssue(IScanIssue):
    
    def __init__(self, http_service, url, http_messages, name, detail, severity):
        self._http_service = http_service
        self._url = url
        self._http_messages = http_messages
        self._name = name
        self._detail = detail
        self._severity = severity
    
    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name
    
    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity
    
    def getConfidence(self):
        return "Certain"
    
    def getIssueDetail(self):
        return self._detail

    def getIssueBackground(self):
        return None
    
    def getRemediationBackground(self):
        return None

    def getRemediationDetail(self):
        return None
    
    def getHttpMessages(self):
        return self._http_messages
    
    def getHttpService(self):
        return self._http_service
