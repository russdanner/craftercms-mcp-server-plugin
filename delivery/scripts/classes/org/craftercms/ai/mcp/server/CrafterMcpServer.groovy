/**
* MIT License
*
* Copyright (c) 2018-2025 Crafter Software Corporation. All Rights Reserved.
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/

package org.craftercms.ai.mcp.server;

@Grab(group='com.google.code.gson', module='gson', version='2.13.2')
@Grab(group='io.jsonwebtoken', module='jjwt-api', version='0.13.0')
@Grab(group='io.jsonwebtoken', module='jjwt-impl', version='0.13.0')
@Grab(group='io.jsonwebtoken', module='jjwt-jackson', version='0.13.0', scope='runtime')
@Grab(group='org.slf4j', module='slf4j-api', version='2.0.17')

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.ServletException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URI;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.Jwks;

import java.util.Base64;

import org.craftercms.ai.mcp.server.tools.*
import org.craftercms.ai.mcp.server.resources.*
import org.craftercms.ai.mcp.server.prompts.*
import org.craftercms.ai.mcp.server.auth.*
import org.craftercms.ai.mcp.server.auth.validator.*
import org.craftercms.engine.service.context.SiteContext


import java.io.BufferedReader;
import java.io.IOException;
import java.net.URLEncoder;
import groovy.json.JsonSlurper


class CrafterMcpServer {

    private static final Logger logger = LoggerFactory.getLogger(CrafterMcpServer.class);

    private static final Gson gson = new Gson();

    private String serverId;
    private volatile boolean running;

    private boolean previewMode
    public boolean getPreviewMode() { return previewMode; }
    public void setPreviewMode(boolean value) { previewMode = value }

    private LinkedBlockingQueue<JsonObject> streamQueue = new LinkedBlockingQueue<>();

    private Map<String, Set<String>> subscriptions = new ConcurrentHashMap<>();
    private Map<String, String> sessions = new ConcurrentHashMap<>();
    private Map<String, Long> sessionCreationTimes = new ConcurrentHashMap<>();

    private ArrayList<McpTool> mcpTools = new ArrayList<>();
    public ArrayList<McpTool> getMcpTools() { return mcpTools; }
    public void setMcpTools(ArrayList<McpTool> value) { mcpTools = value; }

    private ArrayList<McpResource> mcpResources = new ArrayList<>();
    public ArrayList<McpResource> getMcpResources() { return mcpResources; }
    public void setMcpResources(ArrayList<McpResource> value) { mcpResources = value; }

    private ArrayList<McpResourceTemplate> mcpResourceTemplates = new ArrayList<>();
    public ArrayList<McpResourceTemplate> getMcpResourceTemplates() { return mcpResourceTemplates; }
    public void setMcpResourceTemplates(ArrayList<McpResourceTemplate> value) { mcpResourceTemplates = value; }

    private ArrayList<McpPrompt> mcpPrompts = new ArrayList<>();
    public ArrayList<McpPrompt> getMcpPrompts() { return mcpPrompts; }
    public void setMcpPrompts(ArrayList<McpPrompt> value) { mcpPrompts = value; }

    private boolean allowPublicAccess
    public boolean getAllowPublicAccess() { return allowPublicAccess }
    public void setAllowPublicAccess(boolean value) { allowPublicAccess = value }

    private AuthValidator authValidator
    public AuthValidator getAuthValidator() { return authValidator; }
    public void setAuthValidator(AuthValidator value) { authValidator = value }

    def oauthMcpServerUrlBase                
    def oauthMcpServerAuthorizationEndpoint  
    def oauthMcpServerTokenEndpoint         
    def oauthMcpServerResourceUrl            
   
    def oauthAuthServerUrlBase              
    def oauthAuthServerAuthorizationEndpoint
    def oauthAuthServerUserinfoEndpoint    
    def oauthAuthServerTokenEndpoint
    def oauthAuthServerClientId       
    def oauthAuthServerSecret        
    def oauthAuthServerJwksUri

    def oauthClientRedirectUrlBase

    CrafterMcpServer() {
        this.serverId = UUID.randomUUID().toString();
        this.running = true;
        this.allowPublicAccess = false; // public access disabled by default
        this.mcpTools = new ArrayList<>();
        this.mcpResources = new ArrayList<>();
        this.mcpResourceTemplates = new ArrayList<>();
        this.mcpPrompts = new ArrayList<>();
    }

    private Set<String> collectPossibleScopes() {
        Set<String> scopes = new HashSet<String>() 

        mcpTools.each { tool ->
            String[] toolScopes = tool.getRequiredScopes()
            List toolScopesList = Arrays.asList((toolScopes) ? toolScopes : new String[0]);
            if(toolScopesList.size() > 0) {
                scopes.addAll(toolScopesList);
            }
        }

        return scopes
    }

    private List<McpTool> collectPublicTools() {
        List<McpTool> tools = new ArrayList<McpTool>()

        mcpTools.each { tool ->
            String[] toolScopes = tool.getRequiredScopes()

            if(toolScopes != null && toolScopes.length == 0) {
                tools.add(tool)
            }
        }

        return tools
    }

    private boolean userScopesMatchToolScopes(String[] userScopes, String[] toolScopes) {
        List userScopesToCheck = Arrays.asList((userScopes) ? userScopes : new String[0]);
        List toolScopesToCheck = Arrays.asList((toolScopes) ? toolScopes : new String[0]);

        logger.info("Validating user: {}, vs tool {}", userScopesToCheck, toolScopesToCheck)
        return toolScopesToCheck.size() == 0 || userScopesToCheck.containsAll(toolScopesToCheck);
    }

    private UserAuthDetails preProcessRequest(HttpServletRequest req, HttpServletResponse resp)
    throws ServletException, IOException {

        UserAuthDetails userAuthDetails = new UserAuthDetails();

        if (!running) {
            resp.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
            sendError(resp, null, -32000, "Server is shutting down");
            return null
        }

        String authHeader = req.getHeader("Authorization");
        // dumpRequest(req)

        StringBuilder jsonInput = new StringBuilder();

        if (!authHeader) {
            if (req.getHeader("X-Crafter-Preview") != null) {
                // if the user is connecting to the server via the preview server:
                // 1. The preview token has already been validated by the time we see it here, all we need to do is validate this
                //    is infact running in a preview server context
                // 2. They should be given every scope required by every tool
                if(previewMode) {
                    logger.info("MCP client connecting to preview server");
                    userAuthDetails.userId = "Preview User";
                    userAuthDetails.scopes = collectPossibleScopes();
                }
                else {
                    logger.info("MCP client claiming be connecting to preview server but the server is not in preview mode. Rejecting Request.");
                    resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                }
            }
            else if(allowPublicAccess) {
                // public access to the server is allowed:
                // 1. Start an anonymous session
                // 2. Give the user no scopes - they should only be able to access resource/tools etc which require no scopes.
                logger.info("MCP client connecting annonymously. Public Services are enabled")
                userAuthDetails.userId = "Anonymous User"
                userAuthDetails.scopes = new String[0];
            }
            else {
                // the server does not allow public access (regardless if it contains tools that require no scopes)
                // the client's request has not provided any authentication so it must be denied access.
                logger.info("MCP client attempt to connect annonymously but public services are disabled")
                resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            }

        } else {
            logger.info("MCP client attempting to connect with authorization. Validating user.")
            String[] userInfo = validateAccessToken(authHeader, resp);

            if (userInfo == null) {
                return null
            }
            else {
                userAuthDetails.userId = (userInfo && userInfo.length >=1) ? userInfo[0] : null;
                userAuthDetails.scopes = (userInfo) ? userInfo : []; //[1] != null ? userInfo[1].split(" ") : new String[0];
                logger.info("Validated Access Token Details: {} user: {}", userInfo, userAuthDetails.userId);
            }
        }

        return userAuthDetails 


    }

    private String[] validateAccessToken(String authHeader, HttpServletResponse resp) throws IOException {
        return authValidator.validate(authHeader, resp) 
    }

    void doOptionsStreaming(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

        resp.setHeader("Access-Control-Allow-Origin", "*");
        resp.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        resp.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, Mcp-Session-Id");
        resp.setHeader("Access-Control-Expose-Headers", "Mcp-Session-Id");
        resp.setStatus(HttpServletResponse.SC_OK);
        
        logger.debug("Handled OPTIONS preflight request");
    }

    void doOAuthGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
            def serverScheme = req.getScheme()
            def serverName = req.getServerName()
            def serverPort = req.getServerPort()
            def mcpServerUrl = "$serverScheme://$serverName/y/"

            resp.setContentType("application/json");
            resp.setCharacterEncoding("UTF-8");
            resp.setHeader("Access-Control-Allow-Origin", "*");

            JsonObject metadata = new JsonObject();
            metadata.addProperty("resource", "$mcpServerUrl/api/craftermcp/mcp");
            JsonArray authServers = new JsonArray();
            authServers.add("https://cognito-idp.us-east-1.amazonaws.com/us-east-1_n5vbtb0ku");
            metadata.add("authorization_servers", authServers);
            metadata.addProperty("bearer_methods_supported", "header");
            metadata.addProperty("jwks_uri", "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_n5VBtB0Ku/.well-known/jwks.json");

            try (PrintWriter out = resp.getWriter()) {
                out.print(gson.toJson(metadata));
                out.flush();
            }

            logger.debug("Served OAuth protected resource metadata");
    }

    void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

        UserAuthDetails userDetails = preProcessRequest(req, resp);

        if(userDetails) {
            StringBuilder jsonInput = new StringBuilder();

            try (BufferedReader reader = req.getReader()) {
                String line;
                while ((line = reader.readLine()) != null) {
                    jsonInput.append(line);
                }
            } catch (IOException e) {
                logger.error("Failed to read request body: {}", e.getMessage(), e);
                sendError(resp, null, -32600, "Invalid Request: Failed to read request body");
                return;
            }

            String jsonString = jsonInput.toString();

            logger.info("Received POST request: {}", jsonString);
            if (jsonString.trim().isEmpty()) {
                logger.warn("Empty request body received");
                sendError(resp, null, -32600, "Invalid Request: Empty request body");
                return;
            }

            resp.setContentType("application/json");
            resp.setCharacterEncoding("UTF-8");
            resp.setHeader("Connection", "close");

            try (PrintWriter out = resp.getWriter()) {

                JsonObject response = handleRequest(jsonString, null, userDetails.userId, userDetails.scopes);

                if (response == null) {
                    logger.error("handleRequest returned null for input: {}", jsonString);
                    sendError(resp, null, -32603, "Internal error: Null response from handler");
                    return;
                }

                String responseString = gson.toJson(response);
                out.print(responseString);
                out.flush();
                logger.info("Sent response: {}", responseString);
            } catch (IOException e) {
                logger.error("IO error in doPost: {}", e.getMessage(), e);
                sendError(resp, null, -32000, "Server error: {}", e.getMessage());
            }
        }
        else {
            logger.info("Client Authorization is expired or invalid");
            sendAuthFailure(req, resp);
        }
    }

    void doPostStreaming(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

        UserAuthDetails userDetails = preProcessRequest(req, resp);

        if(userDetails) {
            String acceptHeader = req.getHeader("Accept");
            logger.info("Received Accept header: {}", acceptHeader);

            String existingSessionId = req.getHeader("Mcp-Session-Id");
            logger.info("Received Mcp-Session-Id header: {}", existingSessionId);

            StringBuilder jsonInput = new StringBuilder();
            try (BufferedReader reader = req.getReader()) {
                String line;
                while ((line = reader.readLine()) != null) {
                    jsonInput.append(line);
                }
            } catch (IOException e) {
                logger.error("Failed to read request body: {}", e.getMessage(), e);
                sendError(resp, null, -32600, "Invalid Request: Failed to read request body");
                return;
            }

            String jsonString = jsonInput.toString();
            logger.info("Received streaming POST request: {}", jsonString);
            if (jsonString.trim().isEmpty()) {
                logger.warn("Empty request body received");
                sendError(resp, null, -32600, "Invalid Request: Empty request body");
                return;
            }

            boolean isInitializeRequest = false;
            String sessionId = existingSessionId;

            try {
                JsonObject request = gson.fromJson(jsonString, JsonObject.class);
                String method = request.has("method") ? request.get("method").getAsString() : "";
                isInitializeRequest = "initialize".equals(method);

                if (isInitializeRequest) {
                    sessionId = UUID.randomUUID().toString();
                    sessions.put(sessionId, serverId);
                    sessionCreationTimes.put(sessionId, System.currentTimeMillis());
                    logger.info("Created new session: {} for initialize request", sessionId);
                } else if (existingSessionId == null || !sessions.containsKey(existingSessionId)) {
                    resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                    sendError(resp, null, -32002, "Invalid session: Missing or invalid Mcp-Session-Id header");
                    return;
                }
            } catch (Exception e) {
                logger.warn("Failed to parse request: {}", e.getMessage());
                sendError(resp, null, -32700, "Parse error: " + e.getMessage());
                return;
            }

            resp.setCharacterEncoding("UTF-8");
            resp.setHeader("Access-Control-Allow-Origin", "*");
            resp.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
            resp.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, Mcp-Session-Id");
            resp.setHeader("Access-Control-Expose-Headers", "Mcp-Session-Id");

            if (sessionId != null) {
                resp.setHeader("Mcp-Session-Id", sessionId);
                logger.info("Set Mcp-Session-Id header: {}", sessionId);
            }

            resp.setContentType("application/json");
            resp.setHeader("Connection", "close");

            try (PrintWriter out = resp.getWriter()) {
                JsonObject response = handleRequest(jsonString, sessionId, userDetails.userId, userDetails.scopes);
                if (response == null) {
                    logger.error("handleRequest returned null for input: {}", jsonString);
                    sendError(resp, null, -32603, "Internal error: Null response from handler");
                    return;
                }
                String responseString = gson.toJson(response);
                out.print(responseString);
                out.flush();
                logger.info("Sent streaming response with session {}: {}", sessionId, responseString);
            } catch (IOException e) {
                logger.error("IO error in streaming doPost: {}", e.getMessage(), e);
                sendError(resp, null, -32000, "Server error: {}", e.getMessage());
            }
        }
        else {
            logger.info("Client Authorization is expired or invalid");
            sendAuthFailure(req, resp);
        }
    }

    void doGetStreaming(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

        UserAuthDetails userDetails = preProcessRequest(req, resp);

        if(userDetails) {
            String existingSessionId = req.getHeader("Mcp-Session-Id");
            if (existingSessionId == null || !sessions.containsKey(existingSessionId)) {
                resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                logger.warn("GET streaming request without valid session");
                return;
            }

            resp.setContentType("application/json");
            resp.setCharacterEncoding("UTF-8");
            resp.setHeader("Connection", "close");
            resp.setHeader("Access-Control-Allow-Origin", "*");
            resp.setHeader("Mcp-Session-Id", existingSessionId);

            logger.info("Handling streamable HTTP GET for session: {}", existingSessionId);

            try (PrintWriter out = resp.getWriter()) {
                JsonObject response = new JsonObject();
                response.addProperty("jsonrpc", "2.0");
                response.addProperty("id", null);
                JsonArray result = new JsonArray();
                response.add("result", result);

                String responseString = gson.toJson(response);
                out.print(responseString);
                out.flush();
                logger.info("Sent GET response for session {}: {}", existingSessionId, responseString);
            } catch (IOException e) {
                logger.error("IO error in streamable GET: {}", e.getMessage(), e);
            }

        }
        else {
            logger.info("Client Authorization is expired or invalid");
            sendAuthFailure(req, resp);
        }
    }

    void doDeleteStreaming(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        // Used by Disconnect
        // TODO: Clean up sessions
    }

    private JsonObject handleRequest(String jsonInput, String sessionId, String userId, String[] scopes) {
        try {
            if (jsonInput == null || jsonInput.trim().isEmpty()) {
                logger.warn("Empty or null JSON input");
                return createErrorResponse(null, -32600, "Invalid Request: Empty or null JSON input");
            }
            JsonObject request = gson.fromJson(jsonInput, JsonObject.class);
            if (request == null || !request.has("jsonrpc") || !request.get("jsonrpc").getAsString().equals("2.0")) {
                logger.warn("Invalid JSON-RPC request: {}", jsonInput);
                return createErrorResponse(null, -32600, "Invalid Request: Must be JSON-RPC 2.0");
            }
            if (!request.has("method")) {
                logger.warn("Missing method in JSON-RPC request: {}", jsonInput);
                return createErrorResponse(null, -32600, "Invalid Request: Missing method");
            }
            String method = request.get("method").getAsString();
            JsonElement id = request.get("id");
            JsonObject params = request.has("params") ? request.get("params").getAsJsonObject() : new JsonObject();

            logger.info("Processing JSON-RPC method: {}, id: {}, session: {}, user: {}", method, id, sessionId, userId);

            switch (method) {
                case "initialize":
                    return handleInitialize(id, sessionId);
                case "tools/list":
                    return handleToolsList(id);
                case "tools/call":
                    return handleToolCall(id, params, userId, scopes);
                case "roots/list":
                    return handleRootsList(id);
                case "resources/list":
                    return handleResourcesList(id);
                case "resources/templates/list":
                    return handleResourceTemplatesList(id);
                case "prompts/get":
                    return handlePromptsGet(id, params);
                case "prompts/list":
                    return handlePromptsList(id);
                case "notifications/list":
                    return handleNotificationsList(id);
                case "subscribe":
                    return handleSubscribe(id, params, sessionId);
                case "unsubscribe":
                    return handleUnsubscribe(id, params, sessionId);
                case "shutdown":
                    return handleShutdown(id);
                case "ping":
                    return handlePing(id, sessionId);
                case "notifications/initialized":
                    return handleNotificationInitialized(id, sessionId);
                default:
                    return createErrorResponse(id, -32601, "Method not found: " + method);
            }
        } catch (JsonParseException e) {
            logger.error("JSON parse error: {}", e.getMessage(), e);
            return createErrorResponse(null, -32700, "Parse error: " + e.getMessage());
        } catch (Exception e) {
            logger.error("Unexpected error processing request: {}", e.getMessage(), e);
            return createErrorResponse(null, -32603, "Internal error: " + e.getMessage());
        }
    }

    private JsonObject handleInitialize(JsonElement id, String sessionId) {
        JsonObject response = new JsonObject();
        response.addProperty("jsonrpc", "2.0");
        response.add("id", id);

        JsonObject result = new JsonObject();
        result.addProperty("protocolVersion", "2025-06-18");

        JsonObject serverInfo = new JsonObject();
        serverInfo.addProperty("name", "CrafterMcpServer");
        serverInfo.addProperty("version", "1.0.0");
        result.add("serverInfo", serverInfo);

        JsonObject capabilities = new JsonObject();
        JsonObject tools = new JsonObject();
        tools.addProperty("listChanged", false);
        capabilities.add("tools", tools);
        JsonObject resources = new JsonObject();
        resources.addProperty("subscribe", false);
        resources.addProperty("listChanged", false);
        capabilities.add("resources", resources);
        JsonObject prompts = new JsonObject();
        prompts.addProperty("listChanged", false);
        capabilities.add("prompts", prompts);
        JsonObject roots = new JsonObject();
        roots.addProperty("listChanged", true);
        capabilities.add("roots", roots);
        result.add("capabilities", capabilities);
        response.add("result", result);

        logger.info("Generated initialize response for session {}: {}", sessionId, gson.toJson(response));
        return response;
    }

    private JsonObject handleNotificationInitialized(JsonElement id, String sessionId) {
        JsonObject response = new JsonObject();
        response.addProperty("jsonrpc", "2.0");
        response.add("id", id);

        JsonObject result = new JsonObject();
        result.addProperty("protocolVersion", "2025-06-18");

        logger.info("Generated handleNotificationInitialized response for session {}: {}", sessionId, gson.toJson(response));
        return response;
    }

    private JsonObject handleRootsList(JsonElement id) {
        JsonObject response = new JsonObject();
        response.addProperty("jsonrpc", "2.0");
        response.add("id", id);

        JsonArray roots = new JsonArray();
        JsonObject root1 = new JsonObject();
        root1.addProperty("uri", "/api/craftermcp");
        root1.addProperty("name", "CrafterCMS MCP Root");
        roots.add(root1);

        JsonObject result = new JsonObject();
        result.add("roots", roots);
        response.add("result", result);

        logger.info("Generated roots/list response: {}", gson.toJson(response));
        return response;
    }

    private JsonObject handleResourcesList(JsonElement id) {
        JsonObject response = new JsonObject();
        response.addProperty("jsonrpc", "2.0");
        response.add("id", id);

        JsonArray resources = new JsonArray();
        for (McpResource resource : mcpResources) {
            JsonObject resourceObj = new JsonObject();
            resourceObj.addProperty("uri", resource.uri);
            resourceObj.addProperty("name", resource.name);
            resources.add(resourceObj);
        }

        JsonObject result = new JsonObject();
        result.add("resources", resources);
        response.add("result", result);

        logger.info("Generated resources/list response: {}", gson.toJson(response));
        return response;
    }

    private JsonObject handleResourceTemplatesList(JsonElement id) {
        JsonObject response = new JsonObject();
        response.addProperty("jsonrpc", "2.0");
        response.add("id", id);

        JsonArray templates = new JsonArray();
        for (McpResourceTemplate template : mcpResourceTemplates) {
            JsonObject templateObj = new JsonObject();
            templateObj.addProperty("uriTemplate", template.uriTemplate);
            templateObj.addProperty("name", template.name);
            templates.add(templateObj);
        }

        JsonObject result = new JsonObject();
        result.add("resourceTemplates", templates);
        response.add("result", result);

        logger.info("Generated resources/templates/list response: {}", gson.toJson(response));
        return response;
    }

    private JsonObject handlePromptsList(JsonElement id) {
        JsonObject response = new JsonObject();
        response.addProperty("jsonrpc", "2.0");
        response.add("id", id);

        JsonArray prompts = new JsonArray();
        for (McpPrompt prompt : mcpPrompts) {
            JsonObject promptObj = new JsonObject();
            promptObj.addProperty("promptTemplate", prompt.promptTemplate);
            promptObj.addProperty("name", prompt.name);
            prompts.add(promptObj);
        }

        JsonObject result = new JsonObject();
        result.add("prompts", prompts);
        response.add("result", result);

        logger.info("Generated prompts/list response: {}", gson.toJson(response));
        return response;
    }

    private JsonObject handlePromptsGet(JsonElement id, JsonObject params) {
        JsonObject response = new JsonObject();
        response.addProperty("jsonrpc", "2.0");
        response.add("id", id);

        String promptName = params.has("name") ? params.get("name").getAsString() : null;
        if (promptName == null) {
            return createErrorResponse(id, -32602, "Missing prompt name");
        }

        McpPrompt prompt = mcpPrompts.stream().filter(p -> p.name.equals(promptName)).findFirst().orElse(null);
        if (prompt == null) {
            return createErrorResponse(id, -32602, "Prompt not found: " + promptName);
        }

        JsonObject result = new JsonObject();
        result.addProperty("promptTemplate", prompt.promptTemplate);
        result.addProperty("name", prompt.name);
        response.add("result", result);

        logger.info("Generated prompts/get response: {}", gson.toJson(response));
        return response;
    }

    private JsonObject handleNotificationsList(JsonElement id) {
        JsonObject response = new JsonObject();
        response.addProperty("jsonrpc", "2.0");
        response.add("id", id);

        JsonArray notifications = new JsonArray();
        JsonObject rootsNotification = new JsonObject();
        rootsNotification.addProperty("method", "notifications/roots/listChanged");
        rootsNotification.addProperty("description", "Sent when the list of roots changes");
        notifications.add(rootsNotification);

        JsonObject result = new JsonObject();
        result.add("notifications", notifications);
        response.add("result", result);

        logger.info("Generated notifications/list response: {}", gson.toJson(response));
        return response;
    }

    private JsonObject handleToolsList(JsonElement id) {
        JsonObject response = new JsonObject();
        response.addProperty("jsonrpc", "2.0");
        response.add("id", id);

        JsonArray tools = new JsonArray();
        for (McpTool mcpToolRecord : mcpTools) {

            JsonObject currentTool = new JsonObject();
            currentTool.addProperty("name", mcpToolRecord.getToolName());
            currentTool.addProperty("description", (String)mcpToolRecord.getToolDescription());

            JsonObject inputSchema = new JsonObject();
            inputSchema.addProperty("type", "object");

            JsonObject properties = new JsonObject();
            for (McpTool.ToolParam param : mcpToolRecord.getParams()) {
                JsonObject property = new JsonObject();
                property.addProperty("type", param.type);
                property.addProperty("description", param.description);
                properties.add(param.name, property);
            }

            inputSchema.add("properties", properties);
            currentTool.add("inputSchema", inputSchema);
            tools.add(currentTool);
        }

        JsonObject result = new JsonObject();
        result.add("tools", tools);
        response.add("result", result);

        logger.info("Generated tools/list response: {}", gson.toJson(response));
        return response;
    }

    private JsonObject handleToolCall(JsonElement id, JsonObject params, String userId, String[] scopes) {
        if (!params.has("name") || params.get("name").isJsonNull()) {
            return createErrorResponse(id, -32602, "Missing tool name");
        }
        String toolName = params.get("name").getAsString();
        JsonObject arguments = params.has("arguments") ? params.get("arguments").getAsJsonObject() : new JsonObject();

        logger.info("Calling tool: {} with arguments: {} for user: {}", toolName, gson.toJson(arguments), userId);

        JsonObject response = new JsonObject();
        response.addProperty("jsonrpc", "2.0");
        response.add("id", id);

        McpTool toolToCall = mcpTools.stream().filter(t -> t.getToolName().equals(toolName)).findFirst().orElse(null);
        if (toolToCall == null) {
            return createErrorResponse(id, -32602, "Invalid tool: " + toolName);
        }

        if(!userScopesMatchToolScopes(scopes, toolToCall.getRequiredScopes())) {
            return createErrorResponse(id, -32602, "Insufficient permissions for tool: " + toolName);
        }

        // For the moment we're not authenticating each tool. They must be authenticated when we invoke them

        // CredentialTranslator translator = new CredentialTranslator();
        // String toolCredentials = translator.translateCredentials(userId, scopes, toolToCall);
        // if (toolCredentials == null) {
        //     logger.error("Temporarily totally fine with no auth credentials")
        //     // return createErrorResponse(id, -32000, "Tool authentication failed: " + toolName);
        // }

        Map<String,String> callArgs = new HashMap<>()
        String siteId = SiteContext.getCurrent().getSiteName()
        if (toolToCall.hasProperty("siteId")) {
            toolToCall.siteId = siteId
        }

        // Pre-populate the crafterSite param if it's shown as required, as the LLM often gets this wrong
        if (toolToCall.getParamDescriptor("crafterSite") != null && siteId != null) {
            callArgs.put("crafterSite", siteId)
            arguments.addProperty("crafterSite", siteId)
        }

        for (McpTool.ToolParam arg : toolToCall.getParams()) {
            if (!arguments.has(arg.name)) {
                if (arg.isRequired()) {
                    return createErrorResponse(id, -32602, "Missing argument: " + arg.name);
                }
            } else {
                String argValue = arguments.get(arg.name).getAsString().replaceAll("\"", "");
                callArgs.put(arg.name, argValue)
            }
        }
        //callArgs.add(toolCredentials);
        logger.error("Temporarily not sending credentials to tool")

        String toolResponse = toolToCall.call(callArgs);

        JsonArray content = new JsonArray();
        JsonObject textContent = new JsonObject();
        textContent.addProperty("type", "text");
        textContent.addProperty("text", toolResponse);
        content.add(textContent);

        JsonObject result = new JsonObject();
        result.add("content", content);
        response.add("result", result);

        logger.info("Generated tool/call response: {}", gson.toJson(response));
        return response;
    }

    private JsonObject handleSubscribe(JsonElement id, JsonObject params, String sessionId) {
        if (sessionId == null) {
            return createErrorResponse(id, -32602, "Session ID required for streaming");
        }

        JsonArray events = params.has("events") ? params.get("events").getAsJsonArray() : new JsonArray();
        Set<String> eventSet = new HashSet<>();
        for (JsonElement event : events) {
            eventSet.add(event.getAsString());
        }

        if (eventSet.isEmpty()) {
            eventSet.add("all");
        }

        subscriptions.put(sessionId, eventSet);

        JsonObject response = new JsonObject();
        response.addProperty("jsonrpc", "2.0");
        response.add("id", id);
        JsonObject result = new JsonObject();
        result.addProperty("subscriptionId", sessionId);
        response.add("result", result);

        logger.info("Subscription created: {} for events: {}", sessionId, eventSet);
        return response;
    }

    private JsonObject handleUnsubscribe(JsonElement id, JsonObject params, String sessionId) {
        if (sessionId == null) {
            return createErrorResponse(id, -32602, "Session ID required for streaming");
        }

        subscriptions.remove(sessionId);

        JsonObject response = new JsonObject();
        response.addProperty("jsonrpc", "2.0");
        response.add("id", id);
        response.add("result", new JsonObject());

        logger.info("Subscription removed: {}", sessionId);
        return response;
    }

    private JsonObject handleShutdown(JsonElement id) {
        JsonObject response = new JsonObject();
        response.addProperty("jsonrpc", "2.0");
        response.add("id", id);
        response.add("result", new JsonObject());
        shutdown();
        logger.info("Generated shutdown response: {}", gson.toJson(response));
        return response;
    }

    private JsonObject createAuthFailureResponse(JsonElement id, int code, String message) {
        JsonObject response = new JsonObject();
        response.addProperty("jsonrpc", "2.0");
        if (id != null) {
            response.add("id", id);
        }
        JsonObject error = new JsonObject();
        error.addProperty("code", code);
        error.addProperty("message", message);
        error.addProperty("data", "Invalid or missing authentication token.");
        response.add("error", error);

        logger.warn("Generated authorization failure response: code={}, message={}", code, message);
        return response;
    }

    private JsonObject createErrorResponse(JsonElement id, int code, String message) {
        JsonObject response = new JsonObject();
        response.addProperty("jsonrpc", "2.0");
        
        if (id != null) {
            response.add("id", id);
        }

        JsonObject error = new JsonObject();
        error.addProperty("code", code);
        error.addProperty("message", message);
        response.add("error", error);

        logger.warn("Generated error response: code={}, message={}", code, message);
        return response;
    }

    private void sendResponse(PrintWriter out, JsonObject response, boolean isStreaming) {
        String jsonResponse = gson.toJson(response);
        out.print(isStreaming ? jsonResponse + "\n" : jsonResponse);
        out.flush();
        logger.info("Sent response: {}", jsonResponse);
    }

    private void sendAuthFailure(HttpServletRequest req, HttpServletResponse resp) {

        resp.setContentType("application/json");
        resp.setCharacterEncoding("UTF-8");
        resp.setHeader("Access-Control-Allow-Origin", "*");
        resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        JsonObject respX = createAuthFailureResponse(null, 32001, "Unauthorized")
        logger.info("Served OAuth protected resource metadata");

        resp.addHeader("WWW-Authenticate", "Bearer");

        try (PrintWriter out = resp.getWriter()) {               
            sendResponse(out, respX, false);
        }
    }

    private void sendError(HttpServletResponse resp, JsonElement id, int code, String message) throws IOException {
        resp.setContentType("application/json");
        resp.setCharacterEncoding("UTF-8");
        try (PrintWriter out = resp.getWriter()) {

            sendResponse(out, createErrorResponse(id, code, message), false);
        }
    }

    private void shutdown() {
        running = false;
        logger.info("Server shut down");
        JsonObject shutdownNotification = new JsonObject();
        shutdownNotification.addProperty("jsonrpc", "2.0");
        shutdownNotification.addProperty("method", "server/shutdown");
        JsonObject params = new JsonObject();
        params.addProperty("message", "Server is shutting down");
        shutdownNotification.add("params", params);
        streamQueue.offer(shutdownNotification);
        subscriptions.clear();
        sessions.clear();
        sessionCreationTimes.clear();
    }

    private boolean isSubscribed(String subscriptionId, JsonObject event) {
        String eventType = event.has("method") ? event.get("method").getAsString().split("/")[0] :
                          (event.has("event") ? event.get("event").getAsString() : "");
        Set<String> subscribedEvents = subscriptions.get(subscriptionId);
        return subscribedEvents != null && (subscribedEvents.contains("all") || subscribedEvents.contains(eventType));
    }

    private JsonObject handlePing(JsonElement id, String sessionId) {
        JsonObject response = new JsonObject();
        response.addProperty("jsonrpc", "2.0");
        response.add("id", id);
        response.add("result", new JsonObject());

        logger.info("Generated Ping response for session {}: {}", sessionId, gson.toJson(response));
        return response;
    }

    private void cleanupStaleSessions() {
        long currentTime = System.currentTimeMillis();
        sessionCreationTimes.entrySet().removeIf(entry ->
            (currentTime - entry.getValue()) > TimeUnit.HOURS.toMillis(1));
        sessions.keySet().retainAll(sessionCreationTimes.keySet());
        subscriptions.keySet().retainAll(sessionCreationTimes.keySet());
    }

    private void dumpRequest(HttpServletRequest req) {
        System.out.println("=== OAuth Request Debug Information ===");

        // Basic request info
        System.out.println("Method: " + req.getMethod());
        System.out.println("Request URI: " + req.getRequestURI());
        System.out.println("Request URL: " + req.getRequestURL());
        System.out.println("Query String: " + req.getQueryString());
        System.out.println("Content Type: " + req.getContentType());
        System.out.println("Content Length: " + req.getContentLength());

        // Authorization headers (most important for OAuth)
        System.out.println("Authorization Header: " + req.getHeader("Authorization"));
        System.out.println("Bearer Token: " + (req.getHeader("Authorization") != null && req.getHeader("Authorization").startsWith("Bearer ") ? 
            req.getHeader("Authorization").substring(7) : "None"));

        // OAuth-specific headers
        System.out.println("WWW-Authenticate: " + req.getHeader("WWW-Authenticate"));
        System.out.println("X-Forwarded-Proto: " + req.getHeader("X-Forwarded-Proto"));
        System.out.println("X-Forwarded-Host: " + req.getHeader("X-Forwarded-Host"));
        System.out.println("X-Forwarded-For: " + req.getHeader("X-Forwarded-For"));

        // CORS and origin headers
        System.out.println("Origin: " + req.getHeader("Origin"));
        System.out.println("Referer: " + req.getHeader("Referer"));
        System.out.println("Host: " + req.getHeader("Host"));

        // Content negotiation
        System.out.println("Accept: " + req.getHeader("Accept"));
        System.out.println("Accept-Encoding: " + req.getHeader("Accept-Encoding"));
        System.out.println("Accept-Language: " + req.getHeader("Accept-Language"));

        // User agent and client info
        System.out.println("User-Agent: " + req.getHeader("User-Agent"));

        // Custom MCP headers
        System.out.println("Mcp-Session-Id: " + req.getHeader("Mcp-Session-Id"));
        System.out.println("X-Crafter-Preview: " + req.getHeader("X-Crafter-Preview"));

        // Connection info
        System.out.println("Connection: " + req.getHeader("Connection"));
        System.out.println("Cache-Control: " + req.getHeader("Cache-Control"));

        // Server connection details
        System.out.println("Server Name: " + req.getServerName());
        System.out.println("Server Port: " + req.getServerPort());
        System.out.println("Scheme: " + req.getScheme());
        System.out.println("Protocol: " + req.getProtocol());
        System.out.println("Remote Addr: " + req.getRemoteAddr());
        System.out.println("Remote Host: " + req.getRemoteHost());
        System.out.println("Remote Port: " + req.getRemotePort());
        System.out.println("Remote User: " + req.getRemoteUser());

        // Session info
        System.out.println("Session ID: " + (req.getSession(false) != null ? req.getSession(false).getId() : "No session"));
        System.out.println("Requested Session ID: " + req.getRequestedSessionId());
        System.out.println("Session from Cookie: " + req.isRequestedSessionIdFromCookie());
        System.out.println("Session from URL: " + req.isRequestedSessionIdFromURL());

        // All headers dump
        System.out.println("\n=== All Request Headers ===");
        java.util.Enumeration<String> headerNames = req.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            String headerValue = req.getHeader(headerName);
            System.out.println(headerName + ": " + headerValue);
        }

        // All parameters dump
        System.out.println("\n=== All Request Parameters ===");
        java.util.Enumeration<String> paramNames = req.getParameterNames();
        while (paramNames.hasMoreElements()) {
            String paramName = paramNames.nextElement();
            String[] paramValues = req.getParameterValues(paramName);
            System.out.println(paramName + ": " + java.util.Arrays.toString(paramValues));
        }

        System.out.println("=== End OAuth Debug Information ===\n");
    }


















    public void doAuthorize(HttpServletRequest request, HttpServletResponse response) {
        // Extract parameters
        String clientId = request.getParameter("client_id");
        String redirectUri = request.getParameter("redirect_uri");
        String scope = request.getParameter("scope");
        String state = request.getParameter("state");
        String responseType = request.getParameter("response_type");

        // Validate required parameters
        if (clientId == null || redirectUri == null || responseType == null) {
            // Return error response
            return;
        }

        // Build Cognito authorization URL
        String cognitoAuthUrl = oauthAuthServerAuthorizationEndpoint +
            "?client_id=" + URLEncoder.encode(clientId, "UTF-8") +
            "&redirect_uri=" + URLEncoder.encode(redirectUri, "UTF-8") +
            "&response_type=" + URLEncoder.encode(responseType, "UTF-8") +
            "&scope=" + URLEncoder.encode(scope != null ? scope : "openid", "UTF-8") +
            (state != null ? "&state=" + URLEncoder.encode(state, "UTF-8") : "");

        // Redirect to Cognito
        response.sendRedirect(cognitoAuthUrl);        
    }

    def doOAuthConfig(HttpServletRequest request, HttpServletResponse response) {

        def config = [
        "issuer": oauthMcpServerUrlBase,
        "authorization_endpoint": oauthMcpServerAuthorizationEndpoint,
        "token_endpoint": oauthMcpServerTokenEndpoint, 
        "userinfo_endpoint": oauthAuthServerUserinfoEndpoint,
        "jwks_uri": oauthAuthServerJwksUri,
        "response_types_supported": ["code", "token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256","S256"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": ["openid", "email", "profile"]   
        ]

        return config        
    }

    def doProtectedResource(HttpServletRequest request, HttpServletResponse response) {

        def responsex = [
            "resource": oauthMcpServerResourceUrl,
            "authorization_servers": [
                oauthMcpServerUrlBase
            ],
            "scopes_supported": [
                "email",
                "phone", 
                "openid"
            ],
            "bearer_methods_supported": [
                "header",
                "body"
            ],
            "resource_documentation": "http://localhost/docs/api"
            ]

        return responsex
    }

    def doToken(HttpServletRequest request, HttpServletResponse response) {
        StringBuilder jsonInput = new StringBuilder();


        String code = request.getParameter("code");
        String state = request.getParameter("state");

        try (BufferedReader reader = request.getReader()) {
            String line;
            while ((line = reader.readLine()) != null) {
                jsonInput.append(line);
            }
        }

        def body = jsonInput.toString()

        String cognitoTokenUrl = "$oauthAuthServerTokenEndpoint?grant_type=authorization_code&code=$code&redirect_uri=$oauthClientRedirectUrlBase/callback&client_id=$oauthAuthServerClientId"
        
        // Forward the entire request body and headers to Cognito
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
            .uri(URI.create(cognitoTokenUrl))
            .method(request.getMethod(), HttpRequest.BodyPublishers.ofString(body));

        // Copy relevant headers
        requestBuilder.header("Content-Type", "application/x-www-form-urlencoded");
        def authHeader = "$oauthAuthServerClientId:$oauthAuthServerSecret".bytes.encodeBase64().toString()

        requestBuilder.header("Authorization", "Basic " + authHeader);
        
        HttpResponse<String> cognitoResponse = client.send(requestBuilder.build(), 
        HttpResponse.BodyHandlers.ofString());

        String cognitoResponseBody = cognitoResponse.body()

        response.setStatus(cognitoResponse.statusCode());

        def jsonSlurper = new JsonSlurper()
        def parsed = jsonSlurper.parseText(cognitoResponseBody)
        return parsed
    }
}
