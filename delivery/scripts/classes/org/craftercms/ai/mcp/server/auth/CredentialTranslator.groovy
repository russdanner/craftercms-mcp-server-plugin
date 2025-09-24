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

package org.craftercms.ai.mcp.server.auth

import org.craftercms.ai.mcp.server.tools.*

class CredentialTranslator {
    String translateCredentials(String userId, String[] scopes, McpTool tool) {
        switch (tool.getAuthType()) {
            case CredentialType.NONE:
                return "";

            case CredentialType.API_KEY:
                String apiKey = tool.getAuthConfig().get("apiKey");
                return apiKey != null ? apiKey : "default-api-key";

            case CredentialType.BASIC_AUTH:
                String username = userId;
                String password = tool.getAuthConfig().get("password");
                String credentials = username + ":" + password;
                return "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes());

            case CredentialType.CUSTOM_HEADER:
                String headerName = tool.getAuthConfig().get("headerName");
                String headerValue = tool.getAuthConfig().get("headerValue");
                return headerValue != null ? headerValue : userId;

            default:
                logger.warn("Unsupported auth type for tool {}: {}", tool.getToolName(), tool.getAuthType());
                return null;
        }
    }
}
