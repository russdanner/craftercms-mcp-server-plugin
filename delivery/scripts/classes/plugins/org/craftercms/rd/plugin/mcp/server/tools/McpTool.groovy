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

package plugins.org.craftercms.rd.plugin.mcp.server.tools

import plugins.org.craftercms.rd.plugin.mcp.server.auth.CredentialType

abstract class McpTool {
    String toolName
    String toolDescription
    String returnType
    String[] scopes
    List<ToolParam> params = new ArrayList<>()

    static class ToolParam {
        String name
        String type
        String description
        boolean required

        @Override
        String toString() {
            return "ToolParam{" +
                    "name='" + name + '\'' +
                    ", type='" + type + '\'' +
                    ", description='" + description + '\'' +
                    ", required=" + required +
                    '}';
        }
    }

    /**
     * Call the tool
     * @param args name-value pair corresponding to the ToolParam.name and the value of the param
     * @return the call result
     */
    abstract Object call(Map<String, String> args)

    ToolParam getParamDescriptor(String paramName) {
        return params.stream().filter({p -> p.getName().equals(paramName)}).findFirst().orElse(null)
    }

    public String[] getRequiredScopes() {
        return scopes
    }

    public String getAuthType() {
        // For the moment the server will only handle NONE
        // What this means is that the server asssumes that you must authenticate against it BUT once you do, tools are authenticated.
        // This means that tools are using pre-configured SERVICE authentications
        //
        // Once this is complete we'll circle back to allowing tools to declare that they need to delegate authentication to the user
        // Scenario: I am an MCP server, I offer a tool to work with Box or Crafter Studio or whatever -- but YOU the user need to sign in, and I want the MCP server to facilitate that.
        return CredentialType.NONE;
    }

}
