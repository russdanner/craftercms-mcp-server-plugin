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

package plugins.org.craftercms.rd.plugin.mcp.server.auth.validator

import jakarta.servlet.http.HttpServletResponse;

import java.util.HashSet;

import plugins.org.craftercms.rd.plugin.mcp.server.tools


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class SimpleAuthValidator implements AuthValidator {

    private static final Logger logger = LoggerFactory.getLogger(AuthValidator);

    public String[] scopes; 
    public String[] getScopes() { return scopes; }
    public void setScopes(String[] value) { scopes = value }

    protected HashSet<String> sessions

    public SimpleAuthValidator() {
        sessions = new HashSet<String>();
    }

    public String[] validate(String authHeader, HttpServletResponse resp) throws IOException {


        System.out.println("AUTH VALIDATOR (hard coded to profile:email): "+authHeader)

        if (authHeader == null || "".equals(authHeader)) {
            logger.warn("No valid Authorization header received");
            resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return null;
        }
        else {
//            if(!sessions.contains(authHeader)) {
            //     sessions.put(authHeader)
            //     logger.warn("Invalid authorization header value");
            //     resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            //     return null;
            // }
            // else {
               return ["profile","email"]
//            } 
        }
    }
}
