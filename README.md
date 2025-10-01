# Model Context Protocol (MCP) Server Implementation in CrafterCMS

## Overview
Installs a baseline a MCP server into your CrafterCMS Engine instance.

## Presequsits
This project relies on external dependencies. You will need to configure gapes based dependency downloads and the Groovy sandbox in order for this functionality to work. 
In a test environment you can disable the sandoox rather than using whitelist/blacklist features to ease installation.

### Simple Presequsit Installation
In `CRAFTER_HOME/bin/apache-tomcat/shared/classes/org/crafter/engine/extension/server-config.properties` add the following lines:
```
crafter.engine.groovy.sandbox.enable=false
crafter.engine.groovy.grapes.download.enabled=true
```

## Installation & Configuration

1. Ensure that the presequsits are met (see above.)
2. Install this plugin into the project.
3. Add configuration for authentication `site-config.xml` for the project:

```
     <cors>
        <enable>true</enable>
        <accessControlMaxAge>3600</accessControlMaxAge>
        <accessControlAllowOrigin>*</accessControlAllowOrigin>
        <accessControlAllowMethods>GET\, POST\, PUT\, DELETE\, OPTIONS</accessControlAllowMethods>
        <accessControlAllowHeaders>Content-Type\, Mcp-Session-Id\, mcp-protocol-version</accessControlAllowHeaders>
        <accessControlAllowCredentials>true</accessControlAllowCredentials>
    </cors>

    <crafterMcp>
        <allowPublicAccess>false</allowPublicAccess>
        <auth>
            <oauth>
                <mcpServer>
                    <serverUrlBase>http://BASE_URL</serverUrlBase> 

                    <authorizationEndpoint>${crafterMcp.auth.oauth.mcpServer.serverUrlBase}/authorize</authorizationEndpoint>
                    <tokenEndpoint>${crafterMcp.auth.oauth.mcpServer.serverUrlBase}/token</tokenEndpoint>
                    <resourceUrl>${crafterMcp.auth.oauth.mcpServer.serverUrlBase}/api/craftermcp/stream</resourceUrl>            
                </mcpServer>

                <authServer>
                    <serverUrlBase>https://IPD_SERVER/oauth2</serverUrlBase>
                    <userInfoUrlBase>https://IPD_SERVER/oauth2</userInfoUrlBase>
                    <jwksBase>https://IPD_SERVER/JWKS-Base</jwksBase>

                    <clientId>CLIENT-ID</clientId>
                    <secret>SECRET</secret> 

                    <authorizationEndpoint>${crafterMcp.auth.oauth.authServer.serverUrlBase}/authorize</authorizationEndpoint>
                    <tokenEndpoint>${crafterMcp.auth.oauth.authServer.serverUrlBase}/token</tokenEndpoint>
                    <userinfoEndpoint>${crafterMcp.auth.oauth.authServer.userInfoUrlBase}/userInfo</userinfoEndpoint>
                    <jwksUri>${crafterMcp.auth.oauth.authServer.jwksBase}/.well-known/jwks.json</jwksUri> 
                </authServer>
            </oauth>
        </auth>
    </crafterMcp>
```

4. Add the MCP server to your `application-context.xml` for the project:

```
    <bean class="org.springframework.context.support.PropertySourcesPlaceholderConfigurer" parent="crafter.properties"/>

        <!-- MCP Server -->
    <bean name="crafterMcpServer" class="plugins.org.craftercms.rd.plugin.mcp.server.CrafterMcpServer">
        <property name="previewMode" value="${crafter.security.preview.enabled:false}"/>

        <property name="allowPublicAccess" value="${crafterMcp.allowPublicAccess}"/> 
        <property name="oauthMcpServerUrlBase" value="${crafterMcp.auth.oauth.mcpServer.serverUrlBase}" />
        <!-- property name="oauthMcpServerAuthUrlBase" value="${crafterMcp.auth.oauth.mcpServer.serverUrlBase}" /-->
        <property name="oauthMcpServerAuthorizationEndpoint" value="${crafterMcp.auth.oauth.mcpServer.authorizationEndpoint}" />
        <property name="oauthMcpServerTokenEndpoint" value="${crafterMcp.auth.oauth.mcpServer.tokenEndpoint}" />
        <property name="oauthMcpServerResourceUrl" value="${crafterMcp.auth.oauth.mcpServer.resourceUrl}" />

        <property name="oauthAuthServerUrlBase" value="${crafterMcp.auth.oauth.authServer.serverUrlBase}" />
        <property name="oauthAuthServerAuthorizationEndpoint" value="${crafterMcp.auth.oauth.authServer.authorizationEndpoint}" />
        <property name="oauthAuthServerTokenEndpoint" value="${crafterMcp.auth.oauth.authServer.tokenEndpoint}" />
        <property name="oauthAuthServerUserinfoEndpoint" value="${crafterMcp.auth.oauth.authServer.userinfoEndpoint}" />
        <property name="oauthAuthServerJwksUri" value="${crafterMcp.auth.oauth.authServer.jwksUri}" />
        <property name="oauthAuthServerClientId" value="${crafterMcp.auth.oauth.authServer.clientId}" />
        <property name="oauthAuthServerSecret" value="${crafterMcp.auth.oauth.authServer.secret}" />

        <property name="oauthClientRedirectUrlBase" value="${crafterMcp.auth.oauth.client.redirectUrlBase}" />


        <property name="authValidator">
            <bean name="jwtAuthenticator" class="plugins.org.craftercms.rd.plugin.mcp.server.auth.validator.SimpleAuthValidator">
            </bean>   
        </property>
    </bean>

    <bean name="toolSpringBeanScanner" class="plugins.org.craftercms.rd.plugin.mcp.server.tools.ToolSpringBeanScanner" init-method="scan">
        <property name="mcpServer" ref="crafterMcpServer" />
    </bean>

```




## Adding Tools

### Adding Tools as beans
1. Declare the tool as a bean
2. Wire the bean into the MCP Server:
```
    <bean name="crafterMcpServer" class="org.craftercms.ai.mcp.server.CrafterMcpServer">
        ...
        <property name="mcpTools">
            <list>
                <ref bean="toolIsIngredientAvail" />
                <ref bean="toolGetTemperature" />
            </list>
        </property>
        ...
    </bean>
```

#### Wiring to bean and service records with Reflections
```
    <!-- My Services-->
    <bean name="recipeService" class="foo.RecipeService" />

    <!-- Tools -->
    <bean name="toolIsIngredientAvail" class="org.craftercms.ai.mcp.server.tools.McpToolReflect">
        <property name="serviceObject" ref="recipeService" />
        <property name="methodName" value="isIngredientAvailable" />
        <property name="toolName" value="isIngredientAvailable" />
        <property name="toolDescription" value="returns a response indicating if an ingredient is available or not" />
        <property name="returnType" value="string" />
        <property name="params">
            <list>
                <bean name="param1" class="org.craftercms.ai.mcp.server.tools.McpTool.ToolParam">
                    <property name="name" value="ingrdient" />
                    <property name="type" value="string" />
                    <property name="description" value="The name of the ingredient to check" />
                    <property name="required" value="true" />
                </bean>
            </list>
        </property>
    </bean>

```
#### Wiring to an existing REST API
```
    <bean name="toolGetTemperature" class="org.craftercms.ai.mcp.server.tools.McpToolRest">
        <property name="baseUrl" value="http://localhost:8080" />
        <property name="url" value="/api/foo/temperature.json" />
        <property name="toolName" value="getTemperature" />
        <property name="toolDescription" value="Returns the temperature" />
        <property name="returnType" value="string" />
        <property name="previewToken" value="${ai.crafterPreviewToken}" />
        <property name="params">
            <list>
                <bean name="param1" class="org.craftercms.ai.mcp.server.tools.McpTool.ToolParam">
                    <property name="name" value="city" />
                    <property name="type" value="string" />
                    <property name="description" value="The name of the city to check" />
                    <property name="required" value="true" />
                </bean>
            </list>
        </property>
    </bean>
```

### Wiring tools via Open API spec
```
    <bean name="toolOpenApiSpecParser" class="org.craftercms.ai.mcp.server.tools.ToolOpenApiSpecParser" init-method="parse">
        <property name="baseUrl" value="http://localhost:8080" />
        <property name="openApiSpecUrl" value="https://raw.githubusercontent.com/craftercms/engine/refs/tags/v4.4.2/src/main/api/engine-api.yaml"/>
        <property name="mcpServer" ref="crafterMcpServer" />
        <property name="includeTags">
            <list>
                <value>content</value>
            </list>
        </property>
        <property name="excludeTags">
            <list />
        </property>
    </bean>
```

### Using Annotations
```
package foo

import org.craftercms.ai.mcp.server.tools.DeclareTool
import org.craftercms.ai.mcp.server.tools.DeclareToolParam
 
public class BookingService {
 
    @DeclareTool(toolName="bookFlight", returnType="string", toolDescription="Book a specific seat on a given flight", scopes="wallet, profile, email" )
    @DeclareToolParam (name="flight", type="string", description="The flight the user wants")
    @DeclareToolParam (name="seat", type="string", description="The seat the user wants")
    public String bookFlight(String flight, String seat) {
        return "Booked"
    }
}   
```

## Adding Resources

## Adding Prompts



