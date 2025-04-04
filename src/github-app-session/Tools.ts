import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
  ToolSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { zodToJsonSchema } from "zod-to-json-schema";
import { tokenStore } from "./auth/TokenStore.js";

type ToolInput = z.infer<typeof ToolSchema.shape.inputSchema>;

const ListSubscriptionsSchema = z.object({});

enum ToolName {
  GET_USER_DETAILS = "getUserDetails",
}

export const createServer = () => {
  const server = new Server(
    {
      name: "simple-mcp-server",
      version: "0.0.1",
    },
    {
      capabilities: {
        prompts: {},
        resources: { subscribe: true },
        tools: {},
        logging: {},
      },
    },
  );

  let updateInterval: NodeJS.Timeout | undefined;

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    const tools: Tool[] = [
      {
        name: ToolName.GET_USER_DETAILS,
        description: "A tool that can provide details about the currently authenticated user.",
        inputSchema: zodToJsonSchema(ListSubscriptionsSchema) as ToolInput,
      }
    ];

    return { tools };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name } = request.params;
    const context = request.params?.context as { token?: string } | undefined;
    const sessionToken = context?.token;

    if (name === ToolName.GET_USER_DETAILS) {
      try {
        if (!sessionToken) {
          throw new Error("No authentication token provided");
        }
    
        const tokenData = tokenStore.getToken(sessionToken);
        if (!tokenData) {
          throw new Error("Invalid or expired session token");
        }
    
        const githubToken = tokenData.accessToken;

        const userResponse = await fetch('https://api.github.com/user', {
          headers: {
            'Authorization': `token ${githubToken}`,
            'Accept': 'application/json'
          }
        });
        
        if (!userResponse.ok) {
          throw new Error(`GitHub API request failed: ${userResponse.status} ${userResponse.statusText}`);
        }
        
        const userData = await userResponse.json();
    
        return {
          content: [
            {
              type: "text",
              text: `User Details:
                Name: ${userData.name}
                Login: ${userData.login}
                Bio: ${userData.bio || 'Not provided'}`,
            },
          ],
        };
      } catch (error: unknown) {
        console.log(error);
      }
    }

    throw new Error(`Unknown tool: ${name}`);
  });

  const cleanup = async () => {
    if (updateInterval) {
      clearInterval(updateInterval);
    }
  };

  return { server, cleanup };
};