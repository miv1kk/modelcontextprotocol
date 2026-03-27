#!/usr/bin/env node

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createPerplexityServer } from "./server.js";

async function main() {
  try {
    const server = createPerplexityServer("local-mcp");
    const transport = new StdioServerTransport();
    await server.connect(transport);
  } catch (error) {
    console.error("Fatal error running server:", error);
    process.exit(1);
  }
}

main().catch((error) => {
  console.error("Fatal error running server:", error);
  process.exit(1);
});

