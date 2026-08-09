#!/usr/bin/env node
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

import { createMandareMcpServer, loadMcpConfig } from './server.js';

/**
 * stdio entry point (Q17: local stdio server, auth via env). Configure in an
 * MCP host as:
 *
 *   { "command": "mandare-mcp", "env": { "MANDARE_LEDGER_DB": "...", ... } }
 *
 * Environment:
 *   MANDARE_LEDGER_DB            ledger to verify/kill against (default ./mandare-ledger.db)
 *   MANDARE_MCP_HOME             where issued artifacts are written (default .)
 *   MANDARE_VAULT / MANDARE_VAULT_* vault settings for issuance (as the CLI)
 *   MANDARE_WITNESS_URL + MANDARE_WITNESS_PUBLIC_KEY   enable witness checks/certify
 *   MANDARE_GATEWAY_URL          enable the gateway health tool
 *   MANDARE_MCP_ALLOW_REINSTATE=1  expose the reinstate tool (off by default)
 */
async function main(): Promise<void> {
  const server = createMandareMcpServer(loadMcpConfig(process.env));
  await server.connect(new StdioServerTransport());
  // stdio transport: the host owns the lifecycle; stay alive until stdin closes.
}

main().catch((error: unknown) => {
  process.stderr.write(`mandare-mcp: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
