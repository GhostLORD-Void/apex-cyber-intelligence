import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";

const app = express();
app.use(express.json({ limit: "1mb" }));
const PORT = Number(process.env.PORT || 8765);
const TOKEN = process.env.APEX_MCP_TOKEN;
if (!TOKEN) {
  console.error("APEX_MCP_TOKEN is required; refusing to start without authentication.");
  process.exit(1);
}
app.use("/mcp", (req, res, next) => {
  if (req.headers.authorization !== `Bearer ${TOKEN}`) {
    res.setHeader("WWW-Authenticate", "Bearer");
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
});

const server = new McpServer({ name: "apex-cyber-intelligence", version: "0.1.0" });
server.tool("apex_health", "Check APEX MCP service health.", {}, async () => ({
  content: [{ type: "text", text: JSON.stringify({ status: "ok", service: "APEX MCP", version: "0.1.0" }) }]
}));
server.tool("analyze_text", "Offline static triage of supplied text. Does not contact extracted URLs or IPs.", {
  text: z.string().max(100000)
}, async ({ text }) => {
  const urls = [...new Set(text.match(/\\b(?:https?:\\/\\/|www\\.)[^\\s<>\"']+/gi) || [])];
  const emails = [...new Set(text.match(/\\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}\\b/gi) || [])];
  const ipCandidates = [...new Set(text.match(/(?<![\\w.])(?:\\d{1,3}\\.){3}\\d{1,3}(?![\\w.])/g) || [])];
  const ips = ipCandidates.filter(ip => ip.split(".").every(n => Number(n) >= 0 && Number(n) <= 255));
  const terms = ["powershell -enc", "mimikatz", "credential dump", "ransom note", "disable antivirus"].filter(t => text.toLowerCase().includes(t));
  return { content: [{ type: "text", text: JSON.stringify({ text_length: text.length, urls, emails, ip_addresses: ips, suspicious_terms: terms, network_activity: false, note: "Heuristic triage only; analyst verification required." }, null, 2) }] };
});
server.tool("validate_scope", "Check a hostname against an explicit allowlist. This does not contact the target and does not prove authorization.", {
  target: z.string().min(1).max(2048),
  allowed: z.array(z.string().min(1)).max(100)
}, async ({ target, allowed }) => {
  let host;
  try { host = new URL(target.includes("://") ? target : "https://" + target).hostname.toLowerCase().replace(/\\.$/, ""); }
  catch { return { content: [{ type: "text", text: JSON.stringify({ allowed: false, reason: "Invalid hostname", network_activity: false }) }] }; }
  const list = allowed.map(x => x.trim().toLowerCase().replace(/\\.$/, "")).filter(Boolean);
  const matched = list.some(x => host === x || host.endsWith("." + x));
  return { content: [{ type: "text", text: JSON.stringify({ allowed: matched, host, reason: matched ? "Matched explicit allowlist" : "Not in explicit allowlist", network_activity: false }) }] };
});

const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
await server.connect(transport);
app.post("/mcp", (req, res) => transport.handleRequest(req, res, req.body));
app.get("/mcp", (_req, res) => res.status(405).json({ error: "Use POST for stateless MCP requests" }));
app.delete("/mcp", (_req, res) => res.status(405).json({ error: "Stateless endpoint" }));
app.get("/health", (_req, res) => res.json({ status: "ok", endpoint: "/mcp" }));
app.listen(PORT, "127.0.0.1", () => console.log(`APEX MCP listening on 127.0.0.1:${PORT}/mcp`));
