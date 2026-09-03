"use strict";

const { createInterface } = require("readline/promises");

/**
 * `residoo mcp`: a hand-rolled MCP (Model Context Protocol) server over
 * stdio, so Claude Code (or any other MCP client) can query residoo's
 * findings and rotation ledger directly instead of a human running the
 * CLI in a terminal. No `@modelcontextprotocol/sdk` dependency -- residoo
 * has zero runtime dependencies, no exceptions (see CONTRIBUTING.md), and
 * MCP's stdio transport is newline-delimited JSON-RPC 2.0, which Node's
 * own `readline` already handles; every `.jsonl` source adapter in
 * src/sources/ hand-rolls the same kind of line-delimited JSON parsing.
 *
 * This file is the protocol engine only: framing, dispatch, version
 * negotiation, the outgoing writer, shutdown. It has zero domain
 * knowledge of scanning/rotation -- see src/mcpTools.js for the actual
 * tool catalog. `tools` here is just a `Map<name, {name, description,
 * inputSchema, handler}>` handed in by the caller (mirrors `startWatch`'s
 * `sources` being handed in by its caller rather than looked up itself).
 *
 * Implements the Legacy (initialize-handshake) MCP era only
 * (`2025-11-25`/`2025-06-18`/`2025-03-26`), which is Claude Code's own
 * documented DEFAULT for every stdio server -- it only probes stdio
 * servers for the newer, per-request "Modern" era
 * (`server/discover`-based) when a user explicitly sets
 * `MCP_PROTOCOL_NEGOTIATION=auto`. In that opt-in case, the generic
 * "unknown method" handler below answers `server/discover` instantly with
 * a plain JSON-RPC -32601, which is exactly what the MCP spec defines as
 * triggering a Dual-era client's fallback to the Legacy handshake -- so
 * this server works either way, and implementing `server/discover` itself
 * is a deliberate, non-blocking v1 scope decision, not an oversight.
 *
 * Per the spec's own words: "The server MUST NOT write anything to its
 * stdout that is not a valid MCP message." `send()` below is the ONLY
 * function in this file (or in mcpTools.js) allowed to touch `output`;
 * every log line, startup banner, and shutdown summary goes to
 * `errOutput` instead. This is the same "stdout is sacred" discipline
 * watch.js already established, enforced even more strictly here, since
 * a single stray byte on stdout doesn't just create noise -- it can
 * corrupt the client's JSON-RPC stream.
 */

const JSONRPC_VERSION = "2.0";

// All three are "Legacy"-era (initialize-handshake) protocol revisions;
// none of the wire shapes this file implements (initialize result,
// tools/list, tools/call, isError) differ across them, so supporting all
// three costs nothing beyond this list. If the client's requested version
// isn't one of these, DEFAULT_PROTOCOL_VERSION is what we claim instead.
const SUPPORTED_PROTOCOL_VERSIONS = ["2025-11-25", "2025-06-18", "2025-03-26"];
const DEFAULT_PROTOCOL_VERSION = "2025-06-18";

function negotiateProtocolVersion(requested) {
  if (typeof requested === "string" && SUPPORTED_PROTOCOL_VERSIONS.includes(requested)) return requested;
  return DEFAULT_PROTOCOL_VERSION;
}

/**
 * `startMcpServer({tools, serverInfo, instructions, input, output,
 * errOutput})` -> `{promise, stop}`. All I/O injectable (mirrors
 * `startWatch`'s `{sources, options, out, errOut}` contract) so this can
 * be driven by tests with fake streams and a stub tool map, with no real
 * scanning involved.
 */
function startMcpServer({
  tools,
  serverInfo,
  instructions,
  input = process.stdin,
  output = process.stdout,
  errOutput = process.stderr,
} = {}) {
  const rl = createInterface({ input, crlfDelay: Infinity });
  let stopped = false;
  let requestsHandled = 0;

  /**
   * The single write path. `JSON.stringify` already escapes any raw `\n`
   * inside a string VALUE as the two-character sequence `\` `n` (JSON's
   * own grammar, RFC 8259, forbids a literal control character in a
   * string) -- no per-field newline scrubbing is needed here. The only
   * raw 0x0A byte in the whole write is the one appended below, as the
   * stdio transport's own frame delimiter.
   */
  function send(message) {
    let text;
    try {
      text = JSON.stringify(message);
    } catch (err) {
      // `message` contained something JSON.stringify can't serialize (a
      // circular reference, a BigInt) -- a bug in a tool handler, not a
      // reason to crash the connection or silently drop a reply the
      // client may be blocked waiting on. `message.id`, when present,
      // always came from JSON.parse on the client's own request and
      // already passed the id-type check in handleLine, so it's
      // independently safe to reserialize on its own here.
      errOutput.write(`residoo mcp: failed to serialize outgoing message: ${err instanceof Error ? err.message : String(err)}\n`);
      const fallbackId = message && typeof message === "object" && "id" in message ? message.id : null;
      text = JSON.stringify({
        jsonrpc: JSONRPC_VERSION, id: fallbackId,
        error: { code: -32603, message: "Internal error: response could not be serialized" },
      });
    }
    output.write(text + "\n");
  }

  function sendError(id, code, message, data) {
    send({ jsonrpc: JSONRPC_VERSION, id, error: data === undefined ? { code, message } : { code, message, data } });
  }

  function sendResult(id, result) {
    send({ jsonrpc: JSONRPC_VERSION, id, result });
  }

  function handleInitialize(params, id) {
    const protocolVersion = negotiateProtocolVersion(params && params.protocolVersion);
    sendResult(id, {
      protocolVersion,
      capabilities: { tools: {} },
      serverInfo,
      ...(instructions ? { instructions } : {}),
    });
  }

  function handleToolsList(id) {
    const list = [];
    for (const tool of tools.values()) {
      list.push({ name: tool.name, description: tool.description, inputSchema: tool.inputSchema });
    }
    sendResult(id, { tools: list });
  }

  async function handleToolsCall(params, id) {
    if (!params || typeof params !== "object" || typeof params.name !== "string") {
      sendError(id, -32602, "Invalid params: 'name' (string) is required");
      return;
    }
    const tool = tools.get(params.name);
    if (!tool) {
      sendError(id, -32602, `Unknown tool: ${params.name}`);
      return;
    }

    const args = params.arguments && typeof params.arguments === "object" && !Array.isArray(params.arguments)
      ? params.arguments : {};
    let result;
    try {
      // The handler owns its OWN input validation and is expected to
      // return {content, isError:true} for both a bad-argument case and a
      // genuine execution failure -- see SEP-1303: input validation
      // errors are Tool Execution Errors, not Protocol Errors, so the
      // model can see the message and self-correct in the same turn.
      // This dispatcher does not and should not try to tell those two
      // cases apart.
      result = await tool.handler(args);
      if (!result || !Array.isArray(result.content)) {
        // Defensive: a handler bug in mcpTools.js must not corrupt the
        // wire protocol -- fail safe into a well-formed isError result.
        result = { content: [{ type: "text", text: "Tool returned no content (internal error)." }], isError: true };
      }
    } catch (err) {
      // Anything a handler THROWS still lands as a tool execution error,
      // not -32603 -- that code is reserved for bugs in this dispatcher
      // itself, not in a tool. errOutput gets the full detail for
      // operator debugging; the client only ever sees the message string.
      errOutput.write(`residoo mcp: tool "${params.name}" threw: ${err instanceof Error ? (err.stack || err.message) : String(err)}\n`);
      result = { content: [{ type: "text", text: `Failed: ${err instanceof Error ? err.message : String(err)}` }], isError: true };
    }
    sendResult(id, result);
  }

  async function dispatch(method, params, hasId, id) {
    switch (method) {
      case "initialize":
        if (!hasId) return;
        return handleInitialize(params, id);
      case "notifications/initialized":
        // A true notification by the method's own contract: never reply,
        // even if a client mistakenly attached an id -- nothing in v1
        // depends on this flag anyway (no server-initiated requests).
        return;
      case "tools/list":
        if (!hasId) return;
        return handleToolsList(id);
      case "tools/call":
        if (!hasId) return;
        return handleToolsCall(params, id);
      default:
        // Includes a `server/discover` probe from a client with
        // MCP_PROTOCOL_NEGOTIATION=auto (see file doc comment) -- MUST
        // reply fast (no I/O, no await, above) so that fallback resolves
        // immediately rather than after a client-side timeout.
        if (!hasId) return;
        sendError(id, -32601, `Method not found: ${method}`);
    }
  }

  async function handleLine(line) {
    if (line.trim() === "") return false;
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      // Per JSON-RPC 2.0 section 5: if the id could not even be
      // determined (a parse failure means we never got that far), the
      // error response's id MUST be null.
      sendError(null, -32700, "Parse error");
      errOutput.write(`residoo mcp: received unparseable line (${line.length} bytes): ${line.slice(0, 200)}\n`);
      return false;
    }
    if (msg === null || typeof msg !== "object" || Array.isArray(msg)) {
      sendError(null, -32600, "Invalid Request: expected a JSON object");
      return false;
    }

    // Deliberately `hasOwnProperty`, never `msg.id` truthiness -- id:0 is
    // a valid, falsy request id, and conflating "id key absent" (a
    // notification: never reply, even with an error) with "id present but
    // falsy" is exactly the kind of one-character bug that silently
    // breaks a client's parser.
    const hasId = Object.prototype.hasOwnProperty.call(msg, "id");
    const id = hasId ? msg.id : undefined;
    const idIsValidType = id === null || typeof id === "string" || typeof id === "number";

    if (msg.jsonrpc !== JSONRPC_VERSION || typeof msg.method !== "string") {
      if (!hasId) return false; // malformed NOTIFICATION: JSON-RPC promises no reply, ever
      sendError(idIsValidType ? id : null, -32600, "Invalid Request");
      return false;
    }
    if (hasId && !idIsValidType) {
      // id present but not string/number/null: can't trust echoing it
      // back (and can't safely re-serialize it if it's e.g. an object).
      sendError(null, -32600, "Invalid Request: id must be a string, number, or null");
      return false;
    }

    try {
      await dispatch(msg.method, msg.params, hasId, id);
    } catch (err) {
      errOutput.write(`residoo mcp: internal error handling "${msg.method}": ${err instanceof Error ? (err.stack || err.message) : String(err)}\n`);
      if (hasId) sendError(id, -32603, "Internal error");
    }
    return hasId;
  }

  function stop() {
    if (stopped) return;
    stopped = true;
    rl.close(); // unblocks the `for await` loop below on its next iteration
  }

  const promise = (async () => {
    for await (const line of rl) {
      if (stopped) break;
      if (await handleLine(line)) requestsHandled++;
    }
    if (!stopped) stopped = true;
    errOutput.write(`residoo mcp: shutting down. Handled ${requestsHandled} request(s).\n`);
    return { requestsHandled };
  })();

  return { promise, stop };
}

module.exports = { startMcpServer, SUPPORTED_PROTOCOL_VERSIONS, DEFAULT_PROTOCOL_VERSION };
