// Ask lend on the laptop before pi runs selected tools.
// Copy to ~/.pi/agent/extensions/ or a project's .pi/extensions/.
import { spawn } from "node:child_process";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

const GATED_TOOLS = new Set(["bash", "write", "edit"]);

// lend exits 0 when approved, 1 when refused, and 125 when it cannot reach the laptop.
function askLend(payload: object, signal?: AbortSignal): Promise<number> {
  return new Promise((resolve) => {
    const child = spawn("lend", ["approve", "--hook", "pi"], { stdio: ["pipe", "ignore", "ignore"], signal });
    child.on("error", () => resolve(125));
    child.on("close", (code) => resolve(code ?? 125));
    // lend can exit before reading oversized input; its exit code still settles the request.
    child.stdin.on("error", () => {});
    child.stdin.end(JSON.stringify(payload));
  });
}

export default function (pi: ExtensionAPI) {
  pi.on("tool_call", async (event, ctx) => {
    if (!GATED_TOOLS.has(event.toolName)) return;
    const code = await askLend({ agent: "pi", tool: event.toolName, input: event.input, cwd: ctx.cwd }, ctx.signal);
    if (code === 0) return;
    if (code === 1) return { block: true, reason: "Denied in lend on the laptop." };
    if (ctx.hasUI && (await ctx.ui.confirm("lend is unavailable", `Allow ${event.toolName} without laptop approval?`))) return;
    return { block: true, reason: "lend could not reach the laptop for approval." };
  });
}
