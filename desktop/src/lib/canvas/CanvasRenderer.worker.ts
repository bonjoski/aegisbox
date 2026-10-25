import { LogRingBuffer, type LogEntry } from "./LogRingBuffer";

let canvas: OffscreenCanvas | null = null;
let ctx: OffscreenCanvasRenderingContext2D | null = null;
const ringBuffer = new LogRingBuffer(5000);

let width = 800;
let height = 600;
const LINE_HEIGHT = 18;
const FONT_SIZE = 12;

// Adversarial ANSI Sanitizer:
// 1. Strip OSC 52 (clipboard access), OSC 0/2 (title manipulation), DCS
// 2. Strip dynamic cursor repositioning codes that attempt to overwrite previous lines
// 3. Suppress all terminal reflection probes (\x1b[c, \x1b[6n, \x1b]11;?)
export function sanitizeTerminalOutput(raw: string): string {
  // Strip OSC 52 clipboard exfiltration: \x1b]52;...;\x07 or \x1b]52;...\x1b\\
  let s = raw.replace(/\x1b\]52;[^\x07\x1b]*(\x07|\x1b\\)/g, "[BLOCKED_OSC52]");

  // Strip OSC window title manipulation: \x1b]0;...;\x07
  s = s.replace(/\x1b\][0-2];[^\x07\x1b]*(\x07|\x1b\\)/g, "");

  // Strip DCS (Device Control Strings): \x1bP...\x1b\\
  s = s.replace(/\x1bP[^\x1b]*\x1b\\/g, "");

  // Terminal Query Echo Suppression: Strip terminal probe requests
  // \x1b[c (DA1), \x1b[>c (DA2), \x1b[6n (CPR), \x1b]11;? (OSC 11 color query)
  s = s.replace(/\x1b\[\??[0-9;]*[cn]/g, "");
  s = s.replace(/\x1b\]1[0-2];\?(\x07|\x1b\\)/g, "");

  // Strip destructive cursor repositioning: \x1b[2J, \x1b[H, \x1b[K
  s = s.replace(/\x1b\[[0-9;]*[HJKsu]/g, "");

  // Whitelist standard SGR color formatting: \x1b[[0-9;]*m
  // For canvas plain rendering, we strip remaining non-SGR escapes
  s = s.replace(/\x1b\[(?![0-9;]*m)[a-zA-Z]/g, "");

  // Unicode Bidi control characters override stripping
  s = s.replace(/[\u202A-\u202E\u2066-\u2069]/g, "");

  return s;
}

self.onmessage = (event: MessageEvent) => {
  const { type, payload } = event.data;

  switch (type) {
    case "INIT":
      canvas = payload.canvas;
      width = payload.width || 800;
      height = payload.height || 600;
      if (canvas) {
        ctx = canvas.getContext("2d");
        render();
      }
      break;

    case "RESIZE":
      width = payload.width;
      height = payload.height;
      if (canvas) {
        canvas.width = width;
        canvas.height = height;
        render();
      }
      break;

    case "PUSH_LOG":
      const sanitized = sanitizeTerminalOutput(payload.text);
      ringBuffer.push(
        payload.timestampNs || Date.now() * 1e6,
        payload.vmId || "vm-system",
        payload.category || "stdout",
        payload.text,
        sanitized
      );
      render();
      break;

    case "CLEAR":
      ringBuffer.clear();
      render();
      break;
  }
};

function render() {
  if (!ctx || !canvas) return;

  // Background
  ctx.fillStyle = "#09090b";
  ctx.fillRect(0, 0, width, height);

  ctx.font = `${FONT_SIZE}px ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace`;
  ctx.textBaseline = "top";

  const entries = ringBuffer.getSnapshot();
  const maxVisibleLines = Math.floor(height / LINE_HEIGHT);
  const startIdx = Math.max(0, entries.length - maxVisibleLines);

  let y = 8;
  for (let i = startIdx; i < entries.length; i++) {
    const entry = entries[i];
    if (!entry) continue;

    // Color by category / severity
    if (entry.category === "tripwire") {
      ctx.fillStyle = "#f87171"; // Red
    } else if (entry.category === "stderr") {
      ctx.fillStyle = "#fbbf24"; // Amber
    } else if (entry.category === "mcp") {
      ctx.fillStyle = "#34d399"; // Emerald
    } else if (entry.category === "egress") {
      ctx.fillStyle = "#60a5fa"; // Blue
    } else {
      ctx.fillStyle = "#e4e4e7"; // Zinc 200
    }

    // Render timestamp + message
    const lineText = `[${new Date(entry.timestampNs / 1e6).toISOString().substring(11, 19)}] ${entry.sanitizedText}`;
    ctx.fillText(lineText, 12, y);

    y += LINE_HEIGHT;
  }
}
