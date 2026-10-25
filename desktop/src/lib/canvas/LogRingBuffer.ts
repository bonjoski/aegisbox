export interface LogEntry {
  id: number;
  timestampNs: number;
  vmId: string;
  category: "stdout" | "stderr" | "mcp" | "egress" | "tripwire";
  rawText: string;
  sanitizedText: string;
}

export class LogRingBuffer {
  private capacity: number;
  private entries: (LogEntry | null)[];
  private head: number = 0;
  private size: number = 0;
  private seq: number = 0;

  constructor(capacity: number = 5000) {
    this.capacity = capacity;
    this.entries = new Array(capacity).fill(null);
  }

  public push(
    timestampNs: number,
    vmId: string,
    category: "stdout" | "stderr" | "mcp" | "egress" | "tripwire",
    rawText: string,
    sanitizedText: string
  ): LogEntry {
    const entry: LogEntry = {
      id: ++this.seq,
      timestampNs,
      vmId,
      category,
      rawText,
      sanitizedText,
    };

    this.entries[this.head] = entry;
    this.head = (this.head + 1) % this.capacity;
    if (this.size < this.capacity) {
      this.size++;
    }

    return entry;
  }

  public getSnapshot(): LogEntry[] {
    const result: LogEntry[] = new Array(this.size);
    const start = (this.head - this.size + this.capacity) % this.capacity;

    for (let i = 0; i < this.size; i++) {
      result[i] = this.entries[(start + i) % this.capacity]!;
    }

    return result;
  }

  public getLength(): number {
    return this.size;
  }

  public clear(): void {
    this.entries.fill(null);
    this.head = 0;
    this.size = 0;
  }
}
