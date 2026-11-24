export type LogLevel = "debug" | "info" | "warn" | "error";

export class Logger {
  private prefix: string;

  constructor(prefix: string = "sudarshan") {
    this.prefix = prefix;
  }

  private log(level: LogLevel, message: string, ...args: unknown[]) {
    const ts = new Date().toISOString();
    const formattedArgs = args.length > 0 ? " " + args.map((a) => (typeof a === "object" ? JSON.stringify(a) : String(a))).join(" ") : "";
    process.stderr.write(`[${ts}] [${this.prefix}] [${level.toUpperCase()}] ${message}${formattedArgs}\n`);
  }

  debug(message: string, ...args: unknown[]) {
    this.log("debug", message, ...args);
  }

  info(message: string, ...args: unknown[]) {
    this.log("info", message, ...args);
  }

  warn(message: string, ...args: unknown[]) {
    this.log("warn", message, ...args);
  }

  error(message: string, ...args: unknown[]) {
    this.log("error", message, ...args);
  }
}

export const logger = new Logger("sudarshan-gateway");

