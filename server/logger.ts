import pino from "pino";

const isDev = process.env.NODE_ENV !== "production";

export const logger = pino({
  level: process.env.LOG_LEVEL || (isDev ? "debug" : "info"),
  redact: {
    paths: ["password", "passwordHash", "token", "secret", "apiKey", "authorization", "totpSecret", "*.password", "*.passwordHash", "*.token", "*.secret", "*.apiKey", "*.totpSecret"],
    censor: "[REDACTED]",
  },
  transport: isDev
    ? { target: "pino-pretty", options: { colorize: true, translateTime: "HH:MM:ss", ignore: "pid,hostname" } }
    : undefined,
});

/** Create a child logger with a component/module name */
export function createLogger(component: string) {
  return logger.child({ component });
}
