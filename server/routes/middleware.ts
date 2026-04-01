import type { Request, Response, NextFunction } from "express";

/** Admin auth: requires ADMIN_API_KEY env var or localhost-only access */
export function requireAdmin(req: Request, res: Response, next: NextFunction): void {
  const adminKey = process.env.ADMIN_API_KEY;
  if (adminKey) {
    const provided = req.headers["x-admin-key"] || req.query.adminKey;
    if (provided === adminKey) return next();
    res.status(401).json({ message: "Unauthorized: invalid admin key" });
    return;
  }
  // Fallback: restrict to loopback addresses when no ADMIN_API_KEY is set
  const ip = req.ip || req.socket.remoteAddress || "";
  const isLocal = ip === "127.0.0.1" || ip === "::1" || ip === "::ffff:127.0.0.1";
  if (isLocal) return next();
  res.status(403).json({ message: "Forbidden: admin endpoints are restricted to localhost" });
}

/** Validates a URL is safe to fetch (blocks SSRF to internal networks) */
export function isSafeExternalUrl(raw: string): boolean {
  try {
    const u = new URL(raw);
    if (!["http:", "https:"].includes(u.protocol)) return false;
    const hostname = u.hostname.toLowerCase();
    if (hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1") return false;
    if (/^10\.\d/.test(hostname)) return false;
    if (/^172\.(1[6-9]|2\d|3[01])\./.test(hostname)) return false;
    if (/^192\.168\./.test(hostname)) return false;
    if (hostname === "169.254.169.254" || hostname.endsWith(".internal")) return false;
    if (hostname === "0.0.0.0" || hostname === "[::1]") return false;
    return true;
  } catch {
    return false;
  }
}
