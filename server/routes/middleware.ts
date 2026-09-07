import type { Request, Response, NextFunction } from "express";

/** Admin auth: requires ADMIN_API_KEY env var or localhost-only access */
export function requireAdmin(req: Request, res: Response, next: NextFunction): void {
  const adminKey = process.env.ADMIN_API_KEY;
  if (adminKey) {
    const provided = req.headers["x-admin-key"];
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


/**
 * Outbound URL safety lives in `server/utils/ssrf.ts`.
 *
 * `isSafeExternalUrl` used to live here as a hostname string blocklist, which
 * meant two guards existed and disagreed: a host that merely RESOLVES to
 * 127.0.0.1, and decimal/octal/hex IP literals, passed the string check and
 * were refused by the resolving one. Use `isSafeOutboundUrl` / `isPrivateHost`.
 */

