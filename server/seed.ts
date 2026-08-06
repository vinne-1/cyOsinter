import { db } from "./db";
import { users } from "@shared/schema";
import { eq } from "drizzle-orm";
import { hashPassword } from "./auth";
import { storage } from "./storage";
import { createLogger } from "./logger";

const seedLog = createLogger("seed");

export async function seedDatabase() {
  // Optional turnkey admin: when SEED_ADMIN_EMAIL / SEED_ADMIN_PASSWORD are set
  // (docker-compose provides sensible defaults) and the account does not yet
  // exist, create a superadmin so a fresh deployment can be logged into
  // immediately — no manual registration needed.
  const email = process.env.SEED_ADMIN_EMAIL?.trim().toLowerCase();
  const password = process.env.SEED_ADMIN_PASSWORD;
  if (email && password) {
    try {
      const [existing] = await db.select().from(users).where(eq(users.email, email)).limit(1);
      if (!existing) {
        const passwordHash = await hashPassword(password);
        await db.insert(users).values({ email, passwordHash, name: "Administrator", role: "superadmin" });
        seedLog.info({ email }, "Seeded default admin account (set via SEED_ADMIN_* env)");
      }
    } catch (err) {
      seedLog.warn({ err }, "Admin seed skipped (non-fatal)");
    }
  }

  const existingWorkspaces = await storage.getWorkspaces();
  if (existingWorkspaces.length > 0) return;
  seedLog.info("Database ready. Sign in, add a workspace, and run a scan against a domain to populate findings.");
}
