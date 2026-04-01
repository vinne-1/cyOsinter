import { storage } from "./storage";
import { createLogger } from "./logger";

const seedLog = createLogger("seed");

export async function seedDatabase() {
  const existingWorkspaces = await storage.getWorkspaces();
  if (existingWorkspaces.length > 0) return;

  seedLog.info("Database ready - no seed data created. Run a scan against a real domain to discover actual findings.");
}
