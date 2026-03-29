import { storage } from "./storage";

export async function seedDatabase() {
  const existingWorkspaces = await storage.getWorkspaces();
  if (existingWorkspaces.length > 0) return;

  console.log("Database ready - no seed data created. Run a scan against a real domain to discover actual findings.");
}
