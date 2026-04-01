import { defineConfig } from "vitest/config";
import path from "path";

export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    pool: "vmThreads",
    include: ["tests/**/*.test.ts"],
    coverage: {
      provider: "v8" as any,
      // Only instrument files that are actually imported by tests — avoids
      // Windows B:-drive path issues when scanning uncovered files
      all: false,
      include: ["server/**/*.ts", "shared/**/*.ts"],
      exclude: ["server/index.ts", "server/static.ts", "server/seed.ts"],
    },
  },
  resolve: {
    alias: {
      "@shared": path.resolve(__dirname, "shared"),
    },
  },
});
