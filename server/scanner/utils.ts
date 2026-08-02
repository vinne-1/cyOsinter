import { existsSync, statSync } from "fs";
import path from "path";

/**
 * Resolve the absolute path to an external executable, honoring Windows PATHEXT.
 *
 * Node's child_process.spawn (without shell:true) does NOT append `.exe`/`.cmd`
 * on Windows, so `spawn("nuclei")` fails even when `nuclei.exe` is on PATH
 * (e.g. scoop/go shims). This searches the given extra directories and every
 * PATH entry, trying each PATHEXT extension, and returns the first real file.
 * Returns null if nothing is found.
 */
export function resolveExecutable(name: string, extraDirs: string[] = []): string | null {
  const isWin = process.platform === "win32";
  const exts = isWin
    ? ["", ...(process.env.PATHEXT || ".EXE;.CMD;.BAT;.COM").split(";")]
    : [""];
  const dirs = [
    ...extraDirs,
    ...((process.env.PATH || "").split(path.delimiter)),
  ].filter(Boolean);
  for (const dir of dirs) {
    for (const ext of exts) {
      const candidate = path.join(dir, name + ext.toLowerCase());
      try {
        if (existsSync(candidate) && statSync(candidate).isFile()) return candidate;
      } catch {
        /* unreadable path — skip */
      }
    }
  }
  return null;
}

export async function runWithConcurrency<T, R>(
  items: T[],
  concurrency: number,
  fn: (item: T) => Promise<R>,
  signal?: AbortSignal,
): Promise<R[]> {
  const results: R[] = [];
  let i = 0;
  async function worker(): Promise<void> {
    while (i < items.length) {
      if (signal?.aborted) throw new Error("Scan aborted");
      const idx = i++;
      const item = items[idx];
      try {
        results[idx] = await fn(item);
      } catch (err) {
        if (err instanceof Error && err.message === "Scan aborted") throw err;
        results[idx] = undefined as any;
      }
    }
  }
  const workers = Array.from({ length: Math.min(concurrency, items.length) }, () => worker());
  await Promise.all(workers);
  return results;
}
