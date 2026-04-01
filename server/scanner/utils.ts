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
