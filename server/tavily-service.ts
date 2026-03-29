/**
 * Tavily web search for threat intelligence.
 * https://docs.tavily.com/documentation/api-reference/endpoint/search
 */

import { getTavilyKey } from "./api-integrations";

const TAVILY_BASE = "https://api.tavily.com/search";

export async function searchTavilyDork(query: string): Promise<Array<{ title: string; url: string; content: string }>> {
  try {
    const key = getTavilyKey();
    if (!key) return [];
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 30000);
    let json: { results?: Array<{ title?: string; url?: string; content?: string; snippet?: string }> };
    try {
      const res = await fetch(TAVILY_BASE, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${key}`,
        },
        body: JSON.stringify({
          query,
          search_depth: "basic",
          max_results: 10,
          include_answer: false,
        }),
        signal: ctrl.signal,
      });
      clearTimeout(t);
      if (!res.ok) {
        console.warn("[Tavily] Dork search HTTP error:", res.status);
        return [];
      }
      json = await res.json();
    } catch (fetchErr) {
      clearTimeout(t);
      throw fetchErr;
    }
    const rawResults = json.results;
    if (!rawResults || !Array.isArray(rawResults)) return [];
    return rawResults.slice(0, 10).map((r) => ({
      title: String(r.title ?? ""),
      url: String(r.url ?? ""),
      content: String(r.content ?? r.snippet ?? "").slice(0, 500),
    }));
  } catch (err) {
    console.warn("[Tavily] Dork search failed:", err instanceof Error ? err.message : err);
    return [];
  }
}

export async function searchThreatIntel(domain: string): Promise<string> {
  const key = getTavilyKey();
  if (!key) return "";

  const query = `${domain} security vulnerabilities cybersecurity threat`;
  const ctrl = new AbortController();
  let t: ReturnType<typeof setTimeout> | undefined;
  try {
    t = setTimeout(() => ctrl.abort(), 30000); // 30s timeout
    const res = await fetch(TAVILY_BASE, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${key}`,
      },
      body: JSON.stringify({
        query,
        search_depth: "basic",
        max_results: 5,
        include_answer: false,
      }),
      signal: ctrl.signal,
    });
    clearTimeout(t);
    if (!res.ok) {
      console.warn("[Tavily] Search failed:", res.status);
      return "";
    }
    const json = (await res.json()) as { results?: Array<{ content?: string; title?: string }> };
    const results = json.results ?? [];
    const snippets = results
      .map((r) => (r.content ?? r.title ?? "").trim())
      .filter(Boolean)
      .join(" ")
      .slice(0, 500);
    return snippets;
  } catch (err) {
    if (t) clearTimeout(t);
    console.warn("[Tavily] Error:", (err as Error).message);
    return "";
  }
}
