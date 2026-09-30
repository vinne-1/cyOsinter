/**
 * Tor SOCKS5 transport.
 *
 * ## Why these tests no longer stub `fetch`
 *
 * The previous version of this file replaced `globalThis.fetch` with a mock.
 * Every test passed — while the module was completely non-functional.
 *
 * The module passed a `SocksProxyAgent` to `fetch` as `dispatcher`. That agent
 * is a Node **http.Agent**; undici's `dispatcher` option needs an undici
 * **Dispatcher**, so `fetch` threw `TypeError: agent.dispatch is not a
 * function` before any byte left the process. Both `torFetch` and
 * `isTorAvailable` caught it and returned `null` / `false` — which reads
 * exactly like "the Tor daemon is not running", so the feature reported
 * "Tor unavailable" on every run even with Tor healthy.
 *
 * Stubbing `fetch` hid it, because the stub replaced the very call that was
 * broken. These tests mock `node:http` / `node:https` instead — the transport
 * the module now genuinely uses — so a regression to a transport that cannot
 * dial the proxy fails here rather than in production.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { EventEmitter } from "node:events";

/** A fake `http.request` whose behaviour each test dictates. */
const { httpRequest, httpsRequest } = vi.hoisted(() => ({
  httpRequest: vi.fn(),
  httpsRequest: vi.fn(),
}));

// `importOriginal` so the real `Agent` class survives — the agent-type test
// below depends on it, and that test is the regression guard for the bug.
vi.mock("node:http", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:http")>();
  return { ...actual, default: { ...actual, request: httpRequest }, request: httpRequest };
});
vi.mock("node:https", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:https")>();
  return { ...actual, default: { ...actual, request: httpsRequest }, request: httpsRequest };
});
vi.mock("../../../server/logger", () => ({
  createLogger: () => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }),
}));

import {
  isTorAvailable,
  torFetch,
  torFetchJson,
  torFetchText,
  getTorAgent,
  __resetTorAgent,
  normaliseTorProxyUrl,
  TOR_PROXY_URL,
} from "../../../server/scanner/tor-fetch";

/** A response stream the fake request will emit. */
function fakeResponse(opts: { status?: number; body?: string; headers?: Record<string, string>; manual?: boolean } = {}) {
  const res = new EventEmitter() as EventEmitter & {
    statusCode?: number;
    headers: Record<string, string>;
    destroy: () => void;
  };
  res.statusCode = opts.status ?? 200;
  res.headers = opts.headers ?? {};
  // `destroy` must stop delivery, exactly as the real stream does — otherwise
  // the truncation test cannot tell a working cap from a no-op.
  let destroyed = false;
  res.destroy = vi.fn(() => { destroyed = true; });
  const origEmit = res.emit.bind(res);
  res.emit = ((event: string, ...args: unknown[]) =>
    destroyed && event === "data" ? false : origEmit(event, ...args)) as typeof res.emit;

  if (!opts.manual) {
    queueMicrotask(() => {
      if (opts.body) res.emit("data", Buffer.from(opts.body, "utf8"));
      res.emit("end");
    });
  }
  return res;
}

/** Wires the fake transport: `handler` decides what the request does. */
function stubTransport(handler: (req: EventEmitter & { write: unknown; end: unknown; destroy: unknown }, cb: (res: unknown) => void) => void) {
  const impl = (_url: unknown, _opts: unknown, cb: (res: unknown) => void) => {
    const req = new EventEmitter() as EventEmitter & { write: unknown; end: unknown; destroy: unknown };
    req.write = vi.fn();
    req.end = vi.fn(() => handler(req, cb));
    req.destroy = vi.fn();
    return req;
  };
  httpRequest.mockImplementation(impl);
  httpsRequest.mockImplementation(impl);
}

beforeEach(() => {
  __resetTorAgent();
  httpRequest.mockReset();
  httpsRequest.mockReset();
});

afterEach(() => {
  vi.restoreAllMocks();
  __resetTorAgent();
});

describe("TOR_PROXY_URL", () => {
  it("defaults to the local Tor SOCKS port, with remote DNS", () => {
    expect(TOR_PROXY_URL).toBe("socks5h://127.0.0.1:9050");
  });
});

describe("normaliseTorProxyUrl", () => {
  it("rewrites socks5:// so a .onion name is resolved by Tor", () => {
    expect(normaliseTorProxyUrl("socks5://127.0.0.1:9050")).toBe("socks5h://127.0.0.1:9050");
    expect(normaliseTorProxyUrl("socks5://tor:9050")).toBe("socks5h://tor:9050");
    expect(normaliseTorProxyUrl("socks://tor:9050")).toBe("socks5h://tor:9050");
  });

  it("leaves an address that already uses remote DNS unchanged", () => {
    expect(normaliseTorProxyUrl("socks5h://127.0.0.1:9050")).toBe("socks5h://127.0.0.1:9050");
    expect(normaliseTorProxyUrl("socks4a://127.0.0.1:9050")).toBe("socks4a://127.0.0.1:9050");
  });
});

describe("getTorAgent", () => {
  /**
   * The regression guard. `fetch` cannot use an http.Agent, so the transport
   * must be one that can — anything else silently reports Tor as unavailable.
   */
  it("returns a Node http.Agent, which is what http.request requires", async () => {
    const { Agent } = await import("node:http");
    expect(getTorAgent()).toBeInstanceOf(Agent);
  });

  /**
   * socks5 resolves locally. Measured: a live .onion failed in 21ms with
   * ENOTFOUND, and the same URL over socks5h returned 301. shouldLookup
   * is the flag that chooses which of those two happens.
   */
  it("does not resolve the destination locally", () => {
    const agent = getTorAgent() as { shouldLookup?: boolean; proxyUrl?: string };
    expect(agent.shouldLookup).toBe(false);
    expect(agent.proxyUrl).toMatch(/^socks5h:\/\//);
  });

  it("reuses the agent within its TTL", () => {
    expect(getTorAgent()).toBe(getTorAgent());
  });

  it("builds a fresh agent after a reset", () => {
    const first = getTorAgent();
    __resetTorAgent();
    expect(getTorAgent()).not.toBe(first);
  });
});

describe("torFetch", () => {
  it("passes the SOCKS agent to the transport", async () => {
    stubTransport((_req, cb) => cb(fakeResponse({ body: "ok" })));
    await torFetch("http://example.onion/page");

    const [, options] = httpRequest.mock.calls[0]!;
    expect((options as { agent?: unknown }).agent).toBeDefined();
    expect((options as { agent?: unknown }).agent).toBe(getTorAgent());
  });

  it("returns the body and status on success", async () => {
    stubTransport((_req, cb) => cb(fakeResponse({ status: 200, body: "hello from .onion" })));
    const res = await torFetch("http://example.onion/page");

    expect(res?.ok).toBe(true);
    expect(res?.status).toBe(200);
    expect(await res?.text()).toBe("hello from .onion");
  });

  it("marks a non-2xx response as not ok rather than discarding it", async () => {
    stubTransport((_req, cb) => cb(fakeResponse({ status: 503, body: "down" })));
    const res = await torFetch("http://example.onion/page");
    expect(res?.ok).toBe(false);
    expect(res?.status).toBe(503);
  });

  /** ECONNREFUSED on the proxy port is the "Tor is not running" case. */
  it("returns null when the proxy refuses the connection", async () => {
    stubTransport((req) => {
      const err: NodeJS.ErrnoException = new Error("connect ECONNREFUSED 127.0.0.1:9050");
      err.code = "ECONNREFUSED";
      req.emit("error", err);
    });
    expect(await torFetch("http://example.onion/page")).toBeNull();
  });

  it("returns null on timeout", async () => {
    stubTransport((req) => req.emit("timeout"));
    expect(await torFetch("http://slow.onion/page", { timeoutMs: 50 })).toBeNull();
  });

  it("returns null for an unparseable URL rather than throwing", async () => {
    stubTransport((_req, cb) => cb(fakeResponse()));
    expect(await torFetch("not a url")).toBeNull();
  });

  it("sends custom headers, method and body", async () => {
    stubTransport((_req, cb) => cb(fakeResponse({ body: "ok" })));
    await torFetch("http://example.onion/api", {
      headers: { "X-Custom": "test" },
      method: "POST",
      body: '{"q":"search"}',
    });

    const [, options] = httpRequest.mock.calls[0]!;
    expect(options).toMatchObject({
      method: "POST",
      headers: expect.objectContaining({ "X-Custom": "test" }),
    });
  });

  it("uses the https transport for an https URL", async () => {
    stubTransport((_req, cb) => cb(fakeResponse({ body: "ok" })));
    await torFetch("https://check.torproject.org/api/ip");
    expect(httpsRequest).toHaveBeenCalledOnce();
    expect(httpRequest).not.toHaveBeenCalled();
  });

  /**
   * The cap must apply WHILE streaming. Slicing after `text()` cannot prevent
   * the memory exhaustion it claims to, because the body is already resident.
   */
  it("caps an oversized body and stops reading it", async () => {
    const res = fakeResponse({ manual: true });
    stubTransport((_req, cb) => {
      cb(res);
      queueMicrotask(() => {
        // One chunk larger than the cap: the module must take only what fits
        // and stop the stream rather than buffering the rest.
        res.emit("data", Buffer.alloc(600_000, 0x61));
        res.emit("close");
      });
    });

    const out = await torFetch("http://flood.onion/");
    const body = await out?.text();

    expect(body!.length).toBe(500_000);
    expect(out?.truncated).toBe(true);
    // Reading was stopped rather than left to run to completion.
    expect(res.destroy).toHaveBeenCalled();
  });
});

describe("isTorAvailable", () => {
  it("is true only when the check endpoint confirms the traffic went over Tor", async () => {
    stubTransport((_req, cb) => cb(fakeResponse({ body: JSON.stringify({ IsTor: true, IP: "185.220.101.1" }) })));
    expect(await isTorAvailable()).toBe(true);
  });

  /** A proxy that answers but is not Tor would fail .onion lookups confusingly. */
  it("is false when the endpoint says the traffic was NOT over Tor", async () => {
    stubTransport((_req, cb) => cb(fakeResponse({ body: JSON.stringify({ IsTor: false }) })));
    expect(await isTorAvailable()).toBe(false);
  });

  it("is false when the proxy is unreachable", async () => {
    stubTransport((req) => {
      const err: NodeJS.ErrnoException = new Error("ECONNREFUSED");
      err.code = "ECONNREFUSED";
      req.emit("error", err);
    });
    expect(await isTorAvailable()).toBe(false);
  });

  it("is false on a non-JSON body rather than throwing", async () => {
    stubTransport((_req, cb) => cb(fakeResponse({ body: "<html>blocked</html>" })));
    expect(await isTorAvailable()).toBe(false);
  });
});

describe("torFetchJson", () => {
  it("parses a successful JSON body", async () => {
    stubTransport((_req, cb) => cb(fakeResponse({ body: JSON.stringify({ results: [1, 2] }) })));
    expect(await torFetchJson<{ results: number[] }>("http://x.onion/api")).toEqual({ results: [1, 2] });
  });

  it("returns null on an HTTP error", async () => {
    stubTransport((_req, cb) => cb(fakeResponse({ status: 500, body: "{}" })));
    expect(await torFetchJson("http://x.onion/api")).toBeNull();
  });

  it("returns null when the body is not JSON", async () => {
    stubTransport((_req, cb) => cb(fakeResponse({ body: "not json" })));
    expect(await torFetchJson("http://x.onion/api")).toBeNull();
  });
});

describe("torFetchText", () => {
  it("returns the body text", async () => {
    stubTransport((_req, cb) => cb(fakeResponse({ body: "onion page" })));
    expect(await torFetchText("http://x.onion/")).toBe("onion page");
  });

  it("returns null on an HTTP error", async () => {
    stubTransport((_req, cb) => cb(fakeResponse({ status: 404, body: "nope" })));
    expect(await torFetchText("http://x.onion/")).toBeNull();
  });
});
