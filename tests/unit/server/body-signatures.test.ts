/**
 * Unit tests for server/scanner/body-signatures.ts.
 *
 * Each predicate gates a finding that names a specific technology, so the tests
 * are paired: the real artefact must be recognised, and the thing that used to
 * be mistaken for it must be rejected. The rejection half is the point — a 200
 * from a single-page app is what turned `/api/v1/pods` into a critical
 * "Kubernetes API exposed" finding.
 */
import { describe, it, expect } from "vitest";
import {
  looksLikeHtml,
  looksLikeEnvFile,
  looksLikeGitConfig,
  looksLikeDirectoryListing,
  looksLikePrometheusMetrics,
  looksLikeKubernetesApi,
  looksLikeDockerRegistry,
  looksLikePhpInfo,
  looksLikeApacheServerStatus,
  looksLikeSpringActuator,
  looksLikeOpenApiSpec,
  looksLikeGoPprof,
  looksLikeSqlDump,
  looksLikeLogFile,
  looksLikePrivateKey,
  looksLikeHtpasswd,
  looksLikeTerraformState,
  isDocumentResponse,
} from "../../../server/scanner/body-signatures";

/** The response a single-page app returns for every unknown path. */
const SPA_SHELL = '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Acme</title></head><body><div id="root"></div><script src="/assets/index.9f2c1a.js"></script></body></html>';

describe("looksLikeHtml", () => {
  it("recognises the lowercase doctype the old check missed", () => {
    // `body.trim().startsWith("<!DOCTYPE")` was case sensitive, so every
    // framework emitting `<!doctype html>` had its markup scanned for secrets.
    expect(looksLikeHtml("<!doctype html><html><body>hi</body></html>")).toBe(true);
    expect(looksLikeHtml("<!DOCTYPE html>\n<html></html>")).toBe(true);
  });

  it("survives a byte-order mark, leading whitespace, and a leading comment", () => {
    expect(looksLikeHtml("﻿\n  <!doctype html><html></html>")).toBe(true);
    expect(looksLikeHtml("<!-- generated -->\n<!doctype html><html></html>")).toBe(true);
  });

  it("does not claim plain configuration text is a document", () => {
    expect(looksLikeHtml("APP_ENV=production\nDB_HOST=localhost\n")).toBe(false);
    expect(looksLikeHtml('{"name":"acme","version":"1.0.0"}')).toBe(false);
  });
});

describe("looksLikeEnvFile", () => {
  it("accepts a real dotenv file", () => {
    expect(looksLikeEnvFile("APP_ENV=production\nDB_PASSWORD=hunter2\nexport AWS_REGION=eu-west-1\n")).toBe(true);
  });

  it("rejects the SPA shell a catch-all route serves for /.env", () => {
    expect(looksLikeEnvFile(SPA_SHELL)).toBe(false);
  });

  it("rejects JavaScript source, which is also full of assignments", () => {
    expect(looksLikeEnvFile("const a = 1;\nlet b = 2;\nvar c = 3;\nfunction d() {}\n")).toBe(false);
  });

  it("needs more than one assignment before the shape means anything", () => {
    expect(looksLikeEnvFile("KEY=value")).toBe(false);
  });
});

describe("looksLikeGitConfig", () => {
  it("accepts a real .git/config and rejects a page that merely contains [core]", () => {
    expect(looksLikeGitConfig("[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n")).toBe(true);
    expect(looksLikeGitConfig("<html><body>[core] team page</body></html>")).toBe(false);
  });
});

describe("looksLikeDirectoryListing", () => {
  it("accepts an nginx and an Apache index", () => {
    expect(looksLikeDirectoryListing('<html><head><title>Index of /files</title></head><body><h1>Index of /files</h1><hr><pre><a href="../">../</a></pre></body></html>')).toBe(true);
    expect(looksLikeDirectoryListing('<h1>Index of /backup</h1><table><tr><th><a href="?C=N;O=D">Name</a></th></tr><tr><td><a href="/">Parent Directory</a></td></tr></table>')).toBe(true);
  });

  it("rejects a page that only mentions the phrase", () => {
    expect(looksLikeDirectoryListing("<html><body><p>Our Index of /products is below.</p></body></html>")).toBe(false);
  });
});

describe("looksLikePrometheusMetrics", () => {
  it("accepts a real exposition", () => {
    const body = [
      "# HELP http_requests_total Total requests",
      "# TYPE http_requests_total counter",
      'http_requests_total{method="get"} 1027',
      "# HELP process_cpu_seconds_total CPU time",
      "# TYPE process_cpu_seconds_total counter",
      "process_cpu_seconds_total 4.2",
    ].join("\n");
    expect(looksLikePrometheusMetrics(body)).toBe(true);
  });

  it("rejects the HTML a catch-all route returns for /metrics", () => {
    expect(looksLikePrometheusMetrics(SPA_SHELL)).toBe(false);
  });
});

describe("looksLikeKubernetesApi", () => {
  it("accepts a PodList and rejects the SPA shell", () => {
    expect(looksLikeKubernetesApi('{"kind":"PodList","apiVersion":"v1","items":[]}')).toBe(true);
    expect(looksLikeKubernetesApi(SPA_SHELL)).toBe(false);
  });

  it("rejects unrelated JSON that happens to have a kind field", () => {
    expect(looksLikeKubernetesApi('{"kind":"customer","id":7}')).toBe(false);
  });
});

describe("looksLikeDockerRegistry", () => {
  it("accepts a catalog body and the registry version header", () => {
    expect(looksLikeDockerRegistry('{"repositories":["app","db"]}')).toBe(true);
    expect(looksLikeDockerRegistry("{}", { "Docker-Distribution-Api-Version": "registry/2.0" })).toBe(true);
  });

  it("rejects an empty JSON object with no registry signal", () => {
    expect(looksLikeDockerRegistry("{}")).toBe(false);
  });
});

describe("looksLikePhpInfo / looksLikeApacheServerStatus", () => {
  it("accepts the generated pages and rejects prose about them", () => {
    expect(looksLikePhpInfo("<title>phpinfo()</title>")).toBe(true);
    expect(looksLikePhpInfo("<html><body>We run PHP Version 8 here</body></html>")).toBe(false);
    expect(looksLikeApacheServerStatus("<h1>Apache Server Status for example.com</h1><p>Total accesses: 12</p>")).toBe(true);
    expect(looksLikeApacheServerStatus("<p>Check the Apache Server Status docs</p>")).toBe(false);
  });
});

describe("looksLikeSpringActuator", () => {
  it("accepts a health document and rejects an unrelated JSON status string", () => {
    expect(looksLikeSpringActuator('{"status":"UP","components":{}}')).toBe(true);
    expect(looksLikeSpringActuator('{"status":"active","user":"jo"}')).toBe(false);
  });
});

describe("looksLikeOpenApiSpec", () => {
  it("accepts JSON and YAML specs, rejects a docs landing page", () => {
    expect(looksLikeOpenApiSpec('{"openapi":"3.0.0","info":{"title":"API"},"paths":{}}')).toBe(true);
    expect(looksLikeOpenApiSpec("openapi: 3.0.1\ninfo:\n  title: API\npaths:\n  /x: {}\n")).toBe(true);
    expect(looksLikeOpenApiSpec(SPA_SHELL)).toBe(false);
  });
});

describe("looksLikeGoPprof", () => {
  it("accepts the pprof index and rejects a page linking to it", () => {
    expect(looksLikeGoPprof('<a href="/debug/pprof/goroutine">goroutine</a> full goroutine stack dump')).toBe(true);
    expect(looksLikeGoPprof("<p>See our blog post about /debug/pprof/ tuning</p>")).toBe(false);
  });
});

describe("dumps, logs, keys and archives", () => {
  it("recognises a SQL dump", () => {
    expect(looksLikeSqlDump("-- MySQL dump 10.13\nCREATE TABLE users (id int);")).toBe(true);
    expect(looksLikeSqlDump(SPA_SHELL)).toBe(false);
  });

  it("recognises a timestamped log", () => {
    expect(looksLikeLogFile("2024-01-01T10:00:00 INFO started\n2024-01-01T10:00:01 WARN slow\n2024-01-01T10:00:02 ERROR failed\n")).toBe(true);
    expect(looksLikeLogFile("hello\nworld\n")).toBe(false);
  });

  it("recognises PEM key material and htpasswd hashes", () => {
    expect(looksLikePrivateKey("-----BEGIN RSA PRIVATE KEY-----\nMII...")).toBe(true);
    expect(looksLikeHtpasswd("admin:$apr1$abcd$efghijklmnopqrstuvwx")).toBe(true);
    expect(looksLikeHtpasswd(SPA_SHELL)).toBe(false);
  });

  it("recognises a terraform state file", () => {
    expect(looksLikeTerraformState('{"terraform_version":"1.5.0","lineage":"abc","resources":[]}')).toBe(true);
    expect(looksLikeTerraformState('{"version":4}')).toBe(false);
  });

  it("separates a served document from a route that only renders HTML", () => {
    expect(isDocumentResponse({ "content-type": "application/zip" }, "PK")).toBe(true);
    expect(isDocumentResponse({ "Content-Disposition": 'attachment; filename="q3.csv"' }, "a,b\n1,2")).toBe(true);
    expect(isDocumentResponse({ "content-type": "text/html; charset=utf-8" }, SPA_SHELL)).toBe(false);
  });
});
