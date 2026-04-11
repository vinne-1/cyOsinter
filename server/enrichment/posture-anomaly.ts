/**
 * Posture Anomaly Detection & Forecasting
 *
 * Uses rolling z-score over posture_snapshots to flag statistical regressions.
 * Simple linear regression for short-term forecasting.
 */
import { createLogger } from "../logger";
import { storage } from "../storage";
import type { PostureSnapshot } from "@shared/schema";

const log = createLogger("enrichment:posture-anomaly");

const MIN_SNAPSHOTS = 7;
const WINDOW = 14; // rolling window for baseline
const REGRESSION_SIGMA = 2.0;
const CRITICAL_SIGMA = 3.0;

type Metric = "securityScore" | "criticalCount" | "openPortsCount" | "wafCoverage";

const METRICS: Metric[] = ["securityScore", "criticalCount", "openPortsCount", "wafCoverage"];

// For these metrics, an increase is a regression (bad)
const HIGHER_IS_WORSE: Set<Metric> = new Set<Metric>(["criticalCount", "openPortsCount"]);

/** Compute mean and standard deviation of a number array. */
export function computeStats(values: number[]): { mean: number; std: number } {
  if (values.length === 0) return { mean: 0, std: 0 };
  const mean = values.reduce((s, v) => s + v, 0) / values.length;
  const variance = values.reduce((s, v) => s + (v - mean) ** 2, 0) / values.length;
  return { mean, std: Math.sqrt(variance) };
}

/** Linear regression over (x = index, y = value). Returns { slope, intercept }. */
export function linearRegression(values: number[]): { slope: number; intercept: number } {
  const n = values.length;
  if (n < 2) return { slope: 0, intercept: values[0] ?? 0 };
  const xs = values.map((_, i) => i);
  const meanX = (n - 1) / 2;
  const meanY = values.reduce((s, v) => s + v, 0) / n;
  const ssxy = xs.reduce((s, x, i) => s + (x - meanX) * (values[i] - meanY), 0);
  const ssxx = xs.reduce((s, x) => s + (x - meanX) ** 2, 0);
  const slope = ssxx === 0 ? 0 : ssxy / ssxx;
  const intercept = meanY - slope * meanX;
  return { slope, intercept };
}

/** Forecast metric value N steps ahead. */
export function forecastValue(values: number[], stepsAhead: number): number {
  const { slope, intercept } = linearRegression(values);
  return intercept + slope * (values.length - 1 + stepsAhead);
}

/** Detect anomalies in posture snapshots and persist them. */
export async function detectPostureAnomalies(workspaceId: string): Promise<void> {
  try {
    const snapshots = await storage.getPostureHistory(workspaceId, 30);

    if (snapshots.length < MIN_SNAPSHOTS) {
      log.info({ workspaceId, snapshots: snapshots.length }, "Not enough snapshots for anomaly detection");
      return;
    }

    // Most recent snapshot is snapshots[0] (storage returns desc order)
    const sorted = [...snapshots].reverse(); // oldest first
    const current = sorted[sorted.length - 1];

    for (const metric of METRICS) {
      const allValues = sorted
        .map((s) => s[metric] as number | null)
        .filter((v): v is number => v != null);

      if (allValues.length < MIN_SNAPSHOTS) continue;

      const baselineValues = allValues.slice(-WINDOW - 1, -1); // exclude current
      if (baselineValues.length < MIN_SNAPSHOTS) continue;

      const { mean, std } = computeStats(baselineValues);
      const currentValue = current[metric] as number | null;
      if (currentValue == null) continue;

      if (std < 0.01) continue; // no variance → skip

      const z = (currentValue - mean) / std;
      const absZ = Math.abs(z);

      if (absZ < REGRESSION_SIGMA) continue; // within normal range

      const higherIsBad = HIGHER_IS_WORSE.has(metric);
      const isRegression = higherIsBad ? z > 0 : z < 0;
      const direction: "regression" | "improvement" = isRegression ? "regression" : "improvement";

      // Only alert on regressions
      if (direction === "improvement") continue;

      const severity = absZ >= CRITICAL_SIGMA ? "critical" : "warning";

      await storage.createPostureAnomaly({
        workspaceId,
        metric,
        baselineValue: String(Math.round(mean * 100) / 100),
        currentValue: String(currentValue),
        deviationSigma: String(Math.round(absZ * 1000) / 1000),
        direction,
        severity,
        acknowledged: false,
      });

      // Also fire an alert in the existing alerts system
      await storage.createAlert({
        workspaceId,
        scanId: null,
        findingId: null,
        type: "posture_regression",
        title: `Posture Regression: ${metric}`,
        message: `${metric} changed to ${currentValue} (baseline: ${Math.round(mean)}, ${Math.round(absZ * 10) / 10}σ deviation). This may indicate a new vulnerability or misconfiguration.`,
        severity,
        read: false,
        metadata: { metric, currentValue, baseline: mean, sigma: absZ },
      });

      log.warn({ workspaceId, metric, currentValue, mean, z: absZ, severity }, "Posture anomaly detected");
    }
  } catch (err) {
    log.error({ err, workspaceId }, "Posture anomaly detection failed");
  }
}

/** Get forecast data for a given metric over the next N days. */
export function buildForecast(
  snapshots: PostureSnapshot[],
  metric: Metric,
  daysAhead: number,
): Array<{ day: number; value: number }> {
  const sorted = [...snapshots].reverse();
  const values = sorted
    .map((s) => s[metric] as number | null)
    .filter((v): v is number => v != null);

  if (values.length < 2) return [];

  const results: Array<{ day: number; value: number }> = [];
  for (let d = 1; d <= daysAhead; d++) {
    const predicted = forecastValue(values, d);
    results.push({ day: d, value: Math.round(Math.max(0, predicted) * 10) / 10 });
  }
  return results;
}
