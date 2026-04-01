import { eq } from "drizzle-orm";
import { db } from "./db";
import { findings, findingGroups } from "@shared/schema";
import type { FindingGroup } from "@shared/schema";
import { createLogger } from "./logger";

const log = createLogger("finding-dedup");

function tokenize(text: string): Set<string> {
  return new Set(
    text
      .toLowerCase()
      .split(/[\s\W]+/)
      .filter((t) => t.length > 0),
  );
}

function jaccardSimilarity(a: Set<string>, b: Set<string>): number {
  if (a.size === 0 && b.size === 0) {
    return 1;
  }

  let intersectionSize = 0;
  for (const item of Array.from(a)) {
    if (b.has(item)) {
      intersectionSize++;
    }
  }

  const unionSize = a.size + b.size - intersectionSize;
  if (unionSize === 0) {
    return 1;
  }

  return intersectionSize / unionSize;
}

function extractDomain(asset: string): string {
  try {
    const url = new URL(asset.startsWith("http") ? asset : `https://${asset}`);
    return url.hostname;
  } catch {
    return asset;
  }
}

interface FindingSimilarityInput {
  title: string;
  category: string;
  affectedAsset: string | null;
  remediation: string | null;
}

export function computeSimilarity(
  a: FindingSimilarityInput,
  b: FindingSimilarityInput,
): number {
  const titleScore = jaccardSimilarity(tokenize(a.title), tokenize(b.title));

  const categoryScore = a.category.toLowerCase() === b.category.toLowerCase() ? 1 : 0;

  const remediationScore =
    a.remediation && b.remediation
      ? jaccardSimilarity(tokenize(a.remediation), tokenize(b.remediation))
      : 0;

  const assetA = a.affectedAsset ? extractDomain(a.affectedAsset) : "";
  const assetB = b.affectedAsset ? extractDomain(b.affectedAsset) : "";
  const assetScore =
    assetA && assetB && assetA === assetB ? 1 : 0;

  return titleScore * 0.4 + categoryScore * 0.3 + remediationScore * 0.2 + assetScore * 0.1;
}

const SIMILARITY_THRESHOLD = 0.7;

export async function groupFindings(workspaceId: string): Promise<number> {
  try {
    const allFindings = await db
      .select()
      .from(findings)
      .where(eq(findings.workspaceId, workspaceId));

    if (allFindings.length === 0) {
      return 0;
    }

    const groups: Array<{
      members: typeof allFindings;
      title: string;
      category: string;
      severity: string;
    }> = [];

    const assigned = new Set<string>();

    for (let i = 0; i < allFindings.length; i++) {
      if (assigned.has(allFindings[i].id)) {
        continue;
      }

      const group = [allFindings[i]];
      assigned.add(allFindings[i].id);

      for (let j = i + 1; j < allFindings.length; j++) {
        if (assigned.has(allFindings[j].id)) {
          continue;
        }

        const similarity = computeSimilarity(allFindings[i], allFindings[j]);
        if (similarity > SIMILARITY_THRESHOLD) {
          group.push(allFindings[j]);
          assigned.add(allFindings[j].id);
        }
      }

      if (group.length > 1) {
        const highestSeverityOrder = ["critical", "high", "medium", "low", "info"];
        const bestSeverity = group.reduce((best, f) => {
          const bestIdx = highestSeverityOrder.indexOf(best);
          const fIdx = highestSeverityOrder.indexOf(f.severity);
          return fIdx < bestIdx ? f.severity : best;
        }, "info");

        groups.push({
          members: group,
          title: allFindings[i].title,
          category: allFindings[i].category,
          severity: bestSeverity,
        });
      }
    }

    // Delete existing groups for workspace before re-creating
    await db
      .delete(findingGroups)
      .where(eq(findingGroups.workspaceId, workspaceId));

    let groupCount = 0;

    for (const group of groups) {
      const memberIds = group.members.map((m) => m.id);

      const [created] = await db
        .insert(findingGroups)
        .values({
          workspaceId,
          title: group.title,
          category: group.category,
          severity: group.severity,
          findingIds: memberIds,
          instanceCount: memberIds.length,
          status: "open",
        })
        .returning();

      // Update each finding with the group ID
      for (const memberId of memberIds) {
        await db
          .update(findings)
          .set({ groupId: created.id })
          .where(eq(findings.id, memberId));
      }

      groupCount++;
    }

    log.info({ workspaceId, groupCount }, "Finding groups created");
    return groupCount;
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : "Unknown error";
    log.error({ workspaceId, error: message }, "Failed to group findings");
    throw new Error(`Finding grouping failed: ${message}`);
  }
}

export async function getFindingGroups(workspaceId: string): Promise<FindingGroup[]> {
  try {
    return await db
      .select()
      .from(findingGroups)
      .where(eq(findingGroups.workspaceId, workspaceId));
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : "Unknown error";
    log.error({ workspaceId, error: message }, "Failed to get finding groups");
    throw new Error(`Failed to get finding groups: ${message}`);
  }
}
