import { beforeEach, describe, expect, it, vi } from "vitest";

const { storageMock } = vi.hoisted(() => ({
  storageMock: {
    getWorkspace: vi.fn(),
    getScanProfiles: vi.fn(),
    createScanProfile: vi.fn(),
    updateWorkspace: vi.fn(),
  },
}));

vi.mock("../../../server/storage", () => ({
  storage: storageMock,
}));

vi.mock("../../../server/logger", () => ({
  createLogger: () => ({
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  }),
}));

import { ensurePrebuiltScanProfiles } from "../../../server/scan-profile-defaults";

describe("ensurePrebuiltScanProfiles", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("bootstraps prebuilt profiles once for a workspace that is not bootstrapped", async () => {
    storageMock.getWorkspace.mockResolvedValue({
      id: "ws-1",
      scanProfilesBootstrapped: false,
    });
    storageMock.getScanProfiles.mockResolvedValue([]);
    storageMock.createScanProfile.mockResolvedValue({});
    storageMock.updateWorkspace.mockResolvedValue({});

    await ensurePrebuiltScanProfiles("ws-1");

    expect(storageMock.getScanProfiles).toHaveBeenCalledWith("ws-1");
    expect(storageMock.createScanProfile).toHaveBeenCalledTimes(3);
    expect(storageMock.updateWorkspace).toHaveBeenCalledWith("ws-1", { scanProfilesBootstrapped: true });
  });

  it("does not reseed when workspace is already marked bootstrapped", async () => {
    storageMock.getWorkspace.mockResolvedValue({
      id: "ws-2",
      scanProfilesBootstrapped: true,
    });

    await ensurePrebuiltScanProfiles("ws-2");

    expect(storageMock.getScanProfiles).not.toHaveBeenCalled();
    expect(storageMock.createScanProfile).not.toHaveBeenCalled();
    expect(storageMock.updateWorkspace).not.toHaveBeenCalled();
  });

  it("creates only missing prebuilt profiles before setting the bootstrap marker", async () => {
    storageMock.getWorkspace.mockResolvedValue({
      id: "ws-3",
      scanProfilesBootstrapped: false,
    });
    storageMock.getScanProfiles.mockResolvedValue([
      { id: "p1", workspaceId: "ws-3", name: "Heavy Scan" },
    ]);
    storageMock.createScanProfile.mockResolvedValue({});
    storageMock.updateWorkspace.mockResolvedValue({});

    await ensurePrebuiltScanProfiles("ws-3");

    expect(storageMock.createScanProfile).toHaveBeenCalledTimes(2);
    expect(storageMock.updateWorkspace).toHaveBeenCalledWith("ws-3", { scanProfilesBootstrapped: true });
  });
});
