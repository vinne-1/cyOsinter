import { createContext, useContext, useState, useCallback, useEffect, useRef } from "react";
import { useQuery } from "@tanstack/react-query";
import type { Workspace } from "@shared/schema";

interface WorkspaceContextType {
  workspaces: Workspace[];
  selectedWorkspace: Workspace | null;
  setSelectedWorkspace: (ws: Workspace | null) => void;
  isLoading: boolean;
}

const WorkspaceContext = createContext<WorkspaceContextType>({
  workspaces: [],
  selectedWorkspace: null,
  setSelectedWorkspace: () => {},
  isLoading: false,
});

/**
 * Where the active workspace id is remembered across reloads. Without this the
 * provider fell back to `workspaces[0]` on every navigation, so an analyst
 * working in one workspace was silently thrown back to another on refresh.
 */
const SELECTED_WORKSPACE_KEY = "selectedWorkspaceId";

function readStoredWorkspaceId(): string | null {
  try {
    return localStorage.getItem(SELECTED_WORKSPACE_KEY);
  } catch {
    // Private mode or blocked storage — fall back to auto-selection.
    return null;
  }
}

export function DomainProvider({ children }: { children: React.ReactNode }) {
  const [selectedWorkspace, setSelectedWorkspace] = useState<Workspace | null>(null);

  const { data: workspaces = [], isLoading } = useQuery<Workspace[]>({
    queryKey: ["/api/workspaces"],
  });

  const handleSetWorkspace = useCallback((ws: Workspace | null) => {
    setSelectedWorkspace(ws);
    try {
      if (ws) localStorage.setItem(SELECTED_WORKSPACE_KEY, ws.id);
      else localStorage.removeItem(SELECTED_WORKSPACE_KEY);
    } catch {
      // Persisting is a convenience; never let it break selection.
    }
  }, []);

  const hasAutoSelected = useRef(false);
  useEffect(() => {
    if (isLoading || workspaces.length === 0 || hasAutoSelected.current) return;
    hasAutoSelected.current = true;

    // Restore the previous selection when it is still a workspace the user can
    // see; otherwise fall back to the first one.
    const storedId = readStoredWorkspaceId();
    const restored = storedId ? workspaces.find((w) => w.id === storedId) : undefined;
    handleSetWorkspace(restored ?? workspaces[0]!);
  }, [isLoading, workspaces, handleSetWorkspace]);

  return (
    <WorkspaceContext.Provider value={{ workspaces, selectedWorkspace, setSelectedWorkspace: handleSetWorkspace, isLoading }}>
      {children}
    </WorkspaceContext.Provider>
  );
}

export function useWorkspace() {
  return useContext(WorkspaceContext);
}

export function useDomain() {
  const { workspaces, selectedWorkspace, setSelectedWorkspace, isLoading } = useWorkspace();
  return {
    domains: workspaces.map(w => w.name),
    selectedDomain: selectedWorkspace?.name || null,
    selectedWorkspaceId: selectedWorkspace?.id || null,
    selectedWorkspace,
    workspaces,
    setSelectedDomain: (name: string | null) => {
      const ws = workspaces.find(w => w.name === name) || null;
      setSelectedWorkspace(ws);
    },
    setSelectedWorkspace,
    isLoading,
  };
}
