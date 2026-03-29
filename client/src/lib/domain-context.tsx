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

export function DomainProvider({ children }: { children: React.ReactNode }) {
  const [selectedWorkspace, setSelectedWorkspace] = useState<Workspace | null>(null);

  const { data: workspaces = [], isLoading } = useQuery<Workspace[]>({
    queryKey: ["/api/workspaces"],
  });

  const handleSetWorkspace = useCallback((ws: Workspace | null) => {
    setSelectedWorkspace(ws);
  }, []);

  const hasAutoSelected = useRef(false);
  useEffect(() => {
    if (!isLoading && workspaces.length > 0 && !hasAutoSelected.current) {
      hasAutoSelected.current = true;
      setSelectedWorkspace(workspaces[0]);
    }
  }, [isLoading, workspaces]);

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
