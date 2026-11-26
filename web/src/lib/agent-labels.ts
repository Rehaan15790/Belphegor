import { useCallback, useEffect, useState } from "react";

import { api } from "@/lib/api";
import type { Agent } from "@/lib/types";

// The agent's name, or its key when the name is empty or the agent is unknown.
export function agentName(agent: { key: string; name: string } | undefined, key = ""): string {
  return agent?.name || agent?.key || key;
}

// The agent list is used in several places only to map key to name, so it is fetched
// once and shared. A failed fetch is retried on the next call.
let agentListPromise: Promise<Agent[]> | null = null;
function loadAgentList(): Promise<Agent[]> {
  if (!agentListPromise) {
    agentListPromise = api.agents().catch((err) => {
      agentListPromise = null;
      throw err;
    });
  }
  return agentListPromise;
}

// For screens that only have an agent key (approval and intercept records).
export function useAgentNameByKey(): (key: string) => string {
  const [agents, setAgents] = useState<Map<string, Agent>>(() => new Map());
  useEffect(() => {
    let alive = true;
    loadAgentList()
      .then((list) => {
        if (alive) setAgents(new Map(list.map((a) => [a.key, a])));
      })
      .catch(() => {
        // If the list cannot be fetched, show the key as is (retry on the next mount).
      });
    return () => {
      alive = false;
    };
  }, []);
  return useCallback((key: string) => agentName(agents.get(key), key), [agents]);
}
