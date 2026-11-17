import type {
  AnomalyEntityResult,
  DetectionRuleHit,
  GraphEdge,
  GraphNode,
  Incident,
  RelationshipGraph,
  SecurityLogEvent,
  SeverityLevel,
} from '../../shared/types';

export interface CorrelatedCluster {
  clusterId: string;
  primaryIp: string;
  affectedUsers: string[];
  affectedHosts: string[];
  events: SecurityLogEvent[];
  ruleHits: DetectionRuleHit[];
  anomalyResults: AnomalyEntityResult[];
}

const SEVERITY_RANK: Record<SeverityLevel, number> = {
  Critical: 4,
  High: 3,
  Medium: 2,
  Low: 1,
  Info: 0,
};

export function correlateEvents(
  events: SecurityLogEvent[],
  ruleHits: DetectionRuleHit[],
  anomalies: AnomalyEntityResult[],
): CorrelatedCluster[] {
  const eventMap = new Map<string, SecurityLogEvent>();
  for (const ev of events) {
    eventMap.set(ev.id, ev);
  }

  // Collect all event IDs implicated by rule hits
  const hitByEventId = new Map<string, DetectionRuleHit[]>();
  const suspiciousEventIds = new Set<string>();

  for (const hit of ruleHits) {
    for (const evId of hit.matchedEventIds) {
      suspiciousEventIds.add(evId);
      if (!hitByEventId.has(evId)) hitByEventId.set(evId, []);
      hitByEventId.get(evId)!.push(hit);
    }
  }

  // Also include follow-on events from same primary IP within 45 min of any hit
  for (const hit of ruleHits) {
    const firstMs = Date.parse(hit.firstSeen) - 5 * 60_000;
    const lastMs = Date.parse(hit.lastSeen) + 45 * 60_000;
    for (const ev of events) {
      if (
        (ev.sourceIp === hit.primaryIp || hit.affectedUsers.includes(ev.username)) &&
        ev.epochMs >= firstMs &&
        ev.epochMs <= lastMs &&
        (ev.eventType === 'privilege_escalation' ||
          ev.eventType === 'data_export' ||
          ev.eventType === 'firewall_block' ||
          ev.eventType === 'api_access' ||
          ev.eventType === 'login_success' ||
          ev.eventType === 'login_failed')
      ) {
        // Avoid pulling unrelated normal corporate users' daytime traffic into spray hits
        if (hit.ruleId === 'R-003' && ev.sourceIp !== hit.primaryIp && ev.eventType !== 'login_success') {
          continue;
        }
        if (hit.ruleId === 'R-003' && ev.sourceIp !== hit.primaryIp) {
          continue;
        }
        suspiciousEventIds.add(ev.id);
      }
    }
  }

  // Build adjacency graph among suspicious events sharing IP or (same user + temporal proximity <= 45 min)
  const suspEvents = Array.from(suspiciousEventIds)
    .map((id) => eventMap.get(id))
    .filter((e): e is SecurityLogEvent => Boolean(e))
    .sort((a, b) => a.epochMs - b.epochMs);

  const adj = new Map<string, Set<string>>();
  for (const ev of suspEvents) {
    adj.set(ev.id, new Set());
  }

  for (let i = 0; i < suspEvents.length; i++) {
    for (let j = i + 1; j < suspEvents.length; j++) {
      const a = suspEvents[i];
      const b = suspEvents[j];
      const timeDiffMin = Math.abs(b.epochMs - a.epochMs) / 60_000;
      const sameIp = a.sourceIp === b.sourceIp && timeDiffMin <= 90;
      const sameUserClose = a.username === b.username && timeDiffMin <= 45;
      const sharedRule =
        (hitByEventId.get(a.id) ?? []).some((ha) =>
          (hitByEventId.get(b.id) ?? []).some((hb) => ha.id === hb.id),
        );

      if (sameIp || sameUserClose || sharedRule) {
        adj.get(a.id)!.add(b.id);
        adj.get(b.id)!.add(a.id);
      }
    }
  }

  // Connected Components via BFS
  const visited = new Set<string>();
  const clusters: CorrelatedCluster[] = [];
  let clusterIdx = 1;

  for (const ev of suspEvents) {
    if (visited.has(ev.id)) continue;
    const queue = [ev.id];
    visited.add(ev.id);
    const componentEvents: SecurityLogEvent[] = [];

    while (queue.length > 0) {
      const currId = queue.shift()!;
      const currEv = eventMap.get(currId);
      if (currEv) componentEvents.push(currEv);

      for (const neighbor of adj.get(currId) ?? []) {
        if (!visited.has(neighbor)) {
          visited.add(neighbor);
          queue.push(neighbor);
        }
      }
    }

    componentEvents.sort((a, b) => a.epochMs - b.epochMs);
    const clusterHitSet = new Map<string, DetectionRuleHit>();
    for (const ce of componentEvents) {
      for (const h of hitByEventId.get(ce.id) ?? []) {
        clusterHitSet.set(h.id, h);
      }
    }
    const clusterHits = Array.from(clusterHitSet.values());
    if (clusterHits.length === 0) continue;

    // Determine primary suspicious IP (highest reputation or highest event count among hits)
    const ipScore = new Map<string, number>();
    for (const ce of componentEvents) {
      const prev = ipScore.get(ce.sourceIp) ?? 0;
      ipScore.set(ce.sourceIp, prev + ce.ipReputationScore + 10);
    }
    const primaryIp =
      Array.from(ipScore.entries()).sort((a, b) => b[1] - a[1])[0]?.[0] ??
      componentEvents[0].sourceIp;

    const affectedUsers = Array.from(new Set(componentEvents.map((e) => e.username)));
    const affectedHosts = Array.from(new Set(componentEvents.map((e) => e.targetHost)));

    const relevantAnomalies = anomalies.filter(
      (a) =>
        (a.entityType === 'ip' && ipScore.has(a.label)) ||
        (a.entityType === 'user' && affectedUsers.includes(a.label)),
    );

    clusters.push({
      clusterId: `INC-${String(clusterIdx++).padStart(4, '0')}`,
      primaryIp,
      affectedUsers,
      affectedHosts,
      events: componentEvents,
      ruleHits: clusterHits,
      anomalyResults: relevantAnomalies,
    });
  }

  return clusters;
}

export function buildRelationshipGraph(
  events: SecurityLogEvent[],
  incidents: Incident[],
): RelationshipGraph {
  const nodeMap = new Map<string, GraphNode>();
  const edgeMap = new Map<string, GraphEdge>();

  const ensureNode = (node: Omit<GraphNode, 'degree'>) => {
    if (!nodeMap.has(node.id)) {
      nodeMap.set(node.id, { ...node, degree: 0 });
    } else {
      const existing = nodeMap.get(node.id)!;
      if (node.riskScore > existing.riskScore) {
        existing.riskScore = node.riskScore;
      }
      if (SEVERITY_RANK[node.severity] > SEVERITY_RANK[existing.severity]) {
        existing.severity = node.severity;
      }
    }
  };

  const addEdge = (source: string, target: string, relation: string, isSuspicious: boolean) => {
    const id = `${source}->${target}:${relation}`;
    if (!edgeMap.has(id)) {
      edgeMap.set(id, { id, source, target, relation, weight: 1, isSuspicious });
    } else {
      const e = edgeMap.get(id)!;
      e.weight += 1;
      if (isSuspicious) e.isSuspicious = true;
    }
  };

  const suspiciousEventIds = new Set<string>();
  for (const inc of incidents) {
    ensureNode({
      id: `inc:${inc.id}`,
      type: 'incident',
      label: inc.id,
      sublabel: inc.title,
      riskScore: inc.riskScore,
      severity: inc.severity,
      metadata: {
        status: inc.status,
        events: inc.eventIds.length,
        rules: inc.ruleHits.length,
      },
    });
    for (const evId of inc.eventIds) {
      suspiciousEventIds.add(evId);
    }
  }

  // Add entities from incidents and representative baseline traffic
  const incidentByEvent = new Map<string, Incident>();
  for (const inc of incidents) {
    for (const evId of inc.eventIds) {
      incidentByEvent.set(evId, inc);
    }
  }

  for (const ev of events) {
    const linkedInc = incidentByEvent.get(ev.id);
    const isSusp = suspiciousEventIds.has(ev.id);
    const sev: SeverityLevel = linkedInc ? linkedInc.severity : ev.baseSeverity;
    const risk = linkedInc ? linkedInc.riskScore : ev.ipReputationScore;

    const ipId = `ip:${ev.sourceIp}`;
    const userId = `user:${ev.username}`;
    const hostId = `host:${ev.targetHost}`;

    ensureNode({
      id: ipId,
      type: 'ip',
      label: ev.sourceIp,
      sublabel: `${ev.city}, ${ev.country}`,
      riskScore: Math.max(ev.ipReputationScore, isSusp ? risk : 0),
      severity: isSusp ? sev : ev.ipReputationScore >= 70 ? 'Medium' : 'Info',
      metadata: {
        asn: ev.asn,
        reputation: ev.ipReputationScore,
        country: ev.country,
      },
    });

    ensureNode({
      id: userId,
      type: 'user',
      label: ev.username,
      sublabel: isSusp ? 'Impacted Account' : 'Verified Identity',
      riskScore: isSusp ? risk : 12,
      severity: isSusp ? sev : 'Info',
      metadata: {
        account: ev.username,
      },
    });

    ensureNode({
      id: hostId,
      type: 'host',
      label: ev.targetHost,
      sublabel: 'Target Asset',
      riskScore: isSusp ? Math.round(risk * 0.85) : 10,
      severity: isSusp ? sev : 'Info',
      metadata: {
        host: ev.targetHost,
      },
    });

    addEdge(ipId, userId, ev.eventType, isSusp);
    addEdge(userId, hostId, ev.eventType, isSusp);

    if (linkedInc) {
      const incNodeId = `inc:${linkedInc.id}`;
      addEdge(ipId, incNodeId, 'attributed_source', true);
      addEdge(userId, incNodeId, 'involved_account', true);
      addEdge(hostId, incNodeId, 'targeted_asset', true);

      // Include key milestone events as nodes for deep forensic tracing
      if (
        ev.eventType === 'privilege_escalation' ||
        ev.eventType === 'data_export' ||
        ev.eventType === 'login_success' ||
        ev.eventType === 'firewall_block'
      ) {
        const evtNodeId = `evt:${ev.id}`;
        ensureNode({
          id: evtNodeId,
          type: 'event',
          label: `${ev.id} (${ev.eventType})`,
          sublabel: ev.timestamp.slice(11, 19) + ' UTC',
          riskScore: risk,
          severity: ev.baseSeverity === 'Info' ? 'Medium' : ev.baseSeverity,
          metadata: {
            bytes: ev.bytesTransferred,
            status: ev.statusCode,
          },
        });
        addEdge(ipId, evtNodeId, 'originated', true);
        addEdge(evtNodeId, incNodeId, 'evidence', true);
      }
    }
  }

  // Compute node degrees & connected components count
  const adj = new Map<string, Set<string>>();
  for (const id of nodeMap.keys()) adj.set(id, new Set());
  for (const edge of edgeMap.values()) {
    adj.get(edge.source)?.add(edge.target);
    adj.get(edge.target)?.add(edge.source);
    const sNode = nodeMap.get(edge.source);
    const tNode = nodeMap.get(edge.target);
    if (sNode) sNode.degree += 1;
    if (tNode) tNode.degree += 1;
  }

  let componentCount = 0;
  const visited = new Set<string>();
  for (const id of nodeMap.keys()) {
    if (visited.has(id)) continue;
    componentCount++;
    const q = [id];
    visited.add(id);
    while (q.length > 0) {
      const curr = q.shift()!;
      for (const n of adj.get(curr) ?? []) {
        if (!visited.has(n)) {
          visited.add(n);
          q.push(n);
        }
      }
    }
  }

  const nodes = Array.from(nodeMap.values());
  const pivotNodes = [...nodes]
    .sort((a, b) => b.degree - a.degree)
    .slice(0, 6)
    .map((n) => ({ id: n.id, label: n.label, type: n.type, degree: n.degree }));

  return {
    nodes,
    edges: Array.from(edgeMap.values()),
    componentCount,
    pivotNodes,
  };
}
