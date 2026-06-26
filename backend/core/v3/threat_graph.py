"""
AI Threat Graph (V3.0)
========================
Builds a directed graph of threat actors, techniques, infrastructure,
and affected entities from forensic evidence.

Nodes: process | file | ip | domain | user | host | technique | artifact
Edges: spawned | connected_to | accessed | used_by | lateral_moved_to | exfiltrated_to

Exports to:
  - JSON (for API consumption)
  - DOT format (Graphviz visualization)
  - STIX 2.1 bundle (threat intel sharing)

Usage:
    from core.v3.threat_graph import ThreatGraph

    graph = ThreatGraph(case_id="CASE-001")
    graph.ingest_processes(processes)
    graph.ingest_connections(connections)
    graph.ingest_dfir_report(dfir_report)
    graph.ingest_ioc_report(ioc_report)
    graph.analyze()

    print(graph.summary())
    graph.export_json(Path("evidence/threat_graph.json"))
"""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from loguru import logger


# ── Node / Edge types ─────────────────────────────────────────────────────────

NODE_TYPES = {
    "process", "file", "ip", "domain", "url",
    "user", "host", "technique", "artifact", "service",
}

EDGE_TYPES = {
    "spawned",           # process -> process
    "connected_to",      # process -> ip/domain
    "accessed",          # process -> file
    "used_by",           # technique -> process/artifact
    "lateral_moved_to",  # host -> host
    "exfiltrated_to",    # host -> ip/domain
    "dropped",           # process -> file (malware dropped)
    "injected_into",     # process -> process (injection)
    "authenticated_to",  # user -> host
    "impersonated",      # technique -> user
}


@dataclass
class GraphNode:
    node_id: str
    node_type: str       # process | ip | domain | file | user | host | technique | artifact
    label: str
    properties: dict = field(default_factory=dict)
    risk_score: float = 0.0
    mitre_technique: str = ""
    first_seen: str = ""
    last_seen: str = ""
    is_ioc: bool = False
    is_suspicious: bool = False


@dataclass
class GraphEdge:
    edge_id: str
    source_id: str
    target_id: str
    edge_type: str
    label: str = ""
    properties: dict = field(default_factory=dict)
    timestamp: str = ""
    confidence: float = 0.8


@dataclass
class ThreatGraphSummary:
    total_nodes: int
    total_edges: int
    critical_nodes: list[str]      # node labels with high risk
    attack_paths: list[list[str]]  # detected multi-hop attack paths
    mitre_coverage: list[str]      # unique MITRE techniques observed
    ioc_nodes: list[str]
    generated_at: str


class ThreatGraph:
    """
    Directed threat graph built from forensic evidence.
    Integrates process trees, network connections, IOCs, DFIR findings,
    and timeline events into a unified threat model.
    """

    def __init__(self, case_id: str) -> None:
        self.case_id = case_id
        self._nodes: dict[str, GraphNode] = {}
        self._edges: dict[str, GraphEdge] = {}
        self._node_index: dict[str, str] = {}  # label_lower -> node_id

    # ── Node/edge helpers ─────────────────────────────────────────────────────

    def _get_or_create_node(
        self,
        node_type: str,
        label: str,
        properties: dict | None = None,
        risk_score: float = 0.0,
        mitre: str = "",
        is_ioc: bool = False,
        is_suspicious: bool = False,
    ) -> GraphNode:
        key = f"{node_type}:{label.lower()}"
        if key in self._node_index:
            node = self._nodes[self._node_index[key]]
            # Update if new info
            if risk_score > node.risk_score:
                node.risk_score = risk_score
            if is_ioc:
                node.is_ioc = True
            if is_suspicious:
                node.is_suspicious = True
            if properties:
                node.properties.update(properties)
            return node

        node_id = str(uuid.uuid4())[:8]
        now = datetime.now(timezone.utc).isoformat()
        node = GraphNode(
            node_id=node_id,
            node_type=node_type,
            label=label,
            properties=properties or {},
            risk_score=risk_score,
            mitre_technique=mitre,
            first_seen=now,
            last_seen=now,
            is_ioc=is_ioc,
            is_suspicious=is_suspicious,
        )
        self._nodes[node_id] = node
        self._node_index[key] = node_id
        return node

    def _add_edge(
        self,
        source: GraphNode,
        target: GraphNode,
        edge_type: str,
        label: str = "",
        properties: dict | None = None,
        confidence: float = 0.8,
    ) -> GraphEdge:
        # Deduplicate edges by source+target+type
        dedup_key = f"{source.node_id}-{edge_type}-{target.node_id}"
        if dedup_key in self._edges:
            return self._edges[dedup_key]

        edge = GraphEdge(
            edge_id=str(uuid.uuid4())[:8],
            source_id=source.node_id,
            target_id=target.node_id,
            edge_type=edge_type,
            label=label or edge_type,
            properties=properties or {},
            timestamp=datetime.now(timezone.utc).isoformat(),
            confidence=confidence,
        )
        self._edges[dedup_key] = edge
        return edge

    # ── Ingestion ─────────────────────────────────────────────────────────────

    def ingest_processes(self, processes: list[dict]) -> None:
        """Build process nodes and parent-child spawn edges."""
        pid_to_node: dict[int, GraphNode] = {}

        for proc in processes:
            name = proc.get("ImageFileName") or proc.get("Name") or "unknown"
            pid = int(proc.get("PID") or proc.get("pid") or 0)
            ppid = int(proc.get("PPID") or proc.get("ppid") or 0)
            is_sus = bool(proc.get("_suspicious") or proc.get("is_suspicious"))
            reasons = proc.get("_suspicious_reasons") or []

            node = self._get_or_create_node(
                "process", f"{name}:{pid}",
                properties={"pid": pid, "ppid": ppid, "cmdline": proc.get("CommandLine", "")},
                risk_score=7.0 if is_sus else 2.0,
                is_suspicious=is_sus,
            )
            pid_to_node[pid] = node

        # Build spawn edges
        for proc in processes:
            pid = int(proc.get("PID") or proc.get("pid") or 0)
            ppid = int(proc.get("PPID") or proc.get("ppid") or 0)
            if pid in pid_to_node and ppid in pid_to_node:
                self._add_edge(
                    pid_to_node[ppid], pid_to_node[pid],
                    "spawned", confidence=0.95,
                )

        logger.debug("Threat graph: ingested {} process(es)", len(processes))

    def ingest_connections(self, connections: list[dict]) -> None:
        """Build network connection edges between processes and remote endpoints."""
        for conn in connections:
            remote_addr = conn.get("ForeignAddr") or conn.get("remote_addr") or ""
            remote_port = conn.get("ForeignPort") or conn.get("remote_port") or 0
            proc_name = conn.get("Owner") or conn.get("process_name") or "unknown"
            pid = int(conn.get("PID") or conn.get("OwningProcess") or conn.get("pid") or 0)

            if not remote_addr or remote_addr in ("0.0.0.0", "::", "127.0.0.1"):
                continue

            proc_node = self._get_or_create_node(
                "process", f"{proc_name}:{pid}",
                properties={"pid": pid},
            )
            remote_node = self._get_or_create_node(
                "ip", remote_addr,
                properties={"port": remote_port},
            )
            self._add_edge(
                proc_node, remote_node,
                "connected_to",
                label=f":{remote_port}",
                properties={"port": remote_port, "state": conn.get("State", "")},
            )

    def ingest_dfir_report(self, report: Any) -> None:
        """Ingest findings from a DFIRReport (V2.3)."""
        try:
            for finding in report.findings:
                if finding.severity in ("critical", "high"):
                    # Create a technique node
                    if finding.mitre_technique:
                        tech_node = self._get_or_create_node(
                            "technique", finding.mitre_technique,
                            properties={"tactic": finding.mitre_tactic, "title": finding.title},
                            risk_score=finding.score,
                            mitre=finding.mitre_technique,
                        )
                    # Create entity nodes for affected entities
                    for entity in finding.affected_entities[:3]:
                        if not entity or len(entity) < 2:
                            continue
                        ntype = "ip" if _looks_like_ip(entity) else "process"
                        ent_node = self._get_or_create_node(
                            ntype, entity,
                            risk_score=finding.score,
                            is_suspicious=True,
                        )
                        if finding.mitre_technique:
                            self._add_edge(
                                tech_node, ent_node, "used_by",
                                confidence=finding.confidence,
                            )
        except Exception as exc:
            logger.debug("DFIR report ingestion error: {}", exc)

    def ingest_ioc_report(self, ioc_report: Any) -> None:
        """Ingest IOC matches from an IOCReport."""
        try:
            for ioc in ioc_report.all_iocs:
                ntype = {
                    "domain": "domain", "ip": "ip", "ipv4": "ip",
                    "url": "url", "hash": "file", "md5": "file", "sha256": "file",
                }.get(ioc.ioc_type, "artifact")

                self._get_or_create_node(
                    ntype, ioc.ioc_value,
                    properties={"priority": ioc.priority, "occurrences": ioc.occurrences},
                    risk_score=ioc.score,
                    mitre=ioc.mitre_technique,
                    is_ioc=True,
                    is_suspicious=ioc.score >= 7.0,
                )
        except Exception as exc:
            logger.debug("IOC report ingestion error: {}", exc)

    def ingest_timeline(self, timeline_events: list[dict]) -> None:
        """Ingest timeline events — adds temporal context to nodes."""
        for event in timeline_events:
            if not event.get("is_suspicious"):
                continue
            proc = event.get("process_name") or event.get("process") or ""
            pid = int(event.get("pid") or 0)
            ts = event.get("timestamp") or ""
            etype = event.get("event_type") or ""

            if proc:
                key = f"process:{proc}:{pid}".lower()
                if key in self._node_index:
                    node = self._nodes[self._node_index[key]]
                    if not node.first_seen or ts < node.first_seen:
                        node.first_seen = ts
                    if not node.last_seen or ts > node.last_seen:
                        node.last_seen = ts

    # ── Analysis ──────────────────────────────────────────────────────────────

    def analyze(self) -> ThreatGraphSummary:
        """
        Analyze the graph for attack paths and threat patterns.
        Returns a summary with critical nodes and multi-hop attack paths.
        """
        critical = [
            n.label for n in self._nodes.values()
            if n.risk_score >= 8.0 or n.is_ioc
        ]

        mitre_coverage = list({
            n.mitre_technique for n in self._nodes.values()
            if n.mitre_technique
        })

        ioc_nodes = [n.label for n in self._nodes.values() if n.is_ioc]

        # Simple attack path detection: find chains of suspicious nodes
        attack_paths = self._find_attack_paths()

        return ThreatGraphSummary(
            total_nodes=len(self._nodes),
            total_edges=len(self._edges),
            critical_nodes=critical[:20],
            attack_paths=attack_paths[:5],
            mitre_coverage=sorted(mitre_coverage),
            ioc_nodes=ioc_nodes[:20],
            generated_at=datetime.now(timezone.utc).isoformat(),
        )

    def _find_attack_paths(self) -> list[list[str]]:
        """Find multi-hop paths through suspicious nodes using DFS."""
        paths: list[list[str]] = []
        sus_nodes = {n.node_id for n in self._nodes.values() if n.is_suspicious or n.risk_score >= 7.0}

        # Build adjacency for suspicious nodes
        adj: dict[str, list[str]] = {nid: [] for nid in sus_nodes}
        for edge in self._edges.values():
            if edge.source_id in sus_nodes and edge.target_id in sus_nodes:
                adj[edge.source_id].append(edge.target_id)

        # DFS from each suspicious node, find paths of length >= 2
        def dfs(node_id: str, path: list[str], visited: set[str]) -> None:
            if len(path) >= 2:
                paths.append([self._nodes[n].label for n in path])
            if len(path) >= 5:
                return
            for neighbor in adj.get(node_id, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    dfs(neighbor, path + [neighbor], visited)

        for start in list(sus_nodes)[:20]:  # Limit to 20 starting nodes
            dfs(start, [start], {start})

        return paths[:5]

    # ── Export ────────────────────────────────────────────────────────────────

    def export_json(self, output_path: Path) -> Path:
        """Export graph as JSON (API-ready format)."""
        summary = self.analyze()
        data = {
            "case_id": self.case_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": asdict(summary),
            "nodes": [asdict(n) for n in self._nodes.values()],
            "edges": [asdict(e) for e in self._edges.values()],
        }
        output_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        logger.info("Threat graph exported: {} nodes, {} edges", len(self._nodes), len(self._edges))
        return output_path

    def export_dot(self, output_path: Path) -> Path:
        """Export as Graphviz DOT format for visualization."""
        lines = [f'digraph "ThreatGraph_{self.case_id}" {{']
        lines.append('  rankdir=LR;')
        lines.append('  node [style=filled, fontname="Helvetica"];')

        colors = {
            "process": "lightblue", "ip": "orange", "domain": "yellow",
            "file": "lightgreen", "technique": "red", "user": "plum",
            "host": "lightgray", "artifact": "wheat", "url": "lightyellow",
        }

        for node in self._nodes.values():
            color = colors.get(node.node_type, "white")
            if node.is_ioc:
                color = "tomato"
            elif node.risk_score >= 8:
                color = "red"
            label = node.label[:40].replace('"', "'")
            lines.append(
                f'  "{node.node_id}" [label="{label}", fillcolor="{color}", '
                f'shape={"diamond" if node.node_type == "technique" else "ellipse"}];'
            )

        for edge in self._edges.values():
            lines.append(
                f'  "{edge.source_id}" -> "{edge.target_id}" [label="{edge.edge_type}"];'
            )

        lines.append("}")
        output_path.write_text("\n".join(lines), encoding="utf-8")
        return output_path

    def export_stix(self, output_path: Path) -> Path:
        """
        Export as a minimal STIX 2.1 bundle for threat intel sharing.
        Converts IOC nodes to STIX Indicators and relationships.
        """
        bundle_id = f"bundle--{uuid.uuid4()}"
        objects: list[dict] = []

        for node in self._nodes.values():
            if not node.is_ioc:
                continue
            stix_type_map = {
                "ip": "ipv4-addr", "domain": "domain-name",
                "url": "url", "file": "file",
            }
            stix_type = stix_type_map.get(node.node_type)
            if not stix_type:
                continue

            indicator = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "created": datetime.now(timezone.utc).isoformat(),
                "modified": datetime.now(timezone.utc).isoformat(),
                "name": node.label,
                "pattern": f"[{stix_type}:value = '{node.label}']",
                "pattern_type": "stix",
                "valid_from": node.first_seen or datetime.now(timezone.utc).isoformat(),
                "labels": ["malicious-activity"],
                "confidence": int(node.risk_score * 10),
            }
            if node.mitre_technique:
                indicator["external_references"] = [{
                    "source_name": "mitre-attack",
                    "external_id": node.mitre_technique,
                    "url": f"https://attack.mitre.org/techniques/{node.mitre_technique.replace('.', '/')}",
                }]
            objects.append(indicator)

        bundle = {
            "type": "bundle",
            "id": bundle_id,
            "spec_version": "2.1",
            "objects": objects,
        }
        output_path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
        logger.info("STIX bundle exported: {} indicators", len(objects))
        return output_path

    def summary(self) -> str:
        s = self.analyze()
        return (
            f"Threat Graph — {self.case_id}\n"
            f"  Nodes: {s.total_nodes}  Edges: {s.total_edges}\n"
            f"  Critical nodes: {len(s.critical_nodes)}\n"
            f"  IOC nodes: {len(s.ioc_nodes)}\n"
            f"  MITRE techniques: {', '.join(s.mitre_coverage[:8])}\n"
            f"  Attack paths: {len(s.attack_paths)}"
        )


def _looks_like_ip(value: str) -> bool:
    import re
    return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value))
