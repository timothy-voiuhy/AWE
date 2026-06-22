from dataclasses import dataclass, field


@dataclass
class GraphNode:
    id:    str
    kind:  str
    label: str
    data:  dict  = field(default_factory=dict)
    x:     float = 0.0
    y:     float = 0.0


@dataclass
class GraphEdge:
    source_id: str
    target_id: str
    kind:      str
    label:     str = ""


@dataclass
class GraphData:
    nodes: list[GraphNode] = field(default_factory=list)
    edges: list[GraphEdge] = field(default_factory=list)

    def node_map(self) -> dict[str, GraphNode]:
        return {n.id: n for n in self.nodes}
