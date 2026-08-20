"""Matplotlib service chart and Obsidian canvas topology."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from va_workspace.models import EngagementState


def write_service_chart(state: EngagementState) -> Path | None:
    names: list[str] = []
    for host in state.hosts:
        names.extend(host.service_names)
    if not names:
        return None
    counts = Counter(names).most_common(15)
    labels = [item[0] for item in counts]
    values = [item[1] for item in counts]

    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    dest = state.path / "01-overview" / "attachments" / "services-bar.png"
    dest.parent.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(10, 4.5))
    ax.bar(labels, values, color="#4c6ef5")
    ax.set_ylabel("Hosts")
    ax.set_title("Top discovered services")
    plt.xticks(rotation=35, ha="right")
    fig.tight_layout()
    fig.savefig(dest, dpi=120)
    plt.close(fig)
    return dest


def write_canvas(state: EngagementState) -> Path:
    nodes: list[dict[str, object]] = [
        {
            "id": "network",
            "type": "text",
            "text": state.client or "Network",
            "x": 0,
            "y": 0,
            "width": 280,
            "height": 80,
        }
    ]
    edges: list[dict[str, object]] = []
    columns = max(1, int(len(state.hosts) ** 0.5) + 1)
    for index, host in enumerate(state.hosts):
        node_id = f"host-{host.slug}"
        col = index % columns
        row = index // columns
        nodes.append(
            {
                "id": node_id,
                "type": "file",
                "file": f"02-hosts/{host.slug}/host.md",
                "x": 380 + col * 320,
                "y": (row - columns // 2) * 140,
                "width": 300,
                "height": 90,
            }
        )
        edges.append(
            {
                "id": f"edge-{host.slug}",
                "fromNode": "network",
                "toNode": node_id,
                "label": ", ".join(host.service_names[:4]),
            }
        )
    dest = state.path / "01-overview" / "network.canvas"
    dest.write_text(json.dumps({"nodes": nodes, "edges": edges}, indent=2) + "\n", encoding="utf-8")
    return dest
