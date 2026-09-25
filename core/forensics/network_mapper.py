"""
Network graph visualizer for URL redirect chains.
Returns matplotlib Figure. Caller is responsible for saving or displaying.
"""

import networkx as nx
from matplotlib.figure import Figure
from utils.logger import get_logger

logger = get_logger(__name__)


def _truncate(label: str, length: int = 40) -> str:
    """Helper to truncate long URLs/IPs for visual readability."""
    if not label:
        return ""
    label_str = str(label)
    if len(label_str) > length:
        return label_str[:length - 3] + "..."
    return label_str


def build_network_graph(url_trail: dict) -> Figure:
    """
    Constructs a directed graph representing the redirect chain.
    """
    # Create the figure directly to avoid matplotlib pyplot state machine side-effects
    fig = Figure(figsize=(10, 6), facecolor="white")
    ax = fig.add_subplot(111)
    
    try:
        hops = url_trail.get("hops", [])
        final_ip = url_trail.get("final_ip", "")
        
        # Build the exact ordered sequence of nodes
        sequence = list(hops)
        if final_ip:
            sequence.append(final_ip)
            
        # Handle the empty case immediately
        if not sequence:
            ax.text(0.5, 0.5, "No URL trail available", ha="center", va="center", fontsize=14)
            ax.axis("off")
            return fig
            
        G = nx.DiGraph()
        node_colors = []
        labels = {}
        
        for i, node_val in enumerate(sequence):
            G.add_node(i)
            labels[i] = _truncate(node_val)
            
            # Connect to the previous node
            if i > 0:
                G.add_edge(i - 1, i)
                
            # Assign colors based on node position and type
            if i == 0:
                node_colors.append("blue")
            elif i == len(sequence) - 1 and final_ip and str(node_val) == str(final_ip):
                node_colors.append("red")
            else:
                node_colors.append("grey")
                
        # Layout the nodes (spring_layout works reasonably well for chains)
        pos = nx.spring_layout(G, seed=42)
        
        # Draw the graph onto our specific axes
        nx.draw_networkx(
            G, 
            pos=pos, 
            ax=ax,
            labels=labels,
            node_color=node_colors,
            node_size=2500,
            font_size=9,
            font_color="black",
            edge_color="black",
            arrows=True,
            arrowsize=20
        )
        
        # Remove borders and axes ticks for clean visualization
        ax.axis("off")
        
    except Exception as e:
        logger.error(f"Error building network graph: {e}")
        ax.clear()
        ax.text(0.5, 0.5, f"Graph generation failed.", ha="center", va="center", color="red", fontsize=12)
        ax.axis("off")
        
    return fig
