import csv
import networkx as nx
import matplotlib.pyplot as plt
from networkx.drawing.nx_pydot import graphviz_layout

G = nx.DiGraph()

with open("cfg.dat", "r") as f:
    reader = csv.DictReader(f)
    for row in reader:
        G.add_edge(int(row["src"]), int(row["dst"]))

# Hierarchical layout (straight DAG)
pos = graphviz_layout(G, prog="dot")

plt.figure(figsize=(9, 10))
nx.draw(
    G,
    pos,
    with_labels=True,
    node_size=900,
    node_color="lightblue",
    edge_color="gray",
    arrows=True,
    font_size=10,
    connectionstyle="arc3,rad=0.0"
)

plt.tight_layout()
# plt.show()
plt.savefig("graph.png", dpi=300)
