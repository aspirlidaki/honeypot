"""
Cluster attacker IPs from Cowrie SSH honeypot data to find botnets.

The idea: bots in the same botnet share the same credential list, so IPs
that try the same (username, password) pairs are probably from the same botnet.
Rare shared pairs are much stronger evidence than common ones.

Pipeline:
  1.  Load CSV
  2.  Build pair->IPs and IP->pairs mappings
  3.  Compute IDF per credential pair
  4.  Build TF-IDF vectors; compute pairwise cosine similarity (sparse matrix)
  5.  Run Leiden community detection
  6.  Analyse clusters, visualise, export CSV

Why cosine similarity (V3 vs V2):
  V2 used sum-of-IDF as edge weight, which is biased by credential list size —
  a bot that tried 10k pairs looked similar to everyone just from volume.
  Cosine similarity normalises for this.

Why Leiden (V3 vs V2):
  Louvain can produce internally disconnected communities (proven flaw, 2019).
  Leiden adds a refinement step that guarantees all communities are connected.
"""
import csv                          # reading the input CSV file
import math                         # math.log() for IDF calculation
import collections                  # defaultdict and Counter
from pathlib import Path            # robust file paths regardless of working directory

import numpy as np                  # fast numeric arrays and L2 norm
import scipy.sparse as sp           # sparse matrix: IP × credential (TF-IDF)
import networkx as nx               # graph data structure and layout algorithms
import igraph as ig                 # fast graph backend required by leidenalg
import leidenalg                    # Leiden community detection algorithm
import matplotlib
matplotlib.use('Agg')               # non-interactive backend (saves to file)
import matplotlib.pyplot as plt
import matplotlib.cm as cm

# ---------------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------------

DATA_FILE = Path(__file__).parent / "cowrie_ip_username_pass_anon.csv"

# Minimum cosine similarity to form an edge.
# 0.0 = completely different credential sets, 1.0 = identical sets.
# 0.10 requires at least ~10% normalised credential overlap.
MIN_COSINE_SIM = 0.10

# Leiden resolution parameter: higher = more, smaller communities.
# 1.0 is the standard default (equivalent to plain modularity maximisation).
LEIDEN_RESOLUTION = 1.0

OUTPUT_PLOT = "attacker_graph.png"
OUTPUT_CSV  = "cluster_results.csv"

def load_data(filepath):
    """Load (ip, username, password) triples from the honeypot CSV."""
    records = []
    with open(filepath, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            records.append((
                row["ip"].strip(),
                row["username"].strip(),
                row["password"].strip()
            ))
    print(f"[Step 1] Loaded {len(records):,} rows from '{filepath}'.")
    return records


def build_mappings(records):
    """
    Build pair_to_ips and ip_to_pairs lookup dicts.
    Sets are used so retrying the same credentials doesn't inflate counts —
    we care about the pattern of what was tried, not repetition.
    """
    pair_to_ips = collections.defaultdict(set)
    ip_to_pairs = collections.defaultdict(set)

    for ip, username, password in records:
        pair = (username, password)
        pair_to_ips[pair].add(ip)
        ip_to_pairs[ip].add(pair)

    all_ips = sorted(ip_to_pairs.keys())

    print(f"[Step 2] {len(all_ips):,} unique IPs, "
          f"{len(pair_to_ips):,} unique credential pairs.")
    print(f"         Pairs used by more than one IP: "
          f"{sum(1 for s in pair_to_ips.values() if len(s) > 1):,}")

    return pair_to_ips, ip_to_pairs, all_ips


def compute_idf(pair_to_ips, total_ips):
    """
    IDF(pair) = log(N / df), where df = number of IPs that tried this pair.
    High IDF = rare pair = strong signal. Low IDF = common pair = weak signal.
    e.g. 345gs5662d34/345gs5662d34 (56% of IPs) -> IDF 0.578; perl/warning (7 IPs) -> IDF 6.563.
    """
    idf = {}
    N = total_ips

    for pair, ip_set in pair_to_ips.items():
        df = len(ip_set)            # how many IPs tried this pair
        idf[pair] = math.log(N / df)

    scores = list(idf.values())
    print(f"[Step 3] IDF computed for {len(idf):,} pairs.")
    print(f"         Range: {min(scores):.3f} (most common) "
          f"to {max(scores):.3f} (rarest)")

    return idf


# GRAPH CONSTRUCTION
def build_graph(ip_to_pairs, all_ips, idf):
    """
    Build a weighted graph: nodes = IPs, edge weight = cosine similarity
    of their TF-IDF credential vectors.

    Uses sparse matrix multiplication (M_norm @ M_norm.T) instead of a
    pairwise loop — the canary pair alone (k=2791) would need ~3.9M iterations
    the old way.

    Only edges with similarity >= MIN_COSINE_SIM are kept.
    """
    ip_idx    = {ip:   i for i, ip   in enumerate(all_ips)}
    all_pairs = list(idf.keys())
    pair_idx  = {pair: j for j, pair in enumerate(all_pairs)}

    # sparse IP × credential matrix in COO format
    rows, cols, vals = [], [], []
    for ip, pair_set in ip_to_pairs.items():
        i = ip_idx[ip]
        for pair in pair_set:
            rows.append(i)
            cols.append(pair_idx[pair])
            vals.append(idf[pair])

    M = sp.csr_matrix(
        (vals, (rows, cols)),
        shape=(len(all_ips), len(all_pairs)),
        dtype=np.float32,
    )

    # L2-normalise rows; M_norm @ M_norm.T[i,j] = cosine_sim(i,j)
    norms = np.asarray(M.power(2).sum(axis=1)).flatten() ** 0.5
    norms[norms == 0] = 1.0          # avoid division by zero for isolated IPs
    M_norm = sp.diags(1.0 / norms) @ M

    S = sp.triu(M_norm @ M_norm.T, k=1).tocoo()   # upper triangle, skip diagonal

    G = nx.Graph()
    for ip in all_ips:
        G.add_node(ip)

    for i, j, w in zip(S.row, S.col, S.data):
        if w >= MIN_COSINE_SIM:
            G.add_edge(all_ips[i], all_ips[j], weight=float(w))

    print(f"[Step 4] Graph built: {G.number_of_nodes():,} nodes, "
          f"{G.number_of_edges():,} edges.")
    print(f"         (Cosine similarity threshold: {MIN_COSINE_SIM})")

    return G


# COMMUNITY DETECTION

def detect_communities(G, resolution=1.0):
    """
    Run Leiden community detection on the weighted graph.
    seed=42 for reproducibility.

    Leiden fixes Louvain's main flaw: Louvain's local-move phase can leave
    communities internally disconnected. Leiden's refinement step checks and
    corrects this after each aggregation.
    """
    print(f"[Step 5] Running Leiden community detection "
          f"(resolution={resolution}) ...")

    nodes    = list(G.nodes())
    node_idx = {n: i for i, n in enumerate(nodes)}

    edges   = [(node_idx[u], node_idx[v]) for u, v in G.edges()]
    weights = [float(G[u][v]["weight"])   for u, v in G.edges()]

    ig_G = ig.Graph(n=len(nodes), edges=edges)

    partition = leidenalg.find_partition(
        ig_G,
        leidenalg.RBConfigurationVertexPartition,   # supports resolution param
        weights=weights or None,
        resolution_parameter=resolution,
        seed=42,
    )

    result = {
        nodes[node_i]: comm_id
        for comm_id, members in enumerate(partition)
        for node_i in members
    }

    n_communities = len(set(result.values()))
    print(f"[Step 5] Found {n_communities:,} communities.")
    return result


# CLUSTER ANALYSIS
def analyse_clusters(partition, ip_to_pairs, idf, records):
    """
    For each community: compute size, signature credential (highest IDF-sum
    pair across member IPs), and top credentials by raw frequency.
    """
    print("\n[Step 6] Analysing clusters ...\n")

    community_to_ips = collections.defaultdict(list)
    for ip, comm_id in partition.items():
        community_to_ips[comm_id].append(ip)

    # raw pairs (with repeats) for frequency counting
    ip_to_raw_pairs = collections.defaultdict(list)
    for ip, username, password in records:
        ip_to_raw_pairs[ip].append((username, password))

    clusters = []
    for comm_id, ips in community_to_ips.items():
        # Count raw credential frequency within this community
        pair_count = collections.Counter()
        # Sum IDF scores per pair across all IPs in this community
        pair_idf_sum = collections.Counter()

        for ip in ips:
            for pair in ip_to_pairs[ip]:        # sets, so no retry double-counting
                pair_idf_sum[pair] += idf.get(pair, 0)
            for pair in ip_to_raw_pairs[ip]:
                pair_count[pair] += 1

        clusters.append({
            "community_id":  comm_id,
            "size":          len(ips),
            "ips":           ips,
            "top_by_count":  pair_count.most_common(5),
            "signature":     pair_idf_sum.most_common(3),
        })

    # Sort by cluster size, largest first
    clusters.sort(key=lambda c: c["size"], reverse=True)

    # Print summary table
    print(f"{'Rank':<5} {'CommID':<8} {'Size':>6}  Signature credential (top IDF)")
    print("-" * 75)
    for rank, cl in enumerate(clusters, 1):
        if cl["signature"]:
            sig_pair  = cl["signature"][0][0]
            sig_score = cl["signature"][0][1]
            sig_str = f"'{sig_pair[0]}/{sig_pair[1]}'  (IDF-sum={sig_score:.1f})"
        else:
            sig_str = "-"
        print(f"{rank:<5} {cl['community_id']:<8} {cl['size']:>6}  {sig_str}")
        if rank >= 20:
            remaining = len(clusters) - 20
            print(f"      ... and {remaining} more clusters (mostly singletons) ...")
            break

    # Print summary stats
    sizes = [c["size"] for c in clusters]
    print(f"\nSummary:")
    print(f"  Total communities   : {len(clusters):,}")
    print(f"  Largest cluster     : {max(sizes):,} IPs")
    print(f"  Clusters >= 10 IPs  : {sum(1 for s in sizes if s >= 10):,}")
    print(f"  Clusters >= 2 IPs   : {sum(1 for s in sizes if s >= 2):,}")
    print(f"  Singletons (1 IP)   : {sizes.count(1):,}")

    return clusters


# VISUALISATION

def visualise_graph(G, partition, output_file, max_nodes=600):
    """
    Draw the largest connected component coloured by community.
    Singletons excluded. Capped at max_nodes for readability.
    Node size = degree; edge width = cosine similarity.
    """
    print(f"\n[Step 7] Visualising graph -> '{output_file}' ...")

    # Find connected components with at least 2 nodes
    components = [c for c in nx.connected_components(G) if len(c) >= 2]
    if not components:
        print("         No edges in graph — nothing to draw.")
        return

    # Take the largest connected component
    lcc_nodes = max(components, key=len)
    original_size = len(lcc_nodes)
    if original_size > max_nodes:
        lcc_nodes = set(sorted(lcc_nodes)[:max_nodes])
        print(f"         Showing {max_nodes} of {original_size} nodes.")

    sub = G.subgraph(lcc_nodes)

    unique_comms  = list(set(partition[n] for n in sub.nodes()))
    cmap          = matplotlib.colormaps.get_cmap("tab20")
    comm_to_color = {c: cmap(i % 20) for i, c in enumerate(unique_comms)}
    node_colors   = [comm_to_color[partition[n]] for n in sub.nodes()]

    degrees    = dict(sub.degree())
    node_sizes = [20 + degrees[n] * 10 for n in sub.nodes()]

    weights     = [sub[u][v].get("weight", 0) for u, v in sub.edges()]
    max_w       = max(weights) if weights else 1
    edge_widths = [0.2 + 2.5 * (w / max_w) for w in weights]

    pos = nx.spring_layout(sub, seed=42, weight="weight", k=0.5)

    fig, ax = plt.subplots(figsize=(18, 13))
    ax.set_facecolor("#0d0d1a")
    fig.patch.set_facecolor("#0d0d1a")
    ax.set_title(
        f"Attacker Similarity Graph (TF-IDF weighted)\n"
        f"{sub.number_of_nodes()} IPs  *  {sub.number_of_edges()} edges  *  "
        f"colour = community/botnet",
        fontsize=13, fontweight="bold", color="white", pad=12
    )

    nx.draw_networkx_nodes(
        sub, pos,
        node_color=node_colors,
        node_size=node_sizes,
        alpha=0.90,
        ax=ax
    )
    nx.draw_networkx_edges(
        sub, pos,
        width=edge_widths,
        alpha=0.25,
        edge_color="#7777aa",
        ax=ax
    )
    # Only draw labels if the subgraph is small enough to be readable
    if sub.number_of_nodes() <= 80:
        nx.draw_networkx_labels(
            sub, pos,
            font_size=6,
            font_color="white",
            ax=ax
        )

    ax.axis("off")
    plt.tight_layout()
    plt.savefig(output_file, dpi=150, bbox_inches="tight",
                facecolor=fig.get_facecolor())
    plt.close()
    print(f"         Saved to '{output_file}'.")


# CSV OUTPUT
def save_results(clusters, output_file):
    """Write cluster assignments to CSV: ip, community_id, cluster_size, signature_credential."""
    with open(output_file, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["ip", "community_id", "cluster_size",
                          "signature_credential"])

        for cl in clusters:
            sig = ""
            if cl["signature"]:
                u, p = cl["signature"][0][0]
                sig = f"{u}/{p}"
            for ip in cl["ips"]:
                writer.writerow([ip, cl["community_id"], cl["size"], sig])

    print(f"[Step 8] Results saved to '{output_file}' "
          f"({sum(cl['size'] for cl in clusters):,} rows).")


# MAIN

def main():
    print("=" * 65)
    print("  HONEYPOT ATTACKER CLUSTERING  -  VERSION 3")
    print("  Cosine Similarity Graph + Leiden Community Detection")
    print("=" * 65)
    print()

    # Load the raw honeypot data
    records = load_data(DATA_FILE)

    # Build pair->IPs and IP->pairs mappings
    pair_to_ips, ip_to_pairs, all_ips = build_mappings(records)

    # Compute how rare each credential pair is (IDF)
    idf = compute_idf(pair_to_ips, len(all_ips))

    # Build the graph with cosine similarity edges (sparse matrix method)
    G = build_graph(ip_to_pairs, all_ips, idf)

    # Find communities using Leiden
    partition = detect_communities(G, LEIDEN_RESOLUTION)

    # Analyse and print cluster stats
    clusters = analyse_clusters(partition, ip_to_pairs, idf, records)

    # Draw and save the graph image
    visualise_graph(G, partition, OUTPUT_PLOT)

    #  Save IP -> cluster mapping to CSV
    save_results(clusters, OUTPUT_CSV)

    print("\nDone.")


if __name__ == "__main__":
    main()
