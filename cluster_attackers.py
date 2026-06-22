"""
HONEYPOT ATTACKER CLUSTERING
Cosine Similarity Edges + Leiden Community Detection


GOAL
Find groups of attacker IPs that are probably from the same botnet,
based on the username/password pairs they tried on our SSH honeypot.

THE CORE IDEA
Bots in the same botnet run the same attack software with the same
credential list, so they try the same username/password pairs.

If two IPs try the same pairs they are probably in the same botnet.
The rarer the shared pairs, the more confident we can be.

We model this as a graph where each node is an attacker IP, each edge
connects two IPs that share at least one credential pair, and the edge
weight is the sum of IDF scores of those shared pairs so that rare pairs
count more than common ones.

Dense subgraphs are probable botnets.

WHY TF-IDF
The naive version (V1) weighted edges by raw count of shared pairs. This
failed because one credential pair (345gs5662d34 / 345gs5662d34) was used
by 56% of all IPs, creating huge fake mega-clusters.

V2 uses IDF (Inverse Document Frequency) to down-weight common credentials.
The formula is log(total_IPs / IPs_that_used_this_pair), so a pair used by
2791 IPs gets a score of 0.578 (nearly useless) while a pair used by only
7 IPs gets 6.563 (very meaningful).

The edge weight between two IPs is the sum of IDF scores of their shared
pairs. Sharing a rare pair gives a heavy edge, sharing only common pairs
gives a light one.
"""
import argparse
import csv
import math
import collections

import numpy as np
import scipy.sparse as sp
import networkx as nx
import igraph as ig
import leidenalg
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.cm as cm


DATA_FILE = "cowrie_ip_username_pass_anon.csv"

# Minimum cosine similarity needed to form an edge between two IPs.
# 0.0 means completely different credential sets, 1.0 means identical.
# Setting this to 0.10 requires at least roughly 10% normalised overlap.
MIN_COSINE_SIM = 0.10

# Higher resolution means more communities but smaller ones.
LEIDEN_RESOLUTION = 1.0

OUTPUT_PLOT = "attacker_graph.png"
OUTPUT_CSV  = "cluster_results.csv"


def load_data(filepath):
    """
    Read the CSV and return a list of (ip, username, password) triples.
    Raises an error early if any of the required columns are missing.
    """
    REQUIRED = {"ip", "username", "password"}
    records = []
    with open(filepath, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        missing = REQUIRED - set(reader.fieldnames or [])
        if missing:
            raise ValueError(
                f"CSV is missing required column(s): {', '.join(sorted(missing))}. "
                f"Found: {reader.fieldnames}"
            )
        for row in reader:
            records.append((
                row["ip"].strip(),
                row["username"].strip(),
                row["password"].strip()
            ))
    print(f"Loaded {len(records):,} rows from '{filepath}'.")
    return records


def build_mappings(records):
    """
    Build two lookup dicts from the raw records.

    pair_to_ips maps each credential pair to the set of IPs that tried it.
    ip_to_pairs maps each IP to the set of credential pairs it tried.

    We use sets so each IP/pair combination is only counted once regardless
    of how many times that IP retried the same credentials. We care about
    the pattern of what was tried, not the repetition count.
    """
    pair_to_ips = collections.defaultdict(set)
    ip_to_pairs = collections.defaultdict(set)

    for ip, username, password in records:
        pair = (username, password)
        pair_to_ips[pair].add(ip)
        ip_to_pairs[ip].add(pair)

    all_ips = sorted(ip_to_pairs.keys())

    print(f"{len(all_ips):,} unique IPs, {len(pair_to_ips):,} unique credential pairs.")
    print(f"Pairs used by more than one IP: "
          f"{sum(1 for s in pair_to_ips.values() if len(s) > 1):,}")

    return pair_to_ips, ip_to_pairs, all_ips


# IDF = log( total_IPs / IPs_that_used_this_pair )

def compute_idf(pair_to_ips, total_ips):
    """
    Compute IDF for every credential pair, which basically tells us how rare it is.

    A high IDF (around 8.5) means almost nobody tried this pair, so two IPs
    sharing it is strong evidence they are from the same botnet.
    A low IDF (around 0.5) means tons of IPs tried it, so it is basically
    useless as a signal.

    Some examples from this dataset:
        345gs5662d34 / 345gs5662d34 was tried by 2791 IPs so IDF is 0.578 (useless)
        admin / admin was tried by 452 IPs so IDF is 2.398 (moderate)
        perl / warning was tried by only 7 IPs so IDF is 6.563 (very useful)
    """
    idf = {}
    N = total_ips

    for pair, ip_set in pair_to_ips.items():
        df = len(ip_set)
        idf[pair] = math.log(N / df)

    scores = list(idf.values())
    print(f"IDF computed for {len(idf):,} pairs.")
    print(f"Range: {min(scores):.3f} (most common) to {max(scores):.3f} (rarest)")

    return idf


def build_graph(ip_to_pairs, all_ips, idf):
    """
    Build an undirected weighted graph where edge weights are cosine similarities.

    Each IP is represented as a vector in credential space where each dimension
    is a credential pair and the value is that pair's IDF score (or 0 if the IP
    never tried it). Cosine similarity between two such vectors is the edge weight.

    This normalises for credential list size so an IP that tried 10,000 pairs is
    compared on the same scale as one that tried 50. Only the pattern matters,
    not the volume.

    We use a sparse matrix to compute all similarities at once instead of looping
    over every pair of IPs. With 5000 IPs a naive loop would be 12.5 million
    comparisons, which is way too slow. The matrix approach does it in one call.

    The process: build a matrix M where rows are IPs and columns are credential
    pairs, fill in IDF scores, normalise each row by its length, then multiply
    M by its own transpose. The result at position i,j is the cosine similarity
    between IP i and IP j. We only keep the upper triangle to avoid duplicates.
    """
    ip_idx    = {ip:   i for i, ip   in enumerate(all_ips)}
    all_pairs = list(idf.keys())
    pair_idx  = {pair: j for j, pair in enumerate(all_pairs)}

    # fill in the non-zero IDF values for each IP's credential pairs
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

    # normalise each row by its L2 norm so volume doesn't dominate
    norms = np.asarray(M.power(2).sum(axis=1)).flatten() ** 0.5
    norms[norms == 0] = 1.0  # avoid dividing by zero for isolated IPs
    M_norm = sp.diags(1.0 / norms) @ M

    # multiply to get all cosine similarities, upper triangle only to skip duplicates
    S = sp.triu(M_norm @ M_norm.T, k=1).tocoo()

    G = nx.Graph()
    for ip in all_ips:
        G.add_node(ip)

    for i, j, w in zip(S.row, S.col, S.data):
        if w >= MIN_COSINE_SIM:
            G.add_edge(all_ips[i], all_ips[j], weight=float(w))

    print(f"Graph built: {G.number_of_nodes():,} nodes, {G.number_of_edges():,} edges.")
    print(f"(Cosine similarity threshold: {MIN_COSINE_SIM})")

    return G


def detect_communities(G, resolution=1.0):
    """
    Run the Leiden algorithm to find communities (clusters) in the graph.

    Leiden (2019) is the successor to Louvain (2008). Both algorithms try to
    maximise modularity, which measures whether communities are significantly
    denser than you would expect in a random network with the same degree
    distribution. Higher modularity means the communities are more real.

    Leiden's key improvement over Louvain is that Louvain can produce
    communities that are internally disconnected. Leiden adds a refinement
    phase that guarantees every community is well-connected.

    We use seed=42 so results are reproducible across runs.
    """
    print(f"Running Leiden community detection (resolution={resolution}) ...")

    nodes    = list(G.nodes())
    node_idx = {n: i for i, n in enumerate(nodes)}

    # convert NetworkX graph to igraph format since leidenalg needs igraph
    edges   = [(node_idx[u], node_idx[v]) for u, v in G.edges()]
    weights = [float(G[u][v]["weight"])   for u, v in G.edges()]

    ig_G = ig.Graph(n=len(nodes), edges=edges)

    partition = leidenalg.find_partition(
        ig_G,
        leidenalg.RBConfigurationVertexPartition,
        weights=weights or None,
        resolution_parameter=resolution,
        seed=42,
    )

    # map back from igraph node indices to IP strings
    result = {
        nodes[node_i]: comm_id
        for comm_id, members in enumerate(partition)
        for node_i in members
    }

    n_communities = len(set(result.values()))
    print(f"Found {n_communities:,} communities.")
    return result


def analyse_clusters(partition, ip_to_pairs, idf, records):
    """
    Turn the raw partition (IP to community id) into human-readable stats.

    For each community we find the size, the signature credential (the pair
    with the highest total IDF contribution across all IPs in that community,
    which is the most discriminating credential for that botnet), and the top
    credentials by raw frequency.

    We use ip_to_pairs which stores sets, so each pair is counted once per IP
    and retries don't inflate the counts.
    """
    print("\nAnalysing clusters ...\n")

    # group IPs by their assigned community
    community_to_ips = collections.defaultdict(list)
    for ip, comm_id in partition.items():
        community_to_ips[comm_id].append(ip)

    # also build a version with repeats so we can count raw attempt frequency
    ip_to_raw_pairs = collections.defaultdict(list)
    for ip, username, password in records:
        ip_to_raw_pairs[ip].append((username, password))

    clusters = []
    for comm_id, ips in community_to_ips.items():
        pair_count   = collections.Counter()
        pair_idf_sum = collections.Counter()

        for ip in ips:
            # sum IDF scores per pair across all IPs in this community
            for pair in ip_to_pairs[ip]:
                pair_idf_sum[pair] += idf.get(pair, 0)
            # count raw occurrences for frequency stats
            for pair in ip_to_raw_pairs[ip]:
                pair_count[pair] += 1

        clusters.append({
            "community_id":  comm_id,
            "size":          len(ips),
            "ips":           ips,
            "top_by_count":  pair_count.most_common(5),
            "signature":     pair_idf_sum.most_common(3),
        })

    # show largest clusters first
    clusters.sort(key=lambda c: c["size"], reverse=True)

    print(f"{'Rank':<5} {'CommID':<8} {'Size':>6}  Signature credential (top IDF)")
    print("-" * 75)
    for rank, cl in enumerate(clusters, 1):
        if cl["signature"]:
            sig_pair  = cl["signature"][0][0]
            sig_score = cl["signature"][0][1]
            sig_str = f"{sig_pair[0]}/{sig_pair[1]}  (IDF-sum={sig_score:.1f})"
        else:
            sig_str = "none"
        print(f"{rank:<5} {cl['community_id']:<8} {cl['size']:>6}  {sig_str}")
        if rank >= 20:
            remaining = len(clusters) - 20
            print(f"      ... and {remaining} more clusters (mostly singletons) ...")
            break

    sizes = [c["size"] for c in clusters]
    print(f"\nSummary:")
    print(f"  Total communities   : {len(clusters):,}")
    print(f"  Largest cluster     : {max(sizes):,} IPs")
    print(f"  Clusters >= 10 IPs  : {sum(1 for s in sizes if s >= 10):,}")
    print(f"  Clusters >= 2 IPs   : {sum(1 for s in sizes if s >= 2):,}")
    print(f"  Singletons (1 IP)   : {sizes.count(1):,}")

    return clusters


def visualise_graph(G, partition, output_file, max_nodes=600):
    """
    Draw the largest connected component coloured by community.

    Each dot is an attacker IP, each line means those two IPs share credential
    pairs. Line thickness shows cosine similarity (thicker means more similar),
    dot size shows how many neighbours the IP has, and colour shows community
    membership so IPs in the same probable botnet get the same colour.

    We skip isolated nodes since they just add visual clutter, and we cap the
    total nodes shown at max_nodes so large graphs stay readable.
    """
    print(f"\nVisualising graph, saving to '{output_file}' ...")

    # only include components with at least 2 nodes, singletons are just noise
    components = [c for c in nx.connected_components(G) if len(c) >= 2]
    if not components:
        print("No edges in graph, nothing to draw.")
        return

    lcc_nodes = max(components, key=len)
    original_size = len(lcc_nodes)
    if original_size > max_nodes:
        lcc_nodes = set(list(lcc_nodes)[:max_nodes])
        print(f"Showing {max_nodes} of {original_size} nodes.")

    sub = G.subgraph(lcc_nodes)

    # assign one colour per community
    unique_comms  = list(set(partition[n] for n in sub.nodes()))
    cmap          = matplotlib.colormaps.get_cmap("tab20")
    comm_to_color = {c: cmap(i % 20) for i, c in enumerate(unique_comms)}
    node_colors   = [comm_to_color[partition[n]] for n in sub.nodes()]

    # node size proportional to degree so more connected IPs stand out
    degrees    = dict(sub.degree())
    node_sizes = [20 + degrees[n] * 10 for n in sub.nodes()]

    # edge width proportional to cosine similarity
    weights     = [sub[u][v].get("weight", 0) for u, v in sub.edges()]
    max_w       = max(weights) if weights else 1
    edge_widths = [0.2 + 2.5 * (w / max_w) for w in weights]

    # spring layout pulls strongly connected nodes together
    pos = nx.spring_layout(sub, seed=42, weight="weight", k=0.5)

    fig, ax = plt.subplots(figsize=(18, 13))
    ax.set_facecolor("#0d0d1a")
    fig.patch.set_facecolor("#0d0d1a")
    ax.set_title(
        f"Attacker Similarity Graph (TF-IDF weighted)\n"
        f"{sub.number_of_nodes()} IPs, {sub.number_of_edges()} edges, "
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
    # only draw IP labels if the graph is small enough to be readable
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
    print(f"Saved to '{output_file}'.")


def save_results(clusters, output_file):
    """
    Save cluster assignments to CSV.

    Each row is one IP with its community id, the total size of that cluster,
    and the signature credential (the highest IDF-sum pair for that community,
    formatted as username/password).
    """
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

    print(f"Results saved to '{output_file}' "
          f"({sum(cl['size'] for cl in clusters):,} rows).")


def main():
    parser = argparse.ArgumentParser(
        description="Cluster SSH honeypot attackers by credential similarity."
    )
    parser.add_argument(
        "--input", "-i",
        default=DATA_FILE,
        help=f"Path to the input CSV file (default: {DATA_FILE}). "
             "Must have columns: ip, username, password."
    )
    args = parser.parse_args()

    print("=" * 65)
    print("  HONEYPOT ATTACKER CLUSTERING  -  VERSION 3")
    print("  Cosine Similarity Graph + Leiden Community Detection")
    print("=" * 65)
    print()

    records = load_data(args.input)
    pair_to_ips, ip_to_pairs, all_ips = build_mappings(records)
    idf = compute_idf(pair_to_ips, len(all_ips))
    G = build_graph(ip_to_pairs, all_ips, idf)
    partition = detect_communities(G, LEIDEN_RESOLUTION)
    clusters = analyse_clusters(partition, ip_to_pairs, idf, records)
    visualise_graph(G, partition, OUTPUT_PLOT)
    save_results(clusters, OUTPUT_CSV)

    print("\nDone.")


if __name__ == "__main__":
    main()
