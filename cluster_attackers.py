"""
  HONEYPOT ATTACKER CLUSTERING  -  Botnet Discovery via Graph Analysis
  VERSION 3 - Cosine Similarity Edges & Leiden Community Detection

GOAL
Find groups of attacker IP addresses that are likely part of the same botnet,
based on the (username, password) pairs they try on the SSH honeypot.

THE CORE IDEA
Bots in the same botnet all run the same attack software with the same
credential list. This means they try the same (username, password) pairs.

If two IPs try the same pairs ,they are probably the same botnet.
The more rare pairs they share, the more certain we are.

We model this as a graph:
    - Each node  = one attacker IP
    - Each edge  = two IPs share at least one credential pair
    - Edge weight = sum of IDF scores of shared pairs (rare pairs count more)

Dense subgraphs = probable botnets.

WHY TF-IDF 
V1 weighted edges by raw count of shared pairs. This failed because one
credential pair (345gs5662d34 / 345gs5662d34) was used by 56% of all IPs,
creating three enormous fake mega-clusters.

V2 uses IDF (Inverse Document Frequency) to down-weight common credentials:

    IDF(pair) = log( total_IPs / IPs_that_used_this_pair )

    - Common pair used by 2791 IPs  ->  IDF = 0.578  (nearly worthless)
    - Rare pair used by 7 IPs       ->  IDF = 6.563  (very meaningful)

The edge weight between two IPs is the SUM of IDF scores of their shared pairs.
Two IPs sharing a rare pair get a heavy edge; sharing only common pairs gets a
light edge. Louvain then correctly groups by meaningful shared behaviour.

PIPELINE
1  Load the CSV data
2  Build mappings: pair -> IPs,  IP -> pairs
3  Compute IDF for every credential pair
4  Build TF-IDF vectors per IP; compute cosine similarity (sparse matrix)
5  Run Leiden community detection
6  Analyse each community (size, signature credential)
7  Visualise the graph
8  Save results to CSV

"""
import argparse                      # CLI argument parsing
import csv                          # reading the input CSV file
import math                         # math.log() for IDF calculation
import collections                  # defaultdict and Counter

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

DATA_FILE = "cowrie_ip_username_pass_anon.csv"   # default; overridden by --input

# Minimum cosine similarity to form an edge.
# 0.0 = completely different credential sets, 1.0 = identical sets.
# 0.10 requires at least ~10% normalised credential overlap.
MIN_COSINE_SIM = 0.10

# Leiden resolution parameter: higher = more, smaller communities.
# 1.0 is the standard default (equivalent to plain modularity maximisation).
LEIDEN_RESOLUTION = 1.0

OUTPUT_PLOT = "attacker_graph.png"
OUTPUT_CSV  = "cluster_results.csv"

### load data from CSV file, returning a list of (ip, username, password) triples

def load_data(filepath):
    """
    Read the CSV file and return a list of (ip, username, password) triples.
    Each row represents one login attempt by one attacker.
    Required columns: ip, username, password.
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
    print(f"[Step 1] Loaded {len(records):,} rows from '{filepath}'.")
    return records




def build_mappings(records):
    """
    Build two dictionaries from the raw records:

    pair_to_ips:
        Key:   (username, password) tuple — one unique credential pair
        Value: set of IP addresses that tried this pair
        Used to: compute IDF and find which IPs to connect with an edge

    ip_to_pairs:
        Key:   IP address string
        Value: set of (username, password) pairs this IP tried
        Used to: look up what credentials belong to a given IP

    We use SETS so each (IP, pair) combination is counted only once,
    regardless of how many times that IP retried the same credentials.
    We care about the PATTERN of what was tried, not the repetition count.
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


#IDF = log( total_IPs / IPs_that_used_this_pair )

def compute_idf(pair_to_ips, total_ips):
    """
    Compute the IDF (Inverse Document Frequency) score for every credential pair.

    IDF measures how RARE a credential pair is across all attacker IPs.

    Formula:
        IDF(pair) = log( N / df )

        where:
            N  = total number of unique IP addresses in the dataset (4,973)
            df = number of IPs that tried this specific pair (document frequency)

    What the values mean:
        High IDF = very rare pair, tried by almost nobody
            -> sharing this pair is strong evidence of being the same botnet
        Low IDF  = very common pair, tried by many IPs
            -> sharing this pair tells us almost nothing useful
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


# BUILDING THE GRAPH  (V3: cosine similarity via sparse matrix multiplication)
def build_graph(ip_to_pairs, all_ips, idf):
    """
    Build an undirected weighted NetworkX graph using cosine similarity.

    Each IP is represented as a TF-IDF vector in credential space:
        v[ip][pair] = IDF(pair)  if the IP tried that pair, else 0

    The edge weight between two IPs is their cosine similarity:
        cos_sim(a, b) = (v_a · v_b) / (||v_a|| × ||v_b||)

    This normalises for credential list size.  An IP that tried 10,000 pairs
    is compared on the same scale as one that tried 50 — only the PATTERN of
    credentials matters, not the volume.

    Plain-English walkthrough of the sparse matrix approach:

        Step A — build a spreadsheet (matrix M):
            Rows    = attacker IPs  (one row per IP)
            Columns = credential pairs  (one column per unique pair)
            Cell    = IDF score of that pair, or 0 if the IP never tried it
            Most cells are 0 (each IP tries only a tiny fraction of all pairs),
            so we store it as a "sparse" matrix — only the non-zero cells.

        Step B — normalise each row (divide by its length):
            Without this, an IP that tried 10,000 pairs would always look more
            similar to everything than one that tried 50, just due to volume.
            Dividing each row by its L2 norm (its "length" in vector space)
            puts every IP on the same scale — only the PATTERN matters.

        Step C — multiply M_norm by its own transpose (M_norm.T):
            The result S[i][j] is the dot product of IP i's row and IP j's row.
            Because both rows are normalised, this dot product equals the cosine
            similarity — a number between 0 (nothing in common) and 1 (identical
            credential sets).  One matrix multiply gives us ALL pairs at once.

        Step D — keep only the upper triangle (avoid duplicate pairs):
            S[i][j] and S[j][i] are the same similarity. triu(k=1) keeps only
            the cells above the diagonal, so each pair is processed once.

    Why not just loop over every pair of IPs?
        With ~5,000 IPs that would be 12.5 million comparisons.  The one common
        pair (345gs5662d34) alone appears in 2,791 IPs — looping over those
        would generate ~3.9 million iterations by itself.  The matrix multiply
        handles the entire dataset in one vectorised call.

    Only edges with cosine similarity >= MIN_COSINE_SIM are kept.
    """
    ip_idx    = {ip:   i for i, ip   in enumerate(all_ips)}
    all_pairs = list(idf.keys())
    pair_idx  = {pair: j for j, pair in enumerate(all_pairs)}

    # Step A: fill in the IP × credential spreadsheet (sparse, only non-zero cells)
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

    # Step B: normalise each row by its L2 norm (vector length)
    norms = np.asarray(M.power(2).sum(axis=1)).flatten() ** 0.5
    norms[norms == 0] = 1.0                      # keep isolated IPs stable
    M_norm = sp.diags(1.0 / norms) @ M

    # Steps C & D: multiply to get all cosine similarities, upper triangle only
    S = sp.triu(M_norm @ M_norm.T, k=1).tocoo()

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


# LEIDEN COMMUNITY DETECTION  (V3: replaces Louvain)

def detect_communities(G, resolution=1.0):
    """
    Run the Leiden algorithm to find communities (clusters) in the graph.

    Leiden (2019) is the state-of-the-art successor to Louvain (2008).
    Both algorithms maximise MODULARITY Q:

        Q = (1/2m) × Σ [w_ij − (k_i × k_j) / 2m] × δ(c_i, c_j)

        m    = total edge weight in the graph
        w_ij = weight of the edge between nodes i and j  (0 if no edge)
        k_i  = weighted degree of node i (sum of its edge weights)
        (k_i × k_j) / 2m  = expected edge weight under a random null model
        δ    = 1 if i and j are in the same community, else 0

    High Q = communities are much denser internally than expected by chance.

    Leiden's improvement over Louvain: Louvain can produce communities that
    are internally disconnected (a node can end up in a community with no
    direct edge to some members).  Leiden adds a refinement phase after each
    aggregation step that guarantees all communities are well-connected.

    seed=42 ensures reproducible results across runs.
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
    Convert the raw partition (IP -> community_id) into human-readable stats.

    For each community, we compute:
        - size: number of IPs in this community
        - signature credential: the (username, password) pair with the highest
          total IDF contribution across all IPs in the community — the most
          discriminating credential for this botnet
        - top credentials by raw frequency: most-tried pairs in this community

    ip_to_pairs values are sets, so each pair is counted once per IP when
    accumulating IDF sums — no retry double-counting.
    """
    print("\n[Step 6] Analysing clusters ...\n")

    # Group IPs by their community ID
    community_to_ips = collections.defaultdict(list)
    for ip, comm_id in partition.items():
        community_to_ips[comm_id].append(ip)

    # Build a raw (with repeats) version of ip -> pairs for frequency counting
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
            # ip_to_pairs[ip] is already a set, so no double-counting of retries
            for pair in ip_to_pairs[ip]:
                pair_idf_sum[pair] += idf.get(pair, 0)
            # Count raw occurrences for frequency stats
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
    Draw the largest connected component of the graph, coloured by community.

    Each dot (node) = one attacker IP.
    Each line (edge) = those two IPs share credential pairs.
    Line thickness = edge weight (TF-IDF sum). Thicker = more similar.
    Dot size = node degree (how many neighbours). Bigger = more connected.
    Dot colour = community membership. Same colour = same probable botnet.

    We only draw components with >= 2 nodes (singletons add visual noise).
    We cap at max_nodes for readability on large graphs.
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
        lcc_nodes = set(list(lcc_nodes)[:max_nodes])
        print(f"         Showing {max_nodes} of {original_size} nodes.")

    sub = G.subgraph(lcc_nodes)

    # Assign one colour per community
    unique_comms  = list(set(partition[n] for n in sub.nodes()))
    cmap          = matplotlib.colormaps.get_cmap("tab20")
    comm_to_color = {c: cmap(i % 20) for i, c in enumerate(unique_comms)}
    node_colors   = [comm_to_color[partition[n]] for n in sub.nodes()]

    # Node size proportional to degree (more connections = bigger dot)
    degrees    = dict(sub.degree())
    node_sizes = [20 + degrees[n] * 10 for n in sub.nodes()]

    # Edge width proportional to weight (stronger connection = thicker line)
    weights     = [sub[u][v].get("weight", 0) for u, v in sub.edges()]
    max_w       = max(weights) if weights else 1
    edge_widths = [0.2 + 2.5 * (w / max_w) for w in weights]

    # Spring layout positions nodes so strongly connected ones cluster together
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


# NEW CSV OUTPUT FORMAT
def save_results(clusters, output_file):
    """
    Save cluster assignments to a CSV file.

    Columns:
        ip                   : the anonymised attacker IP address
        community_id         : the cluster ID assigned by Leiden
        cluster_size         : total number of IPs in this cluster
        signature_credential : the most discriminating credential for this cluster
                               (highest IDF-sum pair), formatted as username/password
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

    print(f"[Step 8] Results saved to '{output_file}' "
          f"({sum(cl['size'] for cl in clusters):,} rows).")


#MAIN FUNCTION

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

    # Load the raw honeypot data
    records = load_data(args.input)

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
