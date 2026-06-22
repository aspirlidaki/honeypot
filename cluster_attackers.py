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
weight is the cosine similarity of their TF-IDF credential vectors so
that rare pairs count more than common ones.

Dense subgraphs are probable botnets.

WHY TF-IDF
The naive version (V1) weighted edges by raw count of shared pairs. This
failed because one credential pair (345gs5662d34 / 345gs5662d34) was used
by 56% of all IPs, creating huge fake mega-clusters.

V2 uses IDF (Inverse Document Frequency) to down-weight common credentials.
The formula is log(total_IPs / IPs_that_used_this_pair), so a pair used by
2791 IPs gets a score of 0.578 (nearly useless) while a pair used by only
7 IPs gets 6.563 (very meaningful).

V3 replaced raw IDF-sum edge weights with cosine similarity and switched
from Louvain to Leiden community detection.

WHY VOCABULARY FILTERING (V4)
IDF alone is insufficient when a near-universal credential appears across
33-56% of all IPs. After L2 normalisation, cosine similarity still picks
up the influence of such credentials because they contribute to the vector
length of every IP that carries them. The correct fix is to treat them as
stopwords and remove them from the vocabulary entirely, so they have no
presence in any vector and cannot form or strengthen any edge.

V4 applies two filters before computing IDF:
  - Drop any credential used by more than MAX_DF_FRACTION (10%) of all IPs.
    This removes canary credentials and other near-universal stopwords.
  - Drop credentials only one IP ever tried (singletons). They cannot link
    any pair of IPs, and they inflate vector norms without contributing signal.

IPs whose entire credential set was filtered out become singletons —
they link to nobody, which is correct rather than a bug.
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

# Vocabulary filters applied before IDF is computed.
# Credentials used by more than MAX_DF_FRACTION of all IPs are stopwords.
# Credentials used by fewer than MIN_DF IPs are singletons and are also dropped.
MAX_DF_FRACTION = 0.10   # drop a credential used by more than 10% of all IPs
MIN_DF          = 2      # drop a credential only one IP ever tried

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


def keep_useful_pairs(pair_to_ips, n_ips):
    """
    Compute IDF for credential pairs that survive vocabulary filtering.

    Two classes of credential are excluded before IDF is computed:

    Stopwords (df > MAX_DF_FRACTION * n_ips): credentials so common that
    sharing them carries no information about botnet membership. The canary
    credential (345gs5662d34/345gs5662d34, ~56% of IPs) is the canonical
    example. IDF gives it a score of only 0.578, but after L2 normalisation
    cosine similarity re-inflates its influence because it contributes to the
    vector norm of every IP that tried it. Removing it from the vocabulary
    entirely is the correct fix: it has no dimension in any vector, so it
    cannot form or strengthen any edge.

    Singletons (df < MIN_DF): credentials only one IP ever tried. They cannot
    link any pair of IPs (their dimension is zero for every other IP's vector),
    and they inflate the norms of the IPs that tried them, weakening those IPs'
    cosine similarity with their genuine botnet peers.

    Prints the list of dropped stopwords as a sanity check.
    Returns a dict of (pair -> IDF) for the surviving pairs only.
    """
    max_df = MAX_DF_FRACTION * n_ips
    idf = {}
    dropped = []

    for pair, ips in pair_to_ips.items():
        df = len(ips)
        if df > max_df:
            dropped.append(pair)
            continue
        if df < MIN_DF:
            continue
        idf[pair] = math.log(n_ips / df)

    n_singletons = sum(1 for s in pair_to_ips.values() if len(s) < MIN_DF)
    print(f"Vocabulary filter: {len(idf):,} pairs kept "
          f"(dropped {len(dropped)} stopwords, {n_singletons:,} singletons).")
    print(f"Dropped too-common credentials ({len(dropped)}): "
          f"{[f'{u}/{p}' for u, p in dropped[:5]]}")

    if idf:
        scores = list(idf.values())
        print(f"IDF range after filtering: {min(scores):.3f} to {max(scores):.3f}")

    return idf


def build_graph(ip_to_pairs, all_ips, idf):
    """
    Build an undirected weighted graph where edge weights are cosine similarities.

    Each IP is represented as a sparse vector in credential space. Only pairs
    surviving the vocabulary filter (present in idf) appear as dimensions.
    IPs whose every credential was filtered out have all-zero vectors — they
    link to nobody and become singletons, which is correct.

    The process: build a matrix M where rows are IPs and columns are the kept
    credential pairs, fill in IDF scores, L2-normalise each row (IPs with a
    zero row stay zero rather than producing NaN), then compute S = M @ M.T.
    The entry at position (i, j) is the cosine similarity between IP i and IP j.
    We only keep the upper triangle to avoid duplicates and drop entries below
    MIN_COSINE_SIM before constructing the graph.
    """
    ip_idx    = {ip:   i for i, ip   in enumerate(all_ips)}
    all_pairs = list(idf.keys())
    pair_idx  = {pair: j for j, pair in enumerate(all_pairs)}

    # fill in IDF scores for each IP's credential pairs; skip filtered-out pairs
    rows, cols, vals = [], [], []
    for ip, pair_set in ip_to_pairs.items():
        i = ip_idx[ip]
        for pair in pair_set:
            if pair not in pair_idx:
                continue
            rows.append(i)
            cols.append(pair_idx[pair])
            vals.append(idf[pair])

    M = sp.csr_matrix(
        (vals, (rows, cols)),
        shape=(len(all_ips), len(all_pairs)),
        dtype=np.float32,
    )

    # L2-normalise each row; IPs with all-zero rows (every credential filtered)
    # receive inv=0 so their rows stay zero and they form no edges
    norms = np.sqrt(np.asarray(M.multiply(M).sum(axis=1)).ravel())
    inv   = np.divide(1.0, norms, out=np.zeros_like(norms), where=norms > 0)
    M     = sp.diags(inv) @ M

    # multiply to get all cosine similarities, upper triangle only to skip duplicates
    S = sp.triu(M @ M.T, k=1).tocoo()

    G = nx.Graph()
    for ip in all_ips:
        G.add_node(ip)

    for i, j, w in zip(S.row, S.col, S.data):
        if w >= MIN_COSINE_SIM:
            G.add_edge(all_ips[i], all_ips[j], weight=float(w))

    print(f"Graph built: {G.number_of_nodes():,} nodes, {G.number_of_edges():,} edges.")
    print(f"(Cosine similarity threshold: {MIN_COSINE_SIM})")
    if G.number_of_edges() == 0:
        print(f"Warning: no edges formed. Try lowering MIN_COSINE_SIM.")

    return G


def detect_communities(G):
    """
    Run the Leiden algorithm to find communities (clusters) in the graph.

    Uses plain modularity (ModularityVertexPartition) with no resolution
    parameter — the standard Leiden configuration. Leiden (2019) is the
    successor to Louvain (2008) and adds a refinement phase that guarantees
    every output community is well-connected.

    We use seed=42 so results are reproducible across runs.
    """
    print("Running Leiden community detection (plain modularity) ...")

    nodes    = list(G.nodes())
    node_idx = {n: i for i, n in enumerate(nodes)}

    # convert NetworkX graph to igraph format since leidenalg needs igraph
    edges   = [(node_idx[u], node_idx[v]) for u, v in G.edges()]
    weights = [float(G[u][v]["weight"])   for u, v in G.edges()]

    ig_G = ig.Graph(n=len(nodes), edges=edges)

    partition = leidenalg.find_partition(
        ig_G,
        leidenalg.ModularityVertexPartition,
        weights=weights or None,
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
    present in the most cluster members among the kept vocabulary, with IDF
    as a tiebreak), and the top credentials by raw attempt frequency.

    Pairs absent from idf (filtered stopwords and singletons) are excluded
    from the signature selection — they are not informative.
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
        pair_count = collections.Counter()
        # sig_score[pair] = (member_count, idf_value) — only for kept pairs
        sig_score  = {}

        for ip in ips:
            for pair in ip_to_pairs[ip]:
                if pair in idf:
                    count, _ = sig_score.get(pair, (0, 0.0))
                    sig_score[pair] = (count + 1, idf[pair])
            for pair in ip_to_raw_pairs[ip]:
                pair_count[pair] += 1

        if sig_score:
            sig_pair = max(sig_score.items(),
                           key=lambda kv: (kv[1][0], kv[1][1]))[0]
        else:
            sig_pair = None

        clusters.append({
            "community_id":  comm_id,
            "size":          len(ips),
            "ips":           ips,
            "top_by_count":  pair_count.most_common(5),
            "signature":     sig_pair,
        })

    # show largest clusters first
    clusters.sort(key=lambda c: c["size"], reverse=True)

    print(f"{'Rank':<5} {'CommID':<8} {'Size':>6}  Signature credential")
    print("-" * 70)
    for rank, cl in enumerate(clusters, 1):
        sig = cl["signature"]
        sig_str = f"{sig[0]}/{sig[1]}" if sig else "none"
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
    components = sorted(
        [c for c in nx.connected_components(G) if len(c) >= 2],
        key=len, reverse=True
    )
    if not components:
        print("No edges in graph, nothing to draw.")
        return

    # collect nodes from the largest components first, filling up to max_nodes;
    # when a component is too large to fit whole, take the highest-degree nodes
    selected = set()
    for comp in components:
        if len(selected) >= max_nodes:
            break
        remaining = max_nodes - len(selected)
        if len(comp) <= remaining:
            selected |= comp
        else:
            sub_temp = G.subgraph(comp)
            by_deg = sorted(comp, key=lambda n: sub_temp.degree(n), reverse=True)
            selected |= set(by_deg[:remaining])

    total_non_singleton = sum(len(c) for c in components)
    if total_non_singleton > max_nodes:
        print(f"Showing {len(selected)} of {total_non_singleton} non-singleton nodes "
              f"across {len(components)} components.")

    sub = G.subgraph(selected)

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
        f"Attacker Similarity Graph (TF-IDF weighted, stopwords removed)\n"
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
    and the signature credential (the pair most cluster members share among the
    kept vocabulary, formatted as username/password).
    """
    with open(output_file, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["ip", "community_id", "cluster_size",
                          "signature_credential"])

        for cl in clusters:
            sig_pair = cl["signature"]
            sig = f"{sig_pair[0]}/{sig_pair[1]}" if sig_pair else ""
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
    parser.add_argument(
        "--output-plot",
        default=OUTPUT_PLOT,
        help=f"Path for the output graph image (default: {OUTPUT_PLOT})."
    )
    parser.add_argument(
        "--output-csv",
        default=OUTPUT_CSV,
        help=f"Path for the output CSV file (default: {OUTPUT_CSV})."
    )
    args = parser.parse_args()

    print("=" * 65)
    print("  HONEYPOT ATTACKER CLUSTERING  -  VERSION 4")
    print("  TF-IDF with Stopword Removal + Leiden Community Detection")
    print("=" * 65)
    print()

    records = load_data(args.input)
    pair_to_ips, ip_to_pairs, all_ips = build_mappings(records)
    idf = keep_useful_pairs(pair_to_ips, len(all_ips))
    G = build_graph(ip_to_pairs, all_ips, idf)
    partition = detect_communities(G)
    clusters = analyse_clusters(partition, ip_to_pairs, idf, records)
    visualise_graph(G, partition, args.output_plot)
    save_results(clusters, args.output_csv)

    print("\nDone.")


if __name__ == "__main__":
    main()
