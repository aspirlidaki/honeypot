# honeypot-clustering

Botnet discovery from Cowrie SSH honeypot logs. Attacker IPs are clustered based
on the (username, password) credential pairs they attempt — bots in the same botnet
run the same attack software with the same credential list, so shared pairs reveal
group membership.

## Dataset

Cowrie SSH honeypot, FORTH / C-SOC. 268,875 login attempts from 4,973 unique IPs
across 40,474 unique credential pairs. IP addresses are anonymised (`IP_42`, etc.).

## Method

Each IP is represented as a TF-IDF vector in credential space. Cosine similarity
between vectors forms the edge weights of a graph. Leiden community detection then
finds groups of IPs with similar credential behaviour (probable botnets).

Full methodology, results, and algorithm explanations:
[clustering_report.md](clustering_report.md)

## Usage

```bash
pip install networkx scipy numpy leidenalg igraph matplotlib
python cluster_attackers.py
```

**Output files:**

| File | Contents |
|---|---|
| `cluster_results.csv` | Every IP with community ID, cluster size, and signature credential |
| `attacker_graph.png` | Graph visualisation coloured by community |

## Results (V3)

| Metric | Value |
|---|---|
| Total communities | 188 |
| Largest cluster | 856 IPs — Admin/Admin botnet |
| Clusters ≥ 10 IPs | 13 |
| Singletons (no shared credentials) | 159 |

Notable clusters: Mirai-style IoT scanner (856 IPs), canary botnet family
(~3,358 IPs across 9 sub-clusters), Debian-targeting botnet (372 IPs),
Go-based multi-protocol scanner (160 IPs), SIP/VoIP fraud scanner (24 IPs).
