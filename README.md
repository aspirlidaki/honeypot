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
pip install -r requirements.txt
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
| Total communities | 255 |
| Largest cluster | 3,329 IPs — Canary botnet (root/3245gs5662d34) |
| Clusters ≥ 10 IPs | 9 |
| Singletons (no shared credentials) | 224 |

Notable clusters: Canary botnet (3,329 IPs), Admin/Admin botnet (393 IPs),
root/root botnet (377 IPs), Debian-targeting botnet (196 IPs),
Go-based multi-protocol scanner (160 IPs), SIP/VoIP fraud scanner (24 IPs),
Raspberry Pi scanner (17 IPs), Perl exploit tool (7 IPs).
