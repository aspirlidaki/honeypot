# Botnet Discovery via SSH Honeypot Credential Clustering

Unsupervised identification of botnet membership from Cowrie SSH honeypot logs. Attacker IP addresses are clustered by the (username, password) credential pairs they attempt; bots belonging to the same botnet run identical attack software with the same credential dictionary, so shared pairs serve as evidence of group membership.

## Dataset

| Property | Value |
|---|---|
| Source | Cowrie SSH honeypot, FORTH / C-SOC |
| Total login attempts | 268,875 |
| Unique attacker IPs | 4,973 |
| Unique credential pairs | 40,474 |
| Pairs shared by more than one IP | 25,149 (62%) |

IP addresses are anonymised (`IP_42`, etc.). The 62% shared-pair rate provides the statistical basis for clustering.

## Method

Each attacker IP is represented as a sparse TF-IDF vector in a credential-pair feature space. The pipeline proceeds in four stages:

1. **Vocabulary filtering.** Credential pairs used by more than 10% of all IPs are removed as stopwords — they are too prevalent to discriminate between botnets, and their presence in all vectors causes L2 normalisation to re-inflate their influence even after IDF down-weighting. Credential pairs used by exactly one IP (singletons) are also removed: they contribute no inter-IP signal and inflate vector norms without informing any edge weight.

2. **TF-IDF weighting.** Each surviving credential pair is assigned an IDF score of `log(N / df)`, where *N* = 4,973 and *df* is the number of IPs that attempted it. Rare pairs receive high scores; pairs at the 10% cutoff receive the minimum retained score of 2.398.

3. **Cosine similarity graph.** The IDF-weighted vectors are L2-normalised and the full similarity matrix is computed via sparse matrix multiplication (`M̂ · M̂ᵀ`). An undirected edge is placed between two IPs if their cosine similarity exceeds 0.10. This threshold requires at least roughly 10% normalised credential overlap and is stable regardless of the number of credentials each IP attempted.

4. **Community detection.** Leiden community detection with plain modularity (`ModularityVertexPartition`, seed = 42) partitions the graph into communities of IPs with similar credential behaviour. Leiden's refinement phase guarantees that every output community is internally well-connected, which Louvain does not.

Full methodology, mathematical derivations, and per-community threat analysis: [clustering_report.md](clustering_report.md)

## Reproducing the Results

```bash
pip install -r requirements.txt
python cluster_attackers.py
```

| Output file | Contents |
|---|---|
| `cluster_results.csv` | Every IP with community ID, cluster size, and signature credential |
| `attacker_graph.png` | Graph visualisation of the largest connected component, coloured by community |

## Results

### Vocabulary statistics (V4)

Three stopwords were identified and removed (df > 497):

| Credential | IPs using it | Fraction |
|---|---|---|
| `345gs5662d34/345gs5662d34` | 2,791 | 56.1% |
| `root/3245gs5662d34` | 1,658 | 33.3% |
| `root/@qwer2025` | 799 | 16.1% |

After removing 3 stopwords and 15,325 singletons, **25,146 credential pairs** are retained for analysis (IDF range: 2.398 – 7.819).

### Clustering summary

| Metric | Value |
|---|---|
| Total communities | 215 |
| Largest community | 3,367 IPs |
| Communities ≥ 10 IPs | 10 |
| Communities of 2–9 IPs | 29 |
| Singletons (isolated IPs) | 186 |

### Community inventory

| Size | Signature credential | Interpretation |
|---|---|---|
| 3,367 | `ubuntu/3245gs5662d34` | Canary-family botnet |
| 393 | `admin/admin` | IoT default-credential scanner (Mirai-style) |
| 379 | `root/root` | Linux server default-credential scanner |
| 197 | `root/debian` | Debian/Ubuntu-targeting botnet |
| 161 | `root/------fuck------` | Unknown botnet |
| 135 | Chrome-like HTTP User-Agent | Multi-protocol Go scanner (Chrome UA variant) |
| 34 | `root/Abcd1234` | Credential-stuffing tool (leaked-password dictionary) |
| 25 | `User-Agent: Go-http-client/1.1` | Multi-protocol Go scanner (bare client variant) |
| 24 | SIP OPTIONS request | VoIP/PBX fraud scanner |
| 17 | `pi/raspberryraspberry993311` | Raspberry Pi default-credential scanner |
| 8 | Raw TLS ClientHello bytes | TLS service probe on port 22 |
| 7 | `perl/warning` | Perl-based exploit tool |
| 7 | `a/a` | Minimal brute-force tool |
| 3 | `eth/ethereum12345` | Ethereum mining deployment |
| 2 × 15 | Various crypto-miner usernames | Small credential-sharing pairs |
| 1 × 186 | — | Isolated IPs (no shared credentials after filtering) |

### Version comparison

| Metric | V1 | V2 | V3 | **V4** |
|---|---|---|---|---|
| Edge weighting | Raw shared-pair count | IDF sum | Cosine similarity | Cosine similarity |
| Vocabulary filter | None | None | None | **Stopwords + singletons** |
| Community algorithm | Louvain | Louvain | Leiden | **Leiden (plain modularity)** |
| Total communities | 179 | 188 | 255 | **215** |
| Largest community | 1,974 IPs | 856 IPs | 3,329 IPs | **3,367 IPs** |
| Communities ≥ 10 IPs | 6 | 13 | 9 | **10** |
| Singletons | 159 | 159 | 224 | **186** |
