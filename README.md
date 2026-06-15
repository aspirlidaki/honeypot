# Honeypot Attacker Clustering — Technical Report
Version 2 — TF-IDF Weighted Graph Analysis

| | |
|---|---|
| **Institution** | FORTH / C-SOC |
| **Honeypot** | Cowrie SSH (port 22) |
| **Data file** | `cowrie_ip_username_pass_anon.csv` |
| **Analysis date** | June 2026 |
| **Stack** | Python 3 · `networkx` · `python-louvain` · `matplotlib` |

---

## 1. Dataset

| Metric | Value |
|---|---|
| Total login attempts | 268,875 |
| Unique attacker IPs | 4,973 |
| Unique credential pairs | 40,474 |
| Pairs shared by more than one IP | 25,149 (62%) |

62% of credential pairs appear across multiple IPs — the statistical basis for clustering. Bots in the same botnet share the same credential dictionary; shared pairs are the signal.

---

## 2. Method

### Hypothesis
Two IPs that share many credential pairs are likely part of the same botnet. The rarer the shared pair, the stronger the signal.

### Pipeline

| Step | Operation |
|---|---|
| 1 | Load CSV → list of `(ip, username, password)` triples |
| 2 | Build `pair → IPs` and `IP → pairs` mappings (sets, so retries don't inflate counts) |
| 3 | Compute IDF per credential pair: `IDF = log(N / df)` |
| 4 | Build weighted graph: edge weight = sum of IDF scores of shared pairs, threshold ≥ 1.0 |
| 5 | Run Louvain community detection (`resolution=1.0`, `randomize=False`) |
| 6 | Extract signature credential per cluster (highest IDF-sum pair) |
| 7 | Visualise and export |

### IDF Weighting

```
IDF(pair) = log( N / df )

N  = 4,973   (total unique IPs)
df = number of IPs that tried this pair
```

| Credential pair | IPs | IDF | Signal strength |
|---|---|---|---|
| `345gs5662d34/345gs5662d34` | 2,791 | 0.578 | Very low |
| `root/3245gs5662d34` | 1,658 | 1.098 | Low |
| `root/@qwer2025` | 799 | 1.828 | Low–medium |
| `admin/admin` | 452 | 2.398 | Medium |
| `root/root` | 272 | 2.906 | Medium |
| `root/debian` | 184 | 3.298 | Medium–high |
| `root/123456` | 131 | 3.634 | Medium–high |
| `OPTIONS sip:.../Via: SIP/2.0/...` | ~24 | ~5.3 | High |
| `perl/warning` | 7 | 6.563 | High |
| `eth/ethereum12345` | 3 | 7.413 | Very high |
| Any pair used by exactly 1 IP | 1 | 8.512 | Maximum |

`MIN_EDGE_WEIGHT = 1.0`: the canary pair (IDF = 0.578) cannot form an edge alone, preventing the 9 canary sub-clusters from being artificially merged.

### Why Not Version 1

V1 used raw shared-pair count as edge weight. The credential `345gs5662d34/345gs5662d34` (used by 56% of IPs) connected over half the graph with equal weight to genuinely rare pairs, producing three artificial mega-clusters of 1,974 / 1,294 / 1,282 IPs.

Threshold sensitivity confirmed the problem was the weighting, not the cutoff:

| Min shared pairs | Edges | Communities | Largest cluster |
|---|---|---|---|
| 1 | 4,228,666 | 179 | 1,973 |
| 2 | 1,592,317 | 979 | 1,308 |
| 5 | 46,099 | 1,823 | 310 |
| 10 | 25,296 | 2,370 | 329 |
| 50 | 422 | 4,913 | 29 |

No stable threshold exists — IDF weighting is the correct fix.

---

## 3. Results

### V1 vs V2

| Metric | V1 | V2 |
|---|---|---|
| Edge weighting | Raw count | IDF sum |
| Largest cluster | 1,974 IPs | **856 IPs** |
| Clusters ≥ 10 IPs | 6 | **13** |
| Clusters ≥ 2 IPs | 21 | **29** |
| Artificial mega-clusters | 3 | **0** |
| Singletons | 159 | 159 |
| Total communities | 179 | **188** |

### Cluster Distribution

| Size | Count | Identity |
|---|---|---|
| 856 | 1 | Admin/Admin botnet |
| 556 | 1 | Canary sub-cluster A |
| 465 | 1 | Canary sub-cluster B |
| 432 | 1 | Canary sub-cluster C |
| 429 | 1 | Canary sub-cluster D |
| 384 | 1 | Canary sub-cluster E |
| 383 | 1 | Canary sub-cluster F |
| 372 | 1 | Debian-targeting botnet |
| 314 | 1 | Canary sub-cluster G |
| 254 | 1 | Canary sub-cluster H |
| 160 | 1 | HTTP/Go scanner |
| 141 | 1 | Ubuntu-targeting botnet |
| 24 | 1 | SIP/VoIP scanner |
| 8 | 1 | TLS binary probe |
| 7 | 1 | Perl exploit tool |
| 3 | 1 | Ethereum miner |
| 2 | 13 | Crypto-miner pairs (BTC/XMR/ETH) |
| 1 | 159 | Singletons |
| **Total** | **188** | |

### Graph

600-node sample of the largest connected component. Colour = community.

![Attacker Similarity Graph](attacker_graph.png)

---

## 4. Cluster Analysis

**Community 14 — Admin/Admin Botnet (856 IPs)**
Signature: `admin/admin` (IDF-sum = 1,060). Credential dictionary targets consumer routers, IP cameras, NAS devices, and single-board computers using factory-default credentials. Consistent with Mirai-style IoT scanning.

---

**Communities 7, 9, 6, 20, 10, 21, 4, 32, 1 — Canary Botnet Family (~3,358 IPs)**
Signature: `root/3245gs5662d34`. Nine sub-clusters unified by the canary credential `345gs5662d34/345gs5662d34`. TF-IDF separates them by secondary credential differences (likely deployment waves or geographic groups).

| Community | Size | Note |
|---|---|---|
| 7 | 556 | |
| 9 | 465 | |
| 6 | 432 | |
| 20 | 429 | |
| 10 | 384 | |
| 21 | 383 | |
| 4 | 314 | |
| 32 | 254 | |
| 1 | 141 | Signature: `ubuntu/Test123!` |

The canary string is a deliberate operator fingerprint — a nonsense value inserted to identify their bots in honeypot logs. Scale and technique indicate a professional threat actor.

---

**Community 2 — Debian-Targeting Botnet (372 IPs)**
Signature: `root/debian` (IDF-sum = 600). Targets Debian-based Linux servers with default root credentials (Debian, Ubuntu, Raspberry Pi OS).

---

**Community 13 — HTTP/Go Scanner (160 IPs)**
Signature: HTTP headers (`User-Agent: Mozilla/5.0`, `Accept: */*`) sent as SSH credentials. Not an SSH brute-force tool — a Go-based multi-protocol scanner probing port 22 for misconfigured HTTP servers or Redis instances.

---

**Community 46 — SIP/VoIP Scanner (24 IPs)**
Signature: `OPTIONS sip:nm SIP/2.0` / `Via: SIP/2.0/TCP nm;branch=foo`. All 24 IPs send the same 7-line SIP OPTIONS request. Target: VoIP PBX systems for toll fraud.

---

**Community 38 — TLS Binary Probe (8 IPs)**
Signature: Raw TLS ClientHello bytes (`\x16\x03\x03`). Probing port 22 for services accidentally running TLS (HTTPS, LDAPS).

---

**Community 101 — Perl Exploit Tool (7 IPs)**
Signature: `perl/warning` (IDF = 6.563). All 7 IPs try exactly this one pair. Fingerprint of a specific Perl-based exploit tool.

---

**Community 106 — Ethereum Miner (3 IPs)**
Signature: `eth/ethereum12345`. Attempting to install Ethereum mining software on compromised servers.

---

**Crypto-Miner Pairs — 13 clusters × 2 IPs**

| Username | Password | Currency |
|---|---|---|
| `admin` | `eth!123` | Ethereum |
| `wallet` | `wallet12345` | — |
| `wallet` | `wallet@12345` | — |
| `bitcoin` | `BTC#2025` | Bitcoin |
| `xmr` | `xmr%2025` | Monero |
| `xmr` | `XMR1234` | Monero |
| `bitcoin` | `bitcoin123` | Bitcoin |
| `eth` | `eth12345` | Ethereum |
| `xmr` | `xmr%123` | Monero |
| + 4 more | various | BTC/XMR/ETH |

Monero dominates: CPU-efficient RandomX mining and untraceable transactions make it the standard for illicit crypto-mining.

---

## 5. Threat Intelligence

**Canary credential = professional operator.** `345gs5662d34` across ~3,000 IPs in 9 sub-clusters is not accidental. The operator inserted it deliberately to fingerprint their fleet. Scale and technique rule out opportunistic actors.

**Port 22 captures non-SSH traffic.** HTTP scanners (160 IPs), SIP scanners (24 IPs), and TLS probers (8 IPs) were all captured. Attackers scan all open ports for any exploitable service.

**Crypto-mining is the primary motive.** At least 16 communities show explicit mining intent. Monero is preferred universally.

**IoT default credentials dominate.** The largest cluster (856 IPs) targets `admin/admin`, `root/debian`, `orangepi/orangepi` — factory defaults on routers, cameras, and embedded devices.

**Singletons are not lone attackers.** 159 IPs with no shared credentials may be low-activity bots, unique-wordlist operators (specifically designed to defeat clustering), researchers, or other honeypots.

---

## 6. Defensive Indicators

| Indicator | Action |
|---|---|
| SSH username or password = `345gs5662d34` | Block immediately — confirmed botnet traffic |
| SIP headers in SSH credentials | Block + alert — VoIP fraud scanner |
| `admin/admin`, `root/debian`, `orangepi/orangepi` | Enforce credential policy on all devices |
| Usernames `xmr`, `bitcoin`, `eth`, `wallet` | Alert — probable crypto-miner deployment |
| Go HTTP client User-Agent on port 22 | Block at firewall |

---

## 7. Next Steps

- **V3 — Cosine similarity edges:** represent each IP as a TF-IDF vector; use cosine similarity as edge weight. Normalises for credential list size — a high-volume bot that tried 10,000 pairs won't appear artificially similar to everyone.
- **Leiden algorithm:** replace Louvain. Leiden guarantees internally connected communities and finds more fine-grained structure.
- **GeoIP enrichment:** map sub-clusters geographically — are the 9 canary sub-clusters from distinct regions?
- **Timestamp analysis:** if available, correlate attack timing across clusters.
- **Multi-honeypot correlation:** combining logs from multiple sensors dramatically improves cluster resolution.

---

## 8. Output Files

| File | Description |
|---|---|
| `cluster_attackers.py` | Analysis script (V3, cosine similarity + Leiden) |
| `cluster_results.csv` | Every IP with community ID, cluster size, signature credential |
| `attacker_graph.png` | Graph visualisation (600-node sample) |
| `cowrie_ip_username_pass_anon.csv` | Raw honeypot data |

---

## 9. Version 3 — Mathematical Foundations

V3 replaces two components from V2: the edge weight formula and the community detection algorithm.

---

### 9.1 TF-IDF Vectors and Cosine Similarity

**The problem with V2's sum-of-IDF edges**

V2 set edge weight = $\sum_p \text{IDF}(p)$ over shared pairs. This is biased: an IP that tried 10,000 pairs accumulates high similarity scores with everyone because of volume, not because of genuine behavioural overlap.

**V3 edge weight: cosine similarity**

Each IP $i$ becomes a vector $\mathbf{v}_i$ where each dimension is one credential pair:

$$\mathbf{v}_i[p] = \begin{cases} \text{IDF}(p) & \text{if IP}_i \text{ tried pair } p \\ 0 & \text{otherwise} \end{cases}$$

The IDF formula is unchanged from V2:

$$\text{IDF}(p) = \log\!\left(\frac{N}{df_p}\right) \qquad N = 4{,}973 \text{ total IPs}, \quad df_p = \text{IPs that tried pair } p$$

The edge weight between two IPs is their **cosine similarity** — the angle between their vectors:

$$\text{edge}(a, b) = \cos(\mathbf{v}_a, \mathbf{v}_b) = \frac{\mathbf{v}_a \cdot \mathbf{v}_b}{\|\mathbf{v}_a\|\;\|\mathbf{v}_b\|}$$

$$\mathbf{v}_a \cdot \mathbf{v}_b = \sum_{p \,\in\, \text{shared}} \text{IDF}(p)^2 \qquad \|\mathbf{v}_i\| = \sqrt{\sum_p \mathbf{v}_i[p]^2}$$

Range: $0$ (completely different) to $1$ (identical credential sets). Because both vectors are divided by their lengths, volume is normalised out.

**Efficient computation via sparse matrix multiplication**

$$M[i, p] = \text{IDF}(p) \text{ if IP}_i \text{ tried } p, \text{ else } 0 \qquad (M \in \mathbb{R}^{4973 \times 40474}, \text{ sparse})$$

$$\hat{M} = \text{row-normalised } M \qquad \hat{M}[i,\,\cdot\,] = \frac{M[i,\,\cdot\,]}{\|M[i,\,\cdot\,]\|}$$

$$S = \hat{M}\,\hat{M}^\top \qquad S[i,j] = \cos(\mathbf{v}_i, \mathbf{v}_j)$$

This replaces the $O(\sum_p k_p^2)$ `itertools.combinations` loop from V2 — the canary pair alone ($k_p = 2{,}791$) previously generated ${\approx}3.9\text{M}$ Python iterations.

---

### 9.2 Modularity and the Leiden Algorithm

**What both Louvain and Leiden optimise**

Both algorithms maximise modularity $Q$:

$$Q = \frac{1}{2m}\sum_{i,j}\!\left[w_{ij} - \frac{k_i\,k_j}{2m}\right]\delta(c_i,\,c_j)$$

| Symbol | Meaning |
|---|---|
| $m$ | Total edge weight in the graph |
| $w_{ij}$ | Edge weight between nodes $i$ and $j$ (0 if no edge) |
| $k_i$ | Weighted degree of node $i$ (sum of its edge weights) |
| $\frac{k_i k_j}{2m}$ | Expected edge weight under a random null model |
| $\delta(c_i, c_j)$ | 1 if same community, 0 otherwise |

**Why Leiden replaces Louvain**

Louvain's local-move phase can produce **internally disconnected** communities — a known mathematical flaw (Traag et al., 2019). Leiden fixes this by inserting a refinement step after each aggregation that verifies and corrects connectivity, guaranteeing:

- Every community is internally connected.
- Communities satisfy a $\gamma$-separation criterion (minimum internal density relative to external connections).

---

### 9.3 V2 vs V3 Comparison

| Aspect | V2 | V3 |
|---|---|---|
| Edge weight | $\sum_p \text{IDF}(p)$ over shared pairs | $\cos(\mathbf{v}_a, \mathbf{v}_b)$ — normalised |
| Volume bias | Yes — high-volume IPs inflate weights | No — L2 normalisation removes it |
| Graph build method | `itertools.combinations` (O(k²) per pair) | Sparse matrix multiply ($\hat{M}\hat{M}^\top$) |
| Community algorithm | Louvain — may produce disconnected communities | Leiden — guarantees well-connected communities |
| Threshold | `MIN_EDGE_WEIGHT = 1.0` (raw IDF sum) | `MIN_COSINE_SIM = 0.10` (0–1 scale) |
