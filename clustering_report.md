# Honeypot Attacker Clustering — Technical Report
Version 4 : TF-IDF with Stopword Removal + Leiden Community Detection

| | |
|---|---|
| **Institution** | FORTH / C-SOC |
| **Honeypot** | Cowrie SSH (port 22) |
| **Data file** | `cowrie_ip_username_pass_anon.csv` |
| **Analysis date** | June 2026 |
| **Stack** | Python 3 · `networkx` · `scipy.sparse` · `leidenalg` · `igraph` · `matplotlib` |

---

## 1. Dataset

| Metric | Value |
|---|---|
| Total login attempts | 268,875 |
| Unique attacker IPs | 4,973 |
| Unique credential pairs | 40,474 |
| Pairs shared by more than one IP | 25,149 (62%) |

62% of credential pairs appear across multiple IPs. Bots in the same botnet share the same credential dictionary, so shared rare pairs are the primary clustering signal.

---

## 2. Method

### Pipeline

| Step | Operation |
|---|---|
| 1 | Load CSV → `(ip, username, password)` triples |
| 2 | Build `pair → IPs` and `IP → pairs` mappings (sets, so retries don't inflate counts) |
| 3 | Filter vocabulary: drop stopwords (df > 10% of IPs) and singletons (df = 1) |
| 4 | Compute IDF per surviving pair: `IDF = log(N / df)` |
| 5 | Build sparse TF-IDF matrix; L2-normalise rows; compute cosine similarities |
| 6 | Add edge between IPs if cosine similarity ≥ 0.10 |
| 7 | Run Leiden community detection (plain modularity, `seed=42`) |
| 8 | Extract signature credential per cluster (most-shared kept pair, IDF tiebreak) |
| 9 | Visualise and export |

### IDF Weighting

`IDF(pair) = log(N / df)` where N = 4,973. Rare pairs score high; common pairs score low.

| Credential pair | IPs | IDF |
|---|---|---|
| `345gs5662d34/345gs5662d34` | 2,791 | 0.578 |
| `admin/admin` | 452 | 2.398 |
| `root/debian` | 184 | 3.298 |
| `perl/warning` | 7 | 6.563 |
| `eth/ethereum12345` | 3 | 7.413 |

**Stopwords** (df > 10% of IPs) are removed before IDF is computed. Sharing them carries no discriminating signal, and IDF alone cannot neutralise their effect: after L2 normalisation, a near-universal credential's dimension approaches 1.0 for any IP whose vector it dominates — the only complete fix is to remove it from the vector space. **Singletons** (df = 1) appear in only one vector, cannot contribute to any edge, and inflate that IP's norm, weakening its cosine similarity to genuine botnet peers. After filtering, minimum IDF rises to ~2.30.

---

## 3. Results

### Version Comparison

| Metric | V1 | V2 | V3 | V4 |
|---|---|---|---|---|
| Edge weighting | Raw count | IDF sum | Cosine | Cosine |
| Vocabulary filter | None | None | None | Stopwords + singletons |
| Community algorithm | Louvain | Louvain | Leiden | Leiden |
| Threshold | min shared pairs | IDF sum ≥ 1.0 | cosine ≥ 0.10 | cosine ≥ 0.10 |
| Largest cluster | 1,974 | 856 | 3,329 | 3,367 |
| Clusters ≥ 10 IPs | 6 | 13 | 9 | 10 |
| Clusters ≥ 2 IPs | 21 | 29 | 31 | 29 |
| Singletons | 159 | 159 | 224 | 186 |
| Total communities | 179 | 188 | 255 | 215 |

### Cluster Distribution (V4)

| Size | Count | Identity |
|---|---|---|
| 3,367 | 1 | Canary-adjacent botnet (`ubuntu/3245gs5662d34`) |
| 393 | 1 | Admin/Admin botnet |
| 379 | 1 | root/root botnet |
| 197 | 1 | Debian-targeting botnet |
| 161 | 1 | Unknown (`root/------fuck------`) |
| 135 | 1 | HTTP/Chrome-UA scanner |
| 34 | 1 | root/Abcd1234 cluster |
| 25 | 1 | Go-http-client scanner |
| 24 | 1 | SIP/VoIP scanner |
| 17 | 1 | Raspberry Pi scanner |
| 8 | 1 | TLS binary probe |
| 7 | 1 | Perl exploit tool |
| 7 | 1 | a/a cluster |
| 3 | 1 | Ethereum miner |
| 2 | 15 | Small credential-sharing pairs |
| 1 | 186 | Singletons |

![Attacker Similarity Graph](attacker_graph.png)

---

## 4. Cluster Analysis

**Community 0 — Canary-Adjacent Botnet (3,367 IPs)**
Signature: `ubuntu/3245gs5662d34`. The two primary canary credentials are removed as stopwords in V4, so the community is identified by a less-common variant that survived filtering. The canary string is a deliberate fingerprint inserted by the operator to identify their fleet in honeypot logs. Scale and technique point to a professional threat actor.

---

**Community 1 — Admin/Admin Botnet (393 IPs)**
Signature: `admin/admin`. Targets consumer routers, IP cameras, NAS devices, and single-board computers with factory-default credentials. Consistent with Mirai-style IoT scanning.

---

**Community 2 — root/root Botnet (377 IPs)**
Signature: `root/root`. Targets Linux servers and embedded devices where the root account still has its default password. Similar target profile to Community 3 but distinct credential lists.

---

**Community 3 — Debian-Targeting Botnet (196 IPs)**
Signature: `root/debian`. Targets Debian-based systems (Debian, Ubuntu, Raspberry Pi OS) with default root credentials.

---

**Communities 5 & 7 — HTTP/Go Scanner (135 + 25 IPs)**
V3's single 160-IP Go scanner splits into two groups after stopword removal. Community 5 (135 IPs) uses a full Chrome-like User-Agent; Community 7 (25 IPs) uses only `Go-http-client/1.1`. Both send HTTP headers as SSH credentials — multi-protocol scanners probing port 22 for misconfigured HTTP or Redis services. The common credential that previously masked the distinction is now removed.

**Community 6 — root/Abcd1234 Cluster (34 IPs)**
Signature: `root/Abcd1234`. First visible in V4 after stopword removal. The password follows a guessable pattern (capitalised word + digits), consistent with credential-stuffing tools operating from leaked-password dictionaries.

---

**Community 7 — SIP/VoIP Scanner (24 IPs)**
Signature: `OPTIONS sip:nm SIP/2.0`. All 24 IPs send the same 7-line SIP OPTIONS request as SSH credentials, targeting VoIP PBX systems for toll fraud.

---

**Community 8 — Raspberry Pi Scanner (17 IPs)**
Signature: `pi/raspberryraspberry993311`. Targets Raspberry Pi devices with the default `pi` credentials from early Raspberry Pi OS images.

---

**Community 9 — TLS Binary Probe (8 IPs)**
Signature: Raw TLS ClientHello bytes (`\x16\x03\x03`). Probing port 22 for services accidentally running TLS (HTTPS, LDAPS, etc.).

---

**Community 10 — Perl Exploit Tool (7 IPs)**
Signature: `perl/warning` (IDF = 6.563). All 7 IPs try exactly this one pair — the fingerprint of a specific Perl-based exploit tool.

---

**Community 12 — Ethereum Miner (3 IPs)**
Signature: `eth/ethereum12345`. Attempting to install Ethereum mining software on compromised servers.

---

**Small pairs — 15 clusters × 2 IPs**
Crypto-miner usernames (`xmr`, `bitcoin`, `eth`, `wallet`) and miscellaneous pairs. Monero is the most common target — its CPU-friendly RandomX algorithm and untraceable transactions make it the standard choice for illicit mining.

---

## 5. Threat Intelligence

The canary credential (`345gs5662d34`) appearing across 3,367 IPs is a deliberate fingerprint: inserting a recognisable string into a botnet's credential dictionary lets operators identify their fleet in honeypot logs. Scale rules out opportunistic actors.

Port 22 captured traffic never intended for SSH — HTTP scanners, SIP scanners, and TLS probers all appear because attackers routinely probe all open ports for any exploitable service. Crypto-mining is the dominant observed motive; at least 16 communities show explicit mining intent, with Monero consistently preferred.

IoT default credentials (`admin/admin`, `root/debian`) dominate the largest clusters, reflecting how many embedded devices remain unpatched. The 186 singleton IPs may be low-activity bots, operators using unique per-machine wordlists to defeat clustering, researchers, or other honeypots — they cannot be assigned to any botnet from this data alone.

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

- **GeoIP enrichment:** map sub-clusters geographically — are canary sub-clusters from distinct regions?
- **Timestamp analysis:** correlate attack timing across clusters if timestamps are available.
- **Multi-honeypot correlation:** combining logs from multiple sensors significantly improves cluster resolution.

---

## 8. Output Files

| File | Description |
|---|---|
| `cluster_attackers.py` | Analysis script (V4) |
| `cluster_results.csv` | Every IP with community ID, cluster size, signature credential |
| `attacker_graph.png` | Graph visualisation (600-node sample) |
| `cowrie_ip_username_pass_anon.csv` | Raw honeypot data |

---

## 9. Algorithm Deep Dive

### 9.0 Vocabulary Filtering (V4)

**Why IDF alone is not enough**

For an IP that tried only the canary pair (`345gs5662d34/345gs5662d34`, IDF = 0.578):

$$\hat{v}_a[\text{canary}] = \frac{0.578}{\|\mathbf{v}_a\|} = \frac{0.578}{0.578} = 1.0$$

After L2 normalisation, the canary dimension is 1.0 — its maximum. Any other IP sharing the canary gets a non-zero cosine with IP $a$, regardless of whether their other credentials match. If they share any additional common credential, the cosine exceeds 0.10 and a spurious edge forms. The only complete fix is to remove the dimension entirely.

**Vocabulary filter**

$$\text{keep pair } p \iff 2 \leq df_p \leq \lfloor 0.10 \times N \rfloor = 497$$

Three stopwords dropped: `345gs5662d34/345gs5662d34` (df=2,791), `root/3245gs5662d34` (df=1,658), `root/@qwer2025` (df=799). After filtering, 25,146 pairs remain; minimum IDF ≈ 2.30.

IPs whose entire credential set is filtered become all-zero vectors, handled by a safe divide:

$$\text{inv}_i = \begin{cases} \|\mathbf{v}_i\|^{-1} & \|\mathbf{v}_i\| > 0 \\ 0 & \text{otherwise} \end{cases}$$

Zero-norm IPs form no edges and become singleton communities — correct, since their only activity was universal credentials that provide no evidence of botnet membership.

---

### 9.1 IDF

$$\text{IDF}(p) = \log\!\left(\frac{N}{df_p}\right), \quad N = 4{,}973$$

The log compresses a ratio range of 1.78–4,973 into a workable scale of 0.578–8.512. A pair used by every IP scores 0; a pair used by one IP scores $\log(N)$. Values fall naturally in $[0, \log N]$ with no manual tuning.

| $df$ | IDF | Example |
|---|---|---|
| 2,791 | 0.578 | `345gs5662d34/345gs5662d34` |
| 452 | 2.398 | `admin/admin` |
| 184 | 3.298 | `root/debian` |
| 7 | 6.563 | `perl/warning` |
| 1 | 8.512 | any unique pair |

---

### 9.2 TF-IDF Vectors

Each IP is a sparse vector with one dimension per credential pair:

$$\mathbf{v}_i[p] = \begin{cases} \text{IDF}(p) & \text{if IP}_i \text{ tried pair } p \\ 0 & \text{otherwise} \end{cases}$$

TF is binary — whether a pair was tried, not how many times. A typical IP tries 50–200 distinct pairs out of 40,474, giving >99% sparsity. Two IPs running the same attack tool will have nearly identical vectors; two IPs from different botnets will point in nearly perpendicular directions in this high-dimensional space.

---

### 9.3 Cosine Similarity

$$\cos(\mathbf{v}_a, \mathbf{v}_b) = \frac{\mathbf{v}_a \cdot \mathbf{v}_b}{\|\mathbf{v}_a\| \cdot \|\mathbf{v}_b\|}, \quad \text{where } \mathbf{v}_a \cdot \mathbf{v}_b = \sum_{p \,\in\, \text{shared}} \text{IDF}(p)^2$$

Dividing by both magnitudes removes volume bias — a bot with 10,000 attempts and one with 50 are compared on the same scale.

**Example:**
```
IP_A: root/123456 (3.634) + perl/warning (6.563) + admin/admin (2.398)
IP_B: root/123456 (3.634) + perl/warning (6.563)

dot(A,B) = 3.634² + 6.563² = 56.28
||A||    = sqrt(56.28 + 2.398²) = 7.877
||B||    = sqrt(56.28) = 7.502
cos(A,B) = 56.28 / (7.877 × 7.502) = 0.952
```

The rare shared pair (`perl/warning`, IDF=6.563) drives similarity to 0.952. Under V2, these IPs would get the same raw IDF-sum edge weight as two IPs sharing ten common credentials summing to 10.2 — cosine similarity distinguishes the two cases.

---

### 9.4 Efficient Computation via Sparse Matrix Multiplication

Computing similarities pair-by-pair is infeasible: the canary pair (df=2,791) alone generates ~3.9 × 10⁶ pairs. Instead, three steps:

**Step 1 — Build** $M \in \mathbb{R}^{N \times P}$ where $M[i,p] = \text{IDF}(p)$ if IP$_i$ tried $p$, else 0. Stored in CSR format; ~1 million non-zeros out of ~200 million possible entries.

**Step 2 — Normalise** each row: $\hat{M}[i,\cdot] = M[i,\cdot] / \|M[i,\cdot]\|_2$.

**Step 3 — Multiply:** $S = \hat{M}\hat{M}^\top$. Entry $S[i,j]$ equals $\cos(\mathbf{v}_i, \mathbf{v}_j)$. `scipy.sparse` executes this as a single BLAS call. Only the upper triangle is extracted, and entries below MIN\_COSINE\_SIM = 0.10 are discarded before the graph is built.

---

### 9.5 Modularity

Leiden maximises modularity $Q$:

$$Q = \frac{1}{2m}\sum_{i,j}\!\left[w_{ij} - \frac{k_i\,k_j}{2m}\right]\delta(c_i,\,c_j)$$

| Symbol | Meaning |
|---|---|
| $m$ | Total edge weight |
| $w_{ij}$ | Cosine similarity (0 if no edge) |
| $k_i k_j / 2m$ | Expected weight under a random null model (Configuration Model) |
| $\delta(c_i, c_j)$ | 1 if $i,j$ are in the same community |

$Q > 0$ means community members are more connected than chance predicts. Well-clustered networks reach $Q \approx 0.3$–$0.7$. **Known limitation:** communities smaller than $\sqrt{2m}$ may be merged into larger neighbours to increase $Q$ even when genuinely distinct — a property of the modularity objective itself. Resolution parameter $\gamma = 1.0$ throughout (standard modularity).

---

### 9.6 Leiden Algorithm

Three phases run repeatedly until stable:

1. **Local moving.** Each node moves to the neighbouring community giving the largest $Q$ gain. Repeats until no single move helps. Can leave communities internally disconnected — this is where Louvain stops.

2. **Refinement.** Before collapsing communities into super-nodes, Leiden checks internal connectivity and splits any disconnected subsets. Every surviving community is guaranteed internally reachable. This is the key difference from Louvain.

3. **Aggregation.** Each community collapses to a super-node; cross-community edges carry total original weight. Phases 1–2 repeat on the coarser graph. This multilevel structure enables detection of communities at different scales.

`seed=42` fixes random node ordering for reproducibility.

---

### 9.7 V2 vs V3

| Aspect | V2 | V3 |
|---|---|---|
| Edge weight | $\sum_p \text{IDF}(p)$ (raw IDF sum) | $\cos(\mathbf{v}_a, \mathbf{v}_b)$ (normalised) |
| Volume bias | Yes — high-volume IPs inflate all weights | No — L2 normalisation removes it |
| Graph construction | `itertools.combinations`, O(k²) per pair | Sparse matrix multiply, one vectorised call |
| Community algorithm | Louvain — disconnected communities possible | Leiden — connectivity guaranteed |
| Threshold | IDF sum ≥ 1.0 | cosine ≥ 0.10 |

---

### 9.8 V3 vs V4

The only change from V3 to V4 is vocabulary filtering.

| Aspect | V3 | V4 |
|---|---|---|
| Vocabulary | All 40,474 pairs | Pairs with $2 \leq df \leq 497$ |
| Stopwords | Retained (IDF=0.578, partial cosine influence) | Removed — zero dimensions in all vectors |
| Singletons | Retained | Removed |
| IDF minimum | 0.578 | ~2.30 |
| IPs with all-zero rows | Cannot occur | Possible; become singletons |
| Zero-row handling | Divide-by-one fallback | Safe divide: inv=0 keeps row zero |
| Leiden variant | `RBConfigurationVertexPartition`, γ=1.0 | `ModularityVertexPartition` (plain modularity) |
| Signature method | Highest IDF-sum pair | Most-shared kept pair, IDF tiebreak |

Both Leiden variants maximise the same $Q$ at $\gamma = 1$. The switch makes the algorithm choice explicit and ensures vocabulary filtering — not a resolution change — is the single variable between V3 and V4.
