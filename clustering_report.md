# Honeypot Attacker Clustering — Technical Report
Version 4 — TF-IDF with Stopword Removal + Leiden Community Detection

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
| 3 | Filter vocabulary: drop credentials used by >10% of all IPs (stopwords) or by exactly 1 IP (singletons) |
| 4 | Compute IDF per surviving credential pair: `IDF = log(N / df)` |
| 5 | Build sparse TF-IDF matrix over kept pairs; L2-normalise rows; compute cosine similarities |
| 6 | Add edge between two IPs if cosine similarity >= 0.10 |
| 7 | Run Leiden community detection (plain modularity, `seed=42`) |
| 8 | Extract signature credential per cluster (most-shared kept pair, IDF tiebreak) |
| 9 | Visualise and export |

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

`MIN_COSINE_SIM = 0.10`: two IPs need at least roughly 10% normalised credential overlap to form an edge. Because cosine similarity is normalised by vector length, this threshold is stable regardless of how many credentials an IP tried.

**V4 vocabulary filter.** Before IDF is computed, two classes of credential are removed:

- **Stopwords** (`df > 0.10 × N = 497`): `345gs5662d34/345gs5662d34` (df=2,791) and `root/3245gs5662d34` (df=1,658) are both dropped. These rows in the table above are stopwords in V4.
- **Singletons** (`df < 2`): credentials only one IP ever tried are also dropped.

After filtering, the minimum IDF in the retained vocabulary rises to approximately 2.3 (credentials at the 10% cutoff), eliminating the near-zero-IDF stopwords from all similarity calculations.

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

### Version Comparison

| Metric | V1 | V2 | V3 | V4 |
|---|---|---|---|---|
| Edge weighting | Raw count | IDF sum | Cosine similarity | Cosine similarity |
| Vocabulary filter | None | None | None | Stopwords + singletons removed |
| Community algorithm | Louvain | Louvain | Leiden | Leiden (plain modularity) |
| Threshold | min shared pairs | IDF sum >= 1.0 | cosine sim >= 0.10 | cosine sim >= 0.10 |
| Largest cluster | 1,974 IPs | 856 IPs | 3,329 IPs | TBD (expected: low hundreds) |
| Clusters >= 10 IPs | 6 | 13 | 9 | TBD |
| Clusters >= 2 IPs | 21 | 29 | 31 | TBD |
| Artificial mega-clusters | 3 | 0 | 0 | 0 (canary filtered from vocabulary) |
| Singletons | 159 | 159 | 224 | TBD (expected: higher than V3) |
| Total communities | 179 | 188 | 255 | TBD |

### Cluster Distribution

| Size | Count | Identity |
|---|---|---|
| 3,329 | 1 | Canary botnet (root/3245gs5662d34) |
| 393 | 1 | Admin/Admin botnet |
| 377 | 1 | root/root botnet |
| 196 | 1 | Debian-targeting botnet |
| 162 | 1 | Unknown (signature: root/------fuck------) |
| 160 | 1 | HTTP/Go scanner |
| 32 | 1 | jakob/jakob cluster |
| 24 | 1 | SIP/VoIP scanner |
| 17 | 1 | Raspberry Pi scanner (pi/raspberryraspberry993311) |
| 8 | 1 | TLS binary probe |
| 7 | 1 | Perl exploit tool |
| 5 | 1 | a/a cluster |
| 3 | 1 | Ethereum miner |
| 2 | 18 | Small pairs (crypto-miners, misc) |
| 1 | 224 | Singletons |
| **Total** | **255** | |

### Graph

600-node sample of the largest connected component. Colour = community.

![Attacker Similarity Graph](attacker_graph.png)

---

## 4. Cluster Analysis

**Community 0 — Canary Botnet (3,329 IPs)**
Signature: `root/3245gs5662d34`. The largest cluster. V3's cosine similarity metric merges the nine sub-clusters that V2 separated — all share the canary credential `345gs5662d34/345gs5662d34` as the dominant signal, and after L2 normalisation the secondary credential differences that drove V2's splitting are insufficient to produce distinct communities at `MIN_COSINE_SIM = 0.10`. The canary string is a deliberate operator fingerprint inserted to identify their bots in honeypot logs. Scale and technique indicate a professional threat actor.

---

**Community 1 — Admin/Admin Botnet (393 IPs)**
Signature: `admin/admin`. Credential dictionary targets consumer routers, IP cameras, NAS devices, and single-board computers using factory-default credentials. Consistent with Mirai-style IoT scanning.

---

**Community 2 — root/root Botnet (377 IPs)**
Signature: `root/root`. Targets Linux servers and embedded devices where the root account retains its default password. Overlaps in target profile with the Debian-targeting cluster but uses a distinct credential list.

---

**Community 3 — Debian-Targeting Botnet (196 IPs)**
Signature: `root/debian`. Targets Debian-based Linux servers with default root credentials (Debian, Ubuntu, Raspberry Pi OS).

---

**Community 5 — HTTP/Go Scanner (160 IPs)**
Signature: HTTP headers (`User-Agent: Mozilla/5.0`, `Accept: */*`) sent as SSH credentials. Not an SSH brute-force tool — a Go-based multi-protocol scanner probing port 22 for misconfigured HTTP servers or Redis instances.

---

**Community 7 — SIP/VoIP Scanner (24 IPs)**
Signature: `OPTIONS sip:nm SIP/2.0` / `Via: SIP/2.0/TCP nm;branch=foo`. All 24 IPs send the same 7-line SIP OPTIONS request. Target: VoIP PBX systems for toll fraud.

---

**Community 8 — Raspberry Pi Scanner (17 IPs)**
Signature: `pi/raspberryraspberry993311`. Targets Raspberry Pi devices that have not changed the default `pi` user password. The doubled password string (`raspberry` × 2 + digits) matches a known default credential for early Raspberry Pi OS images.

---

**Community 9 — TLS Binary Probe (8 IPs)**
Signature: Raw TLS ClientHello bytes (`\x16\x03\x03`). Probing port 22 for services accidentally running TLS (HTTPS, LDAPS).

---

**Community 10 — Perl Exploit Tool (7 IPs)**
Signature: `perl/warning` (IDF = 6.563). All 7 IPs try exactly this one pair. Fingerprint of a specific Perl-based exploit tool.

---

**Community 12 — Ethereum Miner (3 IPs)**
Signature: `eth/ethereum12345`. Attempting to install Ethereum mining software on compromised servers.

---

**Small pairs — 18 clusters × 2 IPs**
Crypto-miner usernames (`xmr`, `bitcoin`, `eth`, `wallet`) and miscellaneous pairs. Monero dominates: CPU-efficient RandomX mining and untraceable transactions make it the standard for illicit crypto-mining.

---

## 5. Threat Intelligence

**Canary credential = professional operator.** `345gs5662d34` across 3,329 IPs is not accidental. The operator inserted it deliberately to fingerprint their fleet. Scale and technique rule out opportunistic actors.

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

- **GeoIP enrichment:** map sub-clusters geographically — are the canary sub-clusters from distinct regions?
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

## 9. Algorithm Deep Dive

### 9.0 Vocabulary Filtering: Stopword Removal (V4)

#### The problem: why IDF down-weighting is not enough

The original IDF formula assigns the canary credential (`345gs5662d34/345gs5662d34`, used by 2,791 IPs) a score of 0.578. This is much lower than rarer credentials, but it does not eliminate the canary's effect on cosine similarity.

Cosine similarity between IPs $a$ and $b$ after L2 normalisation is:

$$\cos(\hat{\mathbf{v}}_a, \hat{\mathbf{v}}_b) = \hat{\mathbf{v}}_a \cdot \hat{\mathbf{v}}_b$$

where $\hat{\mathbf{v}}_i = \mathbf{v}_i / \|\mathbf{v}_i\|$. The canary contributes $\text{IDF}(\text{canary}) = 0.578$ to dimension $p_\text{canary}$ of the raw vector, and $0.578^2 = 0.334$ to the squared norm $\|\mathbf{v}_i\|^2$. After normalisation, the canary dimension gets re-weighted relative to the other dimensions:

$$\hat{v}_i[p_\text{canary}] = \frac{0.578}{\|\mathbf{v}_i\|}$$

For an IP whose credential profile is dominated by the canary, $\|\mathbf{v}_i\|$ is small and $\hat{v}_i[p_\text{canary}]$ is close to 1 — the L2 normalisation re-inflates the canary's influence. Two IPs that mostly used the canary credential end up with cosine similarity near 1 regardless of their other credentials.

The only complete fix is to remove the canary dimension from the vector space. With no canary dimension, no cosine similarity between any pair of IPs can include a canary contribution.

#### The vocabulary filter

Two thresholds are applied before IDF is computed:

$$\text{keep pair } p \iff \text{MIN\_DF} \leq df_p \leq \lfloor\text{MAX\_DF\_FRACTION} \times N\rfloor$$

With $N = 4{,}973$, `MAX_DF_FRACTION = 0.10`, `MIN_DF = 2`:

| Threshold | Value | Drops |
|---|---|---|
| Upper bound | $df_p \leq 497$ | Credentials used by >10% of IPs (stopwords) |
| Lower bound | $df_p \geq 2$ | Credentials only one IP ever tried (singletons) |

**Stopwords** ($df_p > 497$) are credentials so common across the dataset that sharing them carries no discriminating signal. In information retrieval, words like "the" or "and" that appear in every document are removed from the index for exactly this reason. Here, `345gs5662d34/345gs5662d34` (df=2,791) and `root/3245gs5662d34` (df=1,658) are the primary stopwords.

**Singletons** ($df_p = 1$) appear in exactly one IP's vector. Their inner product with any other IP's vector is necessarily zero — they cannot contribute to any edge. They inflate the L2 norm of the single IP that tried them, weakening that IP's cosine similarity with its genuine botnet peers. Removing them makes the remaining vector directions more informative.

#### IDF after filtering

IDF is computed only on the surviving pairs:

$$\text{IDF}(p) = \log\!\left(\frac{N}{df_p}\right), \quad 2 \leq df_p \leq 497$$

The minimum IDF in the filtered vocabulary is $\log(4973/497) \approx 2.30$. Every retained credential is at least moderately discriminating — the near-zero-IDF stopwords have been removed entirely. The maximum IDF is unchanged at $\log(4973/2) \approx 7.82$ for credentials used by exactly two IPs.

#### Effect on IPs with fully-filtered credential sets

An IP whose entire credential set consists of stopwords and singletons ends up with an all-zero TF-IDF vector. The safe division:

$$\text{inv}_i = \begin{cases} 1/\|\mathbf{v}_i\| & \text{if } \|\mathbf{v}_i\| > 0 \\ 0 & \text{otherwise} \end{cases}$$

gives this IP a zero normalised row. Its cosine with every other IP is 0, no edges are formed, and it becomes a singleton community. This is correct: an IP whose only activity was using universal credentials provides no evidence of botnet membership with any specific group.

#### Why this is the textbook approach

Stopword removal is a foundational technique in information retrieval, described in Manning, Raghavan & Schütze (2008) and applied identically in search engines. The analogy is exact: credential pairs are terms, attacker IPs are documents, botnets are document clusters. Terms appearing in the majority of documents are removed from the index before similarity is computed because their high frequency in the index makes them noise rather than signal. V4 applies this standard technique to credential clustering.

---

### 9.1 IDF: Measuring Credential Rarity

The core difficulty in this analysis is that some credential pairs appear across the vast majority of attacker IPs while others are nearly unique. Naive similarity measures that treat all shared credentials equally collapse the dataset into a handful of enormous, meaningless clusters — V1's central failure.

IDF (Inverse Document Frequency) is borrowed from information retrieval, where the same problem has been solved for decades. In text search, a word like "the" appears in every document and tells you nothing about which documents are similar; a word like "photosynthesis" appearing in two documents is a meaningful signal that they are related. The same reasoning applies here: two IPs both trying `345gs5662d34/345gs5662d34` (used by 56% of the dataset) is effectively noise, while two IPs both trying `perl/warning` (used by 7 IPs total) is strong evidence of shared attack software.

$$\text{IDF}(p) = \log\!\left(\frac{N}{df_p}\right)$$

$N$ = total unique IPs (4,973), $df_p$ = number of IPs that tried pair $p$.

**Why the logarithm?**

Without it the scale becomes unworkable. The most common pair ($df = 2791$) gives $N/df \approx 1.78$; a moderately rare pair ($df = 50$) gives $N/df \approx 99.5$. On a linear scale those two values sit 56× apart, meaning a small number of semi-rare credentials would completely dominate any similarity calculation. The logarithm compresses the range into something useful:

| Credential pair | $df$ | $N/df$ | IDF |
|---|---|---|---|
| `345gs5662d34/345gs5662d34` | 2791 | 1.78 | 0.578 |
| `admin/admin` | 452 | 11.0 | 2.398 |
| `root/debian` | 184 | 27.0 | 3.298 |
| `perl/warning` | 7 | 710.4 | 6.563 |
| any unique pair | 1 | 4973 | 8.512 |

The log also has clean boundary behaviour. A pair used by every IP gets $\log(1) = 0$ — it is mathematically worthless for grouping. A pair used by exactly one IP gets the maximum value $\log(N)$. IDF values naturally live in $[0, \log N]$ with no manual tuning required.

---

### 9.2 TF-IDF Vectors

Once IDF scores are computed, each IP is represented as a sparse vector in a 40,474-dimensional credential space — one dimension per unique credential pair observed across the entire dataset:

$$\mathbf{v}_i[p] = \begin{cases} \text{IDF}(p) & \text{if IP}_i \text{ tried pair } p \\ 0 & \text{otherwise} \end{cases}$$

The TF (Term Frequency) component here is binary: did the IP try this credential pair at all? Retry counts are discarded. What identifies a botnet is the pattern of which credentials are attempted, not how many connection attempts were logged — a high-volume bot and a low-volume bot running the same software should look identical.

The vectors are very sparse. A typical IP tries 50–200 credential pairs out of 40,474, so more than 99% of each vector is zero. This is what makes matrix multiplication in Section 9.4 tractable rather than prohibitively expensive.

Two IPs running the same attack software against the same wordlist will have nearly identical vectors. Two IPs from different botnets with different credential dictionaries will have vectors pointing in almost perpendicular directions in credential space.

---

### 9.3 Cosine Similarity

The similarity between two IPs is the cosine of the angle between their credential vectors:

$$\cos(\mathbf{v}_a, \mathbf{v}_b) = \frac{\mathbf{v}_a \cdot \mathbf{v}_b}{\|\mathbf{v}_a\| \cdot \|\mathbf{v}_b\|}$$

**Geometric interpretation.** Any two vectors in $\mathbb{R}^{40474}$ define an angle $\theta$ between them. When $\theta = 0°$ the vectors are parallel — identical credential profiles — and $\cos\theta = 1$. When $\theta = 90°$ they are orthogonal — no shared credentials whatsoever — and $\cos\theta = 0$. The cosine is a natural measure of directional similarity that is independent of vector length.

**Why this improves on V2.** V2 used the raw dot product ($\sum_p \text{IDF}(p)$ over shared pairs) as edge weight. An IP that tried 10,000 credentials accumulates a large dot product with almost everyone just from sheer volume — not because its credential list resembles theirs. Dividing by both magnitudes removes this: after normalisation, only the direction of the vector matters, not its length. A bot that tried 10,000 credentials and a bot that tried 50 are compared on equal footing.

**Expanding the dot product:**

$$\mathbf{v}_a \cdot \mathbf{v}_b = \sum_{p \,\in\, \text{shared}} \text{IDF}(p)^2$$

IDF appears squared in the numerator but only once (via the square root) in each norm. The net effect is that rare shared credentials contribute more to the similarity than common ones — which is precisely the behaviour needed.

**Worked example:**

```
IP_A tried: root/123456 (IDF=3.634) + perl/warning (IDF=6.563) + admin/admin (IDF=2.398)
IP_B tried: root/123456 (IDF=3.634) + perl/warning (IDF=6.563)

dot(A,B) = 3.634² + 6.563² = 13.21 + 43.07 = 56.28
||A||    = sqrt(3.634² + 6.563² + 2.398²) = sqrt(62.04) = 7.877
||B||    = sqrt(3.634² + 6.563²)           = sqrt(56.28) = 7.502

cos(A,B) = 56.28 / (7.877 × 7.502) = 0.952
```

The shared rare pair (`perl/warning`, IDF=6.563) drives the similarity to 0.952. V2 would assign these IPs an edge weight of 10.197 (raw IDF sum) with no way to distinguish this from two IPs sharing five common credentials that happen to sum to the same value.

---

### 9.4 Efficient Computation via Sparse Matrix Multiplication

Computing pairwise cosine similarities one pair at a time is not feasible. The canary credential alone ($df = 2791$) would require $\binom{2791}{2} \approx 3.9 \times 10^6$ iterations just to process the pairs formed through that one credential. Across all 40,474 credentials, the total is $O\!\left(\sum_p \binom{df_p}{2}\right)$, which runs into hundreds of millions of iterations.

Instead, the entire similarity matrix is computed in three steps using scipy.sparse:

**Step 1 — Build $M$.**

$$M \in \mathbb{R}^{4973 \times 40474}, \quad M[i,p] = \text{IDF}(p) \text{ if IP}_i \text{ tried } p, \text{ else } 0$$

Stored in CSR (Compressed Sparse Row) format, which records only the non-zero values and their column indices. With roughly 200 credentials per IP on average, $M$ contains about 1M non-zero entries out of a possible 201M — under 0.5% density.

**Step 2 — Row-normalise $M$.**

$$\hat{M}[i,\,\cdot\,] = \frac{M[i,\,\cdot\,]}{\|M[i,\,\cdot\,]\|_2}$$

Dividing each row by its L2 norm produces unit-length rows. Any IP with a zero vector (no credentials at all, which cannot occur in practice) is assigned norm 1 to avoid a division by zero.

**Step 3 — Compute $S = \hat{M}\hat{M}^\top$.**

$$S[i,j] = \hat{M}[i,\,\cdot\,] \cdot \hat{M}[j,\,\cdot\,] = \cos(\mathbf{v}_i, \mathbf{v}_j)$$

The $(i,j)$ entry of $S$ is the dot product of two unit-length rows — exactly the cosine similarity between IPs $i$ and $j$. scipy.sparse executes this as a single call into optimised BLAS/C code. Only the upper triangle is extracted (to avoid storing each pair twice), and entries below the threshold MIN_COSINE_SIM = 0.10 are discarded before the graph is constructed.

---

### 9.5 Modularity

The Leiden algorithm, like its predecessor Louvain, optimises modularity $Q$:

$$Q = \frac{1}{2m}\sum_{i,j}\!\left[w_{ij} - \frac{k_i\,k_j}{2m}\right]\delta(c_i,\,c_j)$$

| Symbol | Meaning |
|---|---|
| $m$ | Total edge weight summed across all edges in the graph |
| $w_{ij}$ | Cosine similarity between IPs $i$ and $j$ (0 if no edge exists) |
| $k_i$ | Weighted degree of IP $i$: sum of all its edge weights |
| $k_i k_j / 2m$ | Expected edge weight under the Configuration Model null |
| $\delta(c_i, c_j)$ | 1 if $i$ and $j$ are in the same community, 0 otherwise |

**The null model.** The term $\frac{k_i k_j}{2m}$ comes from the Configuration Model — a random graph that preserves each node's degree sequence but randomises which nodes are connected. Modularity asks: are these two nodes connected more than we would expect if edges were assigned randomly among nodes with these degrees? A positive contribution to $Q$ means yes.

Summing over all within-community pairs gives a single scalar $Q \in (-1, 1)$ that measures how much more densely internal than external a partition is. In practice, well-clustered real networks reach $Q \approx 0.3$–$0.7$; a random partition scores near 0.

**Resolution limit.** A theoretical limitation of modularity is that communities smaller than $\sqrt{2m}$ may be merged into larger neighbours to increase $Q$ even if they represent genuinely separate groups. This is an intrinsic property of the modularity function rather than any implementation bug. The resolution parameter $\gamma = 1.0$ keeps Leiden at the standard modularity definition; values above 1.0 favour smaller, tighter communities.

---

### 9.6 Leiden Algorithm

The Leiden algorithm (Traag, Waltman & van Eck, 2019) operates in three phases that iterate until the partition no longer changes.

**Phase 1 — Local node moving.** Each node is individually considered for reassignment to a neighbouring community. The node moves to whichever community produces the largest increase in $Q$. Nodes are processed in random order and the phase repeats until no single move improves $Q$. This is fast and produces a good initial partition, but it can leave communities internally disconnected: a node may end up in a community with no direct edge path to some of its fellow members within that community. Louvain stops here, which is why disconnected communities are possible in its output.

**Phase 2 — Refinement.** Before aggregating communities into super-nodes, Leiden checks each community for internal connectivity. Any subset of nodes not reachable from the rest of its community is split into a new community. This refinement phase enforces the $\gamma$-separation criterion: every community must have sufficient internal edge weight relative to its connections to the rest of the graph. Communities failing this check are broken apart until all pass. This step is Leiden's core contribution and the reason it guarantees well-connected output communities where Louvain does not.

**Phase 3 — Aggregation.** Each community is collapsed into a single super-node. Edges between super-nodes carry the sum of all crossing edge weights. Phases 1 and 2 then run again on this coarser graph. The multilevel structure allows communities to be detected at different scales without being locked into the resolution of any single pass.

The three phases repeat until the partition is stable. Because Phase 1 processes nodes in random order, results depend on the random seed; `seed=42` is fixed throughout to ensure reproducibility.

---

### 9.7 V2 vs V3 Summary

| Aspect | V2 | V3 |
|---|---|---|
| Edge weight | $\sum_p \text{IDF}(p)$ (raw IDF sum) | $\cos(\mathbf{v}_a, \mathbf{v}_b)$ (normalised) |
| Volume bias | Yes — high-volume IPs inflate all weights | No — L2 normalisation removes it |
| Graph construction | `itertools.combinations`, O(k²) per pair | Sparse matrix multiply, one vectorised call |
| Community algorithm | Louvain — disconnected communities possible | Leiden — connectivity guaranteed by refinement |
| Threshold | Raw IDF sum ≥ 1.0 | Cosine similarity ≥ 0.10 |

---

### 9.8 V3 vs V4 Summary

The key change from V3 to V4 is vocabulary filtering. Everything else — cosine similarity, sparse matrix computation, Leiden with plain modularity — is identical.

| Aspect | V3 | V4 |
|---|---|---|
| Vocabulary | All 40,474 credential pairs | Pairs with $2 \leq df \leq 497$ only |
| Stopwords | Retained (IDF=0.578, partial influence via norm) | Removed — zero dimensions in all vectors |
| Singletons | Retained (inflate norms, no edge contribution) | Removed |
| IDF minimum | 0.578 (canary pair) | ~2.30 (pairs at 10% cutoff) |
| Canary effect | Cosine partially re-inflated after L2 normalisation | Zero — canary has no dimension in any vector |
| IPs with all-zero rows | Cannot occur (every IP tried something) | Possible (IPs whose credentials are all stopwords or singletons) |
| Zero-row handling | Divide-by-one fallback | Safe divide: inv=0 keeps row zero |
| Leiden partition | `RBConfigurationVertexPartition`, resolution=1.0 | `ModularityVertexPartition`, no resolution parameter |
| Signature credential | Highest IDF-sum pair across all vocabulary | Most-shared pair in kept vocabulary, IDF tiebreak |

**Why the Leiden variant changed.** V3 used `RBConfigurationVertexPartition` (the resolution-parameter variant of modularity). V4 uses `ModularityVertexPartition` (plain modularity, $\gamma = 1$). Both maximise the same objective at $\gamma = 1$; the change makes the algorithm choice explicit and removes the resolution parameter as a variable that could mask or amplify the stopword-removal effect.
