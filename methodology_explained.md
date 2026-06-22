# Understanding the Botnet Clustering — From V1 to V2 and Beyond

**What this document is:**
A plain-language explanation of every decision we made, every version we tried, what worked, what did not, and what the correct approach looks like.

**The goal:**
Find groups of attackers who are **working together** — i.e., find the **botnets**.

---

## Part 1 — The Problem We Are Solving

**What is a botnet, in one sentence?**
A botnet is a group of computers (bots) all **running the same attack software**, controlled by the same person or group. They all try the same usernames and passwords because they all share the same list.

**How does our honeypot help?**
Our SSH honeypot sits on port 22 and records every login attempt:

```
IP_5   tried:  root / 123456
IP_5   tried:  admin / admin
IP_23  tried:  root / 123456
IP_23  tried:  admin / admin
IP_23  tried:  root / password
```

Because IP_5 and IP_23 both tried `root/123456` AND `admin/admin`, they are probably running the same attack tool — probably **the same botnet**.

**The key insight:**
**If two IPs try the same unusual password combination, they are almost certainly part of the same botnet.**

The word **unusual** matters a lot — and it is exactly where V1 fails and V2 improves.

---

## Part 2 — Version 1: What We Did and Why It Wasn't Enough

**The idea behind V1:**
We built a **graph**:
- Every attacker IP = a dot (node)
- Two IPs that share a credential pair = connected by a line (edge)
- The **weight** on the line = how many pairs they share

Then we ran the **Louvain algorithm** to find tightly-connected groups of dots. Each group = one probable botnet.

**V1 in plain English:**
"The more passwords two IPs have in common, the more similar they are."

**What V1 produced:**

| Cluster | Size | Top credential |
|---|---|---|
| Mega-botnet A | **1,974 IPs** | `345gs5662d34 / 345gs5662d34` |
| Mega-botnet B | **1,294 IPs** | `root / 123456` |
| Mega-botnet C | **1,282 IPs** | `345gs5662d34 / 345gs5662d34` |
| HTTP scanner | 160 IPs | HTTP headers |
| SIP scanner | 24 IPs | SIP protocol messages |
| + 175 tiny clusters | 1–38 IPs | various |

Three clusters contained **91% of all 4,973 IPs**. That is a red flag.

**Why V1 was unreliable — the "common word" problem:**

Imagine you want to find groups of friends by looking at what words they use in messages. If you find that two people both used the word "the" — that tells you nothing. Everyone uses "the". But if two people both used the very specific phrase "meet at the usual spot behind the old lighthouse at 3am" — that is a strong signal they know each other.

V1 treated **all credentials equally**. The credential `345gs5662d34 / 345gs5662d34` was used by **2,791 out of 4,973 IPs = 56% of all attackers**. In V1, this single pair connected over half the dataset with equal weight to genuinely rare pairs. The result: three enormous fake mega-clusters.

**The threshold experiment:**

We tested what happens when we require IPs to share more than 1 pair to be connected:

| Min shared pairs | Edges | Communities | Largest cluster | Singletons |
|---|---|---|---|---|
| **1** | 4,228,666 | 179 | **1,973** | 159 |
| **2** | 1,592,317 | 979 | 1,308 | 961 |
| **5** | 46,099 | 1,823 | 310 | 1,796 |
| **10** | 25,296 | 2,370 | 329 | 2,343 |
| **20** | 11,858 | 3,003 | 203 | 2,976 |
| **50** | 422 | 4,913 | 29 | 4,892 |

**There is no stable sweet spot.** Every threshold gives a radically different answer. This told us the problem was not the threshold — it was the weighting itself. Common credentials need to be down-weighted, not blocked by a hard cut-off.

---

## Part 3 — Version 2: The TF-IDF Fix

**The idea borrowed from text analysis:**

In information retrieval (Google, document search), this exact problem was solved decades ago with **TF-IDF** (Term Frequency – Inverse Document Frequency).

The logic:
- A word that appears in every document ("the", "and") tells you nothing about which documents are similar — give it a **low weight**
- A word that appears in only 3 documents — if two documents share it, that is very meaningful — give it a **high weight**

We applied this to credentials:
- **"Document"** = an attacker IP address
- **"Word"** = a (username, password) pair
- **IDF score** = how rare is this credential across all IPs?

**The IDF formula:**

```
IDF(credential) = log( total number of IPs / number of IPs that used this credential )
```

**What this gives us in practice:**

| Credential pair | Used by | IDF score | What it means |
|---|---|---|---|
| `345gs5662d34 / 345gs5662d34` | 2,791 IPs (56%) | **0.578** | Nearly useless for grouping |
| `root / 3245gs5662d34` | 1,658 IPs (33%) | **1.098** | Weak signal |
| `admin / admin` | 452 IPs (9%) | **2.398** | Moderate signal |
| `root / root` | 272 IPs (5.5%) | **2.906** | Moderate signal |
| `perl / warning` | 7 IPs (0.14%) | **6.563** | Very strong signal |
| Any pair used by 1 IP | 1 IP | **8.512** | Maximum — but useless (no partner to compare with) |

**How V2 builds the graph differently:**

In V2, the **edge weight** between two IPs = **sum of IDF scores** of all their shared credentials.

Worked example:

```
IP_A tried: root/123456 (IDF=3.6)  and  perl/warning (IDF=6.6)
IP_B tried: root/123456 (IDF=3.6)  and  perl/warning (IDF=6.6)
IP_C tried: root/123456 (IDF=3.6)  and  admin/admin  (IDF=2.4)

V1 weights:
  A-B: 2  (2 shared pairs)
  A-C: 1  (1 shared pair)

V2 weights:
  A-B: 3.6 + 6.6 = 10.2  (strong link — rare shared pair)
  A-C: 3.6        =  3.6  (weak link — only common pair)
```

Louvain now correctly puts A and B in the same community (strong link), while A-C and B-C remain weakly connected.

**What V2 produced:**

| Cluster | Size | Signature (highest-IDF pair) |
|---|---|---|
| Admin/Admin botnet | **856 IPs** | `admin / admin` |
| Canary sub-cluster A | 556 IPs | `root / 3245gs5662d34` |
| Canary sub-cluster B | 465 IPs | `root / 3245gs5662d34` |
| Canary sub-cluster C | 432 IPs | `root / 3245gs5662d34` |
| Canary sub-cluster D | 429 IPs | `root / 3245gs5662d34` |
| Canary sub-cluster E | 384 IPs | `root / 3245gs5662d34` |
| Canary sub-cluster F | 383 IPs | `root / 3245gs5662d34` |
| Debian-targeting botnet | 372 IPs | `root / debian` |
| Canary sub-cluster G | 314 IPs | `root / 3245gs5662d34` |
| Canary sub-cluster H | 254 IPs | `root / 3245gs5662d34` |
| HTTP/Go scanner | 160 IPs | HTTP headers |
| Ubuntu-targeting botnet | 141 IPs | `ubuntu / Test123!` |
| SIP/VoIP scanner | 24 IPs | SIP protocol headers |
| TLS binary probe | 8 IPs | Raw TLS bytes |
| Perl exploit tool | 7 IPs | `perl / warning` |
| Ethereum miner | 3 IPs | `eth / ethereum12345` |
| 13 crypto-miner pairs | 2 IPs each | `xmr`, `bitcoin`, `eth` variants |
| 159 singletons | 1 IP each | No shared credentials with anyone |

**V1 vs V2 — the key numbers:**

| What changed | V1 | V2 | Better? |
|---|---|---|---|
| Largest cluster | 1,974 IPs | **856 IPs** | Yes — more realistic |
| Clusters >= 10 IPs | 6 | **13** | Yes — more resolved |
| Clusters >= 2 IPs | 21 | **29** | Yes — more botnets found |
| Former mega-clusters | 3 giant blobs | **Broken into sub-botnets** | Yes |
| Singletons | 159 | 159 | Same |
| Total communities | 179 | 188 | More fine-grained |

**What V2 still gets wrong:**

1. ~~**The canary pair (IDF=0.578) still creates edges**~~ — **Fixed.** `MIN_EDGE_WEIGHT` raised to `1.0`. The canary pair alone (IDF=0.578) can no longer form an edge by itself.
2. **Louvain has a resolution limit** — it mathematically cannot find communities below a certain size relative to the total graph. Small botnets near the limit may get incorrectly merged.
3. **Sum-of-IDF ignores credential list size** — an IP that tried 10,000 credentials will share more pairs with everyone, not because it is more similar, but simply because it tried more things. The proper fix normalises for this (see V3 below).

---

## Part 4 — What the Singletons Tell Us

159 IPs shared no credential pairs with anyone else. They get their own single-node communities in the results.

**We kept them in all output files** (`cluster_results.csv`) but excluded them from the graph image (they would just be 159 floating dots with no meaning).

These IPs could be:
- Very small botnets that only hit our honeypot once or twice
- Human attackers testing manually
- Bots using freshly generated, per-machine unique wordlists (some advanced operators do this specifically to defeat clustering)
- Other honeypots checking if our honeypot is responsive

**We cannot determine which botnet they belong to from this data alone.** More honeypots, or more data from this one over a longer period, would likely reveal that many singletons share credentials with each other.

---

## Part 5 — What Changed in V3

V3 introduced two fixes to the remaining problems in V2.

**Fix 1 — Replace Louvain with the Leiden Algorithm**

Louvain (2008) has a known mathematical flaw: it can produce communities that are internally disconnected. Leiden (2019) adds a refinement phase that checks connectivity within each community before aggregating, guaranteeing well-connected output.

---

**Fix 2 — Use Cosine Similarity Instead of Sum-of-IDF**

V2's edge weight was the raw sum of IDF scores for shared pairs. An IP that tried 10,000 credentials accumulates higher sums with almost everyone — not because its credential list is similar, but because it tried more things. V3 replaces this with cosine similarity.

Each IP is represented as a TF-IDF vector (one dimension per credential pair, value = IDF of that pair, 0 otherwise). The edge weight is then the cosine of the angle between the two vectors:

```
cos_sim(IP_a, IP_b) = (vector_a · vector_b) / (|vector_a| × |vector_b|)

0.0 = completely different credential sets
1.0 = identical credential sets
```

Dividing by both vector lengths removes the volume bias — a bot that tried 10,000 credentials and a bot that tried 50 are compared on the same scale.

**V3 pipeline:**

```
Step 1:  Load data
Step 2:  Build pair → IP set and IP → pair set mappings
Step 3:  Compute IDF per credential pair: IDF = log(N / df)
Step 4:  Build sparse TF-IDF matrix M; L2-normalise each row
Step 5:  Compute cosine similarity matrix S = M × M^T
Step 6:  Add edge if cosine similarity >= MIN_COSINE_SIM (0.10)
Step 7:  Run Leiden community detection
Step 8:  Analyse clusters (signature credential, size, top pairs)
Step 9:  Visualise + save
```

**V3 results (4,973 IPs, 40,474 credential pairs):**
- Total communities: 255
- Largest cluster: 3,329 IPs (canary botnet, `root/3245gs5662d34`)
- Clusters >= 10 IPs: 9
- Clusters >= 2 IPs: 31
- Singletons: 224

The V2 canary sub-clusters merged into one community of 3,329 IPs. At `MIN_COSINE_SIM = 0.10`, the secondary credential differences between the V2 sub-clusters are not large enough to prevent edges from forming across them after L2 normalisation. Raising the threshold would split them further but risks losing smaller real clusters.

---

## Part 6 — What Good Results Would Look Like

**Signs of a real botnet cluster:**
- Multiple IPs sharing several **rare** credential pairs
- Cluster size between tens and thousands of IPs (realistic botnet sizes)
- A clear **signature credential** — one or two pairs that almost all IPs in the cluster used and that very few IPs outside the cluster used
- Stable membership — if we re-run with a different random seed, the same IPs should end up in the same cluster

**Signs of a false cluster:**
- Very large size (>2,000 IPs) with no clear rare signature
- The "signature" pair is used by >10% of all IPs (too common)
- Cluster dissolves when we raise the edge weight threshold
- Cluster contains IPs with wildly different secondary credentials

**The 3 clusters we are most confident about (both V1 and V2 agree):**

| Cluster | Why we trust it |
|---|---|
| **SIP scanner** (24 IPs) | All 24 IPs send identical 7-line SIP protocol messages. Tight, clean, unmistakable. |
| **Perl tool** (7 IPs) | All 7 IPs try exactly one pair: `perl/warning`. Only 7 IPs in 4,973 ever tried it. Maximum IDF. |
| **TLS probe** (8 IPs) | All 8 IPs send raw binary TLS bytes. Not human-generated. Identical scanner fingerprint. |

These three clusters would survive even the strictest thresholds because their shared credentials are so rare (IDF > 5.0) that there is no ambiguity.

---

## Summary: The Journey So Far

```
GOAL: Find botnets (groups of IPs working together)

V1 --- Equal edge weights ------> 3 giant fake mega-clusters (too merged)
         |                         Largest: 1,974 IPs
         | Problem found:
         | Common credentials glue everyone together
         v
   Threshold experiment ----------> No stable threshold exists
         |                           Problem is the weighting, not the cutoff
         v
V2 --- TF-IDF edge weights ------> Better separation (13 clusters >= 10 IPs)
       MIN_EDGE_WEIGHT = 1.0         Largest: 856 IPs
       (canary pair can't form edge) Former mega-cluster -> 9 sub-clusters
         |
         | Problems remaining:
         |  1. Louvain has a resolution limit
         |  2. Sum-of-IDF is biased by credential list size
         v
V3 --- Cosine similarity + Leiden -> Volume bias eliminated
       MIN_COSINE_SIM = 0.10         Guaranteed well-connected communities
       (normalised by L2 norm)       255 communities, largest: 3,329 IPs
```

---

## Part 7 — Version 3: The Full Mathematics

V3 implements the two fixes described in Part 5.

---

### Fix A — Cosine Similarity Edges

**Why the sum-of-IDF edge weight from V2 is biased**

An IP that tried 10,000 credential pairs shares more pairs with nearly everyone — not because it is more similar to them, but simply because it tried more things. Its raw IDF sums are inflated by volume alone.

**The fix: represent each IP as a TF-IDF vector**

Each IP $i$ becomes a vector $\mathbf{v}_i$ in credential space, one dimension per unique credential pair:

$$\mathbf{v}_i[p] = \begin{cases} \text{IDF}(p) & \text{if IP}_i \text{ tried credential pair } p \\ 0 & \text{otherwise} \end{cases}$$

where IDF is the same formula used in V2:

$$\text{IDF}(p) = \log\!\left(\frac{N}{df_p}\right)$$

- $N$ = total unique IPs in the dataset (4,973)
- $df_p$ = number of IPs that tried pair $p$ (document frequency)

**The edge weight: cosine similarity**

Instead of summing IDF scores, V3 computes the **angle** between the two IP vectors:

$$\cos(\mathbf{v}_a,\,\mathbf{v}_b) = \frac{\mathbf{v}_a \cdot \mathbf{v}_b}{\|\mathbf{v}_a\|\;\|\mathbf{v}_b\|}$$

where the dot product expands to:

$$\mathbf{v}_a \cdot \mathbf{v}_b = \sum_{p \,\in\, \text{shared pairs}} \text{IDF}(p)^2$$

and the L2 norm (the "length" of the vector) is:

$$\|\mathbf{v}_i\| = \sqrt{\sum_{p \,\in\, \text{all pairs tried by } i} \text{IDF}(p)^2}$$

The result is always in $[0,\,1]$: **0** means completely different credential sets, **1** means identical. Dividing by the norms removes the volume bias — a high-volume bot and a low-volume bot are compared on the same scale.

**Worked example**

```
IP_A tried: root/123456 (IDF=3.6)  +  perl/warning (IDF=6.6)  +  admin/admin (IDF=2.4)
IP_B tried: root/123456 (IDF=3.6)  +  perl/warning (IDF=6.6)

v_A · v_B  =  3.6² + 6.6²                           =  12.96 + 43.56  =  56.52
||v_A||    =  sqrt(3.6² + 6.6² + 2.4²)              =  sqrt(62.28)    =  7.89
||v_B||    =  sqrt(3.6² + 6.6²)                     =  sqrt(56.52)    =  7.52

cos(A, B)  =  56.52 / (7.89 × 7.52)  =  0.953   (very similar — same rare pair)
```

V2 would give the same edge weight of 10.2 whether these IPs share two rare credentials or ten common ones that happen to sum to 10.2. Cosine similarity distinguishes these cases.

**How it is computed efficiently: sparse matrix multiplication**

Building similarity one pair at a time (as V2 did with `itertools.combinations`) is $O(\sum_p k_p^2)$ where $k_p$ = IPs per pair. The canary pair alone ($k = 2,791$) requires $\approx 3.9 \times 10^6$ iterations.

V3 uses a single sparse matrix operation instead:

$$M \in \mathbb{R}^{N \times P}, \quad M[i,p] = \text{IDF}(p) \text{ if IP}_i \text{ tried } p, \text{ else } 0$$

$$\hat{M}[i,\,\cdot\,] = \frac{M[i,\,\cdot\,]}{\|M[i,\,\cdot\,]\|} \quad \text{(L2-normalise each row)}$$

$$S = \hat{M}\,\hat{M}^\top, \quad S[i,j] = \cos(\mathbf{v}_i,\,\mathbf{v}_j)$$

`scipy.sparse` executes this as a single vectorised C call, replacing millions of Python iterations with one matrix multiply.

---

### Fix B — Leiden Algorithm

**What both Louvain and Leiden optimise**

Both algorithms maximise **modularity** $Q$ — the degree to which communities are denser than a random null model:

$$Q = \frac{1}{2m}\sum_{i,j}\!\left[w_{ij} - \frac{k_i\,k_j}{2m}\right]\delta(c_i,\,c_j)$$

| Symbol | Meaning |
|---|---|
| $m$ | Total edge weight in the graph |
| $w_{ij}$ | Weight of edge between nodes $i$ and $j$ (0 if none) |
| $k_i$ | Weighted degree of node $i$: sum of all its edge weights |
| $\frac{k_i k_j}{2m}$ | Expected edge weight under a random null model (Configuration Model) |
| $\delta(c_i, c_j)$ | 1 if $i$ and $j$ are in the same community, 0 otherwise |

High $Q$ means community members are much more connected to each other than chance alone would predict.

**Louvain's flaw**

During its local phase (try moving each node to a neighbour's community), Louvain can produce communities that are **internally disconnected** — a node can end up in a community with no direct edge path to some of its fellow members. This is a mathematical flaw proven in 2019 by Traag, Waltman, and van Eck.

**Leiden's fix**

Leiden (Traag et al., 2019) inserts a **refinement phase** after each aggregation step. Before collapsing a community into a super-node, Leiden checks that every node is reachable from every other node within the community, and corrects any disconnected subsets. This guarantees:

1. **All communities are internally connected** — no disconnected subsets.
2. **$\gamma$-separation** — every community satisfies a minimum internal density relative to its external connections. This produces finer-grained, better-separated clusters.

---

### V3 Pipeline

| Step | Operation | Change from V2 |
|---|---|---|
| 1 | Load CSV | Same |
| 2 | Build mappings (`pair → IPs`, `IP → pairs`) | Same |
| 3 | Compute $\text{IDF}(p) = \log(N / df_p)$ per credential pair | Same |
| 4 | Build sparse TF-IDF matrix $M$; normalise rows; compute $S = \hat{M}\hat{M}^\top$ | **New** — replaces sum-of-IDF + combinations loop |
| 5 | Run **Leiden** community detection (maximises $Q$) | **New** — replaces Louvain |
| 6 | Analyse clusters (signature, size, top credentials) | Same |
| 7 | Visualise + save graph | Same |
| 8 | Export CSV | Same |

