# Honeypot Attacker Clustering — Technical Report
Version 4 — TF-IDF with Stopword Removal + Leiden Community Detection

| | |
|---|---|
| **Institution** | FORTH / C-SOC |
| **Honeypot** | Cowrie SSH (port 22) |
| **Data file** | `cowrie_ip_username_pass_anon.csv` |
| **Analysis date** | June 2026 |
| **Tools** | Python 3, networkx, scipy.sparse, leidenalg, igraph, matplotlib |

---

## 1. Dataset

| Metric | Value |
|---|---|
| Total login attempts | 268,875 |
| Unique attacker IPs | 4,973 |
| Unique credential pairs | 40,474 |
| Pairs shared by more than one IP | 25,149 (62%) |

The honeypot recorded 268,875 SSH login attempts from 4,973 different IP addresses. Each attempt used a username/password pair, and across the whole dataset there are 40,474 distinct pairs. The key number is 62%: more than half of all credential pairs were tried by at least two different IPs. That overlap is what makes clustering possible — if two IPs try the same rare password, there is a good reason for it.

---

## 2. Method

### The core idea

Bots in the same botnet run the same attack software. That software comes loaded with a credential dictionary — a list of username/password pairs to try. So if two IPs share a large number of the same credential pairs, they are probably running the same software and belong to the same botnet. The rarer the shared pair, the stronger that conclusion.

### Step-by-step pipeline

| Step | What happens |
|---|---|
| 1 | Load the CSV into a list of (IP, username, password) records |
| 2 | Build two lookup tables: which IPs tried each pair, and which pairs each IP tried |
| 3 | Filter the vocabulary: drop credentials used by >10% of IPs (stopwords) and credentials used by only one IP (singletons) |
| 4 | Compute an IDF score for each surviving credential pair |
| 5 | Build a TF-IDF matrix, normalise each row, and compute cosine similarities |
| 6 | Connect two IPs with an edge if their cosine similarity is at least 0.10 |
| 7 | Run Leiden community detection to find clusters |
| 8 | Find the signature credential for each cluster and export results |

### IDF — measuring how rare a credential is

IDF stands for Inverse Document Frequency. It comes from text search, where the same problem exists: common words like "the" appear in every document and are useless for figuring out which documents are similar, while rare words like "photosynthesis" appearing in two documents is a strong signal. Here, credential pairs play the role of words, and attacker IPs play the role of documents.

The formula is:

```
IDF(pair) = log( N / df )

N  = 4,973   (total unique IPs)
df = number of IPs that tried this pair
```

A pair tried by 2,791 IPs gets IDF = log(4973/2791) = 0.578 — nearly useless as a signal. A pair tried by only 7 IPs gets IDF = log(4973/7) = 6.563 — very strong signal. The table below shows this for a range of credentials:

| Credential pair | IPs | IDF | V4 status |
|---|---|---|---|
| `345gs5662d34/345gs5662d34` | 2,791 | 0.578 | Stopword — removed |
| `root/3245gs5662d34` | 1,658 | 1.098 | Stopword — removed |
| `root/@qwer2025` | 799 | 1.828 | Stopword — removed |
| `admin/admin` | 452 | 2.398 | Kept (lowest IDF after filtering) |
| `root/root` | 272 | 2.906 | Kept |
| `root/debian` | 184 | 3.298 | Kept |
| `root/123456` | 131 | 3.634 | Kept |
| `OPTIONS sip:.../Via: SIP/2.0/...` | ~24 | ~5.3 | Kept |
| `perl/warning` | 7 | 6.563 | Kept |
| `eth/ethereum12345` | 3 | 7.413 | Kept |
| Any pair used by exactly 1 IP | 1 | 8.512 | Singleton — removed |

The logarithm matters here. Without it, a pair used by 2,791 IPs gives N/df ≈ 1.78, while a moderately rare pair used by 50 IPs gives N/df ≈ 99.5 — those sit 56× apart on a linear scale. The log brings them to 0.578 and 4.598, a much more workable range. It also has a nice property at the extremes: a pair used by every single IP gets log(1) = 0, and a pair used by exactly one IP gets the maximum value log(N).

### Vocabulary filtering (V4)

Before computing IDF at all, two types of credential are removed from the vocabulary.

**Stopwords** are credentials used by more than 10% of all IPs (more than 497 IPs in this dataset). Three were found: `345gs5662d34/345gs5662d34` (56% of IPs), `root/3245gs5662d34` (33%), and `root/@qwer2025` (16%). The reason they have to be removed completely — not just down-weighted — is explained in Section 9.0. The short version is that IDF alone is not enough: even with a low score, these credentials still affect cosine similarity through the normalisation step, and the only proper fix is to take them out of the vector space entirely.

**Singletons** are credentials tried by only one IP. They cannot create an edge between any two IPs, since by definition no other IP shares them. On top of that, they inflate the vector length of the IP that tried them, which weakens that IP's similarity scores with everyone else. Removing them makes the remaining signals cleaner.

After filtering, 25,146 credential pairs remain out of 40,474. IDF scores in the filtered vocabulary range from 2.398 to 7.819.

### Why V1 failed

V1 used raw shared-pair count as the edge weight between two IPs. The credential `345gs5662d34/345gs5662d34`, used by 56% of all IPs, connected most of the graph with the same weight as genuinely rare pairs. The result was three enormous fake clusters of roughly 1,974, 1,294, and 1,282 IPs.

Trying to fix it by raising the minimum threshold did not help:

| Min shared pairs | Edges | Communities | Largest cluster |
|---|---|---|---|
| 1 | 4,228,666 | 179 | 1,973 |
| 2 | 1,592,317 | 979 | 1,308 |
| 5 | 46,099 | 1,823 | 310 |
| 10 | 25,296 | 2,370 | 329 |
| 50 | 422 | 4,913 | 29 |

There is no stable threshold — the problem is that all credentials are treated as equally important, which they are not. IDF weighting is the right fix.

---

## 3. Results

### How each version compares

| Metric | V1 | V2 | V3 | V4 |
|---|---|---|---|---|
| Edge weighting | Raw count | IDF sum | Cosine similarity | Cosine similarity |
| Vocabulary filter | None | None | None | Stopwords + singletons removed |
| Community algorithm | Louvain | Louvain | Leiden | Leiden (plain modularity) |
| Threshold | min shared pairs | IDF sum ≥ 1.0 | cosine sim ≥ 0.10 | cosine sim ≥ 0.10 |
| Largest cluster | 1,974 IPs | 856 IPs | 3,329 IPs | 3,367 IPs |
| Clusters ≥ 10 IPs | 6 | 13 | 9 | 10 |
| Clusters ≥ 2 IPs | 21 | 29 | 31 | 29 |
| Singletons | 159 | 159 | 224 | 186 |
| Total communities | 179 | 188 | 255 | 215 |

### Cluster distribution (V4)

| Size | Count | Identity |
|---|---|---|
| 3,367 | 1 | Canary-family botnet (ubuntu/3245gs5662d34) |
| 393 | 1 | Admin/Admin botnet |
| 379 | 1 | root/root botnet |
| 197 | 1 | Debian-targeting botnet |
| 161 | 1 | Unknown (root/------fuck------) |
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
| **Total** | **215** | |

### Graph

600-node sample of the largest connected component. Each dot is an attacker IP, each line connects two IPs that share credential pairs, and the colour shows which community they belong to.

![Attacker Similarity Graph](attacker_graph.png)

---

## 4. Cluster Analysis

**Community 0 — Canary-Family Botnet (3,367 IPs)**

This is the largest cluster. In V4, the two most common canary credentials (`345gs5662d34/345gs5662d34` and `root/3245gs5662d34`) were removed as stopwords, so the community is now identified by the signature `ubuntu/3245gs5662d34` — a less common variant of the same canary string that survived filtering. The cluster is slightly larger than V3's 3,329 IPs, which tells us that removing the most dominant canary credentials did not break the botnet apart. The remaining canary-family credentials are still enough to tie all these IPs together.

The word "canary" refers to a deliberate fingerprint. The operator of this botnet inserted the string `3245gs5662d34` into their credential list specifically so that they could identify their own bots in honeypot logs. The scale — over 3,000 IPs — and the deliberate fingerprinting both suggest a professional threat actor, not an opportunistic attacker.

---

**Community 1 — Admin/Admin Botnet (393 IPs)**

Signature: `admin/admin`. This credential targets devices that still have their factory-default login — consumer routers, IP cameras, NAS boxes, and similar embedded hardware. This is consistent with Mirai-style scanning, where the goal is to build a botnet from insecure IoT devices rather than attacking servers directly.

---

**Community 2 — root/root Botnet (379 IPs)**

Signature: `root/root`. Targets Linux servers and embedded devices where the root account still has its default password. The target profile overlaps with the Debian-targeting cluster below, but the two groups use different credential lists, so they end up in separate communities.

---

**Community 3 — Debian-Targeting Botnet (197 IPs)**

Signature: `root/debian`. The password "debian" is the default root password on Debian-based Linux images, including Ubuntu and Raspberry Pi OS. This cluster specifically goes after machines built from those images without changing the defaults.

---

**Community 4 — Unknown Botnet (161 IPs)**

Signature: `root/------fuck------`. The unusual password string does not match any known tool fingerprint in public threat intelligence sources. The cluster behaviour is consistent with a botnet using a custom credential list.

---

**Community 5 — HTTP/Chrome-UA Scanner (135 IPs)**

Signature: a full Chrome browser User-Agent string (`Mozilla/5.0 (Macintosh; Intel Mac OS X 13_1) AppleWebKit/537.36`). This is not a password — it is an HTTP header being sent as an SSH credential. These IPs are not trying to brute-force SSH at all; they are running a Go-based multi-protocol scanner that probes any open port for an HTTP server, Redis instance, or other non-SSH service. Port 22 just happens to be in their scan range.

In V3, this group and Community 7 below were one cluster of 160 IPs. The stopword removal in V4 revealed that a shared common credential was masking the difference between two distinct tool variants.

---

**Community 6 — root/Abcd1234 Cluster (34 IPs)**

Signature: `root/Abcd1234`. This cluster was not clearly visible in V3 — it appears after stopword removal. The password `Abcd1234` fits the pattern of "looks strong but is on every leaked-password list": mixed case, numbers, common word. This is consistent with a credential-stuffing tool that uses a dictionary built from real data breaches.

---

**Community 7 — Go-http-client Scanner (25 IPs)**

Signature: `User-Agent: Go-http-client/1.1`. The bare Go HTTP client header, as opposed to the spoofed Chrome UA in Community 5. Same behaviour — HTTP headers sent as SSH credentials — but a different tool or configuration. The split from V3's single HTTP scanner community suggests these are two different operators running similar but distinct software.

---

**Community 8 — SIP/VoIP Scanner (24 IPs)**

Signature: `OPTIONS sip:nm SIP/2.0` and `Via: SIP/2.0/TCP nm;branch=foo`. All 24 IPs send exactly the same SIP OPTIONS request — the standard probe used to check whether a VoIP system is running. SIP is the protocol used by PBX phone systems, and compromising one allows attackers to make calls at the victim's expense (toll fraud). Like the HTTP scanners, these IPs are not actually trying to attack SSH; they are probing for a completely different service on the same port.

---

**Community 9 — Raspberry Pi Scanner (17 IPs)**

Signature: `pi/raspberryraspberry993311`. This targets Raspberry Pi devices that still use the default `pi` user account. The password is `raspberry` repeated twice with digits appended — a known default from early Raspberry Pi OS images. All 17 IPs in this cluster are running the same specific tool.

---

**Community 10 — TLS Binary Probe (8 IPs)**

Signature: raw bytes that start with `\x16\x03\x03` — the beginning of a TLS ClientHello handshake. These IPs are checking whether port 22 is accidentally running a TLS-based service (HTTPS, LDAPS, etc.) instead of SSH. Again, not an SSH attack at all.

---

**Community 12 — Perl Exploit Tool (7 IPs)**

Signature: `perl/warning` (IDF = 6.563). All 7 IPs try exactly this one credential pair and nothing else. `perl/warning` is a known fingerprint of a specific Perl-based exploit tool. The IDF score of 6.563 is very high, meaning this pair is extremely rare across the dataset — it is a reliable cluster identifier.

---

**Community 11 — a/a Cluster (7 IPs)**

Signature: `a/a`. A minimal brute-force tool trying the simplest possible credentials.

---

**Community 13 — Ethereum Miner (3 IPs)**

Signature: `eth/ethereum12345`. These IPs are trying to gain access so they can install Ethereum mining software on the compromised server.

---

**Small pairs (15 clusters of 2 IPs)**

The remaining multi-IP clusters are all pairs of two IPs sharing a single rare credential. Most involve crypto-miner-related usernames (`xmr`, `bitcoin`, `eth`, `wallet`). Monero (`xmr`) appears more often than others — it uses a CPU-friendly mining algorithm (RandomX) and its transactions are untraceable, which makes it the standard choice for illicit mining operations.

---

## 5. Findings

**The canary credential is a professional fingerprint.** The string `3245gs5662d34` appearing across more than 3,000 IPs is not an accident. The botnet operator deliberately put it in their credential list as a tag to identify their bots in exactly this kind of log. The scale rules out any amateur operation.

**Port 22 captures a lot of non-SSH traffic.** The HTTP scanners (135 + 25 IPs), the SIP scanner (24 IPs), and the TLS prober (8 IPs) are all sending non-SSH content. Attackers scan all open ports for whatever service might be running, regardless of what port number convention says it should be.

**Crypto-mining is the most common motive.** At least 16 communities show clear mining intent in their credentials. Monero is preferred throughout.

**IoT default credentials are a major attack surface.** The admin/admin, root/root, and root/debian clusters together account for nearly 970 IPs specifically targeting devices with default factory credentials.

**Singletons are not necessarily lone attackers.** The 186 IPs with no shared credentials after filtering might be low-activity bots, operators running unique wordlists specifically to defeat credential-based clustering, security researchers, or other honeypots.

---

## 6. Defensive Indicators

| Indicator | Recommended action |
|---|---|
| SSH credential contains `3245gs5662d34` | Block immediately — confirmed botnet traffic |
| SIP headers appearing as SSH credentials | Block and alert — VoIP fraud scanner |
| `admin/admin` or `root/debian` login attempts | Audit and enforce credential policies on all devices |
| Usernames `xmr`, `bitcoin`, `eth`, `wallet` | Alert — likely crypto-mining deployment attempt |
| HTTP User-Agent strings in SSH credentials | Block at firewall — multi-protocol scanner |

---

## 7. Possible Next Steps

- **GeoIP enrichment**: map the clusters geographically. Are the canary sub-clusters coming from distinct regions, or is it a globally distributed botnet?
- **Timestamp analysis**: if timestamps are available, check whether cluster members attack in coordinated waves or independently.
- **Multi-honeypot correlation**: data from multiple honeypots would dramatically improve cluster resolution, since rare shared credentials become even stronger signals across larger IP populations.

---

## 8. Output Files

| File | Contents |
|---|---|
| `cluster_attackers.py` | The analysis script (V4) |
| `cluster_results.csv` | Every IP with its community ID, cluster size, and signature credential |
| `attacker_graph.png` | Graph visualisation (600-node sample of the largest component) |
| `cowrie_ip_username_pass_anon.csv` | Raw honeypot data |

---

## 9. How the Algorithms Work

This section explains each algorithm in detail, including the maths. It is meant to be self-contained — you should not need to look anything up to follow it.

### 9.0 Why IDF alone is not enough (the stopword problem)

This is the main theoretical contribution of V4, so it is worth explaining carefully.

After V3, the largest cluster was 3,329 IPs all linked by the canary credential `345gs5662d34/345gs5662d34`. That credential was used by 56% of all IPs, which gave it an IDF of only 0.578. You might expect that such a low score would make it irrelevant — but it does not, because of how cosine similarity works after normalisation.

When we compute cosine similarity, we first divide each IP's vector by its length (this is called L2 normalisation). The problem is that the canary credential contributes 0.578 to the vector of every IP that tried it, and it contributes 0.578² = 0.334 to that IP's squared length. For an IP that mostly used the canary credential and not many others, this means the canary makes up a large fraction of the vector's total length. After dividing by the length, the canary's contribution gets *re-inflated* — it ends up close to 1 for IPs that have little else in their vectors.

Two IPs that both mostly used the canary credential end up with a cosine similarity close to 1, regardless of their other credentials. The only way to fix this completely is to remove the canary from the vector space entirely. If it has no dimension, it cannot affect any cosine calculation at all.

The same logic applies to the other two stopwords (`root/3245gs5662d34` at 33% and `root/@qwer2025` at 16%).

Formally, the V4 vocabulary keeps pair $p$ only if:

$$\text{MIN\_DF} \leq df_p \leq \lfloor\text{MAX\_DF\_FRACTION} \times N\rfloor$$

With N = 4,973, MAX\_DF\_FRACTION = 0.10, and MIN\_DF = 2, this means keeping pairs used by between 2 and 497 IPs.

| Filter | Value | What gets dropped |
|---|---|---|
| Upper bound (stopwords) | df ≤ 497 | Credentials used by >10% of IPs |
| Lower bound (singletons) | df ≥ 2 | Credentials used by exactly one IP |

For singletons: a credential only one IP ever tried has a zero value in every other IP's vector. It cannot create an edge between any two IPs. It also inflates the vector length of the one IP that tried it, weakening that IP's similarity with its genuine botnet peers. There is no reason to keep it.

An IP whose entire credential set is stopwords and singletons ends up with an all-zero TF-IDF vector. Its cosine similarity with every other IP is 0, it forms no edges, and it becomes an isolated node (singleton community). This is the correct outcome: if the only thing an IP did was try credentials that are universal or unique, we have no evidence about which botnet it belongs to.

This technique — removing very common and very rare terms before computing similarity — is the standard approach in text search and is described in Manning, Raghavan & Schütze (2008). V4 applies it directly to credential data.

---

### 9.1 TF-IDF vectors

Each IP is represented as a vector. Think of it as a long list of numbers, one per credential pair in the vocabulary. If IP_42 tried a credential, the corresponding position in the vector holds that credential's IDF score. If it did not try it, the position is 0.

$$\mathbf{v}_i[p] = \begin{cases} \text{IDF}(p) & \text{if IP}_i \text{ tried pair } p \\ 0 & \text{otherwise} \end{cases}$$

The TF (Term Frequency) part is just a binary yes/no: did this IP try this credential at all? We do not count retries, because what identifies a botnet is *which* credentials were tried, not *how many times* they were tried. A high-volume bot and a low-volume bot running the same software should produce the same vector shape.

In practice, each IP typically tries 50–200 credential pairs out of 40,474, so more than 99% of each vector is zeros. This is called a sparse vector. Sparsity matters because it makes the matrix computations in Section 9.4 fast — the computer can skip all the zeros.

---

### 9.2 Cosine similarity

Once each IP has a TF-IDF vector, we need a way to measure how similar two IPs are. The tool we use is cosine similarity:

$$\cos(\mathbf{v}_a, \mathbf{v}_b) = \frac{\mathbf{v}_a \cdot \mathbf{v}_b}{\|\mathbf{v}_a\| \cdot \|\mathbf{v}_b\|}$$

The numerator is the dot product — it sums up IDF² for every credential pair that both IPs tried. The denominator is the product of the two vector lengths, which normalises the result so it always falls between 0 and 1.

Geometrically: two vectors in high-dimensional space define an angle between them. Cosine similarity is literally the cosine of that angle. If two IPs have identical credential profiles their vectors point in the same direction (angle = 0°, cosine = 1). If they share no credentials at all their vectors are perpendicular (angle = 90°, cosine = 0).

The key reason to use cosine similarity rather than the raw dot product (which was V2's approach) is that it is not affected by vector length. An IP that tried 10,000 credentials accumulates a large dot product with almost everyone just from volume, not because its credential list resembles theirs. Dividing by both lengths removes that bias. After normalisation, we are only comparing the *shape* of the credential profiles, not how many credentials each IP tried.

Here is a worked example:

```
IP_A tried: root/123456 (IDF=3.634) + perl/warning (IDF=6.563) + admin/admin (IDF=2.398)
IP_B tried: root/123456 (IDF=3.634) + perl/warning (IDF=6.563)

dot(A,B) = 3.634² + 6.563² = 13.21 + 43.07 = 56.28
||A||    = sqrt(3.634² + 6.563² + 2.398²) = sqrt(62.04) = 7.877
||B||    = sqrt(3.634² + 6.563²)           = sqrt(56.28) = 7.502

cos(A,B) = 56.28 / (7.877 × 7.502) = 0.952
```

The shared rare pair `perl/warning` (IDF = 6.563) is doing most of the work here, because IDF appears squared in the numerator but only once in each norm — so rare shared pairs have an outsized effect on the final score, which is exactly what we want.

---

### 9.3 Building the graph efficiently

After computing cosine similarities, we build a graph where each IP is a node and two IPs are connected by an edge if their cosine similarity is at least 0.10. Then community detection finds the densely connected groups.

The naive approach — computing each pair of IPs one at a time — would not be feasible. There are 4,973 IPs, so there are about 12.4 million pairs, and for each pair we would need to iterate over shared credentials. For the canary credential alone (used by 2,791 IPs), there are about 3.9 million pairs to process just for that one credential.

Instead, the whole similarity matrix is computed in one step using matrix multiplication. We build a matrix M where rows are IPs and columns are credential pairs, filled with IDF scores. We normalise each row (divide by its length). Then we multiply M by its own transpose:

$$S = \hat{M} \cdot \hat{M}^\top$$

The entry at position (i, j) in S is the dot product of the normalised row for IP i and the normalised row for IP j — which is exactly the cosine similarity between those two IPs. The whole thing runs as a single optimised matrix operation using scipy.sparse, which is much faster than any loop.

Because M is very sparse (under 0.5% of entries are non-zero), scipy.sparse can store it efficiently and multiply it quickly without processing all the zeros.

---

### 9.4 Modularity — what community detection is actually optimising

Community detection algorithms search for a partition of the graph into groups. But "partition" is vague — how do we know if one partition is better than another? The answer is modularity, written as Q.

$$Q = \frac{1}{2m}\sum_{i,j}\left[w_{ij} - \frac{k_i k_j}{2m}\right]\delta(c_i, c_j)$$

This looks complicated but the idea is simple. For every pair of IPs that end up in the same community, we compare the actual edge weight between them (`w_ij`) to the edge weight we would expect if the graph were random. If the actual weight is higher than expected, that pair contributes positively to Q. If it is lower, it contributes negatively.

| Symbol | Meaning |
|---|---|
| m | Total of all edge weights in the graph |
| w_ij | Cosine similarity between IPs i and j (0 if no edge) |
| k_i | Sum of all edge weights attached to IP i |
| k_i × k_j / 2m | Expected edge weight if connections were random |
| δ(c_i, c_j) | 1 if i and j are in the same community, 0 otherwise |

The "expected weight if random" term comes from a model called the Configuration Model, which asks: if we kept each IP's total connection strength the same but shuffled who is connected to whom, what weight would we expect between these two IPs? A good community has much higher internal connectivity than this random baseline.

Q ends up between -1 and 1. In practice, real networks with clear community structure score around 0.3 to 0.7. A random partition scores near 0.

One known limitation: modularity can sometimes merge small but genuine communities into a larger neighbour if doing so increases Q. This is a property of the formula itself, not a bug in any implementation.

---

### 9.5 Leiden algorithm

Leiden (Traag, Waltman & van Eck, 2019) is the algorithm we use to maximise modularity. It works in three phases that repeat until the partition stops changing.

**Phase 1 — Move nodes.** Each IP is considered for reassignment to a neighbouring community. It moves to whichever community gives the biggest increase in Q. This repeats in random order until no single move would improve Q anymore. This phase is fast and gets a good initial partition, but it can sometimes create communities that are internally disconnected — a node might get assigned to a community with no path back to most of its members.

**Phase 2 — Fix disconnected communities.** Before collapsing anything, Leiden checks every community for internal connectivity. Any part of a community that is not reachable from the rest is split off into its own new community. This is the main improvement over the older Louvain algorithm, which can leave disconnected communities in its output.

**Phase 3 — Collapse and repeat.** Each community is collapsed into a single super-node, with edges between super-nodes carrying the total weight of all connections between the original communities. Then Phases 1 and 2 run again on this smaller, coarser graph. This allows the algorithm to find structure at multiple scales.

These three phases repeat until the partition is stable. Because Phase 1 processes nodes in random order, the results can vary between runs, so we fix `seed=42` to make them reproducible.

The previous versions (V2 and V3) used Louvain instead of Leiden. Louvain only does Phases 1 and 3 — it skips the connectivity check. Leiden is strictly better for this reason.

---

### 9.6 What changed between versions

**V1 → V2:** Replaced raw shared-pair count with IDF-weighted sum as the edge weight. This fixed the mega-clusters caused by the canary credential.

**V2 → V3:** Replaced the IDF sum with cosine similarity (adds L2 normalisation, removes the volume bias). Switched from Louvain to Leiden. Also replaced the itertools-based pair loop with sparse matrix multiplication, which made the computation practical for the full dataset.

| Aspect | V2 | V3 |
|---|---|---|
| Edge weight | Sum of IDF scores for shared pairs | Cosine similarity (normalised) |
| Volume bias | Yes — IPs that tried more credentials got larger edge weights | No — L2 normalisation removes this |
| Speed | Slow O(k²) loop per credential pair | Fast matrix multiply |
| Community algorithm | Louvain | Leiden |

**V3 → V4:** Added vocabulary filtering (stopwords + singletons). Everything else is the same.

| Aspect | V3 | V4 |
|---|---|---|
| Vocabulary | All 40,474 credential pairs | 25,146 pairs with 2 ≤ df ≤ 497 |
| Stopwords | Kept (low IDF, but still affect cosine via norms) | Removed entirely — no dimension in any vector |
| Singletons | Kept (inflate norms, no edge contribution) | Removed |
| IDF minimum | 0.578 (canary pair) | 2.398 (admin/admin) |
| Canary effect on similarity | Partially re-inflated after normalisation | Zero |
| IPs with all-zero vectors | Cannot happen | Possible — becomes an isolated singleton |
| Leiden partition type | RBConfigurationVertexPartition (resolution=1.0) | ModularityVertexPartition (plain modularity) |

The Leiden variant changed because RBConfigurationVertexPartition and ModularityVertexPartition are equivalent at resolution=1.0, but the plain modularity version makes the choice explicit and removes the resolution parameter as something that could interact with the stopword-removal effect.
