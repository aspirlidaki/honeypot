# Botnet Discovery from SSH Honeypot Logs

This project tries to identify botnets from Cowrie SSH honeypot data by clustering attacker IP addresses based on the username/password pairs they attempt. The idea is simple: bots in the same botnet run the same software with the same credential list, so if two IPs try the same rare pairs, they are probably from the same botnet.

## Dataset

The data comes from a Cowrie SSH honeypot operated by FORTH / C-SOC. It contains 268,875 login attempts from 4,973 unique IP addresses, covering 40,474 unique credential pairs. IP addresses have been anonymised (e.g. `IP_42`). Around 62% of credential pairs appear across more than one IP, which is what makes clustering possible in the first place.

## Method

Each attacker IP is turned into a TF-IDF vector where each dimension corresponds to a credential pair. The IDF score for a pair is `log(N / df)`, where N is the total number of IPs and df is how many IPs tried that pair — so rare pairs get a high score and common pairs get a low one.

Before computing IDF, two types of credential are removed from the vocabulary. First, credentials used by more than 10% of all IPs are treated as stopwords and dropped entirely. These are so common that sharing them tells you nothing about botnet membership, and because of how L2 normalisation works, IDF alone is not enough to neutralise their effect on cosine similarity — they have to be removed from the vector space completely. Second, credentials tried by only one IP (singletons) are also dropped, since they cannot link any two IPs and only weaken the vectors of the IPs that carry them.

After filtering, cosine similarity between the TF-IDF vectors is used as the edge weight in a graph — two IPs get an edge if their cosine similarity is at least 0.10. Leiden community detection then finds groups of densely connected IPs, which correspond to probable botnets.

The full technical writeup with maths, algorithm details, and per-cluster analysis is in [clustering_report.md](clustering_report.md).

## Running the Script

```bash
pip install -r requirements.txt
python cluster_attackers.py
```

This produces two output files:

| File | Contents |
|---|---|
| `cluster_results.csv` | Every IP with its community ID, cluster size, and signature credential |
| `attacker_graph.png` | Graph of the largest connected component, coloured by community |

## Results

### Vocabulary filtering

Three credentials were removed as stopwords (each used by more than 10% of IPs):

| Credential | IPs | Share of dataset |
|---|---|---|
| `345gs5662d34/345gs5662d34` | 2,791 | 56.1% |
| `root/3245gs5662d34` | 1,658 | 33.3% |
| `root/@qwer2025` | 799 | 16.1% |

After removing those three stopwords and 15,325 singletons, 25,146 credential pairs remain, with IDF scores ranging from 2.398 to 7.819.

### Cluster summary

| Metric | Value |
|---|---|
| Total communities | 215 |
| Largest community | 3,367 IPs |
| Communities ≥ 10 IPs | 10 |
| Communities of 2–9 IPs | 29 |
| Singletons | 186 |

### Identified communities

| Size | Signature credential | Notes |
|---|---|---|
| 3,367 | `ubuntu/3245gs5662d34` | Canary-family botnet — largest group |
| 393 | `admin/admin` | IoT default credential scanner |
| 379 | `root/root` | Linux server default credential scanner |
| 197 | `root/debian` | Targets Debian/Ubuntu systems |
| 161 | `root/------fuck------` | Unknown botnet |
| 135 | Chrome-like HTTP User-Agent | Go-based multi-protocol scanner |
| 34 | `root/Abcd1234` | Credential stuffing, leaked-password dictionary |
| 25 | `User-Agent: Go-http-client/1.1` | Second variant of the Go scanner |
| 24 | SIP OPTIONS request | VoIP fraud scanner |
| 17 | `pi/raspberryraspberry993311` | Targets Raspberry Pi default credentials |
| 8 | Raw TLS bytes | TLS probe on port 22 |
| 7 | `perl/warning` | Perl-based exploit tool |
| 7 | `a/a` | Minimal brute-force tool |
| 3 | `eth/ethereum12345` | Ethereum mining deployment |
| 2 × 15 | Various | Small credential-sharing pairs |
| 1 × 186 | — | Isolated IPs with no shared credentials after filtering |

### How results changed across versions

Each version of the script improved on the last. V1 used raw shared-pair counts and produced three artificial mega-clusters because one credential appeared in 56% of all IPs. V2 added IDF weighting to down-weight common credentials, which helped but did not fully solve the problem. V3 switched to cosine similarity and Leiden community detection. V4 (this version) removes the problematic stopword credentials from the vocabulary entirely before computing anything, which is the correct fix.

| Metric | V1 | V2 | V3 | V4 |
|---|---|---|---|---|
| Edge weighting | Raw count | IDF sum | Cosine similarity | Cosine similarity |
| Vocabulary filter | None | None | None | Stopwords + singletons removed |
| Community algorithm | Louvain | Louvain | Leiden | Leiden |
| Total communities | 179 | 188 | 255 | 215 |
| Largest community | 1,974 IPs | 856 IPs | 3,329 IPs | 3,367 IPs |
| Communities ≥ 10 IPs | 6 | 13 | 9 | 10 |
| Singletons | 159 | 159 | 224 | 186 |
