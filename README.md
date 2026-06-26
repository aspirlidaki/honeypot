# Botnet Discovery from SSH Honeypot Logs

This project identifies botnets from Cowrie SSH honeypot data by clustering attacker IPs on shared credential pairs. Bots in the same botnet run the same software and credential list — two IPs trying the same rare pairs are probably the same botnet.

## Dataset

From FORTH / C-SOC's Cowrie honeypot: 268,875 login attempts, 4,973 unique IPs, 40,474 unique credential pairs (IPs anonymised as `IP_42`, etc.). 62% of credential pairs appear across more than one IP, which is what makes clustering possible.

## Method

Each IP is turned into a TF-IDF vector where each dimension is a credential pair scored by `IDF = log(N / df)` — rare pairs score high, common ones low. Two credential types are removed before computing IDF:

- **Stopwords** (used by >10% of IPs): removed entirely. Sharing them tells you nothing about botnet membership, and IDF alone cannot neutralise their effect after L2 normalisation.
- **Singletons** (used by exactly 1 IP): removed. They cannot link any two IPs and inflate vector norms.

Cosine similarity between vectors forms the edge weights; IPs with similarity ≥ 0.10 are connected. Leiden community detection finds the botnet groups.

Full technical writeup: [clustering_report.md](clustering_report.md)

## Running

```bash
pip install -r requirements.txt
python cluster_attackers.py
```

| Output file | Contents |
|---|---|
| `cluster_results.csv` | Every IP with community ID, cluster size, signature credential |
| `attacker_graph.png` | Graph of the largest connected component, coloured by community |

## Results

### Vocabulary filtering

| Credential | IPs | Share |
|---|---|---|
| `345gs5662d34/345gs5662d34` | 2,791 | 56.1% |
| `root/3245gs5662d34` | 1,658 | 33.3% |
| `root/@qwer2025` | 799 | 16.1% |

25,146 credential pairs remain after filtering; IDF range 2.398–7.819.

### Communities found (V4)

| Size | Signature | Notes |
|---|---|---|
| 3,367 | `ubuntu/3245gs5662d34` | Canary-family botnet |
| 393 | `admin/admin` | IoT default credential scanner |
| 379 | `root/root` | Linux server defaults |
| 197 | `root/debian` | Debian/Ubuntu targeting |
| 161 | `root/------fuck------` | Unknown |
| 135 | Chrome-like HTTP User-Agent | Go multi-protocol scanner |
| 34 | `root/Abcd1234` | Credential stuffing |
| 25 | `User-Agent: Go-http-client/1.1` | Go scanner variant |
| 24 | SIP OPTIONS request | VoIP fraud scanner |
| 17 | `pi/raspberryraspberry993311` | Raspberry Pi defaults |
| 8 | Raw TLS bytes | TLS probe on port 22 |
| 7 | `perl/warning` | Perl exploit tool |
| 7 | `a/a` | Minimal brute-force |
| 3 | `eth/ethereum12345` | Ethereum miner |
| 2 × 15 | Various | Small credential pairs |
| 186 | — | Isolated IPs (no shared credentials after filtering) |

### Version history

| Metric | V1 | V2 | V3 | V4 |
|---|---|---|---|---|
| Edge weight | Raw count | IDF sum | Cosine | Cosine |
| Vocabulary | None | None | None | Stopwords + singletons removed |
| Algorithm | Louvain | Louvain | Leiden | Leiden |
| Communities | 179 | 188 | 255 | 215 |
| Largest | 1,974 | 856 | 3,329 | 3,367 |
| ≥10 IPs | 6 | 13 | 9 | 10 |
| Singletons | 159 | 159 | 224 | 186 |
