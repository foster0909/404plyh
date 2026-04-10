# Recon Engine

Recon Engine is a deep reconnaissance and enumeration framework designed to build a comprehensive map of a target’s external attack surface. It orchestrates multiple industry-standard reconnaissance tools into a unified pipeline, validating and enriching results while organizing them into a structured dataset optimized for manual security research.

The system focuses on **maximum coverage, accuracy, and usability**, transforming raw reconnaissance output into an actionable view of a target’s infrastructure and applications.

---

## Key Features

### Comprehensive Subdomain Discovery

Recon Engine aggregates hostnames from multiple independent intelligence sources to maximize coverage.

Subdomain enumeration is performed using tools such as:

* **subfinder** for large passive OSINT datasets
* **amass (passive mode)** for deep intelligence sources
* **assetfinder** for lightweight discovery
* **Chaos dataset integration** for known internet-scale assets
* **Certificate Transparency enumeration** through `crt.sh` queries

All discovered hostnames are normalized, deduplicated, and merged into a unified candidate list before validation.

---

### DNS Resolution and Validation

Collected domains are validated through high-performance DNS resolution using tools such as:

* **puredns** for accurate DNS resolution and wildcard filtering

This stage resolves **A, AAAA, and CNAME records**, identifies wildcard domains, and flags unresolved or suspicious hosts while preserving potentially valuable findings.

---

### HTTP Service Discovery

Resolved hosts are probed using **httpx**, which gathers detailed service intelligence including:

* HTTP / HTTPS status codes
* redirect chains
* page titles
* server headers
* IP addresses
* technology fingerprints

This stage determines which discovered domains are actively serving applications.

---

### Visual Surface Mapping

Recon Engine captures screenshots of legitimate web responses to provide rapid visual insight into discovered applications.

Screenshots are generated using tools such as:

* **gowitness** for high-speed screenshot automation

Screenshots are stored alongside metadata including domain, status code, page title, technology fingerprints, and infrastructure data.

---

### Network Service Enumeration

Network service discovery is performed using:

* **naabu** for fast port discovery
* **nmap** for deeper service analysis when needed

This stage identifies exposed services across discovered infrastructure, including development interfaces, alternate HTTP services, and potentially misconfigured internal services.

---

### JavaScript Intelligence Extraction

JavaScript assets from discovered applications are analyzed to extract hidden intelligence.

Tools used in this stage include:

* **LinkFinder** for extracting endpoints from JavaScript
* **SecretFinder** for identifying exposed secrets and tokens

Extracted intelligence may reveal:

* API endpoints
* internal routes
* additional hostnames
* storage bucket references
* websocket endpoints

Newly discovered domains are automatically added back into the enumeration pipeline.

---

### Historical Surface Discovery

Recon Engine retrieves historical URLs and application paths from archival datasets using tools such as:

* **gau (GetAllURLs)**
* **waybackurls**

These sources uncover legacy endpoints that may still be accessible but are no longer publicly linked.

---

### Endpoint and Path Enumeration

Active crawling and endpoint discovery are performed using:

* **katana** for modern web crawling
* **hakrawler** for lightweight endpoint discovery

This stage identifies hidden application paths such as login portals, administrative panels, API routes, and documentation endpoints.

---

### Asset and Infrastructure Mapping

Recon Engine correlates discovered assets with underlying infrastructure by analyzing:

* resolved IP addresses
* ASN ownership
* CDN usage
* shared backend systems

Tools such as **amass intel** and infrastructure intelligence lookups assist in mapping relationships between discovered assets.

---

### Structured Data Storage

All reconnaissance findings are stored as structured datasets rather than raw output.

Each asset record includes metadata such as:

* hostname
* IP address
* service status
* open ports
* technology fingerprints
* screenshot references
* discovery sources

This enables the recon results to function as a **searchable intelligence dataset** rather than a simple scan log.

---

### Review-Optimized Output

Results are organized into visual and structured reports to support efficient manual analysis.

Researchers can explore the discovered attack surface through:

* screenshot galleries
* endpoint inventories
* infrastructure groupings
* technology fingerprints
* domain-to-IP relationships

---

## Design Goals

Recon Engine was built around three primary goals:

**Maximum Coverage**
Discover as much of the external attack surface as possible by aggregating intelligence from diverse sources.

**Accurate Validation**
Reduce noise and false positives while preserving potentially useful discoveries.

**Actionable Intelligence**
Transform raw reconnaissance output into a structured dataset that supports efficient vulnerability research.

---

## Use Cases

Recon Engine is designed for workflows such as:

* bug bounty reconnaissance
* external attack surface mapping
* infrastructure discovery
* web application security research
* large-scale reconnaissance automation

---

## Output

The final output is a comprehensive reconnaissance dataset containing discovered domains, validated infrastructure, application surfaces, historical endpoints, and visual service maps.

Rather than producing a flat list of URLs, Recon Engine generates an organized **map of the target’s external attack surface**, enabling researchers to quickly understand and investigate complex environments.
