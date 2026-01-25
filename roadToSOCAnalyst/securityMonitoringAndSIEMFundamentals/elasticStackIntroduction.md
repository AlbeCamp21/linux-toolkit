# Introduction to the Elastic Stack

## 1. What is the Elastic Stack?
The **Elastic Stack** (formerly known as the ELK Stack) is an open-source collection of applications designed to collect, search, analyze, and visualize data from any source in real-time.

### Core Components
* **Elasticsearch:** A distributed, JSON-based search and analytics engine. It handles indexing, storing, and querying data.
* **Logstash:** A data processing pipeline that ingests data from multiple sources, transforms/normalizes it, and sends it to Elasticsearch.
* **Kibana:** The visualization layer. It provides a web interface for searching data and creating custom dashboards.
* **Beats:** Lightweight data shippers installed on remote machines to forward logs and metrics to Logstash or Elasticsearch.



---

## 2. Logstash Pipeline Stages
Logstash operates through a three-step process:
1.  **Input:** Ingests raw logs (via TCP, UDP, Syslog, or flat files).
2.  **Filter:** Modifies, enriches, and normalizes the data (e.g., parsing a string into structured fields).
3.  **Output:** Transmits the processed records to a destination, typically Elasticsearch.



---

## 3. Kibana Query Language (KQL)
KQL is a user-friendly language used to search and filter data within Kibana. It is the primary tool for a SOC Analyst to investigate security events.

### Basic Syntax & Operators
* **Field-Value Pairs:** `field:value` (e.g., `event.code:4625`).
* **Logical Operators:** `AND`, `OR`, `NOT` (e.g., `event.code:4625 AND user.name:admin`).
* **Free Text Search:** Searching for a string across all fields (e.g., `"svc-sql1"`).
* **Comparison Operators:** `:`, `:>`, `:>=`, `:<`, `:<=`, `:!`.
* **Wildcards:** Using `*` to match patterns (e.g., `user.name: admin*`).

### Practical Example
To find failed logins on disabled accounts within a specific timeframe:
`event.code:4625 AND winlog.event_data.SubStatus:0xC0000072 AND @timestamp >= "2023-03-03" AND @timestamp <= "2023-03-06"`

---

## 4. Elastic Common Schema (ECS)
The **ECS** is a shared vocabulary that standardizes field names across the entire Elastic ecosystem.

### Key Advantages for SOC Analysts:
1.  **Unified Data View:** Search Windows logs and Network logs using the same field names (e.g., `source.ip`).
2.  **Enhanced Correlation:** Easily link an IP address across firewalls, endpoints, and cloud logs.
3.  **Future-proofing:** Ensures compatibility with advanced features like Elastic Machine Learning and Security.
4.  **Efficiency:** Reduces the need to memorize specific field names for different data sources (e.g., Winlogbeat vs. Filebeat).



---

## 5. Identifying Data in Kibana
Analysts can discover available fields using two main methods:
* **The "Discover" Feature:** Using free text search (like searching for `"4625"`) to see which fields are automatically populated.
* **Official Documentation:** Consulting the Elastic ECS and Winlogbeat field references to understand what each attribute represents (e.g., `SubStatus` codes).
