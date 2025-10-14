# How to setup ELK Stack (Elasticsearch, Logstash, Kibana, HeartBeat, FileBeat, PacketBeat, AuditBeat, MetricBeat) on a single VM (ELK-SERVER) and configure Filebeat to ship logs to Logstash.

[https://harishnshetty.github.io/projects.html](https://harishnshetty.github.io/projects.html)

[![Video Tutorial](https://github.com/harishnshetty/image-data-project/blob/966666d51a2d0edc8c7093294d2db6b03005273e/ELk.jpg)](https://youtu.be/KwKtMHBQXk4)

| **Beat Name**                                   | **Purpose / What It Collects**        | **Example Use Case**                                     |
|-------------------------------------------------|---------------------------------------|----------------------------------------------------------|
| 🪵 **Filebeat**                                 | Log files                             | Application, system, Nginx, Docker, or custom logs       |
| 📈 **Metricbeat**                               | Metrics (CPU, memory, disk, services) | System, Docker, MySQL, K8s performance metrics           |
| 💓 **Heartbeat**                                | Uptime monitoring                     | Ping websites, APIs, or hosts to check availability      |
| 🔍 **Packetbeat**                               | Network traffic                       | Analyze network flows, latency, DNS, HTTP, MySQL queries |
| 🛡️ **Auditbeat**                               | Security and file integrity auditing  | Detect user logins, file changes, sudo access            |
| ☁️ **Cloudbeat** *(newer — Elastic Cloud only)* | Cloud security posture [Not Covered in Video] | Collect CSPM data from AWS, GCP, Azure           |

---

## Create the Custom VPC

| Name        | ELK-Project      |
|-------------|------------------|
| VPC Network | 10.75.0.0/16     |
| Subnet      | 10.75.1.0/24     |
| Public Net  | 1 without Nat GW |

| OS           | Name           | IP           |
|--------------|----------------|--------------|
| Ubuntu       | ELK-SERVER     | 10.75.1.100  |
| Ubuntu       | Client-Ubuntu  | 10.75.1.10   |
| Amazon-Linux | Client-Amazon  | 10.75.1.11   |

# Create SG ELK-SG

| Service      | Port  | Source |
|--------------|-------|--------|
| SSH          | 22    | ALL    |
| Kibana       | 5601  | ALL    |
| Elasticsearch| 9200  | ALL    |

## Save and Exit

# ReEdit the SG

| Type        | Port/Protocol | Source  |
|-------------|---------------|---------|
| Custom      | All traffic   | ELK-SG  |

# Elk-Server Setup [4 CPU, 8 GB RAM, 29 GB Minimum] c5.xlarge

- Set Private IP: 10.75.1.100
---

## 🧩 **Elasticsearch**

> **Purpose:** Distributed search, analytics, and data storage engine

Elasticsearch is the **core component** of the ELK Stack. It stores, indexes, and analyzes large volumes of data in near real-time. Whether it’s logs, metrics, or application data collected by Beats or Logstash, Elasticsearch enables fast full-text search, aggregations, and data visualization through Kibana.

* **Type:** NoSQL distributed document database
* **Data Format:** JSON-based documents
* **Supports:** Full-text search, structured queries, and aggregations
* **Input Sources:** Filebeat, Metricbeat, Heartbeat, Packetbeat, Auditbeat, Logstash
* **Output Tools:** Kibana dashboards, API queries, alerts

---
```bash
sudo su -
hostnamectl set-hostname ELK-SERVER
echo "10.75.1.100 ELK-SERVER elk" >> /etc/hosts
cat /etc/hosts

apt update
apt install gnupg2 apt-transport-https curl default-jdk vim nano git net-tools -y
ifconfig

shutdown -r now
sudo apt update -y

wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | \
gpg --dearmor -o /etc/apt/trusted.gpg.d/elastic.gpg
echo "deb https://artifacts.elastic.co/packages/9.x/apt stable main" > /etc/apt/sources.list.d/elastic-9.x.list

apt update
apt install elasticsearch -y
```

# Check the Password in the Console Output

```bash
O7CPpzkxYb3VFB0cQ*E_
```

```bash
grep -Ev '^#|^$' /etc/elasticsearch/elasticsearch.yml
echo "-Xms4g
-Xmx4g" > /etc/elasticsearch/jvm.options.d/jvm-heap.options

cp /etc/elasticsearch/elasticsearch.yml /etc/elasticsearch/elasticsearch.yml.bak

sed -i 's/#network.host: 192.168.0.1/network.host: 0.0.0.0/' /etc/elasticsearch/elasticsearch.yml
sed -i 's/#transport.host: 0.0.0.0/transport.host: 0.0.0.0/' /etc/elasticsearch/elasticsearch.yml

systemctl daemon-reload
systemctl enable --now elasticsearch
systemctl start elasticsearch
systemctl status elasticsearch

ss -altnp | grep -E "9200|9300"
```

## Reset the Elastic Password Via Console

```bash
/usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -i
abcd@1234
```

## This Command shows the Right Configuration Confirmation

```bash
curl https://ELK-SERVER:9200 --cacert /etc/elasticsearch/certs/http_ca.crt -u elastic:abcd@1234
```

https://<public-IP>:9200 --> in web browser HTTPS Only

```bash
tail -f /var/log/elasticsearch/elasticsearch.log
```

## Installation step of Kibana

---

## 📊 **Kibana**

> **Purpose:** Visualization, exploration, and management UI for Elasticsearch data

Kibana is the **frontend** of the Elastic Stack — a powerful analytics and visualization tool that allows you to explore, analyze, and monitor data stored in **Elasticsearch**. It provides dashboards, charts, and real-time visualizations to turn raw log and metric data into actionable insights.

* **Type:** Web-based visualization and analytics tool
* **Data Source:** Elasticsearch indices
* **Supports:** Dashboards, saved searches, alerts, and machine learning insights
* **Integrates With:** Filebeat, Metricbeat, Heartbeat, Packetbeat, Auditbeat, Logstash

```bash
apt install kibana -y
cp /etc/kibana/kibana.yml /etc/kibana/kibana_backup.yml

sed -i 's/#server.port: 5601/server.port: 5601/' /etc/kibana/kibana.yml
sed -i 's/#server.host: "localhost"/server.host: "0.0.0.0"/' /etc/kibana/kibana.yml
```

## Replace the generated Encryption Value inside the command

```bash
/usr/share/kibana/bin/kibana-encryption-keys generate

echo -e "xpack.encryptedSavedObjects.encryptionKey: a4478a7b06851c9ade28d49dee092733
xpack.reporting.encryptionKey: 01e570c2a747d5af721a54db9462fe51
xpack.security.encryptionKey: 7dd0a309e7818cf32fabf74ae108118b" >> /etc/kibana/kibana.yml

grep -Ev '^#|^$' /etc/kibana/kibana.yml

systemctl daemon-reload
systemctl enable --now kibana
systemctl start kibana
systemctl status kibana

/usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana

eyJ2ZXIiOiI4LjE0LjAiLCJhZHIiOlsiMTAuNzUuMS4xMDA6OTIwMCJdLCJmZ3IiOiI3YTIxMmQ5NzRjZDE2Yjc4YmRkNWUzZTM1NDFkNTU3OTU1ODkxNGFlNmVmNTJiYzZjMGE5ZDM4MTFhNDZkZDZiIiwia2V5IjoiU3gtWjRwa0J4RkQ1WDk4eTNrLXo6MVlBYWo0RFFGM2Flel8zcjhEZElHUSJ9

/usr/share/kibana/bin/kibana-verification-code
```

## Access it Via the Browser

- http://<public-ip>:5601   ---> http only

```bash
ss -altnp | grep 5601
```

---

# Logstash Installation

## 🔄 **Logstash**

> **Purpose:** Data collection, transformation, and forwarding pipeline

Logstash is a **data processing pipeline** that ingests data from multiple sources, transforms it, and then sends it to **Elasticsearch** (or other outputs). It acts as the bridge between Beats (or other data sources) and Elasticsearch, enabling filtering, parsing, and enrichment of logs and metrics.

* **Type:** Data processing and ETL (Extract, Transform, Load) tool
* **Input Sources:** Filebeat, Metricbeat, Heartbeat, Packetbeat, Auditbeat, or any other logs/metrics
* **Processing:** Filtering, parsing, enriching, and formatting data
* **Output Destinations:** Elasticsearch, Kafka, files, or other sinks
---

```bash
apt install logstash -y

/etc/elasticsearch/certs/

openssl s_client -showcerts -connect ELK-SERVER:9200 </dev/null 2>/dev/null \
| openssl x509 > /etc/logstash/elasticsearch-ca.crt

systemctl daemon-reload
systemctl enable --now logstash
systemctl start logstash
systemctl status logstash

tail -f /var/log/logstash/logstash-plain.log

ss -altnp | grep 5044
```
---
## 🪵 **Filebeat** Installation

> **Purpose:** Lightweight log shipper for collecting and forwarding log data

Filebeat is a **lightweight agent** installed on servers to **collect logs** from different sources and forward them to **Elasticsearch** or **Logstash**. It’s designed to be efficient, with minimal resource usage, and supports a wide range of log types and modules.

* **Type:** Log shipper / forwarder
* **Input Sources:** Application logs, system logs, Nginx, Docker logs, or custom log files
* **Outputs:** Elasticsearch, Logstash, or other supported outputs
* **Modules:** Predefined configurations for common apps like Nginx, Apache, MySQL, System, and Docker

---
[![Video Tutorial](https://github.com/harishnshetty/image-data-project/blob/1e88df558de6aaa7698e904e06fdb94286e3882d/filebeat.JPG)](https://youtu.be/KwKtMHBQXk4)
---
```bash
apt install filebeat -y
cp /etc/filebeat/filebeat.yml /etc/filebeat/filebeat_backup.yml

telnet ELK-SERVER 9200

filebeat test config
filebeat test output

nano /etc/filebeat/filebeat.yml
```

```bash
# filestream is an input for collecting log messages from files.
- type: filestream
  id: my-filestream-id
  enabled: true
  paths:
    - /var/log/*.log
    - /var/log/syslog
```

```bash
# =================================== Kibana ===================================
setup.kibana:
  host: "ELK-SERVER:5601"
```

```bash
# ---------------------------- Elasticsearch Output ----------------------------
output.elasticsearch:
  hosts: ["ELK-SERVER:9200"]
  preset: balanced
  protocol: "https"
  ssl.certificate_authorities: ["/etc/elasticsearch/certs/http_ca.crt"]
  username: "elastic"
  password: "abcd@1234"
```

```bash
filebeat test config -e
filebeat modules list
filebeat modules enable system
cat /etc/filebeat/modules.d/system.yml
sed -i '/enabled:/s/false/true/' /etc/filebeat/modules.d/system.yml
nano /etc/filebeat/modules.d/system.yml

# var.paths: ["/path/to/log1","/path/to/log2","/path/to/logN","/var/log/*.log","/var/log/syslog" ]

filebeat setup -e

systemctl daemon-reload
systemctl enable --now filebeat
systemctl start filebeat
systemctl restart filebeat
systemctl status filebeat
```

<!--  
ufw allow 5044
ufw allow 9200
ufw allow 9300
ufw allow 5601
ufw allow 5400 
-->

## Check in the Discover

```bash
ss -altnp | grep -E "9200|9300|5601"
```

# Client-Ubuntu Setup T2.Micro

- Set Private IP: 10.75.1.10

### 🪵 **Filebeat**

> **Purpose:** Log collection and forwarding

Filebeat is a lightweight shipper that collects and centralizes log data from different sources. It monitors application, system, Nginx, or Docker logs, then forwards them securely to Elasticsearch or Logstash.

* Collects: Application, system, Nginx, Docker, or custom logs
* Outputs: Elasticsearch / Logstash
* **Use case:** Centralized logging and troubleshooting

---

```bash
sudo su -
hostnamectl set-hostname CLIENT-UBUNTU
echo "10.75.1.100 ELK-SERVER elk" >> /etc/hosts
cat /etc/hosts

apt update
apt install gnupg2 apt-transport-https curl default-jdk vim nano git net-tools -y
ifconfig

shutdown -r now
sudo apt update -y

wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | \
gpg --dearmor -o /etc/apt/trusted.gpg.d/elastic.gpg
echo "deb https://artifacts.elastic.co/packages/9.x/apt stable main" > /etc/apt/sources.list.d/elastic-9.x.list

apt update
apt install filebeat -y
cp /etc/filebeat/filebeat.yml /etc/filebeat/filebeat_backup.yml

telnet ELK-SERVER 9200

filebeat test config
filebeat test output

nano /etc/filebeat/filebeat.yml
```

```bash
# filestream is an input for collecting log messages from files.
- type: filestream
  id: my-filestream-id
  enabled: true
  paths:
    - /var/log/*.log
    - /var/log/syslog
```

```bash
# =================================== Kibana ===================================
setup.kibana:
  host: "ELK-SERVER:5601"
```

## Comment out the Elasticsearch Output

```bash
# ------------------------------ Logstash Output -------------------------------
output.logstash:
  hosts: ["ELK-SERVER:5044"]
```

```bash
filebeat test output
filebeat modules list
filebeat modules enable system
cat /etc/filebeat/modules.d/system.yml
sed -i '/enabled:/s/false/true/' /etc/filebeat/modules.d/system.yml
cat /etc/filebeat/modules.d/system.yml

filebeat setup -e

systemctl daemon-reload
systemctl enable --now filebeat
systemctl start filebeat
systemctl restart filebeat
systemctl status filebeat
```

---

# Inside the main Elk-Server Configure Logstash Filtering

```bash
nano /etc/logstash/conf.d/filebeat-client-ubuntu.conf
```

```bash
input {
  beats {
    port => 5044 # Must match the port configured in filebeat.yml
  }
}

filter {
  if [fields][module] == "system" {
    grok {
      match => { "message" => "%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}" }
    }
    mutate {
      add_field => { "source_beat" => "filebeat_system" }
    }
  }
}

output {
  elasticsearch {
    hosts => ["https://ELK-SERVER:9200"]
    ssl_enabled => true
    ssl_certificate_authorities => '/etc/logstash/elasticsearch-ca.crt'
    user => 'elastic'
    password => 'abcd@1234'
    index => "ubuntu-filebeat-%{[@metadata][version]}-%{+YYYY.MM.dd}"
  }
  stdout { 
    codec => rubydebug 
  }
}
```

```bash
cd /etc/elasticsearch/certs/
openssl s_client -showcerts -connect ELK-SERVER:9200 </dev/null 2>/dev/null \
| openssl x509 > /etc/logstash/elasticsearch-ca.crt

sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t

chmod 777  /etc/logstash/conf.d/filebeat-client-ubuntu.conf
chown -R logstash:logstash /usr/share/logstash/data

sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t
sudo -u logstash /usr/share/logstash/bin/logstash -f  /etc/logstash/conf.d/filebeat-client-ubuntu.conf

systemctl daemon-reload
systemctl enable --now logstash
systemctl start logstash
systemctl restart logstash
systemctl status logstash

ss -tulnp | grep 5044
```

# In the Client-Ubuntu Machine FileBeat Installtion

```bash
filebeat setup -e
```

<!-- telnet ELK-SERVER 5601
filebeat setup --dashboards -E setup.kibana.host="ELK-SERVER:5601"
filebeat setup --dashboards -E setup.kibana.host="ELK-SERVER:5601" -e -->

-----------

# Client-Amazon Setup T2.Micro

- Set Private IP: 10.75.1.11

### 🪵 **Filebeat**

> **Purpose:** Log collection and forwarding

Filebeat is a lightweight shipper that collects and centralizes log data from different sources. It monitors application, system, Nginx, or Docker logs, then forwards them securely to Elasticsearch or Logstash.

* Collects: Application, system, Nginx, Docker, or custom logs
* Outputs: Elasticsearch / Logstash
* **Use case:** Centralized logging and troubleshooting

---

```bash
sudo su -
hostnamectl set-hostname CLIENT-Amazon
echo "10.75.1.100 ELK-SERVER elk" >> /etc/hosts
cat /etc/hosts

shutdown -r now

# install only filebeat

sudo dnf update -y

sudo rpm --import https://yum.corretto.aws/corretto.key
sudo curl -L -o /etc/yum.repos.d/corretto.repo https://yum.corretto.aws/corretto.repo
sudo dnf update -y

sudo dnf install gnupg2 curl telnet java-17-amazon-corretto-devel vim nano git -y

sudo tee /etc/yum.repos.d/elasticsearch.repo > /dev/null <<'EOF'
[elasticsearch-9.x]
name=Elasticsearch repository for 9.x packages
baseurl=https://artifacts.elastic.co/packages/9.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=1
autorefresh=1
type=rpm-md
EOF

sudo dnf clean all
sudo dnf makecache
# For Elasticsearch only
# sudo dnf install elasticsearch -y

# For Kibana
# sudo dnf install kibana -y

# For Logstash
# sudo dnf install logstash -y

# For filebeat
sudo dnf install filebeat -y

cp /etc/filebeat/filebeat.yml /etc/filebeat/filebeat.yml.bak

telnet ELK-SERVER 9200

filebeat test config
filebeat test output

nano /etc/filebeat/filebeat.yml
```

```bash
# filestream is an input for collecting log messages from files.
- type: filestream
  id: my-filestream-id
  enabled: true
  paths:
    - /var/log/*.log
    - /var/log/syslog
```

```bash
# =================================== Kibana ===================================
setup.kibana:
  host: "ELK-SERVER:5601"
```

# Generate finger-print in the ELK-server

```bash
cd /etc/elasticsearch/certs/
openssl x509 -in http_ca.crt -noout -fingerprint -sha256 | cut -d '=' -f2 | tr -d ':' | tr 'A-F' 'a-f' >> /etc/filebeat/fingerprint.txt
cat /etc/filebeat/fingerprint.txt
```

## Copy the Generated Cert Key

- 7a212d974cd16b78bdd5e3e3541d5579558914ae6ef52bc6c0a9d3811a46dd6b

```bash
# ---------------------------- Elasticsearch Output ----------------------------
output.elasticsearch:
  hosts: ["ELK-SERVER:9200"]
  preset: balanced
  protocol: "https"
  ssl:
    enabled: true
    ca_trusted_fingerprint: "7a212d974cd16b78bdd5e3e3541d5579558914ae6ef52bc6c0a9d3811a46dd6b"
  username: "elastic"
  password: "abcd@1234"
```

```bash
filebeat test config -e
filebeat modules list
filebeat modules enable system
cat /etc/filebeat/modules.d/system.yml
sed -i '/enabled:/s/false/true/' /etc/filebeat/modules.d/system.yml
nano /etc/filebeat/modules.d/system.yml

filebeat setup -e

systemctl daemon-reload
systemctl enable --now filebeat
systemctl start filebeat
systemctl restart filebeat
systemctl status filebeat
```

<!--  
ufw allow 5044
ufw allow 9200
ufw allow 9300
ufw allow 5601
ufw allow 5400 
-->

## Check in the Discover
---

## install heartbeat inside the ELK-Server


### 💓 **Heartbeat**

> **Purpose:** Uptime and availability monitoring

Heartbeat pings websites, APIs, or network hosts to verify uptime and response time. It logs status changes, response latency, and errors to help track service availability and reliability.

* Checks: HTTP, TCP, ICMP endpoints
* Outputs: Elasticsearch / Logstash
* **Use case:** Uptime monitoring and SLA reporting

---
[![Video Tutorial](https://github.com/harishnshetty/image-data-project/blob/1e88df558de6aaa7698e904e06fdb94286e3882d/heartbeat.JPG)](https://youtu.be/KwKtMHBQXk4)
---
```bash
sudo su -
apt install heartbeat-elastic
cp /etc/heartbeat/heartbeat.yml /etc/heartbeat/heartbeat.yml.bak
nano /etc/heartbeat/heartbeat.yml
```

```yaml
- type: http
  enable: true
  id: Harish-Website
  name: Harish Project Website
  schedule: '@every 15s'
  urls: ["https://harishnshetty.github.io"]

- type: http
  enable: true
  id: times-of-india
  name: Times of India Website
  schedule: '@every 15s'
  urls: ["https://timesofindia.indiatimes.com"]

- type: http
  enable: true
  id: kibana_url
  name: kibana url
  schedule: '@every 45s'
  urls: ["http://ELK-SERVER:5601"]

- type: icmp
  enable: true
  id: local-ping
  name: Localhost Ping
  schedule: '@every 10s'
  hosts: ["localhost"]
```

```bash
# ---------------------------- Elasticsearch Output ----------------------------
output.elasticsearch:
  hosts: ["ELK-SERVER:9200"]
  preset: balanced
  protocol: "https"
  ssl.certificate_authorities: ["/etc/elasticsearch/certs/http_ca.crt"]
  username: "elastic"
  password: "abcd@1234"

sudo heartbeat test config
sudo heartbeat -e -c /etc/heartbeat/heartbeat.yml

sudo systemctl enable heartbeat-elastic
sudo systemctl start heartbeat-elastic
sudo systemctl status heartbeat-elastic
sudo tail -f /var/log/heartbeat/heartbeat.log
```
---
## install metricbeat inside the ELK-Server

### 📈 **Metricbeat**

> **Purpose:** System and service metrics collection

Metricbeat gathers metrics from your OS and services such as CPU, memory, disk usage, and network stats. It can also monitor services like **MySQL**, **Docker**, **Nginx**, and **Kubernetes** to track performance and resource usage.

* Collects: CPU, memory, disk, Docker, MySQL, K8s metrics
* Outputs: Elasticsearch / Logstash
* **Use case:** Infrastructure performance monitoring and alerting

---
[![Video Tutorial](https://github.com/harishnshetty/image-data-project/blob/1e88df558de6aaa7698e904e06fdb94286e3882d/metricbeat.JPG)](https://youtu.be/KwKtMHBQXk4)
---
```bash
sudo su -
apt install metricbeat
cp /etc/metricbeat/metricbeat.yml /etc/metricbeat/metricbeat.yml.bak
nano /etc/metricbeat/metricbeat.yml
```

```bash
# ---------------------------- Elasticsearch Output ----------------------------
output.elasticsearch:
  hosts: ["ELK-SERVER:9200"]
  preset: balanced
  protocol: "https"
  ssl.certificate_authorities: ["/etc/elasticsearch/certs/http_ca.crt"]
  username: "elastic"
  password: "abcd@1234"

sudo metricbeat test config
sudo metricbeat -e -c /etc/metricbeat/metricbeat.yml
sudo metricbeat modules list
sudo metricbeat modules enable system

ls /etc/metricbeat/modules.d/ | grep system
```

| Command                                        | Description                   |
|------------------------------------------------|-------------------------------|
| `sudo metricbeat modules enable docker`        | Monitor Docker containers     |
| `sudo metricbeat modules enable nginx`         | Monitor Nginx                |
| `sudo metricbeat modules enable mysql`         | Monitor MySQL                |
| `sudo metricbeat modules enable elasticsearch` | Monitor Elasticsearch cluster |

```bash
sudo tail -f /var/log/metricbeat/metricbeat
sudo metricbeat -e -c /etc/metricbeat/metricbeat.yml

sudo systemctl enable metricbeat.service
sudo systemctl start metricbeat.service
sudo systemctl status metricbeat.service
```
---

## install Packetbeat inside the ELK-Server


### 🔍 **Packetbeat**

> **Purpose:** Network traffic analysis

Packetbeat analyzes network packets in real-time and decodes application-level protocols like **HTTP**, **DNS**, **MySQL**, and **TLS**. It helps visualize request/response times, latency, and detect anomalies in network communication.

* Captures: Network packets and protocol data
* Outputs: Elasticsearch / Logstash
* **Use case:** Network monitoring and performance diagnostics

---
[![Video Tutorial](https://github.com/harishnshetty/image-data-project/blob/1e88df558de6aaa7698e904e06fdb94286e3882d/packetbeat.JPG)](https://youtu.be/KwKtMHBQXk4)
---

```bash
sudo su -
sudo apt install -y packetbeat
cp /etc/packetbeat/packetbeat.yml /etc/packetbeat/packetbeat.yml.bak
nano /etc/packetbeat/packetbeat.yml
```

```bash
# ---------------------------- Elasticsearch Output ----------------------------
output.elasticsearch:
  hosts: ["ELK-SERVER:9200"]
  preset: balanced
  protocol: "https"
  ssl.certificate_authorities: ["/etc/elasticsearch/certs/http_ca.crt"]
  username: "elastic"
  password: "abcd@1234"

sudo packetbeat test config
sudo packetbeat -e -c /etc/packetbeat/packetbeat.yml

sudo systemctl enable packetbeat
sudo systemctl start packetbeat
sudo systemctl status packetbeat
```

## install Auditbeat inside the ELK-Server



### 🛡️ **Auditbeat**

> **Purpose:** Security and file integrity auditing

Auditbeat monitors system activity for security and compliance. It tracks file modifications, user logins, sudo access, and permission changes to detect suspicious behavior or policy violations.

* Tracks: File integrity, login activity, process auditing
* Outputs: Elasticsearch / Logstash
* **Use case:** Security auditing, compliance, and intrusion detection

---

[![Video Tutorial](https://github.com/harishnshetty/image-data-project/blob/1e88df558de6aaa7698e904e06fdb94286e3882d/auditbeat.JPG)](https://youtu.be/KwKtMHBQXk4)
---

```bash
sudo su -
sudo apt install -y auditbeat
cp /etc/packetbeat/packetbeat.yml /etc/packetbeat/packetbeat.yml.bak
nano /etc/packetbeat/packetbeat.yml
```

```bash
# ---------------------------- Elasticsearch Output ----------------------------
output.elasticsearch:
  hosts: ["ELK-SERVER:9200"]
  preset: balanced
  protocol: "https"
  ssl.certificate_authorities: ["/etc/elasticsearch/certs/http_ca.crt"]
  username: "elastic"
  password: "abcd@1234"

sudo auditbeat test config
sudo auditbeat test output

sudo systemctl enable auditbeat
sudo systemctl start auditbeat
sudo systemctl status auditbeat
```

## Clean-up

- EC2
- VPC
- SG


## For more projects, check out  
[https://harishnshetty.github.io/projects.html](https://harishnshetty.github.io/projects.html)
## Explore New Videos By Click the Image
[![Video Tutorial](https://github.com/harishnshetty/image-data-project/blob/6135e01f68ebd6c691f8fc2304cfcb6d1e867dd6/ecr3.jpg)](https://www.youtube.com/@devopsHarishNShetty)
