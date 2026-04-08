---
name: k8s-network-recon
description: "Kubernetes 集群内网络侦察与服务发现。当已获得 Pod Shell、需要发现集群内其他服务、执行 K8s 内网扫描时使用。覆盖 DNS PTR 反查、SRV 记录枚举、AXFR 域传输、dnscan/K8Spider 使用。任何在 Pod 中需要横向侦察、寻找隐藏服务、确定攻击目标的场景都应使用此技能，即使用户没有明确提到 DNS"
metadata:
  tags: "k8s,kubernetes,dns,recon,service-discovery,dnscan,k8spider,cluster,内网侦察,服务发现"
  category: "cloud"
---

# Kubernetes 集群内网络侦察

在 K8s 集群中横向移动的第一步是弄清楚还有哪些服务在运行。因为 K8s 用 DNS 做服务发现，每个 Service 和 Pod 都有可预测的 DNS 名称，这意味着通过 DNS 反查就能系统性地枚举整个集群。

## K8s DNS 命名规则

| 资源类型 | DNS 格式 | 示例 |
|---------|---------|------|
| Service | `<svc>.<ns>.svc.cluster.local` | `redis.default.svc.cluster.local` |
| Pod | `<pod-ip-dashed>.<ns>.pod.cluster.local` | `10-244-0-5.default.pod.cluster.local` |
| Headless Service | `<pod-name>.<svc>.<ns>.svc.cluster.local` | `web-0.nginx.default.svc.cluster.local` |

> **注意**: DNS 后缀不一定是 `cluster.local`，由集群配置决定。检查 `/etc/resolv.conf` 中的 `search` 行。

### SRV 记录

Service 的 SRV 记录暴露端口信息：
```bash
nslookup -type=srv <service>.<namespace>.svc.cluster.local
# 输出示例: service = 0 50 80 svc.ns.svc.cluster.local
# 即使没有 _proto 前缀，也能查到所有有效端口
```

---

## Phase 1: 确定扫描范围

扫描前需要知道 Service CIDR 的大致范围，否则盲扫效率极低。按可靠度从高到低尝试：

```bash
# 1. 环境变量（最快，几乎必有）
echo $KUBERNETES_SERVICE_HOST
env | grep -i service_host

# 2. DNS 配置（nameserver 地址通常在 Service CIDR 内）
cat /etc/resolv.conf

# 3. DNS 查询（返回的 API Server IP 暴露 CIDR 段）
nslookup kubernetes.default.svc.cluster.local

# 4. 路由表/ARP（辅助推断）
cat /etc/hosts && ip route && arp -a 2>/dev/null

# 5. 避免用 ip addr — sidecar 注入的虚拟网卡会干扰判断
```

从获取到的 IP 推断 Service CIDR（通常 /16 或 /12）。

---

## Phase 2: DNS 批量扫描

### 使用 dnscan

```bash
# 扫描 /16 范围（覆盖大部分 Service IP）
dnscan -subnet 10.100.0.0/16

# 更精确的范围
dnscan -subnet 10.96.0.0/12    # 默认 Service CIDR
dnscan -subnet 10.244.0.0/16   # Pod CIDR (Flannel 默认)
dnscan -subnet 10.42.0.0/16    # Pod CIDR (K3s 默认)
```

### 使用 K8Spider（增强版）

```bash
# PTR 反查 + SRV 记录 + 多线程
k8spider scan -subnet 10.100.0.0/16
```

### 无工具时的手动方法

```bash
# PTR 反查 (逐个 IP)
for i in $(seq 1 254); do
  nslookup 10.100.0.$i 2>/dev/null | grep -v "NXDOMAIN" | grep "name =" &
done; wait

# AXFR 域传输（如果 CoreDNS 允许）
dig axfr cluster.local @$(grep nameserver /etc/resolv.conf | awk '{print $2}')

# Wildcard DNS（已被新版 CoreDNS 废弃，但老版本可能有效）
nslookup any.any.svc.cluster.local
```

---

## Phase 3: 服务利用

发现服务后的后续操作：

```bash
# 直接访问服务
curl <service>.<namespace>.svc.cluster.local

# 带端口访问（从 SRV 记录获取）
curl <service>.<namespace>.svc.cluster.local:<port>

# 常见高价值目标
# - kube-apiserver (6443)
# - etcd (2379)
# - kubelet (10250)
# - dashboard (443/8443)
# - prometheus/grafana (9090/3000)
# - istio/envoy (15000/15001)
# - kyverno (443)
# - argocd (443/80)
```

---

## 相关技能

发现服务后，根据目标类型加载对应技能：
- Istio/Envoy 相关服务 → `Skill(skill="k8s-istio-bypass")`
- Kyverno/OPA Webhook → `Skill(skill="k8s-webhook-abuse")`
- NFS/EFS 存储 → `Skill(skill="k8s-storage-exploit")`
- API Server/Kubelet → `Skill(skill="k8s-container-escape")`

## 工具速查

| 工具 | 用途 | 安装 |
|------|------|------|
| dnscan | K8s DNS 批量扫描 | CTF 预装 / Go 编译 |
| K8Spider | 增强版 dnscan (PTR+SRV+AXFR+多线程) | `go install github.com/Esonhugh/k8spider@latest` |
| nslookup/dig | 手动 DNS 查询 | 系统自带 |
| CDK | 容器渗透工具集（含服务发现） | f8x 安装 |
