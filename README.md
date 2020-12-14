# Cilium Hands-On Lab

## Part 1 - Setup Your Local Lab Environment

In this first exercise, you will install and configure a local Kubernetes
cluster based on minikube and install Cilium into the cluster. Once
Cilium is installed, you will deploy an application which will be used
throughout the remaining exercises to demonstrate the various features of Cilium.

### Install `kubectl`

The `kubectl` Kubernetes client will be used throughout the exercises to
interact with the Kubernetes API. If you already have the latest version
installed, you can skip this section. If none of the provided installation
methods apply for your environment, visit the [Official Installation Guide](https://kubernetes.io/docs/tasks/tools/install-kubectl/).

To check your current version run:

```
kubectl version --client
```

#### Linux Installation

* Install `kubectl` using `curl`:

```
curl -LO "https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x ./kubectl
sudo mv ./kubectl /usr/local/bin/kubectl
```

#### macOS Installation

* Option A - Install `kubectl` with Homebrew (recommended):

```
brew install kubectl
```

If you get a message that the package is already installed, you can upgrade
to the latest version:

```
brew upgrade kubectl
```

* Option B - Install `kubectl` with `curl`:

```
curl -LO "https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/darwin/amd64/kubectl"
chmod +x ./kubectl
sudo mv ./kubectl /usr/local/bin/kubectl
```

#### Windows Installation

[Download the Latest Release](https://storage.googleapis.com/kubernetes-release/release/v1.20.0/bin/windows/amd64/kubectl.exe)

### Validate `kubectl` Installation

Test to ensure the version you installed is up-to-date:

```
kubectl version --client
```

### minikube Installation

minikube runs on Linux, macOS, and Windows. Please follow the instructions
for your operating system.

#### Linux Installation

For Linux users, there are 3 download options (for each architecture):

Binary download:

```
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
sudo install minikube-linux-amd64 /usr/local/bin/minikube
```

Debian package:

```
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube_latest_amd64.deb
sudo dpkg -i minikube_latest_amd64.deb
```

RPM package:

```
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-latest.x86_64.rpm
sudo rpm -ivh minikube-latest.x86_64.rpm
```

#### macOS Installation:

* Option A (recommended) - Brew Package Manager:

```
brew install minikube
```

If you get a message that the package is already installed, you can upgrade
to the latest version:

```
brew upgrade minikube
```

* Option B - download minikube directly:

```
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-darwin-amd64
sudo install minikube-darwin-amd64 /usr/local/bin/minikube
```
#### Windows Installation:

* If the Chocolatey Package Manager is installed, use it to install minikube:

```
choco install minikube
```

* Otherwise, download and run the [Windows Installer](https://storage.googleapis.com/minikube/releases/latest/minikube-installer.exe).

### Start a minikube Cluster

After minikube is installed, start your cluster. From a terminal with administrator access (but not logged in as root), run:

```
minikube start --network-plugin=cni --memory=4096
```

Remove the default CNI configuration to avoid potential conflicts:

```
minikube ssh -- sudo rm /etc/cni/net.d/*.conflist
```

### Interact with the minikube Cluster

To list all pods running in the cluster:

```
cilium-hands-on-lab % kubectl get po -A
NAMESPACE     NAME                               READY   STATUS    RESTARTS   AGE
kube-system   coredns-f9fd979d6-6ql48            1/1     Running   0          3m6s
kube-system   etcd-minikube                      1/1     Running   0          3m12s
kube-system   kube-apiserver-minikube            1/1     Running   0          3m12s
kube-system   kube-controller-manager-minikube   1/1     Running   0          3m12s
kube-system   kube-proxy-zxgb4                   1/1     Running   0          3m6s
kube-system   kube-scheduler-minikube            1/1     Running   0          3m12s
kube-system   storage-provisioner                1/1     Running   0          3m12s
```

### Cilium Installation

Install Cilium into the Minikube cluster:

```
kubectl apply -f https://raw.githubusercontent.com/cilium/cilium/v1.9/install/kubernetes/experimental-install.yaml
```

After a few minutes you should see all of the Cilium pods in a `Running` state:

```
cilium-hands-on-lab % kubectl get po -n kube-system
NAME                               READY   STATUS      RESTARTS   AGE
cilium-kqfgj                       1/1     Running     0          59s
cilium-operator-5df7f6cb65-mg5hz   1/1     Running     0          103s
coredns-f9fd979d6-8lngz            1/1     Running     0          79s
etcd-minikube                      1/1     Running     0          2m9s
hubble-generate-certs-nc5z5        0/1     Completed   0          75s
hubble-relay-544876fc89-d7bql      1/1     Running     0          75s
hubble-ui-5df5fb587d-fjfl5         3/3     Running     0          75s
kube-apiserver-minikube            1/1     Running     0          2m9s
kube-controller-manager-minikube   1/1     Running     0          2m9s
kube-proxy-q79ps                   1/1     Running     0          2m4s
kube-scheduler-minikube            1/1     Running     0          2m9s
storage-provisioner                1/1     Running     0          2m9s
```

In the output, you can see the following new pods running:

* Cilium Agent
* Cilium Operator
* Hubble Cert
* Hubble Relay
* Hubble UI

To view the status of the Cilium agent, run the following

```bash
export POD_NAME=$(kubectl get po -n kube-system -l k8s-app=cilium | grep -v NAME | awk '{print $1}')
kubectl exec -itn kube-system $POD_NAME -- cilium status

cilium-hands-on-lab % kubectl exec -itn kube-system $POD_NAME -- cilium status
KVStore:                Ok   Disabled
Kubernetes:             Ok   1.19 (v1.19.4) [linux/amd64]
Kubernetes APIs:        ["cilium/v2::CiliumClusterwideNetworkPolicy", "cilium/v2::CiliumEndpoint", "cilium/v2::CiliumLocalRedirectPolicy", "cilium/v2::CiliumNetworkPolicy", "cilium/v2::CiliumNode", "core/v1::Namespace", "core/v1::Node", "core/v1::Pods", "core/v1::Service", "discovery/v1beta1::EndpointSlice", "networking.k8s.io/v1::NetworkPolicy"]
KubeProxyReplacement:   Probe   [eth0 (Direct Routing)]
Cilium:                 Ok      OK
NodeMonitor:            Listening for events on 2 CPUs with 64x4096 of shared memory
Cilium health daemon:   Ok
IPAM:                   IPv4: 3/255 allocated from 10.0.0.0/24,
BandwidthManager:       Disabled
Host Routing:           Legacy
Masquerading:           BPF   [eth0]   10.0.0.0/24
Controller Status:      22/22 healthy
Proxy Status:           OK, ip 10.0.0.69, 0 redirects active on ports 10000-20000
Hubble:                 Ok              Current/Max Flows: 1151/4096 (28.10%), Flows/s: 2.24   Metrics: Ok
Cluster health:         1/1 reachable   (2020-12-14T01:05:11Z)
```

Here you can see basic information about Cilium configuration and the status
of the local agent. Status includes information about key/value store
connectivity, IPAM allocations, as well as the configuration of various Cilium
features.

What does it report about the Kube Proxy Replacement status?

What is reported about the number of Flows that Hubble is receiving?

How many nodes are reachable?

### Install a Demo Application

Next, you will install a demo applicaiton which will be used throughout the
remaining exercises. This includes an application running across three tenants
as well as a base network policy for tenant A.

```
kubectl create ns tenant-a
kubectl create ns tenant-b
kubectl create ns tenant-c
kubectl apply -f https://raw.githubusercontent.com/seanmwinn/cilium-hands-on-lab/master/tenant-services.yaml -n tenant-a
kubectl apply -f https://raw.githubusercontent.com/seanmwinn/cilium-hands-on-lab/master/tenant-services.yaml -n tenant-b
kubectl apply -f https://raw.githubusercontent.com/seanmwinn/cilium-hands-on-lab/master/tenant-services.yaml -n tenant-c
kubectl apply -n tenant-a -f https://raw.githubusercontent.com/seanmwinn/cilium-hands-on-lab/master/allow-all-within-ns.yaml
kubectl apply -n tenant-a -f https://raw.githubusercontent.com/seanmwinn/cilium-hands-on-lab/master/to-dns-only.yaml
```

Here are the policies being applied:

allow-all-within-ns.yaml:

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: allow-all-within-ns-policy
spec:
  endpointSelector: {}
  egress:
  - toEndpoints:
    - {}
  ingress:
  - fromEndpoints:
    - {}
```

to-dns-only.yaml:

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: to-dns-only
spec:
  endpointSelector: {}
  egress:
    - toEndpoints:
        - matchLabels:
            io.kubernetes.pod.namespace: kube-system
            k8s-app: kube-dns
      toPorts:
        - ports:
            - port: '53'
              protocol: UDP
          rules:
            dns:
              - matchPattern: '*'
```

In the first policy, the empty endpointSelector `{}` means that the policy
will match all endpoints within a namespace. The ingress and egress policies
also specify the empty set `{}` which means that it will allow from all traffic
and to all traffic within a namespace.

In the second policy, the egress policy is more specific. You can see
a rule has been specified limiting outbound traffic to only pods matching the
labels for the `kube-dns` service along with another rule limiting traffic to
port 53 using only UDP.

As you can see, Cilium network policies can provide fine-grained access controls
between Kuberetes applications - not just by port or protocol, but also based on
an identity - or a label applied to the pods running in a cluster. Many pods in
a kubernetes cluster can, and often do, share an identity, greatly reducing the
amount of overhead necessary to secure your applications.

## Part 2 - Cilium Deep-dive

### Exploring eBPF

Start a new shell in the running Cilium agent pod:

```bash
export POD_NAME=$(kubectl get po -n kube-system -l k8s-app=cilium | grep -v NAME | awk '{print $1}')
kubectl exec -itn kube-system $POD_NAME -- /bin/bash
```

#### View eBPF Raw Data

In the exercise, you will explore the eBPF state of your Cilium agent container.
The commands used in the exercise are meant to demonstrate the basics of eBPF,
however it is not necessary to understand anything about eBPF to use Cilium.
This is presented so that you will have a basic understanding of how Cilium
implements eBPF into the network data path.

* View a list of eBPF programs presently attached to network devices:

```
root@minikube:/usr/bin# bpftool net

xdp:

tc:
eth0(2) clsact/ingress bpf_netdev_eth0.o:[from-netdev] id 1263
eth0(2) clsact/egress bpf_netdev_eth0.o:[to-netdev] id 1269
cilium_net(7) clsact/ingress bpf_host_cilium_net.o:[to-host] id 1257
cilium_host(8) clsact/ingress bpf_host.o:[to-host] id 1235
cilium_host(8) clsact/egress bpf_host.o:[from-host] id 1245
cilium_vxlan(9) clsact/ingress bpf_overlay.o:[from-overlay] id 1217
cilium_vxlan(9) clsact/egress bpf_overlay.o:[to-overlay] id 1222
lxc7706342551da(13) clsact/ingress bpf_lxc.o:[from-container] id 1233
lxc_health(24) clsact/ingress bpf_lxc.o:[from-container] id 1247

flow_dissector:
```

Do you see any entries that might be related to Cilium?

* Run a command to view a list of running eBPF programs:

```
root@minikube:/usr/bin# bpftool prog
1217: sched_cls  tag 20ac549643fd38fa  gpl
 loaded_at 2020-12-14T00:57:04+0000  uid 0
 xlated 912B  jited 625B  memlock 4096B  map_ids 41,59
1222: sched_cls  tag 57afe8b782a3abe6  gpl
 loaded_at 2020-12-14T00:57:05+0000  uid 0
 xlated 24072B  jited 15904B  memlock 24576B  map_ids 52,50,51,41,54,48,59
...
1274: sched_cls  tag 48d26f069d0a48cc  gpl
 loaded_at 2020-12-14T00:57:10+0000  uid 0
 xlated 20264B  jited 12372B  memlock 20480B  map_ids 41,54,44,68,57,50,51,56,55,45,48,39,53
```

In the above, you can see a list of eBPF programs currently running. For each
program you can also see an associated list of map_ids.

Take note of one of the program ids and the map_ids referenced in your cluster.

* Run a command to view a list of eBPF maps:

```
root@minikube:/usr/bin# bpftool map
39: hash  flags 0x1
	key 20B  value 48B  max_entries 65535  memlock 8916992B
41: percpu_hash  flags 0x1
	key 8B  value 16B  max_entries 1024  memlock 114688B
...
196: hash  flags 0x1
	key 8B  value 24B  max_entries 16384  memlock 1576960B
197: prog_array  flags 0x0
	key 4B  value 4B  max_entries 25  memlock 4096B
	owner_prog_type sched_cls  owner jited
```

This is a listing of eBPF maps. This is where eBPF programs store and retrieve
data used by eBPF applications.

Do you see any of the map_ids that you recorded from the previous step?

Exit from the Cilium Agent container:

```
exit
```

eBPF is a complex Linux kernel technology. Cilium abstracts this all away from
the user, making it easy to adopt eBPF for any Kubernetes platform. If you would
like to learn more about eBPF, visit https://ebpf.io.

### Explore the Cilium Agent

The Cilium Agent runs on each node and exposes an API in the form of a Unix
domain socket. The `cilium-cni` binary, which is executed each time a pod is
started or deleted, interacts with the Cilium API to create the resources
needed to support an eBPF data path for your applications. In the following
exercise, you will explore these resources and get a better understanding of how
the Cilium agent works.

Connect to the minikube node via SSH:

```
minikube ssh
```

View a list of network interfaces on the node:

```
ip addr list | grep cilium
7: cilium_net@cilium_host: <BROADCAST,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
8: cilium_host@cilium_net: <BROADCAST,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    inet 10.0.0.69/32 scope link cilium_host
9: cilium_vxlan: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN group default qlen 1000
```

These interfaces are implemented on each node by the Cilium Agent using eBPF
programs. Information about these network devices are stored using the same eBPF
maps you explored previously. Depending on the type of data path being
implemented, Cilium will use some or all of these interfaces.

View a list of network interfaces assigned to pods:

```
$ ip addr list | grep lxc
26: lxccd1ef91cb08c@if25: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
28: lxce86f4486e182@if27: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
30: lxcf3ac7d514126@if29: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
32: lxc8216a9b4cfbc@if31: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
34: lxc8f0496b8367d@if33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
36: lxc867041b51d4f@if35: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
40: lxc_health@if39: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
42: lxc4eb394ce4cd1@if41: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
44: lxc6be8c7e5a565@if43: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
46: lxc63e26e7369bf@if45: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
```

Each interface with the `lxc` prefix is part of a virtual ethernet pair
connecting a container to the host's network namespace. eBPF programs direct
the traffic towards the destination, whether that's on the local host or a
remote node. You should also see an interface named `lxc_health` that Cilium
uses to validate the health of all agents in a cluster.

Record the IP address of any interface from your list of output along with the
id associated (the value to the left of the colon on each line).

To view the eBPF map configuration on the minikube node:

```
bpftool map
```

If you got an error that the command is not found, thats expected. Cilium does
not require any eBPF programs to be installed on the host. Everything necessary
is included with the containers provided by a Cilium installation.

Log out from the minikube node:

```
exit
```

Start up a new shell session to your Cilium agent pod:

```bash
export POD_NAME=$(kubectl get po -n kube-system -l k8s-app=cilium | grep -v NAME | awk '{print $1}')
kubectl exec -itn kube-system $POD_NAME -- /bin/bash
```

View a list of Cilium endpoints stored in eBPF maps:

```
root@minikube:/home/cilium# cilium bpf endpoint list
IP ADDRESS       LOCAL ENDPOINT INFO
10.0.0.69:0      (localhost)
10.0.0.194:0     id=2024  flags=0x0000 ifindex=32  mac=3A:14:64:66:19:56 nodemac=3E:EC:1D:66:B6:29
10.0.0.13:0      id=3654  flags=0x0000 ifindex=34  mac=DE:FA:52:F5:A9:54 nodemac=82:54:77:7D:B8:4C
10.0.0.47:0      id=205   flags=0x0000 ifindex=26  mac=6A:00:AA:FE:50:FE nodemac=26:3E:92:17:63:03
10.0.0.203:0     id=4051  flags=0x0000 ifindex=28  mac=4A:CA:A2:F0:C9:2D nodemac=BA:2F:DB:CC:C9:03
10.0.0.190:0     id=3468  flags=0x0000 ifindex=36  mac=8A:22:CA:03:D4:D1 nodemac=1A:D4:5F:DA:0F:7B
10.0.0.198:0     id=850   flags=0x0000 ifindex=46  mac=FE:5F:DC:64:76:32 nodemac=82:D2:B4:5B:47:04
10.0.0.120:0     id=2495  flags=0x0000 ifindex=42  mac=E6:11:D4:87:6E:EF nodemac=EA:D4:B0:31:46:86
10.0.0.33:0      id=3237  flags=0x0000 ifindex=30  mac=E6:5F:05:0E:7C:8B nodemac=6E:C1:DF:84:45:98
10.0.0.223:0     id=811   flags=0x0000 ifindex=40  mac=32:3A:7D:CA:4C:10 nodemac=5E:80:0C:34:57:5A
10.0.0.229:0     id=84    flags=0x0000 ifindex=44  mac=9A:A0:1A:3C:D4:3A nodemac=22:39:02:45:64:53
192.168.64.5:0   (localhost)
```

Do you see the IP address recorded previously?

On that same line, what's the `ifindex` reported?

Do you notice any association with the information you recorded?

#### Exploring Cilium Custom Resources

Cilium stores all of its configured state in a key/value store. By default,
Cilium stores this data using Kubernetes custom resource definitions (CRDs) that
are automatically backed by the Kubernetes etcd data store. In very large
clusters, it's suggested to use a dedicated etcd key/value store for Cilium.

Upon startup, each Cilium agent will register a CiliumNode object using the
Cilium API. A CiliumNode is a Kubernetes custom resource definition (CRD)
implemented by Cilium. A new CiliumNode will be registered for every node  in a
cluster running Cilium. You can see the Cilium node objects in your cluster by
running:

```
root@minikube:/home/cilium# cilium node list
Name       IPv4 Address   Endpoint CIDR   IPv6 Address   Endpoint CIDR
minikube   192.168.64.5   10.0.0.0/24
```

For each pod that starts on a Cilium node, the Cilium Agent will create a
CiliumEndpoint. To view the list of Cilium endpoints on any node run:

```
root@minikube:/home/cilium# cilium endpoint list
ENDPOINT   POLICY (ingress)   POLICY (egress)   IDENTITY   LABELS (source:key[=value])                                           IPv6   IPv4         STATUS
           ENFORCEMENT        ENFORCEMENT
84         Disabled           Disabled          8091       k8s:io.cilium.k8s.policy.cluster=default                                     10.0.0.229   ready
                                                           k8s:io.cilium.k8s.policy.serviceaccount=hubble-relay
                                                           k8s:io.kubernetes.pod.namespace=kube-system
                                                           k8s:k8s-app=hubble-relay
205        Disabled           Disabled          44640      k8s:app=frontend-service                                                     10.0.0.47    ready
                                                           k8s:io.cilium.k8s.policy.cluster=default
                                                           k8s:io.cilium.k8s.policy.serviceaccount=default
                                                           k8s:io.kubernetes.pod.namespace=tenant-b
...
4051       Disabled           Disabled          13226      k8s:app=backend-service                                                      10.0.0.203   ready
                                                           k8s:io.cilium.k8s.policy.cluster=default
                                                           k8s:io.cilium.k8s.policy.serviceaccount=default
                                                           k8s:io.kubernetes.pod.namespace=tenant-b
```

You should see the list of endpoints that Cilium is responsible for managing.
Note you will only see Cilium managed endpoints. Pods that use host networking,
or any pod that was launched using another CNI configuration prior to Cilium
being installed, are not managed by Cilium and, therefore, have no
CiliumEndpoint object created. In the case of pods created by another CNI, they
will become managed by Cilium following a pod restart.

For each entry, you can see the endpoint id, egress/ingress policy enforcement
status, identity, the associated labels, IP address, and current status.

The endpoint id is a unique identifier for each endpoint assigned by Cilium.

Policy enforcement status indicates whether or not a Cilium Agent is enforcing
network policy to or from a pod along with the directionality (egress/ingress).

The identity is used by Cilium for policy enforcement - and is central to the
core concept of being identity-based. In many cases, pods that are backends to
the same service will often share the same identity.

Labels are used by Cilium to establish an identity. Two pods that share the same
labels will also share the same identity. The Cilium Agent is responsible for
creating a new identity each time a pod starts on a node.

Using the labels, find the identity for the backend-service in tenant-a. View
the full details of the Cilium endpoint for the backend-service (use the id from
the service we just located):

```
root@minikube:/home/cilium# cilium endpoint get 3654
[
  {
    "id": 3654,
    "spec": {
      "label-configuration": {},
      "options": {
        "Conntrack": "Enabled",
        "ConntrackAccounting": "Enabled",
        "ConntrackLocal": "Disabled",
        "Debug": "Disabled",
        "DebugLB": "Disabled",
        "DebugPolicy": "Disabled",
        "DropNotification": "Enabled",
        "MonitorAggregationLevel": "Medium",
        "NAT46": "Disabled",
        "PolicyAuditMode": "Disabled",
        "PolicyVerdictNotification": "Enabled",
        "TraceNotification": "Enabled"
      }
    },
...

```

Here you can see even more details about the backend-service pod. You can also
see details about the policies being applied to this endpoint. Take some time to
explore all the fields in the JSON output.

View the list of CiliumIdentities in your cluster:

```
cilium identity list
ID      LABELS
1       reserved:host
2       reserved:world
3       reserved:unmanaged
4       reserved:health
5       reserved:init
6       reserved:remote-node
2087    k8s:io.cilium.k8s.policy.cluster=default
        k8s:io.cilium.k8s.policy.serviceaccount=coredns
        k8s:io.kubernetes.pod.namespace=kube-system
        k8s:k8s-app=kube-dns
8091    k8s:io.cilium.k8s.policy.cluster=default
        k8s:io.cilium.k8s.policy.serviceaccount=hubble-relay
        k8s:io.kubernetes.pod.namespace=kube-system
        k8s:k8s-app=hubble-relay
13226   k8s:app=backend-service
        k8s:io.cilium.k8s.policy.cluster=default
        k8s:io.cilium.k8s.policy.serviceaccount=default
        k8s:io.kubernetes.pod.namespace=tenant-b
13623   k8s:app=backend-service
        k8s:io.cilium.k8s.policy.cluster=default
        k8s:io.cilium.k8s.policy.serviceaccount=default
        k8s:io.kubernetes.pod.namespace=tenant-c
26625   k8s:app=frontend-service
        k8s:io.cilium.k8s.policy.cluster=default
        k8s:io.cilium.k8s.policy.serviceaccount=default
        k8s:io.kubernetes.pod.namespace=tenant-a
32675   k8s:io.cilium.k8s.policy.cluster=default
        k8s:io.cilium.k8s.policy.serviceaccount=hubble-ui
        k8s:io.kubernetes.pod.namespace=kube-system
        k8s:k8s-app=hubble-ui
44640   k8s:app=frontend-service
        k8s:io.cilium.k8s.policy.cluster=default
        k8s:io.cilium.k8s.policy.serviceaccount=default
        k8s:io.kubernetes.pod.namespace=tenant-b
49206   k8s:app=frontend-service
        k8s:io.cilium.k8s.policy.cluster=default
        k8s:io.cilium.k8s.policy.serviceaccount=default
        k8s:io.kubernetes.pod.namespace=tenant-c
57313   k8s:app=backend-service
        k8s:io.cilium.k8s.policy.cluster=default
        k8s:io.cilium.k8s.policy.serviceaccount=default
        k8s:io.kubernetes.pod.namespace=tenant-a
```

Note the special identities listed here. Cilium uses these to identify traffic
that come from the local host `reserved:host`, externally `reserved:world`, from
an unmanaged pod `reserved:unmanaged`, from a health endpoint `reserved:health`,
from an initializing endpoint `reserved:init`, or from a remote node
`reserved:remote-node`.

You can also see the identities created by Cilium for each set of pod labels.
Tenants A, B, and C each have exactly two identities created - one for the
frontend-service and another for the backend-service.

### Service Load-Balancing

Cilium is responsible for load balancing all Cluster IP services by default.
In addition, Cilium can be further configured to handle additional traffic using
eBPF, eliminating the need to run kube-proxy in your Kubernetes clusters.
Cilium stores information about services as CiliumService CRDs. View the list
of CiliumService custom resources configured in your cluster:

```
root@minikube:/home/cilium# cilium service list
ID   Frontend             Service Type   Backend
1    10.96.0.1:443        ClusterIP      1 => 192.168.64.5:8443
2    10.96.0.10:53        ClusterIP      1 => 10.0.0.120:53
3    10.96.0.10:9153      ClusterIP      1 => 10.0.0.120:9153
4    10.99.134.196:80     ClusterIP      1 => 10.0.0.229:4245
5    10.110.59.94:80      ClusterIP      1 => 10.0.0.198:8081
6    10.104.92.70:80      ClusterIP      1 => 10.0.0.190:80
7    192.168.64.5:30334   NodePort       1 => 10.0.0.190:80
8    0.0.0.0:30334        NodePort       1 => 10.0.0.190:80
9    10.111.41.5:80       ClusterIP      1 => 10.0.0.13:80
10   10.105.241.92:80     ClusterIP      1 => 10.0.0.47:80
11   192.168.64.5:30434   NodePort       1 => 10.0.0.47:80
12   0.0.0.0:30434        NodePort       1 => 10.0.0.47:80
13   10.110.108.125:80    ClusterIP      1 => 10.0.0.203:80
14   10.109.177.129:80    ClusterIP      1 => 10.0.0.33:80
15   192.168.64.5:32692   NodePort       1 => 10.0.0.33:80
16   0.0.0.0:32692        NodePort       1 => 10.0.0.33:80
17   10.102.67.159:80     ClusterIP      1 => 10.0.0.194:80
```

The output includes a list of fronted IP addresses, the services type, as well as
the number of any associated backends along with their IP address and port.
Cilium stores these as an eBPF map on each agent node. Viewing the map details
yields a very similar output:

```
root@minikube:/home/cilium# cilium bpf lb list
SERVICE ADDRESS      BACKEND ADDRESS
10.105.241.92:80     0.0.0.0:0 (10) [ClusterIP]
                     10.0.0.47:80 (10)
192.168.64.5:30334   10.0.0.190:80 (7)
                     0.0.0.0:0 (7) [NodePort]
10.96.0.10:53        10.0.0.120:53 (2)
                     0.0.0.0:0 (2) [ClusterIP]
0.0.0.0:30334        10.0.0.190:80 (8)
                     0.0.0.0:0 (8) [NodePort, non-routable]
10.104.92.70:80      0.0.0.0:0 (6) [ClusterIP]
                     10.0.0.190:80 (6)
192.168.64.5:32692   10.0.0.33:80 (15)
                     0.0.0.0:0 (15) [NodePort]
10.96.0.10:9153      0.0.0.0:0 (3) [ClusterIP]
                     10.0.0.120:9153 (3)
10.96.0.1:443        192.168.64.5:8443 (1)
                     0.0.0.0:0 (1) [ClusterIP]
0.0.0.0:32692        0.0.0.0:0 (16) [NodePort, non-routable]
                     10.0.0.33:80 (16)
0.0.0.0:30434        10.0.0.47:80 (12)
                     0.0.0.0:0 (12) [NodePort, non-routable]
10.109.177.129:80    0.0.0.0:0 (14) [ClusterIP]
                     10.0.0.33:80 (14)
10.102.67.159:80     0.0.0.0:0 (17) [ClusterIP]
                     10.0.0.194:80 (17)
10.110.59.94:80      0.0.0.0:0 (5) [ClusterIP]
                     10.0.0.198:8081 (5)
10.111.41.5:80       0.0.0.0:0 (9) [ClusterIP]
                     10.0.0.13:80 (9)
192.168.64.5:30434   0.0.0.0:0 (11) [NodePort]
                     10.0.0.47:80 (11)
10.110.108.125:80    10.0.0.203:80 (13)
                     0.0.0.0:0 (13) [ClusterIP]
10.99.134.196:80     10.0.0.229:4245 (4)
                     0.0.0.0:0 (4) [ClusterIP]
```

### Network Policy

Cilium can apply identity-aware network policy at Layers 3, 4, and 7. Using
simple YAML definitions, users can define network polciy for their applications
without having to learn the complexity of eBPF.

While Cilium has full support for the default Kubernetes network policy spec,
Cilium creates custom resource definitions for CiliumNetworkPolicies as well as
CiliumClusterwideNetworkPolicies. Using these custom resources, users can build
policies using Cilium Identities, labels, and CIDR sets. With full support for
layer 7 policies, users can define specific actions, such as restricting actions to only GET for a HTTP application.

CiliumNetworkPolicies only apply in the namespace they are created in. This is
where CiliumClusterwideNetworkPolicies can help to enforce cluster-wide
security requirements. Some examples might include allowing outbound access to
only a specific CIDR range or restricting outbound destinations to a list of DNS
names.

List the network policies currently deployed in the cluster:

```
root@minikube:/home/cilium# cilium policy get
[
  {
    "endpointSelector": {
      "matchLabels": {
        "k8s:io.kubernetes.pod.namespace": "tenant-a"
      }
    },
    "ingress": [
      {
        "fromEndpoints": [
          {
            "matchLabels": {
              "k8s:io.kubernetes.pod.namespace": "tenant-a"
            }
          }
        ]
      }
    ],
    "egress": [
      {
        "toEndpoints": [
          {
            "matchLabels": {
              "k8s:io.kubernetes.pod.namespace": "tenant-a"
            }
          }
        ]
      }
    ],
    "labels": [
      {
        "key": "io.cilium.k8s.policy.derived-from",
        "value": "CiliumNetworkPolicy",
        "source": "k8s"
      },
      {
        "key": "io.cilium.k8s.policy.name",
        "value": "allow-all-within-ns-policy",
        "source": "k8s"
      },
      {
        "key": "io.cilium.k8s.policy.namespace",
        "value": "tenant-a",
        "source": "k8s"
      },
      {
        "key": "io.cilium.k8s.policy.uid",
        "value": "2ace0b73-57d6-47d4-9160-e77bebba6bfd",
        "source": "k8s"
      }
    ]
  },
...
```

In the output you can see the details of the policies include the ingress and
egress rules define. In the bottom half of each entry you can see the metadata
including the name, source, namespace, and the policy uid. Note this is the same
policy installed in Part 1 of this guide `allow-all-within-ns-policy`.

### Ciilum Operator

The Cilium Operator is responsible for doing various cluster-level tasks that
only need to be performed by a single actor. This includes garbage
collection against the key value store, interacting with cloud provider APIs
to communicate with their IPAM providers, and more. It's not a critical data path
component. The cluster can often run without the operator for some time without
any problems, however the lack of a working operator will eventually surface as
newly created pods not able to be scheduled. When this happens, the Cilium
agents will report that there are no more available identities which is a sign of
eBPF map exhaustion. This will often require some form of tuning, which should
only be done with the help of Isovalent's technical support.


## Hubble Observability

Hubble builds on top of Cilium and eBPF to enable deep visibility into the communication and behavior of services as well as the networking infrastructure in a completely transparent manner. One of the design goals of Hubble is to achieve all of this at large scale.

### Hubble Server

Hubble’s server component is embedded into the Cilium agent in order to achieve high performance with low-overhead. The gRPC services offered by Hubble server may be consumed locally via a Unix domain socket or, more typically, through Hubble Relay.

View the current status of Hubble:

```
root@minikube:/home/cilium# hubble status
Healthcheck (via unix:///var/run/cilium/hubble.sock): Ok
Current/Max Flows: 4096/4096 (100.00%)
Flows/s: 3.16
```

Hubble's health check reports as being `Ok`. In addition, Hubble reports the
number of flows stored in its buffer along with the rate of flows per second.

List the current Hubble configuration:

```
root@minikube:/home/cilium# hubble config view
config: /root/.config/hubble/config.yaml
debug: false
server: unix:///var/run/cilium/hubble.sock
timeout: 5s
tls: false
tls-allow-insecure: false
tls-ca-cert-files: []
tls-client-cert-file: ""
tls-client-key-file: ""
tls-server-name: ""
```

Hubble's API is also implemented in the form of a Unix domain socket. You can
also see additional configuration values for Hubble. In this lab, Hubble is
configured without TLS, but fully supports mutual TLS authentication to protect
any data it exposes.

Speaking of Hubble data, list the network flows on the local Hubble node:

```
root@minikube:/home/cilium# hubble observe
TIMESTAMP             SOURCE                                           DESTINATION                                      TYPE          VERDICT     SUMMARY
Dec 14 07:52:08.642   192.168.64.5:8443                                kube-system/coredns-f9fd979d6-88nqn:49392        to-endpoint   FORWARDED   TCP Flags: ACK
Dec 14 07:52:13.570   kube-system/hubble-ui-5df5fb587d-sn286:54528     kube-system/hubble-relay-544876fc89-4flb9:4245   to-endpoint   FORWARDED   TCP Flags: ACK
Dec 14 07:52:13.570   kube-system/hubble-relay-544876fc89-4flb9:4245   kube-system/hubble-ui-5df5fb587d-sn286:54528     to-endpoint   FORWARDED   TCP Flags: ACK
Dec 14 07:52:13.653   10.0.0.69:58368                                  kube-system/hubble-relay-544876fc89-4flb9:4245   to-endpoint   FORWARDED   TCP Flags: SYN
Dec 14 07:52:13.653   kube-system/hubble-relay-544876fc89-4flb9:4245   10.0.0.69:58368                                  to-stack      FORWARDED   TCP Flags: SYN, ACK
...
```

The output shows the network flows for this host along with source, destination,
the type of traffic, the policy verdict and any additional TCP flags present.
You can see even more network flow details using JSON format:

```
root@minikube:/home/cilium# hubble observe -o json
```

```json
{
  "time":"2020-12-14T07:58:04.526869639Z",
  "verdict":"FORWARDED",
  "ethernet":
  {
    "source":"ea:d4:b0:31:46:86",
    "destination":"e6:11:d4:87:6e:ef"
  },
  "IP":
  {
    "source":"10.0.0.69",
    "destination":"10.0.0.120",
    "ipVersion":"IPv4"
  },
  "l4":
  {
    "TCP":
    {
      "source_port":59974,
      "destination_port":8080,
      "flags":
      {
        "SYN":true
      }
    }
  },
  "source":
  {
    "identity":1,
    "labels":["reserved:host"]
  },
  "destination":
  {
    "ID":2495,
    "identity":2087,
    "namespace":"kube-system",
    "labels":["k8s:io.cilium.k8s.policy.cluster=default","k8s:io.cilium.k8s.policy.serviceaccount=coredns","k8s:io.kubernetes.pod.namespace=kube-system","k8s:k8s-app=kube-dns"],
    "pod_name":"coredns-f9fd979d6-88nqn"
  },
  "Type":"L3_L4",
  "node_name":"minikube",
  "event_type":
  {
    "type":4
  },
  "traffic_direction":
  "INGRESS",
  "trace_observation_point":"TO_ENDPOINT",
  "Summary":"TCP Flags: SYN"
}
```

Hubble output is local to the node where the traffic is being observed. The
Hubble server on each Cilium agent stores the flow data for traffic local to
the node. Take a moment to examine the contents of the JSON output.

### Hubble Client

Hubble client can be downloaded and installed so you can observe network flows
using your local workstation. Install the [latest release](https://github.com/cilium/hubble/releases)
for your operating system by downloading the associated file and unzipping it.

Example provided for macOS:

```
wget https://github.com/cilium/hubble/releases/download/v0.7.1/hubble-darwin-amd64.tar.gz
tar -xvf hubble-darwin-amd64.tar.gz
chmod +x hubble
mv hubble /usr/local/bin/hubble
```

### Hubble Relay

Hubble Relay provides an aggregated view of Hubble data across the cluster.
View the output of network flows using Hubble Client via hubble-relay:

In one shell:
```
kubectl port-forward -n kube-system svc/hubble-relay 8080:80
```

Open an additional shell prompt to run Hubble Client:

```
hubble observe --server localhost:8080
TIMESTAMP             SOURCE                                           DESTINATION                                      TYPE          VERDICT     SUMMARY
Dec 14 08:39:13.654   kube-system/hubble-relay-544876fc89-4flb9:4245   10.0.0.69:47142                                  to-stack      FORWARDED   TCP Flags: ACK, PSH
Dec 14 08:39:13.655   10.0.0.69:47142                                  kube-system/hubble-relay-544876fc89-4flb9:4245   to-endpoint   FORWARDED   TCP Flags: RST
Dec 14 08:39:14.048   10.0.0.69:47144                                  kube-system/hubble-relay-544876fc89-4flb9:4245   to-endpoint   FORWARDED   TCP Flags: SYN
Dec 14 08:39:14.049   kube-system/hubble-relay-544876fc89-4flb9:4245   10.0.0.69:47144                                  to-stack      FORWARDED   TCP Flags: SYN, ACK
Dec 14 08:39:14.049   10.0.0.69:47144                                  kube-system/hubble-relay-544876fc89-4flb9:4245   to-endpoint   FORWARDED   TCP Flags: ACK
Dec 14 08:39:14.049   10.0.0.69:47144                                  kube-system/hubble-relay-544876fc89-4flb9:4245   to-endpoint   FORWARDED   TCP Flags: ACK, FIN
...
```


### Hubble UI

Hubble UI is a web interface which enables automatic discovery of the services
dependency graph at the L3/L4 and even L7 layer, allowing user-friendly
visualization and filtering of data flows as a service map. Hubble UI provides
a graphical view of the data obtained from Hubble Relay.

To access Hubble UI, first open a port-forward to the service:

```
kubectl port-forward -n kube-system svc/hubble-ui 8080:80
```

In a web browser, navigate to http://localhost:8080

In the top-left pulldown menu, select `tenant-a`.

In a new shell window, execute the following to generate some traffic:

```
kubectl exec -n tenant-a frontend-service -- curl backend-service.tenant-a
```

You should see the network flow in Hubble UI as `forwarded` traffic.

Next, generate some traffic which should be denied.

```
kubectl exec -n tenant-a frontend-service -- curl backend-service.tenant-b
kubectl exec -n tenant-a frontend-service -- curl www.google.com
```

Use Hubble UI to confirm the network flows are reported as `dropped`.

Apply the tenant-a-policy.yaml:

```
kubectl apply -f https://raw.githubusercontent.com/seanmwinn/cilium-hands-on-lab/master/tenant-a-policy.yaml -n tenant-a
```

Run the same commands that failed previously, however this time they should
be forwarded by the policy you just added:

```
kubectl exec -n tenant-a frontend-service -- curl backend-service.tenant-b
kubectl exec -n tenant-a frontend-service -- curl www.google.com
```

However, the following commands will still be denied by policy:

```
kubectl exec -n tenant-a frontend-service -- curl backend-service.tenant-c
kubectl exec -n tenant-a frontend-service -- curl www.yahoo.com
```

Finally, apply a policy which allows pods in the `tenant-c` namespace to only be able to access the HTTP GET method:

```
kubectl apply -f https://raw.githubusercontent.com/seanmwinn/cilium-hands-on-lab/master/to-namespace-c-public-url.yaml -n tenant-a
```

This is the policy being applied:

```YAML
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: to-namespace-c-public-url-policy
spec:
  endpointSelector: {}
  egress:
    - toEndpoints:
        - matchLabels:
            io.kubernetes.pod.namespace: tenant-c
            app: backend-service
      toPorts:
      - ports:
        - port: "80"
          protocol: TCP
        rules:
          http:
          - method: "GET"
            path: "/public"
```

The following URLs are denied with HTTP 403:

```
kubectl exec -n tenant-a frontend-service -- curl backend-service.tenant-c
kubectl exec -n tenant-a frontend-service -- curl backend-service.tenant-c/private
```

However, the following is allowed:

```
kubectl exec -n tenant-a frontend-service -- curl backend-service.tenant-c/public
```
