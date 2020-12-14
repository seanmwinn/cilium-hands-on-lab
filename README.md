# Cilium Hands-On Lab

## Part 1 - Setup Your Local Lab Environment

In this first exercise, you will install and configure a local Kubernetes
cluster based on minikube and install Cilium into the cluster. Once
Cilium is installed, you will deploy an application which will be used
throughout the remaining exercises to demonstrate the various features of Cilium.

### Install `kubectl`

The `kubectl` Kubernetes client will be used throughout the exercises to
interact with the Kubernetes API. If you already have the latest version
installed, you can skip this section.

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
kubectl create -f tenant-services.yaml -n tenant-a
kubectl create -f tenant-services.yaml -n tenant-b
kubectl create -f tenant-services.yaml -n tenant-c
kubectl apply -n tenant-a -f allow-all-within-ns.yaml
kubectl apply -n tenant-a -f to-dns-only.yaml
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

#### Explore the Cilium Data Path

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
maps you explored previously.

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

If you got an error that the command is not found, that is expected. Cilium does
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

Upon startup, each Cilium agent will register a CiliumNode object with the
Kubernetes API server. A CiliumNode is a custom resource definition (CRD)
implemented by Cilium. A new CiliumNode will be registered for every node in a
cluster running Cilium. You can see the Cilium node object for your minikube
node by running:

```
root@minikube:/home/cilium# cilium node list
Name       IPv4 Address   Endpoint CIDR   IPv6 Address   Endpoint CIDR
minikube   192.168.64.5   10.0.0.0/24
```
