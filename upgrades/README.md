# Cilium Hands-On Lab

## Part 1 - Setup Your Local Lab Environment

In this first exercise, you will install and configure a local Kubernetes
cluster based on kind and install Cilium into the cluster. Once
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

### Helm installation

helm runs on Linux, macOS and Windows. Please follow the instructions
for your operating system.

#### macOS Installation:

* Option A (recommended) - Brew Package Manager:

```
brew install helm
```

If you get a message that the package is already installed, you can upgrade
to the latest version:

```
brew upgrade helm
```


#### Linux Installation

```
curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/master/scripts/get-helm-3
chmod 700 get_helm.sh
./get_helm.sh
```

#### Windows Installation:

* Use chocolatey (if available) to install helm:

```
choco install kubernetes-helm
```

### kind Installation

kind runs on Linux, macOS, and Windows. Please follow the instructions
for your operating system.

#### Linux Installation

```
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.9.0/kind-linux-amd64
chmod +x ./kind
mv ./kind /some-dir-in-your-PATH/kind
```

#### macOS Installation:

* Option A (recommended) - Brew Package Manager:

```
brew install kind
```

If you get a message that the package is already installed, you can upgrade
to the latest version:

```
brew upgrade kind
```

* Option B - download kind directly:

```
curl -Lo /usr/local/bin/kind https://kind.sigs.k8s.io/dl/v0.9.0/kind-darwin-amd64
```
#### Windows Installation:

* Option A - Use chocolatey (if available) to install kind:

```
choco install kind
```

* Or install kind via PowerShell:

```
curl.exe -Lo kind-windows-amd64.exe https://kind.sigs.k8s.io/dl/v0.9.0/kind-windows-amd64
Move-Item .\kind-windows-amd64.exe c:\some-dir-in-your-PATH\kind.exe
```

### Start a kind Cluster

After kind is installed, start your cluster. From a terminal with administrator access (but not logged in as root), run:

```
kind create cluster --config kind-config.yaml
```


### Interact with the kind Cluster

To list all pods running in the cluster:

```
cilium-hands-on-lab %  kubectl get po -A
NAMESPACE            NAME                                         READY   STATUS    RESTARTS   AGE
kube-system          coredns-f9fd979d6-8r2q8                      0/1     Pending   0          105s
kube-system          coredns-f9fd979d6-wzzst                      0/1     Pending   0          105s
kube-system          etcd-kind-control-plane                      1/1     Running   0          115s
kube-system          kube-apiserver-kind-control-plane            1/1     Running   0          115s
kube-system          kube-controller-manager-kind-control-plane   1/1     Running   0          114s
kube-system          kube-proxy-kds2j                             1/1     Running   0          89s
kube-system          kube-proxy-lx54r                             1/1     Running   0          105s
kube-system          kube-scheduler-kind-control-plane            1/1     Running   0          114s
local-path-storage   local-path-provisioner-78776bfc44-6mzh5      0/1     Pending   0          105s
```

The control plane is in a `Running` state, however pods that rely on CNI are
stuck in a `Pending` state. They will startup after Cilium is installed in
the next step.

## Cilium Upgrades

Install Cilium version 1.8.6 into the kind cluster:

```
helm install cilium cilium/cilium --version 1.8.6 \
  --namespace kube-system \
  --set prometheus.enabled=true \
  --set operator.prometheus.enabled=true \
  --set ipam.mode=kubernetes
```

After a few minutes you should see all of the kube-system pods in a `Running` state:

```
cilium-hands-on-lab % kubectl get po -n kube-system
NAME                                         READY   STATUS    RESTARTS   AGE
cilium-64gd6                                 1/1     Running   0          93s
cilium-operator-65dd4ddf44-97cwf             1/1     Running   0          93s
cilium-operator-65dd4ddf44-vsn8g             1/1     Running   0          93s
cilium-q9tj6                                 1/1     Running   0          93s
coredns-f9fd979d6-8r2q8                      1/1     Running   0          6m10s
coredns-f9fd979d6-wzzst                      1/1     Running   0          6m10s
etcd-kind-control-plane                      1/1     Running   0          6m20s
kube-apiserver-kind-control-plane            1/1     Running   0          6m20s
kube-controller-manager-kind-control-plane   1/1     Running   0          6m19s
kube-proxy-kds2j                             1/1     Running   0          5m54s
kube-proxy-lx54r                             1/1     Running   0          6m10s
kube-scheduler-kind-control-plane            1/1     Running   0          6m19s
```

## Part 2 - Cilium DaemonSet Update Strategy

Describe the Cilium DaemonSet to display the updateStrategy.

```
kubectl get ds -n kube-system cilium -o json | jq
```

The section we are interested in is:

```json
"updateStrategy": {
  "rollingUpdate": {
    "maxUnavailable": 2
    },
  "type": "RollingUpdate"
  }
}
```

For the purposes of this lab, we want to reduce maxUnavailable to `1`:

```
kubectl edit ds -n kube-system cilium
```

Change the value from `2` to `1` and save the file:

```json
"updateStrategy": {
  "rollingUpdate": {
    "maxUnavailable": 1
    },
  "type": "RollingUpdate"
  }
}
```

Next deploy the Cilium Pre-Flight check for the target upgrade version:

```
helm install cilium-preflight cilium/cilium --version 1.9.3 \
  --namespace=kube-system \
  --set preflight.enabled=true \
  --set agent=false \
  --set operator.enabled=false
```

Wait for the Cilium preflight daemonset to download and start on each node.
The Cilium preflight check is used to pre-stage images, as well as to perform
a few checks against network policies to ensure no errors exist.

```
kubectl get po -n kube-system
NAME                                         READY   STATUS             RESTARTS   AGE
cilium-cpg45                                 1/1     Running            2          18h
cilium-f8b7d                                 1/1     Running            2          18h
cilium-operator-796cbb48df-4c6cz             1/1     Running            4          18h
cilium-operator-796cbb48df-9zglq             1/1     Running            4          18h
cilium-pre-flight-check-4f6nq                1/1     Running            0          43s
cilium-pre-flight-check-7dd64f68d4-www52     1/1     Running            0          43s
Cilium-pre-flight-check-ftdgf                1/1     Running            0          43s
coredns-f9fd979d6-8r2q8                      1/1     Running            3          20h
coredns-f9fd979d6-wzzst                      1/1     Running            3          20h
```

Next, delete the cilium preflight deployment:

```
helm delete cilium-preflight --namespace=kube-system
```

And finally, upgrade Cilium to the newest release:

```
helm upgrade cilium cilium/cilium --version 1.9.3 \
  --namespace kube-system \
  --set prometheus.enabled=true \
  --set operator.prometheus.enabled=true \
  --set ipam.mode=kubernetes \
  --set upgradeCompatibility=1.8
```

Because we set maxUnavailable to 1, we should see the Cilium agent pods updated
on one node at any time.

```
watch kubectl get po -n kube-system -l k8s-app=cilium
```


Rolling Back:

To rollback to the previous release:

```
helm history cilium --namespace=kube-system
helm rollback cilium [REVISION] --namespace=kube-system
```

Again, we can see the Cilium daemonset redeploy the pods in the cluster on
one node at a time:

```
watch kubectl get po -n kube-system -l k8s-app=cilium
```
