kind create cluster --config ~/dev/cilium-hands-on-lab/clustermesh/kind-config1.yaml --name c1

helm install cilium cilium/cilium --version 1.9.3 \
  --namespace kube-system \
  --set ipam.mode=kubernetes \
  --set cluster.id=1 \
  --set cluster.name=cluster1

helm install metallb bitnami/metallb \
  --namespace kube-system \
  -f ~/dev/cilium-hands-on-lab/clustermesh/configmap.yaml

./cilium clustermesh enable --create-ca --service-type LoadBalancer
./cilium hubble enable

kubectl get secret --context kind-c1 -n kube-system cilium-ca -o yaml > cilium-ca.yaml

kind create cluster --config ~/dev/cilium-hands-on-lab/clustermesh/kind-config2.yaml --name c2

helm install cilium cilium/cilium --version 1.9.3 \
  --namespace kube-system \
  --set ipam.mode=kubernetes \
  --set cluster.id=2 \
  --set cluster.name=cluster2

helm install metallb bitnami/metallb \
  --namespace kube-system \
  -f ~/dev/cilium-hands-on-lab/clustermesh/configmap2.yaml

kubectl apply -f cilium-ca.yaml --context kind-c2
./cilium clustermesh enable
./cilium hubble enable

./cilium clustermesh connect --destination-context kind-c1
