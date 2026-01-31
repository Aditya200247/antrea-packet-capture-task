# Antrea LFX Test Task: PacketCapture Controller

A Kubernetes DaemonSet controller that performs on-demand packet captures using `tcpdump` and `nsenter`.

## Architecture

- **Language**: Go 1.24
- **Mechanism**:
  - The controller runs as a **DaemonSet** on every node.
  - It watches Pods **only on its local node** using a field selector (`spec.nodeName`) to minimize API server load.
  - When the annotation `tcpdump.antrea.io: "<N>"` is added to a Pod, the controller:
    1. Finds the container's PID on the host by scanning `/proc/*/cgroup`.
    2. Uses `nsenter -t <PID> -n` to enter the target network namespace.
    3. Runs `tcpdump` to capture traffic to `/var/log/antrea-captures/`.
  - When the annotation is removed, the capture is stopped and files are deleted.

## Prerequisites

- [Kind](https://kind.sigs.k8s.io/)
- Docker

## Setup

1. **Create Cluster** (Manual Step):
   If you haven't, create a Kind cluster with CNI disabled:
   ```bash
   kind create cluster --config kind-config.yaml
   ```

2. **Build and Load Image**:
   ```bash
   docker build -t antrea-lfx-controller:latest .
   kind load docker-image antrea-lfx-controller:latest
   ```

3. **Deploy**:
   ```bash
   kubectl apply -f deploy/rbac.yaml
   kubectl apply -f deploy/daemonset.yaml
   ```

## Usage

1. **Deploy Test Pod**:
   ```bash
   kubectl apply -f deploy/test-pod.yaml
   ```

2. **Start Capture**:
   Annotate the pod to start capturing (keep max 5 files of 1MB):
   ```bash
   kubectl annotate pod test-pod tcpdump.antrea.io="5"
   ```

3. **Verify**:
   Check the logs of the controller:
   ```bash
   kubectl logs -l app=capture-controller -n default
   ```

   Exec into the valid controller pod (on the same node) to see files:
   ```bash
   # Find the controller pod on the same node
   NODE=$(kubectl get pod test-pod -o jsonpath='{.spec.nodeName}')
   CONTROLLER=$(kubectl get pod -l app=capture-controller --field-selector spec.nodeName=$NODE -o name)
   kubectl exec $CONTROLLER -- ls -l /var/log/antrea-captures/
   ```

4. **Stop Capture**:
   ```bash
   kubectl annotate pod test-pod tcpdump.antrea.io-
   ```

## Key Optimizations

- **FieldSelector**: Uses `spec.nodeName` in the Informer to ensuring scalable watching (O(1) logic per node instead of O(N) global watch).
- **Direct /proc Scanning**: Avoids dependency on `crictl` or `docker` socket, making the controller runtime-agnostic (containerd/cri-o) as long as it has hostPID access.
- **Context Management**: uses Go `context` for robust process cancellation.

