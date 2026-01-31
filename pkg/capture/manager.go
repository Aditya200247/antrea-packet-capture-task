package capture

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	corev1 "k8s.io/api/core/v1"
)

const (
	AnnotationKey = "tcpdump.antrea.io"
	CaptureDir    = "/var/log/antrea-captures"
)

type CaptureManager struct {
	mu       sync.Mutex
	captures map[string]context.CancelFunc // Key: namespace/name
}

func NewCaptureManager() *CaptureManager {
	if err := os.MkdirAll(CaptureDir, 0755); err != nil {
		slog.Error("Failed to create capture directory", "err", err)
	}
	return &CaptureManager{
		captures: make(map[string]context.CancelFunc),
	}
}

func (cm *CaptureManager) SyncCapture(pod *corev1.Pod) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	key := pod.Namespace + "/" + pod.Name
	val, hasAnnotation := pod.Annotations[AnnotationKey]
	_, isRunning := cm.captures[key]

	// 1. Start if annotation present and not running
	if hasAnnotation && !isRunning {
		slog.Info("Starting capture", "pod", key, "limit", val)
		ctx, cancel := context.WithCancel(context.Background())
		cm.captures[key] = cancel
		go cm.runTcpdump(ctx, pod, val, key)
	}

	// 2. Stop if annotation removed and is running
	if !hasAnnotation && isRunning {
		slog.Info("Stopping capture (annotation removed)", "pod", key)
		cm.stop(key, pod.Namespace, pod.Name)
	}

	// 3. Stop if Pod is deleting
	if pod.DeletionTimestamp != nil && isRunning {
		slog.Info("Stopping capture (pod terminating)", "pod", key)
		cm.stop(key, pod.Namespace, pod.Name)
	}

	return nil
}

func (cm *CaptureManager) StopCaptureByKey(key string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Parse the key "namespace/name" to generate the filename for cleanup
	parts := strings.Split(key, "/")
	if len(parts) != 2 {
		slog.Error("Invalid key format in StopCaptureByKey", "key", key)
		return
	}
	namespace := parts[0]
	name := parts[1]

	cm.stop(key, namespace, name)
}

// Internal stop helper - assumes lock is held
func (cm *CaptureManager) stop(key, namespace, podName string) {
	if cancel, ok := cm.captures[key]; ok {
		cancel()
		delete(cm.captures, key)
		cm.cleanupFiles(namespace, podName)
	}
}

func (cm *CaptureManager) cleanupFiles(namespace, podName string) {
	// FIX: Include Namespace in filename to avoid collisions
	// Pattern: capture-<Namespace>-<PodName>.pcap*
	pattern := filepath.Join(CaptureDir, fmt.Sprintf("capture-%s-%s.pcap*", namespace, podName))
	matches, err := filepath.Glob(pattern)
	if err != nil {
		slog.Error("Failed to glob cleanup files", "err", err)
		return
	}
	for _, f := range matches {
		if err := os.Remove(f); err != nil {
			slog.Error("Failed to remove capture file", "file", f, "err", err)
		} else {
			slog.Info("Removed capture file", "file", f)
		}
	}
}

func (cm *CaptureManager) runTcpdump(ctx context.Context, pod *corev1.Pod, limit string, key string) {
	// 1. Get ContainerID
	if len(pod.Status.ContainerStatuses) == 0 {
		slog.Error("No container statuses found", "pod", pod.Name)
		cm.mu.Lock()
		delete(cm.captures, key)
		cm.mu.Unlock()
		return
	}

	containerID := pod.Status.ContainerStatuses[0].ContainerID
	// Format: containerd://<id> or cri-o://<id>
	parts := strings.Split(containerID, "://")
	if len(parts) < 2 {
		slog.Error("Invalid container ID format", "id", containerID)
		cm.mu.Lock()
		delete(cm.captures, key)
		cm.mu.Unlock()
		return
	}
	cid := parts[1]

	// 2. Find PID
	pid, err := findPidByContainerID(cid)
	if err != nil {
		slog.Error("Failed to find PID for container", "id", cid, "err", err)
		cm.mu.Lock()
		delete(cm.captures, key)
		cm.mu.Unlock()
		return
	}

	// 3. Build Command
	// FIX: Include Namespace in filename
	pcapFile := filepath.Join(CaptureDir, fmt.Sprintf("capture-%s-%s.pcap", pod.Namespace, pod.Name))

	args := []string{
		"-t", fmt.Sprintf("%d", pid),
		"-n",
		"--",
		"tcpdump",
		"-Z", "root",
		"-i", "any",
		"-C", "1",
		"-W", limit,
		"-w", pcapFile,
	}

	slog.Info("Executing nsenter", "args", args)
	cmd := exec.CommandContext(ctx, "nsenter", args...)
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.Canceled {
			slog.Info("Capture stopped gracefully", "pod", pod.Name)
		} else {
			slog.Error("Tcpdump exited with error", "err", err)
		}
	}
}

func findPidByContainerID(containerID string) (int, error) {
	dirs, err := os.ReadDir("/proc")
	if err != nil {
		return 0, fmt.Errorf("failed to read /proc: %w", err)
	}

	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		if _, err := fmt.Sscanf(d.Name(), "%d", new(int)); err != nil {
			continue
		}

		cgroupPath := filepath.Join("/proc", d.Name(), "cgroup")
		f, err := os.Open(cgroupPath)
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(f)
		found := false
		for scanner.Scan() {
			if strings.Contains(scanner.Text(), containerID) {
				found = true
				break
			}
		}
		f.Close()

		if found {
			var pid int
			fmt.Sscanf(d.Name(), "%d", &pid)
			return pid, nil
		}
	}
	return 0, fmt.Errorf("pid not found for container %s", containerID)
}
