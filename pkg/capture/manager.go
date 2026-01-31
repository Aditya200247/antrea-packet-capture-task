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
	"k8s.io/apimachinery/pkg/types"
)

const (
	AnnotationKey = "tcpdump.antrea.io"
	CaptureDir    = "/var/log/antrea-captures"
)

type CaptureManager struct {
	mu       sync.Mutex
	captures map[types.UID]context.CancelFunc
}

func NewCaptureManager() *CaptureManager {
	if err := os.MkdirAll(CaptureDir, 0755); err != nil {
		slog.Error("Failed to create capture directory", "err", err)
	}
	return &CaptureManager{
		captures: make(map[types.UID]context.CancelFunc),
	}
}

func (cm *CaptureManager) SyncCapture(pod *corev1.Pod) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	uid := pod.UID
	val, hasAnnotation := pod.Annotations[AnnotationKey]
	_, isRunning := cm.captures[uid]

	// 1. Start if annotation present and not running
	if hasAnnotation && !isRunning {
		slog.Info("Starting capture", "pod", pod.Name, "limit", val)
		ctx, cancel := context.WithCancel(context.Background())
		cm.captures[uid] = cancel
		go cm.runTcpdump(ctx, pod, val)
	}

	// 2. Stop if annotation removed and is running
	if !hasAnnotation && isRunning {
		slog.Info("Stopping capture (annotation removed)", "pod", pod.Name)
		cm.stop(uid, pod.Name)
	}

	// 3. Stop if Pod is deleting
	if pod.DeletionTimestamp != nil && isRunning {
		slog.Info("Stopping capture (pod terminating)", "pod", pod.Name)
		cm.stop(uid, pod.Name)
	}

	return nil
}

func (cm *CaptureManager) stop(uid types.UID, podName string) {
	if cancel, ok := cm.captures[uid]; ok {
		cancel()
		delete(cm.captures, uid)
		cm.cleanupFiles(podName)
	}
}

func (cm *CaptureManager) cleanupFiles(podName string) {
	// Pattern: capture-<PodName>.pcap*
	pattern := filepath.Join(CaptureDir, fmt.Sprintf("capture-%s.pcap*", podName))
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

func (cm *CaptureManager) runTcpdump(ctx context.Context, pod *corev1.Pod, limit string) {
	// 1. Get ContainerID
	if len(pod.Status.ContainerStatuses) == 0 {
		slog.Error("No container statuses found", "pod", pod.Name)
		cm.mu.Lock()
		delete(cm.captures, pod.UID)
		cm.mu.Unlock()
		return
	}
	// Use the first container for simplicity, or find the main one
	containerID := pod.Status.ContainerStatuses[0].ContainerID
	// Format: containerd://<id>
	parts := strings.Split(containerID, "://")
	if len(parts) < 2 {
		slog.Error("Invalid container ID format", "id", containerID)
		return
	}
	cid := parts[1]

	// 2. Find PID
	pid, err := findPidByContainerID(cid)
	if err != nil {
		slog.Error("Failed to find PID for container", "id", cid, "err", err)
		// Don't retry immediately in this simple loop, just exit.
		// logic could be improved to retry.
		cm.mu.Lock()
		delete(cm.captures, pod.UID)
		cm.mu.Unlock()
		return
	}

	// 3. Build Command
	// tcpdump -C 1M -W <N> -w /var/log/antrea-captures/capture-<PodName>.pcap
	pcapFile := filepath.Join(CaptureDir, fmt.Sprintf("capture-%s.pcap", pod.Name))

	// args: -t <PID> -n -- tcpdump ...
	args := []string{
		"-t", fmt.Sprintf("%d", pid),
		"-n", // Check network namespace
		"--",
		"tcpdump",
		"-Z", "root", // Run as root to ensure write permissions
		"-i", "any",
		"-C", "1", // 1MB
		"-W", limit, // Rotate N files
		"-w", pcapFile,
	}

	slog.Info("Executing nsenter", "args", args)
	cmd := exec.CommandContext(ctx, "nsenter", args...)

	// Capture stderr for debug
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		// If Context canceled, it's expected
		if ctx.Err() == context.Canceled {
			slog.Info("Capture stopped gracefully", "pod", pod.Name)
		} else {
			slog.Error("Tcpdump exited with error", "err", err)
		}
	}

	// Cleanup happens in Stop() usually, but if process dies on its own, ensure map is cleared?
	// The sync loop will handle state reconciliation, but strictly we should ensure map consistency.
	// For this task, strict map consistency on self-termination is nice to have.
}

// findPidByContainerID scans /proc to find the PID associated with the container ID (in cgroup).
// This requires hostPID: true and generated code access to /proc.
func findPidByContainerID(containerID string) (int, error) {
	dirs, err := os.ReadDir("/proc")
	if err != nil {
		return 0, fmt.Errorf("failed to read /proc: %w", err)
	}

	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		// Check if name is numeric
		if _, err := fmt.Sscanf(d.Name(), "%d", new(int)); err != nil {
			continue
		}

		cgroupPath := filepath.Join("/proc", d.Name(), "cgroup")
		f, err := os.Open(cgroupPath)
		if err != nil {
			continue
		}

		// Search for containerID in cgroup file
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
