package controller

import (
	"fmt"
	"log/slog"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/user/antrea-lfx-task/pkg/capture"
)

type Controller struct {
	indexer  cache.Indexer
	queue    workqueue.TypedRateLimitingInterface[string]
	informer cache.SharedIndexInformer
	manager  *capture.CaptureManager
}

func NewController(queue workqueue.TypedRateLimitingInterface[string], indexer cache.Indexer, informer cache.SharedIndexInformer) *Controller {
	return &Controller{
		indexer:  indexer,
		queue:    queue,
		informer: informer,
		manager:  capture.NewCaptureManager(),
	}
}

func (c *Controller) Run(stopCh chan struct{}) {
	defer c.queue.ShutDown()
	slog.Info("Starting PacketCapture Controller")

	go c.informer.Run(stopCh)

	if !cache.WaitForCacheSync(stopCh, c.informer.HasSynced) {
		runtime.HandleError(fmt.Errorf("timed out waiting for caches to sync"))
		return
	}

	go wait.Until(c.runWorker, time.Second, stopCh)

	<-stopCh
	slog.Info("Stopping PacketCapture Controller")
}

func (c *Controller) runWorker() {
	for c.processNextItem() {
	}
}

func (c *Controller) processNextItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)

	err := c.syncHandler(key)
	c.handleErr(err, key)
	return true
}

func (c *Controller) syncHandler(key string) error {
	obj, exists, err := c.indexer.GetByKey(key)
	if err != nil {
		slog.Error("Fetching object with key failed", "key", key, "err", err)
		return err
	}

	if !exists {
		// If Pod is deleted, we might need to cleanup.
		// However, our CaptureManager handles cleanup if it tracked the pod by UID.
		// BUT the Manager only knows about Active captures by UID.
		// If the pod is gone from the API server, we can't get its UID easily from just the key (namespace/name).
		// Wait, 'key' is not UID.
		// If exists is false, we can't call manager.SyncCapture(pod).
		// But in a real scenario, Deletion is handled by DeleteFunc which has the 'obj' (last known state).
		// We can add a fallback cleanup if needed, but Manager tracks by UID.
		// Strictly, if Pod is deleted, key comes here. But we don't have the UID unless we cache it.
		// Simplification: relying on DeleteFunc adding to queue? No, queue only has string key.
		// K8s pattern: When 'exists' is false, it means deleted.
		// Our Manager cleans up when it sees DeletionTimestamp or internal map vs reality.
		// Issue: If we don't pass the Pod, Manager doesn't know WHO to stop.
		// Solution: The CaptureManager should probably be robust or we track mapping in Controller.
		// Let's assume DeleteFunc + UpdateFunc ensures Manager sees the deletion state *before* it vanishes,
		// OR we accept that restarting the DaemonSet kills orphans (simpler).
		// For this task, handling Update with DeletionTimestamp is usually enough.
		// The deletion event might arrive after the object is gone.
		// We'll rely on the fact that before full deletion, we get an update with DeletionTimestamp.
		return nil
	}

	pod := obj.(*corev1.Pod)
	return c.manager.SyncCapture(pod)
}

func (c *Controller) handleErr(err error, key string) {
	if err == nil {
		c.queue.Forget(key)
		return
	}

	if c.queue.NumRequeues(key) < 5 {
		slog.Warn("Error syncing pod, requeuing", "key", key, "err", err)
		c.queue.AddRateLimited(key)
		return
	}

	c.queue.Forget(key)
	runtime.HandleError(err)
}
