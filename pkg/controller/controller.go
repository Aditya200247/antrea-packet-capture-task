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
		// Pod is gone. We must ensure any running capture for this key is stopped.
		c.manager.StopCaptureByKey(key)
		return nil
	}

	// Handle "DeletedFinalStateUnknown" which happens if we missed the delete event
	if unknown, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		// We only care about the key to stop the capture
		c.manager.StopCaptureByKey(unknown.Key)
		return nil
	}

	pod, ok := obj.(*corev1.Pod)
	if !ok {
		slog.Error("Object is not a Pod", "key", key)
		return nil
	}

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
