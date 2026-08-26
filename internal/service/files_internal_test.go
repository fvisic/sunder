package service

// Internal tests for the upload concurrency bound (H8): worst-case upload
// memory is MaxConcurrentUploads * MaxBytes, so the semaphore must actually
// hold the line and must respect context cancellation while waiting.

import (
	"context"
	"testing"
	"time"
)

func TestAcquireUploadBoundsConcurrency(t *testing.T) {
	f := &Files{MaxConcurrentUploads: 1}
	release, err := f.acquireUpload(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// The single slot is taken: a second acquire must wait, and a waiting
	// acquire must give up when its context does.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := f.acquireUpload(ctx); err == nil {
		t.Fatal("second acquire must block while the slot is held")
	}
	release()
	release2, err := f.acquireUpload(context.Background())
	if err != nil {
		t.Fatalf("released slot must be reacquirable: %v", err)
	}
	release2()
}

func TestAcquireUploadDefaultCap(t *testing.T) {
	f := &Files{} // MaxConcurrentUploads unset -> defaultUploadConcurrency
	rel, err := f.acquireUpload(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer rel()
	if got := cap(f.uploadSem); got != defaultUploadConcurrency {
		t.Fatalf("default semaphore cap = %d, want %d", got, defaultUploadConcurrency)
	}
}
