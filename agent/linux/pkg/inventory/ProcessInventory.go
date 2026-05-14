package inventory

import (
	"sync"
)

type ProcessContext struct {
	Pid         uint32
	ProcessName string
	CommandLine string
	Uid         uint32
}

type ProcessInventory struct {
	mu        sync.RWMutex
	processes map[uint32]ProcessContext
}

func NewProcessInventory() *ProcessInventory {
	return &ProcessInventory{
		processes: make(map[uint32]ProcessContext),
	}
}

func (pi *ProcessInventory) AddProcess(ctx ProcessContext) {
	pi.mu.Lock()
	defer pi.mu.Unlock()
	pi.processes[ctx.Pid] = ctx
}

func (pi *ProcessInventory) RemoveProcess(pid uint32) {
	pi.mu.Lock()
	defer pi.mu.Unlock()
	delete(pi.processes, pid)
}

func (pi *ProcessInventory) GetProcess(pid uint32) (ProcessContext, bool) {
	pi.mu.RLock()
	defer pi.mu.RUnlock()
	ctx, exists := pi.processes[pid]
	return ctx, exists
}
