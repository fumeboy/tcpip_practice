package main

import (
	"sync"
	"time"
)

type arpEntry struct {
	protocolAddress [4]byte
	hardwareAddress [6]byte
	timestamp       time.Time
}
// arp 缓存表
type arpTable struct {
	storage []*arpEntry
	mutex   sync.RWMutex
}

var arpCache *arpTable = newArpTable()

func newArpTable() *arpTable {
	return &arpTable{
		storage: make([]*arpEntry, 0, 1024),
	}
}

func (tbl *arpTable) lookupUnlocked(protocolAddress [4]byte) *arpEntry {
	for _, entry := range tbl.storage {
		if entry.protocolAddress == protocolAddress {
			return entry
		}
	}
	return nil
}

func (tbl *arpTable) lookup(protocolAddress [4]byte) *arpEntry {
	tbl.mutex.RLock()
	defer tbl.mutex.RUnlock()
	return tbl.lookupUnlocked(protocolAddress)
}

func (tbl *arpTable) update(protocolAddress [4]byte, hardwareAddress [6]byte) bool {
	tbl.mutex.Lock()
	defer tbl.mutex.Unlock()
	entry := tbl.lookupUnlocked(protocolAddress)
	if entry == nil {
		return false
	}
	entry.hardwareAddress = hardwareAddress
	entry.timestamp = time.Now()
	return true
}

func (tbl *arpTable) insert(protocolAddress [4]byte, hardwareAddress [6]byte) bool {
	tbl.mutex.Lock()
	defer tbl.mutex.Unlock()
	if tbl.lookupUnlocked(protocolAddress) != nil {
		return false
	}
	entry := &arpEntry{
		protocolAddress: protocolAddress,
		hardwareAddress: hardwareAddress,
		timestamp:       time.Now(),
	}
	tbl.storage = append(tbl.storage, entry)
	return true
}

func (tbl *arpTable) length() int {
	tbl.mutex.RLock()
	defer tbl.mutex.RUnlock()
	return len(tbl.storage)
}

