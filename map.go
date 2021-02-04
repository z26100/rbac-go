package rbac

import (
	"github.com/mikespook/gorbac"
	"sync"
)

type MapBackend struct {
	roles   gorbac.Roles
	mutex   sync.RWMutex
	parents map[string]map[string]struct{}
}

func NewMapBackend() *MapBackend {
	return &MapBackend{
		roles:   make(gorbac.Roles),
		parents: make(map[string]map[string]struct{}),
		mutex:   sync.RWMutex{},
	}
}

func (b *MapBackend) Close() error {
	b.roles = nil
	b.parents = nil
	return nil
}

func (b *MapBackend) Clear() error {
	b.roles = make(gorbac.Roles)
	b.parents = make(map[string]map[string]struct{})
	return nil
}

func (b *MapBackend) RLock() {
	b.mutex.RLock()
}
func (b *MapBackend) Lock() {
	b.mutex.Lock()
}
func (b *MapBackend) Unlock() {
	b.mutex.Unlock()
}
func (b *MapBackend) RUnlock() {
	b.mutex.RUnlock()
}
func (b *MapBackend) GetRoles() map[string]gorbac.Role {
	return b.roles
}
func (b *MapBackend) GetRole(id string) (gorbac.Role, bool) {
	result := b.roles[id]
	if result == nil {
		return nil, false
	}
	return result, true
}

func (b *MapBackend) SetRole(id string, role gorbac.Role) error {
	b.roles[id] = role
	return nil
}

func (b *MapBackend) DeleteRole(id string) error {
	delete(b.roles, id)
	return nil
}

func (b *MapBackend) GetAllParents() map[string]map[string]struct{} {
	return b.parents
}
func (b *MapBackend) GetParents(id string) (map[string]struct{}, bool) {
	result := b.parents[id]
	if result == nil {
		return nil, false
	}
	return result, true
}
func (b *MapBackend) SetParent(id string, pid string, p struct{}) error {
	b.parents[id][pid] = p
	return nil
}
func (b *MapBackend) SetParents(id string, p map[string]struct{}) {
	b.parents[id] = p
}
func (b *MapBackend) DeleteParents(id string) error {
	delete(b.parents, id)
	return nil
}
func (b *MapBackend) DeleteParent(pid, id string) error {
	delete(b.parents[pid], id)
	return nil
}
