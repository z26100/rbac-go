package rbac

import (
	"github.com/mikespook/gorbac"
)

type Backend interface {
	Lock()
	RLock()
	Unlock()
	RUnlock()
	Clear() error
	Close() error
	GetRoles() map[string]gorbac.Role
	GetRole(id string) (gorbac.Role, bool)
	SetRole(id string, role gorbac.Role) error
	DeleteRole(id string) error
	GetAllParents() map[string]map[string]struct{}
	GetParents(id string) (map[string]struct{}, bool)
	SetParent(id string, pid string, p struct{}) error
	SetParents(id string, p map[string]struct{})
	DeleteParents(id string) error
	DeleteParent(pid, id string) error
}
