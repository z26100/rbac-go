package rbac

import (
	"github.com/mikespook/gorbac"
)

type Backend interface {
	Lock()
	RLock()
	Unlock()
	RUnlock()
	GetRoles() map[string]gorbac.Role
	GetRole(id string) (gorbac.Role, bool)
	SetRole(id string, role gorbac.Role)
	DeleteRole(id string)
	GetAllParents() map[string]map[string]struct{}
	GetParents(id string) (map[string]struct{},bool)
	SetParent(id string,pid string, p struct{})
	SetParents(id string, p map[string]struct{})
	DeleteParents(id string)
	DeleteParent(pid, id string)
}

