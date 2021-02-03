package rbac

import (
	"errors"
	"fmt"
	"github.com/mikespook/gorbac"
	_ "github.com/mikespook/gorbac"
)

func Default() *RBAC {
	return &RBAC{
		backend: NewMapBackend(),
	}
}

// New returns a RBAC structure.
// The default role structure will be used.
func New(backend Backend) *RBAC {
	rbac := &RBAC{
		backend: backend,
	}
	return rbac
}

// RBAC object, in most cases it should be used as a singleton.
type RBAC struct {
	backend Backend
}

var (
	ErrFoundCircle = fmt.Errorf("found circle")
	// ErrRoleNotExist occurred if a role can't be found
	ErrRoleNotExist = errors.New("role does not exist")
	// ErrRoleExist occurred if a role shouldn't be found
	ErrRoleExist = errors.New("role has already existed")
	empty        = struct{}{}
)

// SetParents bind `parents` to the role `id`.
// If the role or any of parents is not existing,
// an error will be returned.
func (rbac *RBAC) SetParents(id string, parents []string) error {
	if _, ok := rbac.backend.GetRole(id); !ok {
		return ErrRoleNotExist
	}
	for _, parent := range parents {
		if _, ok := rbac.backend.GetRole(parent); !ok {
			return ErrRoleNotExist
		}
	}
	if _, ok := rbac.backend.GetParents(id); !ok {
		rbac.backend.SetParents(id,make(map[string]struct{}))
	}
	for _, parent := range parents {
		rbac.backend.SetParent(id,parent, empty)
	}
	return nil
}

// GetParents return `parents` of the role `id`.
// If the role is not existing, an error will be returned.
// Or the role doesn't have any parents,
// a nil slice will be returned.
func (rbac *RBAC) GetParents(id string) ([]string, error) {
	rbac.backend.Lock()
	defer rbac.backend.Unlock()
	if _, ok := rbac.backend.GetRole(id); !ok {
		return nil, ErrRoleNotExist
	}
	ids, ok := rbac.backend.GetParents(id)
	if !ok {
		return nil, nil
	}
	var parents []string
	for parent := range ids {
		parents = append(parents, parent)
	}
	return parents, nil
}

// SetParent bind the `parent` to the role `id`.
// If the role or the parent is not existing,
// an error will be returned.
func (rbac *RBAC) SetParent(id string, parent string) error {
	rbac.backend.Lock()
	defer rbac.backend.Unlock()
	if _, ok := rbac.backend.GetRole(id); !ok {
		return ErrRoleNotExist
	}
	if _, ok := rbac.backend.GetRole(parent); !ok {
		return ErrRoleNotExist
	}
	if _, ok := rbac.backend.GetParents(id); !ok {
		rbac.backend.SetParents(id,make(map[string]struct{}))
	}
	var empty struct{}
	rbac.backend.SetParent(id, parent,empty)
	return nil
}

// RemoveParent unbind the `parent` with the role `id`.
// If the role or the parent is not existing,
// an error will be returned.
func (rbac *RBAC) RemoveParent(id string, parent string) error {
	rbac.backend.Lock()
	defer rbac.backend.Unlock()
	if _, ok := rbac.backend.GetRole(id); !ok {
		return ErrRoleNotExist
	}
	if _, ok := rbac.backend.GetRole(parent); !ok {
		return ErrRoleNotExist
	}
	rbac.backend.DeleteParent(id, parent)
	return nil
}

// Add a role `r`.
func (rbac *RBAC) Add(r gorbac.Role) (err error) {
	rbac.backend.Lock()
	if _, ok := rbac.backend.GetRole(r.ID()); !ok {
		rbac.backend.SetRole(r.ID(), r)
	} else {
		err = ErrRoleExist
	}
	rbac.backend.Unlock()
	return
}

// Remove the role by `id`.
func (rbac *RBAC) Remove(id string) (err error) {
	rbac.backend.Lock()
	if _, ok := rbac.backend.GetRole(id); ok {
		rbac.backend.DeleteRole(id)
		for rid, parents := range rbac.backend.GetAllParents() {
			if rid == id {
				rbac.backend.DeleteParents(rid)
				continue
			}
			for parent := range parents {
				if parent == id {
					rbac.backend.DeleteParent(rid, id)
					break
				}
			}
		}
	} else {
		err = ErrRoleNotExist
	}
	rbac.backend.Unlock()
	return
}

// Get the role by `id` and a slice of its parents id.
func (rbac *RBAC) Get(id string) (r gorbac.Role, parents []string, err error) {
	rbac.backend.RLock()
	var ok bool
	if r, ok = rbac.backend.GetRole(id); ok {
		p, _ := rbac.backend.GetParents(id)
		for parent := range p {
			parents = append(parents, parent)
		}
	} else {
		err = ErrRoleNotExist
	}
	rbac.backend.RUnlock()
	return
}

// IsGranted tests if the role `id` has Permission `p` with the condition `assert`.
func (rbac *RBAC) IsGranted(id string, p gorbac.Permission, assert AssertionFunc) (rslt bool) {
	rbac.backend.RLock()
	rslt = rbac.isGranted(id, p, assert)
	rbac.backend.RUnlock()
	return
}

// AssertionFunc supplies more fine-grained permission controls.
type AssertionFunc func(*RBAC, string, gorbac.Permission) bool

func (rbac *RBAC) isGranted(id string, p gorbac.Permission, assert AssertionFunc) bool {
	if assert != nil && !assert(rbac, id, p) {
		return false
	}
	return rbac.recursionCheck(id, p)
}

func (rbac *RBAC) recursionCheck(id string, p gorbac.Permission) bool {
	if role, ok := rbac.backend.GetRole(id); ok {
		if role.Permit(p) {
			return true
		}
		if parents, ok := rbac.backend.GetParents(id); ok {
			for pID := range parents {
				if _, ok := rbac.backend.GetRole(pID); ok {
					if rbac.recursionCheck(pID, p) {
						return true
					}
				}
			}
		}
	}
	return false
}


// WalkHandler is a function defined by user to handle role
type WalkHandler func(gorbac.Role, []string) error

// Walk passes each Role to WalkHandler
func Walk(rbac *RBAC, h WalkHandler) (err error) {
	if h == nil {
		return
	}
	rbac.backend.Lock()
	defer rbac.backend.Unlock()
	for id := range rbac.backend.GetRoles() {
		var parents []string
		r,_ := rbac.backend.GetRole(id)
		p,_ := rbac.backend.GetParents(id)
		for parent := range p {
			parents = append(parents, parent)
		}
		if err := h(r, parents); err != nil {
			return err
		}
	}
	return
}

// InherCircle returns an error when detecting any circle inheritance.
func InherCircle(rbac *RBAC) (err error) {
	rbac.backend.Lock()

	skipped := make(map[string]struct{}, len(rbac.backend.GetRoles()))
	var stack []string

	for id := range rbac.backend.GetRoles() {
		if err = dfs(rbac, id, skipped, stack); err != nil {
			break
		}
	}
	rbac.backend.Unlock()
	return err
}


// https://en.wikipedia.org/wiki/Depth-first_search
func dfs(rbac *RBAC, id string, skipped map[string]struct{}, stack []string) error {
	if _, ok := skipped[id]; ok {
		return nil
	}
	for _, item := range stack {
		if item == id {
			return ErrFoundCircle
		}
	}
	parents,_ := rbac.backend.GetParents(id)
	if len(parents) == 0 {
		stack = nil
		skipped[id] = empty
		return nil
	}
	stack = append(stack, id)
	for pid := range parents {
		if err := dfs(rbac, pid, skipped, stack); err != nil {
			return err
		}
	}
	return nil
}

// AnyGranted checks if any role has the permission.
func AnyGranted(rbac *RBAC, roles []string, permission gorbac.Permission,
	assert AssertionFunc) (rslt bool) {
	rbac.backend.Lock()
	for _, role := range roles {
		if rbac.isGranted(role, permission, assert) {
			rslt = true
			break
		}
	}
	rbac.backend.Unlock()
	return rslt
}

// AllGranted checks if all roles have the permission.
func AllGranted(rbac *RBAC, roles []string, permission gorbac.Permission,
	assert AssertionFunc) (rslt bool) {
	rbac.backend.Lock()
	for _, role := range roles {
		if !rbac.isGranted(role, permission, assert) {
			rslt = true
			break
		}
	}
	rbac.backend.Unlock()
	return !rslt
}
