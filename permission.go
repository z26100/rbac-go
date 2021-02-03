package rbac

import "github.com/mikespook/gorbac"


func NewPermission(id string) gorbac.Permission {
	return &Permission{id}
}

type Permission struct {
	id string
}
func ( p Permission) ID() string {
	return p.id
}
func ( p Permission) Match(permission gorbac.Permission) bool {
	return p.ID()==permission.ID()
}
