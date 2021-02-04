package rbacmap

import (
	rbac2 "github.com/z26100/rbac-go"
	auth "github.com/z26100/rbac-go/auth"
	"testing"
)

func TestEmptyAuth(t *testing.T) {
	auth.NewRBAC()
	defer auth.CloseRBAC()
	role, parents, err := auth.GetRole("test-1")
	if err == nil {
		t.Fatal("no exception")
	}
	if parents != nil {
		t.Fatal("parents must be nil")
	}
	if role != nil {
		t.Fatal("role must be nil")
	}
}

func TestRole(t *testing.T) {
	auth.NewRBAC()
	defer auth.CloseRBAC()
	role, err := auth.NewRole("Test-1")
	if err != nil {
		t.Fatal(err)
	}
	if role.ID() != "test-1" {
		t.Fatal("Id does not match")
	}
	if role.Name != "Test-1" {
		t.Fatal("Name does not match")
	}
}

func TestUniqueRole(t *testing.T) {
	auth.NewRBAC()
	defer auth.CloseRBAC()
	or, err := auth.NewRole("Test-1")
	t.Log(or)
	if err != nil {
		t.Fatal(err)
	}
	dup, err := auth.NewRole("Test-1")
	if err == nil {
		t.Fatal(err)
	}
	if dup != nil {
		t.Fatal(dup, or)
	}
}

func TestParentRole(t *testing.T) {
	auth.NewRBAC()
	defer auth.CloseRBAC()
	p0, err := auth.NewRole("parent-1")
	if err != nil {
		t.Fatal(err)
	}
	c0, err := auth.NewRole("child-1")
	if err != nil {
		t.Fatal(err)
	}
	err = auth.SetParents("child-1", []string{"parent-1"})
	if err != nil {
		t.Fatal(err)
	}
	c, p, err := auth.GetRole("child-1")
	if err != nil {
		t.Fatal(err)
	}
	if c.ID() != c0.ID() {
		t.Fatal("role id unequals expected value")
	}
	if p == nil || len(p) != 1 {
		t.Fatal("wrong number of parents")
	}
	if p[0] != p0.ID() {
		t.Fatal("parent id unexpected")
	}
}

func TestPermission(t *testing.T) {
	auth.NewRBAC()
	defer auth.CloseRBAC()
	r, err := auth.NewRole("role-1")
	if err != nil {
		t.Fatal(err)
	}
	p := auth.AddPermission("P-1")
	if p.Name != "P-1" {
		t.Fatal("unexpected permission id")
	}
	if p.ID() != "P-1" {
		t.Fatal("unexpected permission id")
	}
	err = auth.AssignRole(r, p)
	if err != nil {
		t.Fatal(err)
	}
	granted := auth.IsGranted(r.ID(), *p, nil)
	if !granted {
		t.Fatal("problem with permission grant")
	}
	granted = auth.IsGranted("wrong", *p, nil)
	if granted {
		t.Fatal("problem with permission grant")
	}
}

func TestRegExPermission(t *testing.T) {
	auth.NewRBAC()
	defer auth.CloseRBAC()
	r, err := auth.NewRole("test")
	if err != nil {
		t.Fatal(err)
	}
	p := auth.AddPermission("get:[^:]+$")
	err = auth.AssignRole(r, p)
	if err != nil {
		t.Fatal(err)
	}
	granted := auth.IsGranted("test", rbac2.RBACPermission{
		Name: "get:test",
	}, nil)
	if !granted {
		t.Fatal("problem with permission grant")
	}
	granted = auth.IsGranted("test", rbac2.RBACPermission{
		Name: "get:test:abc",
	}, nil)
	if granted {
		t.Fatal("problem with permission grant")
	}
}
func TestSave(t *testing.T) {
	auth.NewRBAC()
	defer auth.CloseRBAC()
	r, err := auth.NewRole("role-1")
	if err != nil {
		t.Fatal(err)
	}
	p := auth.AddPermission("P-1")
	err = auth.AssignRole(r, p)
	if err != nil {
		t.Fatal(err)
	}
	err = auth.SaveAsFilename("test-out.yaml")
	if err != nil {
		t.Fatal(err)
	}
}

func TestLoad(t *testing.T) {
	auth.NewRBAC()
	defer auth.CloseRBAC()
	err := auth.LoadFromFile("test.yaml")
	if err != nil {
		t.Fatal(err)
	}
}
