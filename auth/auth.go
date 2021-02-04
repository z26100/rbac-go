package auth

import (
	"encoding/json"
	"github.com/mikespook/gorbac"
	log "github.com/z26100/log-go"
	rbac2 "github.com/z26100/rbac"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"gopkg.in/yaml.v3"
	"os"
	"strings"
)

type FileType string

const (
	JSON FileType = "json"
	YAML FileType = "yaml"
	AUTO FileType = "auto"
)

var (
	fileType = AUTO
	rbac     *rbac2.RBAC
)

func NewRole(name string) (*rbac2.RBACRole, error) {
	role := &rbac2.RBACRole{
		Name: name,
	}
	err := rbac.Add(role)
	if err != nil {
		return nil, err
	}
	return role, nil
}

func InterfaceAsString(in []interface{}) []string {
	p := make([]string, len(in))
	for i, j := range in {
		p[i] = j.(string)
	}
	return p
}
func SetParents(id string, parents []string) error {
	return rbac.SetParents(id, parents)
}

func GetRole(id string) (*rbac2.RBACRole, []string, error) {
	role, parents, err := rbac.Get(id)
	if err != nil {
		return nil, nil, err
	}
	return role.(*rbac2.RBACRole), parents, err
}

func AddPermission(name string) *rbac2.RBACPermission {
	permission := &rbac2.RBACPermission{
		Name: name,
	}
	return permission
}

func AssignRole(role *rbac2.RBACRole, permission *rbac2.RBACPermission) error {
	err := rbac.AssignRole(role, permission)
	if err != nil {
		return err
	}
	return rbac.Set(role)
}
func IsGranted(roleId string, p rbac2.RBACPermission, fc rbac2.AssertionFunc) bool {
	return rbac.IsGranted(roleId, p, fc)
}

func IsPermitted(roles []gorbac.Role, action string) bool {
	p := rbac2.RBACPermission{
		Name: strings.TrimSpace(strings.ToLower(action)),
	}
	for _, role := range roles {
		if IsGranted(role.ID(), p, nil) {
			return true
		}
	}
	return false
}

func NewMongo(opts *options.ClientOptions, database string) error {
	client, err := mongo.NewClient(options.Client().ApplyURI(opts.GetURI()).SetAuth(*opts.Auth))
	if err != nil {
		return err
	}
	ctx, cancelFc := rbac2.Ctx()
	defer cancelFc()
	err = client.Connect(ctx)
	if err != nil {
		return err
	}
	err = client.Ping(ctx, nil)
	if err != nil {
		return err
	}
	b, err := rbac2.NewMongoBackend(client, database)
	if err != nil {
		return err
	}
	rbac = rbac2.New(b)
	return nil
}

func NewRBAC() {
	rbac = rbac2.Default()
}

func Clear() {
	rbac.Clear()
}
func CloseRBAC() {
	rbac.Close()
}

func SetFileType(t FileType) {
	fileType = t
}

func LoadFromFile(filename string) error {
	if fileType == AUTO {
		setAutoFileType(filename)
	}
	var data map[string]interface{}
	var err error
	switch fileType {
	case JSON:
		err = loadJson(filename, &data)
	default:
		err = loadYaml(filename, &data)
	}
	roles := data["roles"].(map[string]interface{})
	inher := data["inher"].(map[string]interface{})

	permissions := make(map[string]*rbac2.RBACPermission)
	// Build Roles and add them to goRBAC instance
	for rid, pids := range roles {
		role, err := NewRole(rid)
		if err == nil {
			for _, pid := range pids.([]interface{}) {
				_, ok := permissions[pid.(string)]
				if !ok {
					permissions[pid.(string)] = AddPermission(pid.(string))
				}
				err = rbac.AssignRole(role, permissions[pid.(string)])
			}
		} else {
			log.Error(err)
		}
	}
	// Assign the inheritance relationship
	for rid, parents := range inher {
		if len(parents.([]interface{})) == 0 {
			break
		}
		if err := SetParents(rid, InterfaceAsString(parents.([]interface{}))); err != nil {
			log.Fatal(err)
		}
	}
	return err
}

func SaveAsFilename(filename string) error {
	if fileType == AUTO {
		setAutoFileType(filename)
	}

	// map[RoleId]PermissionIds
	outputRoles := make(map[string][]string)
	// map[RoleId]ParentIds
	outputInher := make(map[string][]string)

	SaveJsonHandler := func(role gorbac.Role, parents []string) error {
		// WARNING: Don't use rbacmap instance in the handler,
		// otherwise it causes deadlock.
		permissions := make([]string, 0)
		for _, p := range role.(*rbac2.RBACRole).GetPermissions() {
			permissions = append(permissions, p.ID())
		}
		outputRoles[role.ID()] = permissions
		outputInher[role.ID()] = parents
		return nil
	}
	if err := rbac2.Walk(rbac, SaveJsonHandler); err != nil {
		return err
	}
	// Save Roles information
	data := make(map[string]interface{})
	data["roles"] = outputRoles
	data["inher"] = outputInher

	var err error
	switch fileType {
	case JSON:
		err = saveJson(filename, data)
	default:
		err = saveYaml(filename, data)
	}
	return err
}

func setAutoFileType(filename string) {
	if strings.HasSuffix(strings.ToLower(filename), ".json") {
		SetFileType(JSON)
	} else {
		SetFileType(YAML)
	}
}
func loadJson(filename string, v interface{}) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewDecoder(f).Decode(v)
}

func saveJson(filename string, v interface{}) error {
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(v)
}

func loadYaml(filename string, v interface{}) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	return yaml.NewDecoder(f).Decode(v)
}

func saveYaml(filename string, v interface{}) error {
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	return yaml.NewEncoder(f).Encode(v)
}
