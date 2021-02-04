package rbac

import (
	"fmt"
	"github.com/mikespook/gorbac"
	"go.mongodb.org/mongo-driver/bson"
	m "go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"sync"
	"time"
)

const (
	defaultTimeout = 10 * time.Second
)

type MongoBackend struct {
	roles    gorbac.Roles
	mutex    sync.RWMutex
	mongo    *m.Client
	parents  map[string]map[string]struct{}
	database string
	timeout  time.Duration
	config   config
	colRoles string
	colInher string
}

func NewMongoBackend(client *m.Client, database string) (*MongoBackend, error) {
	return &MongoBackend{
		mutex:    sync.RWMutex{},
		mongo:    client,
		timeout:  defaultTimeout,
		colRoles: "roles",
		colInher: "inheritance",
		config: config{
			client:         nil,
			database:       database,
			databaseOpts:   nil,
			collectionOpts: nil,
			findOptions:    nil,
			deleteOptions:  nil,
			insertOptions:  nil,
			replaceOptions: &options.ReplaceOptions{
				Upsert: pbool(true),
			},
			updateOptions:           nil,
			findOneAndUpdateOptions: nil,
			findOneAndReplaceOptions: &options.FindOneAndReplaceOptions{
				ReturnDocument: pReturnDocument(options.After),
				Upsert:         pbool(true),
			},
			findOneAndDeleteOptions: &options.FindOneAndDeleteOptions{},
		},
	}, nil
}

func (b *MongoBackend) RLock() {
	b.mutex.RLock()
}

func (b *MongoBackend) Lock() {
	b.mutex.Lock()
}

func (b *MongoBackend) Unlock() {
	b.mutex.Unlock()
}

func (b *MongoBackend) RUnlock() {
	b.mutex.RUnlock()
}

func (b *MongoBackend) GetRoles() map[string]gorbac.Role {
	var res []gorbac.Role
	result := make(map[string]gorbac.Role)
	_, err := FindMany(b.mongo, b.config, b.colRoles, bson.M{}, &res)
	if res == nil || len(res) == 0 || err != nil {
		return result
	}
	for _, r := range res {
		result[r.ID()] = r
	}
	return result
}

func (b *MongoBackend) GetRole(id string) (gorbac.Role, bool) {
	res, err := FindOne(b.mongo, b.config, b.colRoles, id, []*RBACRole{})
	result := res.([]*RBACRole)
	if len(result) == 0 || err != nil {
		return nil, false
	}
	return result[0], true
}

func (b *MongoBackend) SetRole(id string, role gorbac.Role) error {
	_, err := FindOneAndReplace(b.mongo, b.config, b.colRoles, id, role)
	if err != nil {
		return err
	}
	return err
}

func (b *MongoBackend) DeleteRole(id string) error {
	_, err := FindOneAndDelete(b.mongo, b.config, b.colRoles, id)
	return err
}

func (b *MongoBackend) GetAllParents() map[string]map[string]struct{} {
	var res []Inheritance
	result := make(map[string]map[string]struct{})
	_, err := FindMany(b.mongo, b.config, b.colRoles, bson.M{}, &res)
	if res == nil || len(res) == 0 || err != nil {
		return result
	}
	for _, r := range res {
		if result[r.Child] == nil {
			result[r.Child] = make(map[string]struct{})
		}
		result[r.Child][r.Parent] = r.Struct
	}
	return result
}

func (b *MongoBackend) GetParents(id string) (map[string]struct{}, bool) {
	result := make(map[string]struct{})
	res, err := FindMany(b.mongo, b.config, b.colInher, bson.M{"child": id}, []*Inheritance{})
	r := res.([]*Inheritance)
	if res == nil || len(r) == 0 || err != nil {
		return result, false
	}
	for _, r := range r {
		result[r.Parent] = r.Struct
	}
	return result, true
}

func (b *MongoBackend) SetParent(id string, pid string, p struct{}) error {
	replacement := &Inheritance{
		Parent: pid,
		Child:  id,
		Struct: p,
	}
	rid := fmt.Sprintf("%s:%s", id, pid)
	_, err := FindOneAndReplace(b.mongo, b.config, b.colInher, rid, replacement)
	return err
}

func (b *MongoBackend) SetParents(id string, p map[string]struct{}) {
	// nothing to do
}

func (b *MongoBackend) DeleteParents(id string) error {
	_, err := DeleteMany(b.mongo, b.config, b.colInher, bson.M{"child": id})
	return err
}

func (b *MongoBackend) DeleteParent(pid, id string) error {
	rid := fmt.Sprintf("%s:%s", id, pid)
	_, err := DeleteOne(b.mongo, b.config, b.colInher, rid)
	return err
}

func (b *MongoBackend) DropCollections(collectionName ...string) error {
	ctx, cancelFc := Ctx()
	defer cancelFc()
	for _, colName := range collectionName {
		col, err := Collection(b.mongo, b.config, colName)
		if err != nil {
			return err
		}
		err = col.Drop(ctx)
		if err != nil {
			return err
		}
	}
	return nil
}

func (b *MongoBackend) Clear() error {
	return b.DropCollections(b.colInher, b.colRoles)
}

func (b *MongoBackend) Close() error {
	ctx, cancelFc := Ctx()
	defer cancelFc()
	return b.mongo.Disconnect(ctx)
}
