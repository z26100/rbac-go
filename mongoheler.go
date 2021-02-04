package rbac

import (
	"context"
	"errors"
	"go.mongodb.org/mongo-driver/bson"
	m "go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"reflect"
	"time"
)

/*********************
	 MONGO Functions
 *********************/
type config struct {
	client                   *m.Client
	database                 string
	databaseOpts             *options.DatabaseOptions
	collectionOpts           *options.CollectionOptions
	findOptions              *options.FindOptions
	deleteOptions            *options.DeleteOptions
	insertOptions            *options.InsertManyOptions
	replaceOptions           *options.ReplaceOptions
	updateOptions            *options.UpdateOptions
	findOneAndUpdateOptions  *options.FindOneAndUpdateOptions
	findOneAndReplaceOptions *options.FindOneAndReplaceOptions
	findOneAndDeleteOptions  *options.FindOneAndDeleteOptions
}

type Inheritance struct {
	Parent string   `json:"parent" bson:"parent"`
	Child  string   `json:"child" bson:"child"`
	Struct struct{} `json:"struct", bson:"struct"`
}

func FindOne(c *m.Client, config config, collection string, id string, out interface{}) (interface{}, error) {
	return FindMany(c, config, collection, filterById(id), out)
}

func FindMany(c *m.Client, config config, collection string, filter bson.M, out interface{}) (interface{}, error) {
	ctx, cancelFc := Ctx()
	defer cancelFc()
	col, err := Collection(c, config, collection)
	if err != nil {
		return nil, err
	}
	cursor, err := col.Find(ctx, filter, config.findOptions)
	if cursor == nil {
		return nil, errors.New("cursor must not be nil")
	}
	if err != nil {
		return nil, err
	}
	if cursor.Err() != nil {
		return nil, cursor.Err()
	}
	err = cursor.All(ctx, &out)
	return out, err
}

func InsertOne(c *m.Client, config config, collection string, doc interface{}) (interface{}, error) {
	var docs []interface{}
	docs = append(docs, doc)
	return InsertMany(c, config, collection, docs)
}

func InsertMany(c *m.Client, config config, collection string, docs []interface{}) (interface{}, error) {
	ctx, cancelFc := Ctx()
	defer cancelFc()
	col, err := Collection(c, config, collection)
	if err != nil {
		return nil, err
	}
	res, err := col.InsertMany(ctx, docs, config.insertOptions)
	return res, err
}

func FindOneAndUpdate(c *m.Client, config config, collection string, id string, update interface{}) (interface{}, error) {
	ctx, cancelFc := Ctx()
	defer cancelFc()
	col, err := Collection(c, config, collection)
	if err != nil {
		return nil, err
	}
	res := col.FindOneAndUpdate(ctx, filterById(id), update, config.findOneAndUpdateOptions)
	if res == nil {
		return nil, errors.New("result must not be nil")
	}
	return res, res.Err()
}

func UpdateOne(c *m.Client, config config, collection string, id string, update interface{}) (interface{}, error) {
	return UpdateMany(c, config, collection, filterById(id), update)
}

func UpdateMany(c *m.Client, config config, collection string, filter bson.M, update interface{}) (interface{}, error) {
	ctx, cancelFc := Ctx()
	defer cancelFc()
	col, err := Collection(c, config, collection)
	if err != nil {
		return nil, err
	}
	res, err := col.UpdateMany(ctx, filter, update, config.updateOptions)
	return res, err
}
func FindOneAndReplace(c *m.Client, config config, collection string, id string, replacement interface{}) (interface{}, error) {
	ctx, cancelFc := Ctx()
	defer cancelFc()
	col, err := Collection(c, config, collection)
	if err != nil {
		return nil, err
	}
	res := col.FindOneAndReplace(ctx, filterById(id), replacement, config.findOneAndReplaceOptions)
	if res == nil {
		return nil, errors.New("result must not be nil")
	}
	if res.Err() != nil {
		return nil, res.Err()
	}
	r := reflect.New(reflect.TypeOf(replacement).Elem()).Interface()
	err = res.Decode(r)
	return r, err
}

func ReplaceOne(c *m.Client, config config, collection string, filter bson.M, replacement interface{}) (interface{}, error) {
	ctx, cancelFc := Ctx()
	defer cancelFc()
	col, err := Collection(c, config, collection)
	if err != nil {
		return nil, err
	}
	res, err := col.ReplaceOne(ctx, filter, replacement, config.replaceOptions)
	return res, err
}

func FindOneAndDelete(c *m.Client, config config, collection string, id string) (interface{}, error) {
	ctx, cancelFc := Ctx()
	defer cancelFc()
	col, err := Collection(c, config, collection)
	if err != nil {
		return nil, err
	}
	res := col.FindOneAndDelete(ctx, filterById(id), config.findOneAndDeleteOptions)
	if res == nil {
		return nil, errors.New("result must not be nil")
	}
	return res, res.Err()
}

func DeleteOne(c *m.Client, config config, collection string, id string) (interface{}, error) {
	return DeleteMany(c, config, collection, filterById(id))
}

func DeleteMany(c *m.Client, config config, collection string, filter bson.M) (interface{}, error) {
	ctx, cancelFc := Ctx()
	defer cancelFc()
	col, err := Collection(c, config, collection)
	if err != nil {
		return nil, err
	}
	res, err := col.DeleteMany(ctx, filter, config.deleteOptions)
	return res, err
}

func Collection(c *m.Client, config config, collection string) (*m.Collection, error) {
	database := c.Database(config.database, config.databaseOpts)
	if database == nil {
		return nil, errors.New("database must not be nil")
	}
	col := database.Collection(collection, config.collectionOpts)
	if col == nil {
		return nil, errors.New("collection must not be nil")
	}
	return col, nil
}
func Ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 10*time.Second)
}
func filterById(id string) bson.M {
	return bson.M{"_id": id}
}

func pbool(in bool) *bool {
	return &in
}
func pint8(in int8) *int8 {
	return &in
}

func pReturnDocument(doc options.ReturnDocument) *options.ReturnDocument {
	return &doc
}
