package mongostore

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	errInvalidModificationDate = errors.New("invalid session modification date")
)

// MongoStore stores sessions in a MongoDB collection.
type MongoStore struct {
	Codecs     []securecookie.Codec
	Options    *sessions.Options
	collection *mongo.Collection
}

// Session is the model for a session document.
type Session struct {
	ID         primitive.ObjectID `bson:"_id,omitempty"`
	Data       string             `bson:"data"`
	ModifiedAt time.Time          `bson:"modifiedAt"`
}

// NewMongoStore returns a new MongoStore instance.
func NewMongoStore(c *mongo.Collection, opts *sessions.Options, keyPairs ...[]byte) *MongoStore {
	if opts == nil {
		opts = &sessions.Options{
			Path:   "/",
			MaxAge: 86400 * 30,
		}
	}
	ms := &MongoStore{
		Codecs:     securecookie.CodecsFromPairs(keyPairs...),
		Options:    opts,
		collection: c,
	}
	ms.MaxAge(opts.MaxAge)
	return nil
}

// Get returns a session for the given name after adding it to the registry.
//
// It returns a new session if the sessions doesn't exist. Access IsNew on
// the session to check if it is an existing session or a new one.
//
// It returns a new session and an error if the session exists but could
// not be decoded.
func (s *MongoStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	return sessions.GetRegistry(r).Get(s, name)
}

// New returns a session for the given name without adding it to the registry.
//
// The difference between New() and Get() is that calling New() twice will
// decode the session data twice, while Get() registers and reuses the same
// decoded session after the first call.
func (s *MongoStore) New(r *http.Request, name string) (*sessions.Session, error) {
	session := sessions.NewSession(s, name)
	opts := *s.Options
	session.Options = &opts
	session.IsNew = true
	var err error
	if c, errCookie := r.Cookie(name); errCookie == nil {
		if err = securecookie.DecodeMulti(name, c.Value, &session.ID, s.Codecs...); err == nil {
			if err = s.load(r.Context(), session); err == nil {
				session.IsNew = false
			}
		}
	}
	return session, err
}

// Save adds a single session to the response.
func (s *MongoStore) Save(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {
	if session.Options.MaxAge < 0 {
		if err := s.erase(r.Context(), session); err != nil {
			return err
		}
		http.SetCookie(w, sessions.NewCookie(session.Name(), "", session.Options))
		return nil
	}

	if session.ID == "" {
		session.ID = primitive.NewObjectID().Hex()
	}
	if err := s.save(r.Context(), session); err != nil {
		return err
	}
	encoded, err := securecookie.EncodeMulti(session.Name(), session.ID, s.Codecs...)
	if err != nil {
		return err
	}
	http.SetCookie(w, sessions.NewCookie(session.Name(), encoded, session.Options))
	return nil
}

// MaxAge sets the maximum age for the store and the underlying cookie
// implementation. Individual sessions can be deleted by setting Options.MaxAge
// = -1 for that session.
func (s *MongoStore) MaxAge(age int) {
	s.Options.MaxAge = age

	// Set the maxAge for each securecookie instance.
	for _, codec := range s.Codecs {
		if sc, ok := codec.(*securecookie.SecureCookie); ok {
			sc.MaxAge(age)
		}
	}
}

// load retrieves a session document from the MongoDB collection.
func (s *MongoStore) load(ctx context.Context, session *sessions.Session) error {
	var doc Session
	if err := s.collection.FindOne(ctx, bson.M{"_id": session.ID}).Decode(&doc); err != nil {
		return err
	}
	if err := securecookie.DecodeMulti(session.Name(), doc.Data, &session.Values, s.Codecs...); err != nil {
		return err
	}
	return nil
}

// save upserts a session document in the MongoDB collection.
func (s *MongoStore) save(ctx context.Context, session *sessions.Session) error {
	objID, err := primitive.ObjectIDFromHex(session.ID)
	if err != nil {
		return err
	}

	encoded, err := securecookie.EncodeMulti(session.Name(), session.Values, s.Codecs...)
	if err != nil {
		return err
	}

	doc := Session{
		ID:         objID,
		Data:       encoded,
		ModifiedAt: time.Now(),
	}
	opts := options.Update().SetUpsert(true)
	update := bson.D{{Key: "$set", Value: &doc}}
	if _, err := s.collection.UpdateOne(ctx, bson.M{"_id": session.ID}, update, opts); err != nil {
		return err
	}
	return nil
}

// erase deletes a session document from the MongoDB collection.
func (s *MongoStore) erase(ctx context.Context, session *sessions.Session) error {
	return s.collection.FindOneAndDelete(ctx, bson.M{"_id": session.ID}).Err()
}
