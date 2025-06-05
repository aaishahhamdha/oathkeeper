package session_store

import (
	"context"
	"fmt"
	"time"
)

type StoreType string

const (
	InMemoryStore  StoreType = "memory"
	RedisStoreType StoreType = "redis"
)

type StoreConfig struct {
	Type  StoreType   `json:"type"`
	Redis RedisConfig `json:"redis,omitempty"`
}

func InitializeSessionStore(config StoreConfig) (SessionStorer, error) {
	fmt.Printf("SESSION_STORE: Initializing session store with type: %s\n", config.Type)

	switch config.Type {
	case InMemoryStore, "":
		fmt.Printf("SESSION_STORE: Using in-memory session store\n")
		return NewStore(), nil

	case RedisStoreType:
		fmt.Printf("SESSION_STORE: Attempting to initialize Redis session store with addr: %s\n", config.Redis.Addr)
		store, err := NewRedisStore(config.Redis)
		if err != nil {
			fmt.Printf("SESSION_STORE: Redis session store initialization failed: %v\n", err)
			return nil, err
		}
		fmt.Printf("SESSION_STORE: Successfully initialized Redis session store\n")
		return &redisStoreAdapter{store: store}, nil

	default:
		return nil, fmt.Errorf("unsupported session store type: %s", config.Type)
	}
}

type redisStoreAdapter struct {
	store *RedisStore
}

func (a *redisStoreAdapter) AddSession(sess Session) {
	_ = a.store.AddSession(context.Background(), sess)
}

func (a *redisStoreAdapter) GetSession(id string) (Session, bool) {
	return a.store.GetSession(id)
}

func (a *redisStoreAdapter) DeleteSession(id string) {
	a.store.DeleteSession(id)
}

func (a *redisStoreAdapter) CleanExpired() {
	a.store.CleanExpired()
}

func (a *redisStoreAdapter) GetField(id string, field string) (string, bool) {
	return a.store.GetField(id, field)
}

func (a *redisStoreAdapter) GetSessionCount() int {
	return a.store.GetSessionCount()
}

func (a *redisStoreAdapter) SessionExists(id string) bool {
	return a.store.SessionExists(id)
}

func (a *redisStoreAdapter) AddStateEntry(state string, userAgent, requestURL string, upstreamURL string) {
	a.store.AddStateEntry(state, userAgent, requestURL, upstreamURL)
}

func (a *redisStoreAdapter) ValidateAndRemoveState(state string, currentUserAgent string) (StateEntry, bool) {
	entry, err := a.store.ValidateAndRemoveState(context.Background(), state, currentUserAgent)
	if err != nil {
		return StateEntry{}, false
	}
	return entry, entry.State != ""
}

func (a *redisStoreAdapter) CleanExpiredStates(maxAge time.Duration) {
	a.store.CleanExpiredStates(maxAge)
}
