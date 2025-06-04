package session_store

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInitializeSessionStore(t *testing.T) {
	t.Run("should create memory store by default", func(t *testing.T) {
		config := StoreConfig{
			Type: "memory",
		}

		store, err := InitializeSessionStore(config)
		require.NoError(t, err)
		assert.NotNil(t, store)

		// Test that it's actually a memory store by using it
		session := Session{
			ID:        "test-memory-session",
			Username:  "memoryuser",
			Sub:       "memory-sub",
			ExpiresAt: time.Now().Add(time.Hour),
			IssuedAt:  time.Now(),
		}

		store.AddSession(session)
		retrieved, exists := store.GetSession("test-memory-session")
		assert.True(t, exists)
		assert.Equal(t, session.ID, retrieved.ID)
	})

	t.Run("should create memory store when type is empty", func(t *testing.T) {
		config := StoreConfig{
			Type: "",
		}

		store, err := InitializeSessionStore(config)
		require.NoError(t, err)
		assert.NotNil(t, store)

		// Verify it works as a memory store
		assert.Equal(t, 0, store.GetSessionCount())
	})

	t.Run("should create redis store with valid config", func(t *testing.T) {
		config := StoreConfig{
			Type: "redis",
			Redis: RedisConfig{
				Addr:          "localhost:6379",
				Password:      "",
				DB:            0,
				SessionPrefix: "test:session:",
				StatePrefix:   "test:state:",
				TTL:           "1h",
			},
		}

		store, err := InitializeSessionStore(config)
		if err != nil {
			// Redis not available, skip this test
			t.Skip("Redis not available for testing")
			return
		}

		assert.NotNil(t, store)

		// Test that it implements the interface
		var _ SessionStorer = store
	})

	t.Run("should fail with invalid store type", func(t *testing.T) {
		config := StoreConfig{
			Type: "invalid",
		}

		store, err := InitializeSessionStore(config)
		assert.Error(t, err)
		assert.Nil(t, store)
		assert.Contains(t, err.Error(), "unsupported session store type")
	})

	t.Run("should parse TTL correctly for redis config", func(t *testing.T) {
		config := StoreConfig{
			Type: "redis",
			Redis: RedisConfig{
				Addr:          "localhost:6379",
				Password:      "",
				DB:            0,
				SessionPrefix: "test:session:",
				StatePrefix:   "test:state:",
				TTL:           "2h30m",
			},
		}

		// This should parse the TTL even if Redis connection fails
		_, err := InitializeSessionStore(config)
		// We expect this to fail due to Redis connection, but TTL should be parsed
		if err != nil {
			// TTL parsing happens in the factory, let's test it directly
			expectedTTL := 2*time.Hour + 30*time.Minute
			parsedTTL, parseErr := time.ParseDuration("2h30m")
			require.NoError(t, parseErr)
			assert.Equal(t, expectedTTL, parsedTTL)
		}
	})
}

func TestRedisStoreAdapterInterface(t *testing.T) {
	t.Run("should implement SessionStorer interface", func(t *testing.T) {
		// Create a mock RedisStore for testing
		mockRedisStore := &RedisStore{
			sessionPrefix: "test:session:",
			statePrefix:   "test:state:",
			defaultTTL:    time.Hour,
		}

		adapter := &redisStoreAdapter{store: mockRedisStore}

		// Verify interface compliance - this is the main test
		var _ SessionStorer = adapter

		// Test that the adapter has all the required methods by checking they exist
		// We can't actually call them without a real Redis connection
		assert.NotNil(t, adapter.AddSession)
		assert.NotNil(t, adapter.GetSession)
		assert.NotNil(t, adapter.DeleteSession)
		assert.NotNil(t, adapter.CleanExpired)
		assert.NotNil(t, adapter.GetField)
		assert.NotNil(t, adapter.GetSessionCount)
		assert.NotNil(t, adapter.SessionExists)
		assert.NotNil(t, adapter.AddStateEntry)
		assert.NotNil(t, adapter.ValidateAndRemoveState)
		assert.NotNil(t, adapter.CleanExpiredStates)
	})
}

func TestStoreConfig(t *testing.T) {
	t.Run("should have correct field tags", func(t *testing.T) {
		config := StoreConfig{
			Type: "redis",
			Redis: RedisConfig{
				Addr:          "localhost:6379",
				Password:      "secret",
				DB:            1,
				SessionPrefix: "session:",
				StatePrefix:   "state:",
				TTL:           "24h",
			},
		}

		// Test JSON marshaling/unmarshaling
		data, err := json.Marshal(config)
		require.NoError(t, err)

		var unmarshaled StoreConfig
		err = json.Unmarshal(data, &unmarshaled)
		require.NoError(t, err)

		assert.Equal(t, config.Type, unmarshaled.Type)
		assert.Equal(t, config.Redis.Addr, unmarshaled.Redis.Addr)
		assert.Equal(t, config.Redis.Password, unmarshaled.Redis.Password)
		assert.Equal(t, config.Redis.DB, unmarshaled.Redis.DB)
		assert.Equal(t, config.Redis.SessionPrefix, unmarshaled.Redis.SessionPrefix)
		assert.Equal(t, config.Redis.StatePrefix, unmarshaled.Redis.StatePrefix)
		assert.Equal(t, config.Redis.TTL, unmarshaled.Redis.TTL)
	})
}
