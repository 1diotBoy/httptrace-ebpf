package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"power-ebpf/internal/httptrace"
)

type RedisStore struct {
	client    *redis.Client
	keyPrefix string
	ttl       time.Duration
}

func NewRedisStore(addr, password string, db int, keyPrefix string, ttl time.Duration) (*RedisStore, error) {
	if addr == "" {
		return &RedisStore{keyPrefix: keyPrefix, ttl: ttl}, nil
	}

	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("ping redis: %w", err)
	}

	return &RedisStore{
		client:    client,
		keyPrefix: keyPrefix,
		ttl:       ttl,
	}, nil
}

func (s *RedisStore) Save(ctx context.Context, trace httptrace.TraceDocument) error {
	if s == nil || s.client == nil {
		return nil
	}

	body, err := json.Marshal(trace)
	if err != nil {
		return fmt.Errorf("marshal trace %d: %w", trace.ChainID, err)
	}
	kind := trace.Kind
	if kind == "" {
		switch {
		case trace.Request != nil && trace.Response == nil:
			kind = "request"
		case trace.Request == nil && trace.Response != nil:
			kind = "response"
		default:
			kind = "trace"
		}
	}
	// 请求和响应分开存，使用同一个 chain_id 做关联，避免 response 覆盖 request。
	key := fmt.Sprintf("%s:%s:%d", s.keyPrefix, kind, trace.ChainID)
	if err := s.client.Set(ctx, key, body, s.ttl).Err(); err != nil {
		return fmt.Errorf("set redis key %s: %w", key, err)
	}
	return nil
}

func (s *RedisStore) Close() error {
	if s == nil || s.client == nil {
		return nil
	}
	return s.client.Close()
}
