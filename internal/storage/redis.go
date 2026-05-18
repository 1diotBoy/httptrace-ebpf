package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"power-ebpf/internal/httptrace"
)

const redisBodyLimitBytes = 32 * 1024
const requestKey = "POWER-BYPASS-REQUEST-PARAM-MAX"
const responseKey = "POWER-BYPASS-RESPONSE-PARAM-MAX"

type RedisStore struct {
	client    *redis.Client
	keyPrefix string
	ttl       time.Duration
	syncOnce  sync.Once
}

var (
	currentRequestMaxValue  int64 = redisBodyLimitBytes
	requestMaxValueLock     sync.RWMutex
	currentResponseMaxValue int64 = redisBodyLimitBytes
	responseMaxValueLock    sync.RWMutex
)

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

	store := &RedisStore{
		client:    client,
		keyPrefix: keyPrefix,
		ttl:       ttl,
	}
	store.startBodyLimitSync()
	return store, nil
}

func (s *RedisStore) Save(ctx context.Context, trace httptrace.TraceDocument) error {
	if s == nil {
		return nil
	}
	if s.client == nil {
		return nil
	}
	// body, err := json.Marshal(prepareTraceForRedis(trace))
	body, err := json.Marshal(trace)
	if err != nil {
		return fmt.Errorf("marshal trace %d: %w", trace.ChainID, err)
	}
	/*
		if kind == "request" {
			// 增加 chain id map 供java端消费
			setkey := fmt.Sprintf("%s", s.keyPrefix)
			if err := s.client.LPush(ctx, setkey, trace.ChainID).Err(); err != nil {
				return fmt.Errorf("set redis key %s: %w", setkey, err)
			}
		}
		// 请求和响应分开存，使用同一个 chain_id 去关联，避免 response 覆盖 request。
		key := fmt.Sprintf("%s:%s:%d", s.keyPrefix, kind, trace.ChainID)
		if err := s.client.Set(ctx, key, body, s.ttl).Err(); err != nil {
			return fmt.Errorf("set redis key %s: %w", key, err)
		}
	*/

	key := "POWER-HTTP-TRACE"
	if err := s.client.LPush(ctx, key, body).Err(); err != nil {
		return fmt.Errorf("set redis key %s: %w", key, err)
	}
	/* 临时测试,数据保留排查问题*/
	if err := s.client.LPush(ctx, "AAA-diaoge-trace", body).Err(); err != nil {
		return fmt.Errorf("set redis key diaoge-trace: %w", err)
	}
	if err := s.client.Expire(ctx, "AAA-diaoge-trace", 24*time.Hour).Err(); err != nil {
		return fmt.Errorf("expire redis key diaoge-trace: %w", err)
	}
	return nil
}

func (s *RedisStore) startBodyLimitSync() {
	if s == nil || s.client == nil {
		return
	}
	s.syncOnce.Do(func() {
		s.syncBodyLimitsOnce()
		go func() {
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()
			for range ticker.C {
				s.syncBodyLimitsOnce()
			}
		}()
	})
}

func (s *RedisStore) syncBodyLimitsOnce() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := s.syncRedisToMemory(ctx); err != nil {
		log.Printf("redis body limit sync error: %v", err)
	}
}

// 同步redis到内存
func (s *RedisStore) syncRedisToMemory(ctx context.Context) error {
	requestLimit, err := s.readBodyLimitBytes(ctx, requestKey)
	requestMaxValueLock.Lock()
	currentRequestMaxValue = requestLimit
	requestMaxValueLock.Unlock()

	responseLimit, respErr := s.readBodyLimitBytes(ctx, responseKey)
	responseMaxValueLock.Lock()
	currentResponseMaxValue = responseLimit
	responseMaxValueLock.Unlock()

	if err != nil {
		return err
	}
	return respErr
}

func (s *RedisStore) readBodyLimitBytes(ctx context.Context, key string) (int64, error) {
	if s == nil || s.client == nil {
		return redisBodyLimitBytes, nil
	}
	raw, err := s.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return redisBodyLimitBytes, nil
		}
		return redisBodyLimitBytes, fmt.Errorf("get redis key %s: %w", key, err)
	}

	limit, parseErr := parseBodyLimitBytes(raw)
	if parseErr != nil {
		return redisBodyLimitBytes, fmt.Errorf("parse redis key %s value %q: %w", key, raw, parseErr)
	}
	return limit, nil
}

// 用户态截断（已弃用）
func parseBodyLimitBytes(raw string) (int64, error) {
	value, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil {
		return redisBodyLimitBytes, err
	}
	if value <= 0 {
		return redisBodyLimitBytes, nil
	}
	if value <= 512 {
		value *= 1024
	}
	if value > redisBodyLimitBytes {
		value = redisBodyLimitBytes
	}
	return value, nil
}

func (s *RedisStore) RequestCaptureLimitBytes() int {
	requestMaxValueLock.RLock()
	defer requestMaxValueLock.RUnlock()
	if currentRequestMaxValue <= 0 {
		return redisBodyLimitBytes
	}
	return int(currentRequestMaxValue)
}

func (s *RedisStore) ResponseCaptureLimitBytes() int {
	responseMaxValueLock.RLock()
	defer responseMaxValueLock.RUnlock()
	if currentResponseMaxValue <= 0 {
		return redisBodyLimitBytes
	}
	return int(currentResponseMaxValue)
}

// 准备存储到redis的trace document
func prepareTraceForRedis(trace httptrace.TraceDocument) httptrace.TraceDocument {
	cloned := trace
	cloned.Request = prepareParsedMessageForRedis(trace.Request)
	cloned.Response = prepareParsedMessageForRedis(trace.Response)
	return cloned
}

func prepareParsedMessageForRedis(msg *httptrace.ParsedMessage) *httptrace.ParsedMessage {
	if msg == nil {
		return nil
	}
	cloned := *msg
	if cloned.BodySizeBytes == 0 {
		cloned.BodySizeBytes = len(cloned.Body)
	}
	return &cloned
}

func (s *RedisStore) Close() error {
	if s == nil || s.client == nil {
		return nil
	}
	return s.client.Close()
}
