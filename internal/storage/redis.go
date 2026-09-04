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
	// if err := s.client.LPush(ctx, "AAA-diaoge-trace", body).Err(); err != nil {
	// 	return fmt.Errorf("set redis key diaoge-trace: %w", err)
	// }
	// if err := s.client.Expire(ctx, "AAA-diaoge-trace", 24*time.Hour).Err(); err != nil {
	// 	return fmt.Errorf("expire redis key diaoge-trace: %w", err)
	// }
	return nil
}

// 启动body限制值同步线程，每30秒同步一次
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

// 同步redis中的body限制值到内存，每30秒同步一次
func (s *RedisStore) syncBodyLimitsOnce() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := s.syncRedisToMemory(ctx); err != nil {
		log.Printf("同步 Redis 正文上限失败：%v", err)
	}
}

// 同步redis到内存
func (s *RedisStore) syncRedisToMemory(ctx context.Context) error {
	requestLimit, err := s.readBodyLimitBytes(ctx, requestKey)
	requestMaxValueLock.RLock()
	oldRequestLimit := currentRequestMaxValue
	requestMaxValueLock.RUnlock()
	requestMaxValueLock.Lock()
	// 换算成字节
	currentRequestMaxValue = requestLimit
	requestMaxValueLock.Unlock()

	responseLimit, respErr := s.readBodyLimitBytes(ctx, responseKey)
	responseMaxValueLock.RLock()
	oldResponseLimit := currentResponseMaxValue
	responseMaxValueLock.RUnlock()
	responseMaxValueLock.Lock()
	currentResponseMaxValue = responseLimit
	responseMaxValueLock.Unlock()
	if requestLimit != oldRequestLimit || responseLimit != oldResponseLimit {
		log.Printf("Redis 正文上限已同步：request=%dB response=%dB", requestLimit, responseLimit)
	}

	if err != nil {
		return err
	}
	return respErr
}

// redis读取操作
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

// 解析redis中的body限制值，单位为kb、mb、gb。
// 默认不传单位按kb算，20MB以内按kb算，否则按实际单位算
// 超过256kb的值，改成默认值 256kb
func parseBodyLimitBytes(raw string) (int64, error) {
	text := strings.ToLower(strings.TrimSpace(raw))
	if text == "" {
		return redisBodyLimitBytes, fmt.Errorf("empty limit")
	}

	multiplier := int64(1)
	number := text
	switch {
	case strings.HasSuffix(text, "kib"):
		number, multiplier = strings.TrimSpace(strings.TrimSuffix(text, "kib")), 1024
	case strings.HasSuffix(text, "kb"):
		number, multiplier = strings.TrimSpace(strings.TrimSuffix(text, "kb")), 1024
	case strings.HasSuffix(text, "k"):
		number, multiplier = strings.TrimSpace(strings.TrimSuffix(text, "k")), 1024
	case strings.HasSuffix(text, "mib"):
		number, multiplier = strings.TrimSpace(strings.TrimSuffix(text, "mib")), 1024*1024
	case strings.HasSuffix(text, "mb"):
		number, multiplier = strings.TrimSpace(strings.TrimSuffix(text, "mb")), 1024*1024
	case strings.HasSuffix(text, "m"):
		number, multiplier = strings.TrimSpace(strings.TrimSuffix(text, "m")), 1024*1024
	case strings.HasSuffix(text, "gib"):
		number, multiplier = strings.TrimSpace(strings.TrimSuffix(text, "gib")), 1024*1024*1024
	case strings.HasSuffix(text, "gb"):
		number, multiplier = strings.TrimSpace(strings.TrimSuffix(text, "gb")), 1024*1024*1024
	case strings.HasSuffix(text, "g"):
		number, multiplier = strings.TrimSpace(strings.TrimSuffix(text, "g")), 1024*1024*1024
	}

	value, err := strconv.ParseInt(number, 10, 64)
	if err != nil {
		return redisBodyLimitBytes, err
	}
	if value <= 0 {
		return redisBodyLimitBytes, nil
	}
	// 20MB 以内不带单位按 KB 算，带单位按实际单位算
	if multiplier == 1 && value <= 20480 {
		value *= 1024
	}

	// 后续强行限制：为了防止采集参数值过大，导致内存溢出，值大于256kb ，改成默认值 256kb
	if value >= 256*1024 {
		return 256 * 1024, nil
	}

	if value > (int64(^uint32(0)) / multiplier) {
		return redisBodyLimitBytes, fmt.Errorf("limit exceeds uint32 maximum")
	}
	return value * multiplier, nil
}

// 用户态截断（已弃用）
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
