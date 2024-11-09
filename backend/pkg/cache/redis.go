package cache

import (
    "fmt"
    "github.com/go-redis/redis/v8"
    "backend/config"
)

func InitRedis(cfg *config.RedisConfig) (*redis.Client, error) {
    client := redis.NewClient(&redis.Options{
        Addr:         fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
        Password:     cfg.Password,
        DB:           cfg.DB,
        PoolSize:     cfg.PoolSize,
        MinIdleConns: cfg.MinIdleConns,
    })

    // Test connection
    if err := client.Ping(client.Context()).Err(); err != nil {
        return nil, err
    }

    return client, nil
}