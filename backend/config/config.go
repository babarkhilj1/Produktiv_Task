package config

import (
    "time"
    "errors"
    "github.com/spf13/viper"
)

type Config struct {
    App        AppConfig
    Microsoft  MicrosoftConfig
    Keycloak   KeycloakConfig
    Database   DatabaseConfig
    Redis      RedisConfig
    Session    SessionConfig
}

type AppConfig struct {
    Name           string   `mapstructure:"name"`
    Version        string   `mapstructure:"version"`
    Env            string   `mapstructure:"env"`
    Port           int      `mapstructure:"port"`
    Debug          bool     `mapstructure:"debug"`
    AllowedOrigins []string `mapstructure:"allowed_origins"`
}

type MicrosoftConfig struct {
    TenantID     string   `mapstructure:"tenant_id"`
    ClientID     string   `mapstructure:"client_id"`
    ClientSecret string   `mapstructure:"client_secret"`
    RedirectURI  string   `mapstructure:"redirect_uri"`
    Authority    string   `mapstructure:"authority"`
    MetadataURL  string   `mapstructure:"metadata_url"`
    Scopes       []string `mapstructure:"scopes"`
}

type KeycloakConfig struct {
    ServerURL        string               `mapstructure:"server_url"`
    Realm           string               `mapstructure:"realm"`
    ClientID        string               `mapstructure:"client_id"`
    ClientSecret    string               `mapstructure:"client_secret"`
    PublicKey       string               `mapstructure:"public_key"`
    Admin           AdminConfig          `mapstructure:"admin"`
    IdentityProviders IdentityProviders  `mapstructure:"identity_providers"`
}

type AdminConfig struct {
    Username string `mapstructure:"username"`
    Password string `mapstructure:"password"`
    Realm    string `mapstructure:"realm"`
}

type IdentityProviders struct {
    Microsoft MicrosoftIDPConfig `mapstructure:"microsoft"`
}

type MicrosoftIDPConfig struct {
    Enabled                    bool     `mapstructure:"enabled"`
    ClientID                   string   `mapstructure:"client_id"`
    ClientSecret              string   `mapstructure:"client_secret"`
    DefaultScopes             []string `mapstructure:"default_scopes"`
    GUIOrder                  int      `mapstructure:"gui_order"`
    FirstBrokerLoginFlowAlias string   `mapstructure:"first_broker_login_flow_alias"`
    PostBrokerLoginFlowAlias  string   `mapstructure:"post_broker_login_flow_alias"`
}

type DatabaseConfig struct {
    Postgres PostgresConfig `mapstructure:"postgres"`
}

type PostgresConfig struct {
    Host          string        `mapstructure:"host"`
    Port          int           `mapstructure:"port"`
    Name          string        `mapstructure:"name"`
    User          string        `mapstructure:"user"`
    Password      string        `mapstructure:"password"`
    SSLMode       string        `mapstructure:"ssl_mode"`
    MaxOpenConns  int           `mapstructure:"max_open_conns"`
    MaxIdleConns  int           `mapstructure:"max_idle_conns"`
    ConnMaxLife   time.Duration `mapstructure:"conn_max_lifetime"`
}

type RedisConfig struct {
    Host          string        `mapstructure:"host"`
    Port          int           `mapstructure:"port"`
    Password      string        `mapstructure:"password"`
    DB            int           `mapstructure:"db"`
    PoolSize      int           `mapstructure:"pool_size"`
    MinIdleConns  int           `mapstructure:"min_idle_conns"`
    DialTimeout   time.Duration `mapstructure:"dial_timeout"`
    ReadTimeout   time.Duration `mapstructure:"read_timeout"`
    WriteTimeout  time.Duration `mapstructure:"write_timeout"`
    PoolTimeout   time.Duration `mapstructure:"pool_timeout"`
    IdleTimeout   time.Duration `mapstructure:"idle_timeout"`
    MaxRetries    int           `mapstructure:"max_retries"`
    MinRetryDelay time.Duration `mapstructure:"min_retry_delay"`
    MaxRetryDelay time.Duration `mapstructure:"max_retry_delay"`
}

type SessionConfig struct {
    TokenExpiry      time.Duration `mapstructure:"token_expiry"`
    CleanupInterval  time.Duration `mapstructure:"cleanup_interval"`
    MaxActiveSessions int           `mapstructure:"max_active_sessions"`
    TokenLength      int           `mapstructure:"token_length"`
    RefreshEnabled   bool          `mapstructure:"refresh_token_enabled"`
    RefreshExpiry    time.Duration `mapstructure:"refresh_token_expiry"`
}

func LoadConfig() (*Config, error) {
    viper.SetConfigName("config")
    viper.SetConfigType("yml")
    viper.AddConfigPath("./config")
    viper.AddConfigPath(".")

    // Set default values
    setDefaults()

    if err := viper.ReadInConfig(); err != nil {
        return nil, err
    }

    var config Config
    if err := viper.Unmarshal(&config); err != nil {
        return nil, err
    }

    // Validate configuration
    if err := validateConfig(&config); err != nil {
        return nil, err
    }

    return &config, nil
}

func setDefaults() {
    // App defaults
    viper.SetDefault("app.env", "development")
    viper.SetDefault("app.port", 8080)
    viper.SetDefault("app.debug", true)

    // Database defaults
    viper.SetDefault("database.postgres.max_open_conns", 25)
    viper.SetDefault("database.postgres.max_idle_conns", 5)
    viper.SetDefault("database.postgres.conn_max_lifetime", "15m")

    // Redis defaults
    viper.SetDefault("redis.pool_size", 10)
    viper.SetDefault("redis.min_idle_conns", 5)
    viper.SetDefault("redis.dial_timeout", "5s")
    viper.SetDefault("redis.read_timeout", "3s")
    viper.SetDefault("redis.write_timeout", "3s")
    viper.SetDefault("redis.pool_timeout", "4s")
    viper.SetDefault("redis.idle_timeout", "300s")
    viper.SetDefault("redis.max_retries", 3)

    // Session defaults
    viper.SetDefault("session.token_expiry", "24h")
    viper.SetDefault("session.cleanup_interval", "1h")
    viper.SetDefault("session.max_active_sessions", 5)
    viper.SetDefault("session.token_length", 32)
    viper.SetDefault("session.refresh_token_enabled", true)
    viper.SetDefault("session.refresh_token_expiry", "168h")

    // Keycloak defaults
    viper.SetDefault("keycloak.identity_providers.microsoft.enabled", true)
    viper.SetDefault("keycloak.identity_providers.microsoft.gui_order", 1)
    viper.SetDefault("keycloak.identity_providers.microsoft.first_broker_login_flow_alias", "first broker login")
    viper.SetDefault("keycloak.identity_providers.microsoft.post_broker_login_flow_alias", "post broker login")
}

func validateConfig(config *Config) error {
    // Required Microsoft configuration
    if config.Microsoft.TenantID == "" {
        return errors.New("microsoft tenant_id is required")
    }
    if config.Microsoft.ClientID == "" {
        return errors.New("microsoft client_id is required")
    }
    if config.Microsoft.ClientSecret == "" {
        return errors.New("microsoft client_secret is required")
    }

    // Required Keycloak configuration
    if config.Keycloak.ServerURL == "" {
        return errors.New("keycloak server_url is required")
    }
    if config.Keycloak.Realm == "" {
        return errors.New("keycloak realm is required")
    }
    if config.Keycloak.ClientID == "" {
        return errors.New("keycloak client_id is required")
    }
    if config.Keycloak.ClientSecret == "" {
        return errors.New("keycloak client_secret is required")
    }

    // Required Database configuration
    if config.Database.Postgres.Host == "" {
        return errors.New("database host is required")
    }
    if config.Database.Postgres.Name == "" {
        return errors.New("database name is required")
    }
    if config.Database.Postgres.User == "" {
        return errors.New("database user is required")
    }

    // Required Redis configuration
    if config.Redis.Host == "" {
        return errors.New("redis host is required")
    }

    return nil
}

// Helper function to get environment-specific configuration
func (c *Config) GetEnvConfig() interface{} {
    switch c.App.Env {
    case "development":
        return c.getDevelopmentConfig()
    case "production":
        return c.getProductionConfig()
    default:
        return c.getDevelopmentConfig()
    }
}

func (c *Config) getDevelopmentConfig() interface{} {
    return struct {
        Debug bool
        LogLevel string
    }{
        Debug: true,
        LogLevel: "debug",
    }
}

func (c *Config) getProductionConfig() interface{} {
    return struct {
        Debug bool
        LogLevel string
    }{
        Debug: false,
        LogLevel: "info",
    }
}