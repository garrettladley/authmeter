package authmeter

import (
	"errors"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/gofiber/storage/memory"
)

// Config defines the config for middleware.
type Config struct {
	// Next defines a function to skip middleware.
	// Optional. Default: nil
	Next func(*fiber.Ctx) bool

	// SuccessHandler defines a function which is executed for a valid key.
	// Optional. Default: nil
	SuccessHandler fiber.Handler

	// ErrorHandler defines a function which is executed for an invalid key.
	// It may be used to define a custom error.
	// Optional. Default: 401 Invalid or expired key
	ErrorHandler fiber.ErrorHandler

	LimiterConfig
	CreditConfig
	ScopeConfig
	KeyAuthConfig
}

type LimiterConfig struct {
	// Max number of recent connections during `Expiration` seconds before sending a 429 response
	//
	// Default: 5
	Max int

	// Expiration is the time on how long to keep records of requests in memory
	//
	// Default: 1 * time.Minute
	Expiration time.Duration

	// LimitReached is called when a request hits the limit
	//
	// Default: func(c *fiber.Ctx) error {
	//   return c.SendStatus(fiber.StatusTooManyRequests)
	// }
	LimitReached fiber.Handler

	// When set to true, requests with StatusCode >= 400 won't be counted.
	//
	// Default: false
	SkipFailedRequests bool

	// When set to true, requests with StatusCode < 400 won't be counted.
	//
	// Default: false
	SkipSuccessfulRequests bool

	// Store is used to store the state of the middleware
	//
	// Default: an in memory store for this process only
	Storage fiber.Storage

	// LimiterMiddleware is the struct that implements a limiter middleware.
	//
	// Default: a new Fixed Window Rate Limiter
	LimiterMiddleware limiter.LimiterHandler
}

func (l *LimiterConfig) into(kg func(*fiber.Ctx) string) limiter.Config {
	return limiter.Config{
		Max:                    l.Max,
		KeyGenerator:           kg,
		Expiration:             l.Expiration,
		LimitReached:           l.LimitReached,
		SkipFailedRequests:     l.SkipFailedRequests,
		SkipSuccessfulRequests: l.SkipSuccessfulRequests,
		Storage:                l.Storage,
		LimiterMiddleware:      l.LimiterMiddleware,
	}
}

type CreditConfig struct {
	Storage fiber.Storage

	// AllowDebt defines if a user is allowed to go into debt.
	// If cost > balance, the user will be denied access.
	AllowDebt bool

	GetCreditCost func(*fiber.Ctx, fiber.Storage) (int, error)

	GetCreditBalance func(fiber.Storage, string) (int, error)

	DeductCredits func(fiber.Storage, string, int) error
}

type ScopeConfig struct {
	Storage fiber.Storage

	Allow func(c *fiber.Ctx, storage fiber.Storage, key string) (bool, error)
}

type KeyAuthConfig struct {
	// KeyLookup is a string in the form of "<source>:<name>" that is used
	// to extract key from the request.
	// Optional. Default value "header:Authorization".
	// Possible values:
	// - "header:<name>"
	// - "query:<name>"
	// - "form:<name>"
	// - "param:<name>"
	// - "cookie:<name>"
	KeyLookup string

	// AuthScheme to be used in the Authorization header.
	// Optional. Default value "Bearer".
	AuthScheme string

	// Validator is a function to validate key.
	Validator func(*fiber.Ctx, string) (bool, error)

	// Context key to store the bearertoken from the token into context.
	// Optional. Default: "token".
	ContextKey interface{}
}

// ConfigDefault is the default config
var ConfigDefault = Config{
	SuccessHandler: func(c *fiber.Ctx) error {
		return c.Next()
	},
	ErrorHandler: func(c *fiber.Ctx, err error) error {
		if errors.Is(err, ErrMissingOrMalformedAPIKey) {
			return c.Status(fiber.StatusUnauthorized).SendString(err.Error())
		}
		return c.Status(fiber.StatusUnauthorized).SendString("Invalid or expired API Key")
	},
	KeyAuthConfig: KeyAuthConfig{
		KeyLookup:  "header:" + fiber.HeaderAuthorization,
		AuthScheme: "Bearer",
		ContextKey: "token",
	},

	// TODO
	CreditConfig: CreditConfig{},

	// TODO
	ScopeConfig: ScopeConfig{},

	// MARK: remove key generator field from limiter config?
	LimiterConfig: LimiterConfig{
		Max:        5,
		Expiration: 1 * time.Minute,
		LimitReached: func(c *fiber.Ctx) error {
			return c.SendStatus(fiber.StatusTooManyRequests)
		},
		SkipFailedRequests:     false,
		SkipSuccessfulRequests: false,
		LimiterMiddleware:      limiter.FixedWindow{},
	},
}

// Helper function to set default values
func configDefault(config ...Config) Config {
	// return default config if nothing provided
	if len(config) < 1 {
		return ConfigDefault
	}

	// override default config
	cfg := config[0]

	// set default values
	if cfg.SuccessHandler == nil {
		cfg.SuccessHandler = ConfigDefault.SuccessHandler
	}
	if cfg.ErrorHandler == nil {
		cfg.ErrorHandler = ConfigDefault.ErrorHandler
	}

	defaulters := []func(*Config){
		limiterDefault,
		creditDefault,
		keyAuthDefault,
	}

	for _, defaulter := range defaulters {
		defaulter(&cfg)
	}

	return cfg
}

func limiterDefault(cfg *Config) {
	if cfg.Next == nil {
		cfg.Next = ConfigDefault.Next
	}
	if cfg.Max <= 0 {
		cfg.Max = ConfigDefault.Max
	}
	if int(cfg.Expiration.Seconds()) <= 0 {
		cfg.Expiration = ConfigDefault.Expiration
	}
	if cfg.LimitReached == nil {
		cfg.LimitReached = ConfigDefault.LimitReached
	}
	if cfg.LimiterMiddleware == nil {
		cfg.LimiterMiddleware = ConfigDefault.LimiterMiddleware
	}
}

func creditDefault(cfg *Config) {
	if cfg.CreditConfig.Storage == nil {
		cfg.CreditConfig.Storage = memory.New()
	}
	if cfg.GetCreditCost == nil {
		panic("fiber: authmeter middleware requires a GetCreditCost function")
	}
	if cfg.GetCreditBalance == nil {
		panic("fiber: authmeter middleware requires a GetCreditBalance function")
	}
	if cfg.DeductCredits == nil {
		panic("fiber: authmeter middleware requires a DeductCredits function")
	}
}

func scopeDefault(cfg *Config) {
	if cfg.ScopeConfig.Storage == nil {
		cfg.ScopeConfig.Storage = memory.New()
	}
	if cfg.ScopeConfig.Allow == nil {
		panic("fiber: authmeter middleware requires a Allow function")
	}
}

func keyAuthDefault(cfg *Config) {
	if cfg.KeyLookup == "" {
		cfg.KeyLookup = ConfigDefault.KeyLookup
		// set AuthScheme as "Bearer" only if KeyLookup is set to default.
		if cfg.AuthScheme == "" {
			cfg.AuthScheme = ConfigDefault.AuthScheme
		}
	}
	if cfg.Validator == nil {
		panic("fiber: authmeter middleware requires a validator function")
	}
	if cfg.ContextKey == nil {
		cfg.ContextKey = ConfigDefault.ContextKey
	}
}
