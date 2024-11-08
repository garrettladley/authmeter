package authmeter

import (
	"errors"
	"net/url"
	"strings"

	"github.com/gofiber/fiber/v2"
)

var (
	ErrAPIKeyNotAllowed = errors.New("api key not allowed to access this resource")
	ErrCreditsExceeded  = errors.New("credits exceeded")
	// When there is no request of the key thrown ErrMissingOrMalformedAPIKey
	ErrMissingOrMalformedAPIKey = errors.New("missing or malformed API Key")
)

const (
	query  = "query"
	form   = "form"
	param  = "param"
	cookie = "cookie"
)

func New(config ...Config) fiber.Handler {
	// Init config
	cfg := configDefault(config...)

	// Initialize
	parts := strings.Split(cfg.KeyLookup, ":")
	extractor := keyFromHeader(parts[1], cfg.AuthScheme)
	switch parts[0] {
	case query:
		extractor = keyFromQuery(parts[1])
	case form:
		extractor = keyFromForm(parts[1])
	case param:
		extractor = keyFromParam(parts[1])
	case cookie:
		extractor = keyFromCookie(parts[1])
	}

	infallibleExtractor := func(c *fiber.Ctx) string {
		key, err := extractor(c)
		if err != nil {
			return ""
		}
		return key
	}

	limiter := cfg.LimiterConfig.LimiterMiddleware.New(cfg.LimiterConfig.into(infallibleExtractor))

	return func(c *fiber.Ctx) error {
		if cfg.Next != nil && cfg.Next(c) {
			return c.Next()
		}

		if err := limiter(c); err != nil {
			return cfg.ErrorHandler(c, err)
		}

		key, err := extractor(c)
		if err != nil {
			return cfg.ErrorHandler(c, err)
		}

		valid, err := cfg.Validator(c, key)
		if err != nil {
			return cfg.ErrorHandler(c, err)
		}
		if valid {
			c.Locals(cfg.ContextKey, key)
		}

		allowed, err := cfg.Allow(c, cfg.ScopeConfig.Storage, key)
		if err != nil {
			return cfg.ErrorHandler(c, err)
		}
		if !allowed {
			return cfg.ErrorHandler(c, ErrAPIKeyNotAllowed)
		}

		cost, err := cfg.GetCreditCost(c, cfg.CreditConfig.Storage)
		if err != nil {
			return cfg.ErrorHandler(c, err)
		}

		balance, err := cfg.GetCreditBalance(cfg.CreditConfig.Storage, key)
		if err != nil {
			return cfg.ErrorHandler(c, err)
		}

		if !cfg.AllowDebt && (balance < 0 || balance < cost) {
			return cfg.ErrorHandler(c, ErrCreditsExceeded)
		}

		if err := cfg.DeductCredits(cfg.CreditConfig.Storage, key, cost); err != nil {
			return cfg.ErrorHandler(c, err)
		}

		return cfg.SuccessHandler(c)
	}
}

// keyFromHeader returns a function that extracts api key from the request header.
func keyFromHeader(header, authScheme string) func(c *fiber.Ctx) (string, error) {
	return func(c *fiber.Ctx) (string, error) {
		auth := c.Get(header)
		l := len(authScheme)
		if len(auth) > 0 && l == 0 {
			return auth, nil
		}
		if len(auth) > l+1 && auth[:l] == authScheme {
			return auth[l+1:], nil
		}
		return "", ErrMissingOrMalformedAPIKey
	}
}

// keyFromQuery returns a function that extracts api key from the query string.
func keyFromQuery(param string) func(c *fiber.Ctx) (string, error) {
	return func(c *fiber.Ctx) (string, error) {
		key := c.Query(param)
		if key == "" {
			return "", ErrMissingOrMalformedAPIKey
		}
		return key, nil
	}
}

// keyFromForm returns a function that extracts api key from the form.
func keyFromForm(param string) func(c *fiber.Ctx) (string, error) {
	return func(c *fiber.Ctx) (string, error) {
		key := c.FormValue(param)
		if key == "" {
			return "", ErrMissingOrMalformedAPIKey
		}
		return key, nil
	}
}

// keyFromParam returns a function that extracts api key from the url param string.
func keyFromParam(param string) func(c *fiber.Ctx) (string, error) {
	return func(c *fiber.Ctx) (string, error) {
		key, err := url.PathUnescape(c.Params(param))
		if err != nil {
			return "", ErrMissingOrMalformedAPIKey
		}
		return key, nil
	}
}

// keyFromCookie returns a function that extracts api key from the named cookie.
func keyFromCookie(name string) func(c *fiber.Ctx) (string, error) {
	return func(c *fiber.Ctx) (string, error) {
		key := c.Cookies(name)
		if key == "" {
			return "", ErrMissingOrMalformedAPIKey
		}
		return key, nil
	}
}
