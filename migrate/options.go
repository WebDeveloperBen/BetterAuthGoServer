package migrate

import "log/slog"

// Config holds migration configuration.
type Config struct {
	plugins []Source
	logger  *slog.Logger
	dryRun  bool
}

func defaultConfig() Config {
	return Config{
		logger: slog.Default(),
	}
}

// Option configures the migration runner.
type Option func(*Config)

// WithPlugins adds plugin migration sources to run after core migrations.
// Plugins are sorted topologically based on their declared dependencies.
func WithPlugins(plugins ...Source) Option {
	return func(c *Config) {
		c.plugins = append(c.plugins, plugins...)
	}
}

// WithLogger sets a custom logger for migration output.
func WithLogger(logger *slog.Logger) Option {
	return func(c *Config) {
		c.logger = logger
	}
}

// WithDryRun enables dry-run mode which logs what would be executed
// without actually running migrations.
func WithDryRun(dryRun bool) Option {
	return func(c *Config) {
		c.dryRun = dryRun
	}
}
