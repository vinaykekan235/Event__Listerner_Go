package config

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Database DatabaseConfig `yaml:"database"`
	Chains   []ChainConfig  `yaml:"chains"`
}

type DatabaseConfig struct {
	DSN string `yaml:"dsn"`
}

type ChainConfig struct {
	Name           string           `yaml:"name"`
	ChainID        int64            `yaml:"chain_id"`
	RPCURL         string           `yaml:"rpc_url"`
	Confirmations  uint64           `yaml:"confirmations"`
	PollIntervalMS int              `yaml:"poll_interval_ms"`
	BlockBatchSize uint64           `yaml:"block_batch_size"`
	Contracts      []ContractConfig `yaml:"contracts"`
}

type ContractConfig struct {
	Name       string   `yaml:"name"`
	Address    string   `yaml:"address"`
	ABIPath    string   `yaml:"abi_path"`
	StartBlock uint64   `yaml:"start_block"`
	Events     []string `yaml:"events"` // optional whitelist; empty = all events
}

func Load(path string) (*Config, error) {
	_ = godotenv.Load()

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	expanded := os.ExpandEnv(string(raw))

	var c Config
	if err := yaml.Unmarshal([]byte(expanded), &c); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	if c.Database.DSN == "" {
		return nil, fmt.Errorf("database.dsn is empty (set DATABASE_URL in .env)")
	}
	if len(c.Chains) == 0 {
		return nil, fmt.Errorf("no chains configured")
	}
	return &c, nil
}
