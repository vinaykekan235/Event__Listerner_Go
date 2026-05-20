package db

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations.sql
var migrationsSQL string

type Store struct {
	pool *pgxpool.Pool
}

func New(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("pgx pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("ping: %w", err)
	}
	return &Store{pool: pool}, nil
}

func (s *Store) Close() { s.pool.Close() }

func (s *Store) Migrate(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, migrationsSQL)
	return err
}

type Event struct {
	ChainID     int64
	Contract    string
	EventName   string
	BlockNumber uint64
	TxHash      string
	LogIndex    uint
	Data        map[string]any
}

func (s *Store) SaveEvent(ctx context.Context, e Event) error {
	data, err := json.Marshal(e.Data)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO events (chain_id, contract, event_name, block_number, tx_hash, log_index, data)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (chain_id, tx_hash, log_index) DO NOTHING
	`, e.ChainID, e.Contract, e.EventName, e.BlockNumber, e.TxHash, e.LogIndex, data)
	return err
}

// GetCheckpoint returns (lastBlock, exists, error). exists=false means no row yet.
func (s *Store) GetCheckpoint(ctx context.Context, chainID int64) (uint64, bool, error) {
	var block uint64
	err := s.pool.QueryRow(ctx,
		`SELECT last_block FROM checkpoints WHERE chain_id = $1`, chainID,
	).Scan(&block)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, false, nil
		}
		return 0, false, err
	}
	return block, true, nil
}

func (s *Store) SaveCheckpoint(ctx context.Context, chainID int64, block uint64) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO checkpoints (chain_id, last_block) VALUES ($1, $2)
		ON CONFLICT (chain_id) DO UPDATE
		  SET last_block = EXCLUDED.last_block, updated_at = now()
		  WHERE checkpoints.last_block < EXCLUDED.last_block
	`, chainID, block)
	return err
}
