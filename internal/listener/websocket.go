package listener

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/rs/zerolog/log"

	"eventlistener/internal/config"
	"eventlistener/internal/db"
)

type WebSocket struct {
	chain config.ChainConfig
	store *db.Store
}

func NewWebSocket(chain config.ChainConfig, store *db.Store) *WebSocket {
	return &WebSocket{chain: chain, store: store}
}

func (w *WebSocket) Run(ctx context.Context, handle HandleFunc) error {
	for {
		err := w.runOnce(ctx, handle)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		log.Error().Err(err).Str("chain", w.chain.Name).Msg("ws listener crashed, retrying in 5s")
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

func (w *WebSocket) runOnce(ctx context.Context, handle HandleFunc) error {
	client, err := ethclient.DialContext(ctx, w.chain.RPCURL)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer client.Close()

	addresses := make([]common.Address, 0, len(w.chain.Contracts))
	var minStart uint64
	for i, c := range w.chain.Contracts {
		addresses = append(addresses, common.HexToAddress(NormalizeAddr(c.Address)))
		if i == 0 || c.StartBlock < minStart {
			minStart = c.StartBlock
		}
	}

	// Backfill from checkpoint -> head, then subscribe for live logs.
	// WebSocket subscriptions only deliver NEW logs after subscribe, so without
	// this catch-up step we'd miss everything that happened while the service was down.
	cp, ok, err := w.store.GetCheckpoint(ctx, w.chain.ChainID)
	if err != nil {
		return fmt.Errorf("checkpoint: %w", err)
	}
	cursor := minStart
	if ok && cp+1 > cursor {
		cursor = cp + 1
	}

	head, err := client.BlockNumber(ctx)
	if err != nil {
		return fmt.Errorf("block number: %w", err)
	}
	if head > w.chain.Confirmations {
		safe := head - w.chain.Confirmations
		if cursor <= safe {
			if err := w.backfill(ctx, client, addresses, cursor, safe, handle); err != nil {
				return fmt.Errorf("backfill: %w", err)
			}
		}
	}

	query := ethereum.FilterQuery{Addresses: addresses}
	logsCh := make(chan types.Log, 256)
	sub, err := client.SubscribeFilterLogs(ctx, query, logsCh)
	if err != nil {
		return fmt.Errorf("subscribe: %w", err)
	}
	defer sub.Unsubscribe()

	log.Info().Str("chain", w.chain.Name).Int("contracts", len(addresses)).Msg("subscribed (ws)")

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-sub.Err():
			return fmt.Errorf("subscription error: %w", err)
		case lg := <-logsCh:
			if err := handle(ctx, w.chain, lg); err != nil {
				log.Error().Err(err).Str("chain", w.chain.Name).Msg("handler failed")
				continue
			}
			if err := w.store.SaveCheckpoint(ctx, w.chain.ChainID, lg.BlockNumber); err != nil {
				log.Warn().Err(err).Msg("save checkpoint")
			}
		}
	}
}

func (w *WebSocket) backfill(ctx context.Context, client *ethclient.Client, addrs []common.Address, from, to uint64, handle HandleFunc) error {
	batch := w.chain.BlockBatchSize
	if batch == 0 {
		batch = 2000
	}
	log.Info().Str("chain", w.chain.Name).Uint64("from", from).Uint64("to", to).Msg("backfilling")
	for cursor := from; cursor <= to; {
		end := cursor + batch - 1
		if end > to {
			end = to
		}
		q := ethereum.FilterQuery{
			FromBlock: new(big.Int).SetUint64(cursor),
			ToBlock:   new(big.Int).SetUint64(end),
			Addresses: addrs,
		}
		logs, err := client.FilterLogs(ctx, q)
		if err != nil {
			return fmt.Errorf("filter %d-%d: %w", cursor, end, err)
		}
		for _, lg := range logs {
			if err := handle(ctx, w.chain, lg); err != nil {
				log.Error().Err(err).Msg("backfill handler")
			}
		}
		if err := w.store.SaveCheckpoint(ctx, w.chain.ChainID, end); err != nil {
			log.Warn().Err(err).Msg("save checkpoint")
		}
		cursor = end + 1
	}
	return nil
}
