package listener

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/rs/zerolog/log"

	"eventlistener/internal/config"
	"eventlistener/internal/db"
)

type Poller struct {
	chain config.ChainConfig
	store *db.Store
}

func NewPoller(chain config.ChainConfig, store *db.Store) *Poller {
	return &Poller{chain: chain, store: store}
}

func (p *Poller) Run(ctx context.Context, handle HandleFunc) error {
	client, err := ethclient.DialContext(ctx, p.chain.RPCURL)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer client.Close()

	addresses := make([]common.Address, 0, len(p.chain.Contracts))
	var minStart uint64
	for i, c := range p.chain.Contracts {
		addresses = append(addresses, common.HexToAddress(NormalizeAddr(c.Address)))
		if i == 0 || c.StartBlock < minStart {
			minStart = c.StartBlock
		}
	}

	cp, ok, err := p.store.GetCheckpoint(ctx, p.chain.ChainID)
	if err != nil {
		return fmt.Errorf("checkpoint: %w", err)
	}
	cursor := minStart
	if ok && cp+1 > cursor {
		cursor = cp + 1
	}

	interval := time.Duration(p.chain.PollIntervalMS) * time.Millisecond
	if interval == 0 {
		interval = 5 * time.Second
	}
	batch := p.chain.BlockBatchSize
	if batch == 0 {
		batch = 1000
	}

	log.Info().
		Str("chain", p.chain.Name).
		Uint64("from_block", cursor).
		Dur("interval", interval).
		Msg("poller started")

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			head, err := client.BlockNumber(ctx)
			if err != nil {
				log.Warn().Err(err).Str("chain", p.chain.Name).Msg("get head")
				continue
			}
			if head < p.chain.Confirmations {
				continue
			}
			safe := head - p.chain.Confirmations
			if cursor > safe {
				continue
			}
			to := cursor + batch - 1
			if to > safe {
				to = safe
			}
			q := ethereum.FilterQuery{
				FromBlock: new(big.Int).SetUint64(cursor),
				ToBlock:   new(big.Int).SetUint64(to),
				Addresses: addresses,
			}
			logs, err := client.FilterLogs(ctx, q)
			if err != nil {
				log.Warn().Err(err).Uint64("from", cursor).Uint64("to", to).Msg("filter logs")
				continue
			}
			for _, lg := range logs {
				if err := handle(ctx, p.chain, lg); err != nil {
					log.Error().Err(err).Str("chain", p.chain.Name).Msg("handler failed")
				}
			}
			if err := p.store.SaveCheckpoint(ctx, p.chain.ChainID, to); err != nil {
				log.Warn().Err(err).Msg("save checkpoint")
			}
			cursor = to + 1
		}
	}
}
