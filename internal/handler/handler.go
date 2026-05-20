package handler

import (
	"bytes"
	"context"
	"fmt"
	"math/big"
	"os"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/rs/zerolog/log"

	"eventlistener/internal/config"
	"eventlistener/internal/db"
	"eventlistener/internal/listener"
)

type Processor struct {
	store     *db.Store
	contracts map[string]contractEntry // key: "chainID:lowercase_address"
	mu        sync.RWMutex
}

type contractEntry struct {
	cfg           config.ContractConfig
	abi           abi.ABI
	eventByTopic  map[common.Hash]abi.Event
	allowedEvents map[string]bool // empty = allow all
}

func NewProcessor(store *db.Store, chains []config.ChainConfig) (*Processor, error) {
	p := &Processor{
		store:     store,
		contracts: map[string]contractEntry{},
	}
	for _, ch := range chains {
		for _, c := range ch.Contracts {
			abiBytes, err := os.ReadFile(c.ABIPath)
			if err != nil {
				return nil, fmt.Errorf("read abi %s: %w", c.ABIPath, err)
			}
			parsed, err := abi.JSON(bytes.NewReader(abiBytes))
			if err != nil {
				return nil, fmt.Errorf("parse abi %s: %w", c.Name, err)
			}
			byTopic := map[common.Hash]abi.Event{}
			for _, ev := range parsed.Events {
				byTopic[ev.ID] = ev
			}
			allowed := map[string]bool{}
			for _, name := range c.Events {
				allowed[name] = true
			}
			addr := strings.ToLower(listener.NormalizeAddr(c.Address))
			key := fmt.Sprintf("%d:%s", ch.ChainID, addr)
			p.contracts[key] = contractEntry{
				cfg: c, abi: parsed, eventByTopic: byTopic, allowedEvents: allowed,
			}
			log.Info().
				Str("chain", ch.Name).
				Str("contract", c.Name).
				Str("address", addr).
				Int("events_in_abi", len(byTopic)).
				Strs("filter", c.Events).
				Msg("contract registered")
		}
	}
	return p, nil
}

func (p *Processor) Handle(ctx context.Context, chain config.ChainConfig, lg types.Log) error {
	key := fmt.Sprintf("%d:%s", chain.ChainID, strings.ToLower(lg.Address.Hex()))
	p.mu.RLock()
	entry, ok := p.contracts[key]
	p.mu.RUnlock()
	if !ok {
		return nil
	}
	if len(lg.Topics) == 0 {
		return nil
	}
	ev, ok := entry.eventByTopic[lg.Topics[0]]
	if !ok {
		log.Debug().Str("topic", lg.Topics[0].Hex()).Msg("unknown event topic")
		return nil
	}
	if len(entry.allowedEvents) > 0 && !entry.allowedEvents[ev.Name] {
		return nil
	}

	decoded := map[string]any{}

	if len(lg.Data) > 0 {
		if err := entry.abi.UnpackIntoMap(decoded, ev.Name, lg.Data); err != nil {
			return fmt.Errorf("unpack data for %s: %w", ev.Name, err)
		}
	}
	idx := 1
	for _, input := range ev.Inputs {
		if !input.Indexed {
			continue
		}
		if idx >= len(lg.Topics) {
			break
		}
		decoded[input.Name] = decodeTopic(input, lg.Topics[idx])
		idx++
	}
	for k, v := range decoded {
		decoded[k] = toJSONFriendly(v)
	}

	log.Info().
		Str("chain", chain.Name).
		Str("contract", entry.cfg.Name).
		Str("event", ev.Name).
		Uint64("block", lg.BlockNumber).
		Str("tx", lg.TxHash.Hex()).
		Interface("data", decoded).
		Msg("event")

	return p.store.SaveEvent(ctx, db.Event{
		ChainID:     chain.ChainID,
		Contract:    entry.cfg.Name,
		EventName:   ev.Name,
		BlockNumber: lg.BlockNumber,
		TxHash:      lg.TxHash.Hex(),
		LogIndex:    lg.Index,
		Data:        decoded,
	})
}

func decodeTopic(input abi.Argument, topic common.Hash) any {
	switch input.Type.T {
	case abi.AddressTy:
		return common.HexToAddress(topic.Hex()).Hex()
	case abi.IntTy, abi.UintTy:
		return new(big.Int).SetBytes(topic.Bytes())
	case abi.BoolTy:
		return topic[31] == 1
	default:
		// For dynamic types (string, bytes, arrays) Solidity stores keccak256(value)
		// in the topic, not the value itself. We return the hash hex.
		return topic.Hex()
	}
}

func toJSONFriendly(v any) any {
	switch x := v.(type) {
	case *big.Int:
		if x == nil {
			return nil
		}
		return x.String()
	case common.Address:
		return x.Hex()
	case common.Hash:
		return x.Hex()
	case []byte:
		return "0x" + common.Bytes2Hex(x)
	default:
		return v
	}
}
