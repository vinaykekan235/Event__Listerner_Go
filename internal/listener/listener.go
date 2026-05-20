package listener

import (
	"context"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/core/types"

	"eventlistener/internal/config"
	"eventlistener/internal/db"
)

// HandleFunc is called for every log received from a chain.
type HandleFunc func(ctx context.Context, chain config.ChainConfig, lg types.Log) error

type Listener interface {
	Run(ctx context.Context, handle HandleFunc) error
}

// New picks WebSocket subscription or HTTP polling based on the URL scheme.
func New(chain config.ChainConfig, store *db.Store) (Listener, error) {
	if len(chain.Contracts) == 0 {
		return nil, fmt.Errorf("chain %s has no contracts configured", chain.Name)
	}
	switch {
	case strings.HasPrefix(chain.RPCURL, "ws://"), strings.HasPrefix(chain.RPCURL, "wss://"):
		return NewWebSocket(chain, store), nil
	case strings.HasPrefix(chain.RPCURL, "http://"), strings.HasPrefix(chain.RPCURL, "https://"):
		return NewPoller(chain, store), nil
	default:
		return nil, fmt.Errorf("unsupported rpc url scheme: %s", chain.RPCURL)
	}
}

// NormalizeAddr converts XDC's "xdc..." prefix to canonical "0x..." form.
// All other addresses pass through unchanged (still lowercased downstream).
func NormalizeAddr(a string) string {
	if len(a) >= 3 && (a[:3] == "xdc" || a[:3] == "XDC") {
		return "0x" + a[3:]
	}
	return a
}
