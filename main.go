package main

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"eventlistener/internal/config"
	"eventlistener/internal/db"
	"eventlistener/internal/handler"
	"eventlistener/internal/listener"
)

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "15:04:05"})

	cfg, err := config.Load("config.yaml")
	if err != nil {
		log.Fatal().Err(err).Msg("load config")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	store, err := db.New(ctx, cfg.Database.DSN)
	if err != nil {
		log.Fatal().Err(err).Msg("connect db")
	}
	defer store.Close()

	if err := store.Migrate(ctx); err != nil {
		log.Fatal().Err(err).Msg("migrate db")
	}
	log.Info().Msg("db ready")

	proc, err := handler.NewProcessor(store, cfg.Chains)
	if err != nil {
		log.Fatal().Err(err).Msg("init processor")
	}

	var wg sync.WaitGroup
	for _, chain := range cfg.Chains {
		chain := chain
		l, err := listener.New(chain, store)
		if err != nil {
			log.Fatal().Err(err).Str("chain", chain.Name).Msg("create listener")
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := l.Run(ctx, proc.Handle); err != nil && ctx.Err() == nil {
				log.Error().Err(err).Str("chain", chain.Name).Msg("listener stopped")
			}
		}()
	}

	sigC := make(chan os.Signal, 1)
	signal.Notify(sigC, syscall.SIGINT, syscall.SIGTERM)
	<-sigC
	log.Info().Msg("shutdown signal received")
	cancel()
	wg.Wait()
	log.Info().Msg("bye")
}
