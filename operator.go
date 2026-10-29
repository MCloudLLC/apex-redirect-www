package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"mc-apex-redirect/internal/domain"
	"mc-apex-redirect/internal/state"
)

func runOperator(args []string, out io.Writer) error {
	if len(args) < 2 {
		return fmt.Errorf("%s requires a subcommand", args[0])
	}
	path, limits, err := loadStateConfig()
	if err != nil {
		return err
	}
	store, err := state.Open(path, limits)
	if err != nil {
		return err
	}
	defer store.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	flags := flag.NewFlagSet(strings.Join(args[:2], " "), flag.ContinueOnError)
	flags.SetOutput(out)
	switch args[0] + " " + args[1] {
	case "block add":
		var block state.Block
		var expires string
		flags.StringVar(&block.Kind, "kind", "", "domain, wildcard, ip, or cidr")
		flags.StringVar(&block.Value, "value", "", "domain, pattern, address, or CIDR")
		flags.StringVar(&block.Reason, "reason", "", "private reason for the block")
		flags.StringVar(&block.Operator, "operator", "", "operator identifier")
		flags.StringVar(&expires, "expires", "", "optional duration, e.g. 24h")
		if err := parseOperatorFlags(flags, args[2:]); err != nil {
			return err
		}
		if expires != "" {
			duration, err := time.ParseDuration(expires)
			if err != nil || duration <= 0 {
				return errors.New("expires must be a positive duration")
			}
			block.ExpiresAt = time.Now().UTC().Add(duration)
		}
		id, err := store.AddBlock(ctx, block)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(out, "block %d added; redirect denial is active. For domain/wildcard blocks, retire cached TLS management using the documented Caddy workflow.\n", id)
		return err
	case "block list":
		if err := parseOperatorFlags(flags, args[2:]); err != nil {
			return err
		}
		blocks, err := store.ListBlocks(ctx)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(blocks)
	case "block remove":
		id := flags.Int64("id", 0, "block identifier")
		if err := parseOperatorFlags(flags, args[2:]); err != nil {
			return err
		}
		if *id <= 0 {
			return errors.New("id must be positive")
		}
		if err := store.RemoveBlock(ctx, *id); err != nil {
			return err
		}
		_, err = fmt.Fprintf(out, "block %d removed\n", *id)
		return err
	case "admissions list":
		if err := parseOperatorFlags(flags, args[2:]); err != nil {
			return err
		}
		admissions, err := store.ListAdmissions(ctx)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(admissions)
	case "admissions forget":
		name := flags.String("domain", "", "apex reservation to remove")
		if err := parseOperatorFlags(flags, args[2:]); err != nil {
			return err
		}
		apex, err := domain.Apex(*name)
		if err != nil {
			return err
		}
		if err := store.ForgetAdmission(ctx, apex); err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, "reservation removed; admission history and certificate storage are preserved")
		return err
	default:
		return fmt.Errorf("unknown operator command %q", strings.Join(args[:2], " "))
	}
}

func parseOperatorFlags(flags *flag.FlagSet, args []string) error {
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional argument")
	}
	return nil
}
