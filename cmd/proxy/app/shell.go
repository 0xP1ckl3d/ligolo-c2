//go:build !agent
// +build !agent

// Ligolo-ng ‑ shell command extension
// Copyright (C) 2025 Nicolas Chatelain (nicocha30)

package app

import (
	"errors"
	"fmt"
	"strings"

	"github.com/desertbit/grumble"
	"github.com/nicocha30/ligolo-ng/pkg/protocol"
)

func init() {
	App.AddCommand(&grumble.Command{
		Name: "shell",
		Help: "execute a single command on the current agent",
		Args: func(a *grumble.Args) {
			a.String("cmd", "command line to run (quote for spaces)")
		},
		Run: func(c *grumble.Context) error {
			/* ---- sanity checks ---- */
			agent, ok := AgentList[CurrentAgentID]
			if !ok || agent.Session == nil {
				return errors.New("no active agent ‑ use `session`")
			}

			cmdline := c.Args.String("cmd")
			if strings.TrimSpace(cmdline) == "" {
				return errors.New("empty command")
			}

			/* ---- open a new yamux stream ---- */
			stream, err := agent.Session.Open()
			if err != nil {
				return err
			}
			defer stream.Close()

			enc := protocol.NewEncoder(stream)
			dec := protocol.NewDecoder(stream)

			/* ---- send request ---- */
			req := &protocol.ShellRequestPacket{CmdLine: cmdline} // note the &
			if err := enc.Encode(req); err != nil {
			    return err
			}

			/* ---- wait for response ---- */
			if err := dec.Decode(); err != nil {
				return err
			}
			resp, ok := dec.Payload.(*protocol.ShellResponsePacket)
			if !ok {
				return errors.New("unexpected response type")
			}

			/* ---- display output ---- */
			fmt.Print(resp.Output)
			if resp.Err {
				fmt.Println("[remote command returned non‑zero]")
			}
			return nil
		},
	})
}

