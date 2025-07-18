//go:build !agent
// +build !agent

package app

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"

	"github.com/desertbit/grumble"
	"github.com/nicocha30/ligolo-ng/pkg/protocol"
)

func init() {
	App.AddCommand(&grumble.Command{
		Name: "download",
		Help: "download a file from the current agent",
		Args: func(a *grumble.Args) {
			a.String("src", "remote source path")
			a.String("dst", "local destination file")
		},
		Run: func(c *grumble.Context) error {
			src := c.Args.String("src")
			dst := c.Args.String("dst")

			agent, ok := AgentList[CurrentAgentID]
			if !ok || agent.Session == nil {
				return errors.New("no active agent (use `session` first)")
			}
			stream, err := agent.Session.Open()
			if err != nil {
				return err
			}
			defer stream.Close()

			enc := protocol.NewEncoder(stream)
			dec := protocol.NewDecoder(stream)

			req := &protocol.FileDownloadRequest{Path: src}
			if err := enc.Encode(req); err != nil {
				return err
			}
			if err := dec.Decode(); err != nil {
				return err
			}
			resp, ok := dec.Payload.(*protocol.FileDownloadResponse)
			if !ok {
				return errors.New("unexpected response type")
			}
			if resp.Err {
				return fmt.Errorf(resp.ErrString)
			}
			buf := make([]byte, base64.StdEncoding.DecodedLen(len(resp.Data)))
			n, err := base64.StdEncoding.Decode(buf, resp.Data)
			if err != nil {
				return err
			}
			return os.WriteFile(dst, buf[:n], 0644)
		},
	})
}
