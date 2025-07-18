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
		Name: "upload",
		Help: "upload a local file to the current agent",
		Args: func(a *grumble.Args) {
			a.String("src", "local source file")
			a.String("dst", "remote destination path")
		},
		Run: func(c *grumble.Context) error {
			src := c.Args.String("src")
			dst := c.Args.String("dst")

			data, err := os.ReadFile(src)
			if err != nil {
				return err
			}
			b64 := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
			base64.StdEncoding.Encode(b64, data)

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

			req := &protocol.FileUploadRequest{Path: dst, Data: b64}
			if err := enc.Encode(req); err != nil {
				return err
			}
			if err := dec.Decode(); err != nil {
				return err
			}
			resp, ok := dec.Payload.(*protocol.FileUploadResponse)
			if !ok {
				return errors.New("unexpected response type")
			}
			if resp.Err {
				return fmt.Errorf(resp.ErrString)
			}
			return nil
		},
	})
}
