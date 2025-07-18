//go:build !agent
// +build !agent

package app

import (
	"encoding/base64"
	"os"
	"strings"

	"github.com/desertbit/grumble"
	"github.com/nicocha30/ligolo-ng/pkg/protocol"
)

func init() {
	App.AddCommand(&grumble.Command{
		Name: "script",
		Help: "run a remote script (.ps1 or .sh) in memory",
		Args: func(a *grumble.Args) {
			a.String("file", "path to script")
			a.String("args", "script arguments", grumble.Default(""))
		},
		Run: func(c *grumble.Context) error {
			path := c.Args.String("file")
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			b64 := make([]byte, base64.StdEncoding.EncodedLen(len(raw)))
			base64.StdEncoding.Encode(b64, raw)

			lang := "sh"
			if strings.HasSuffix(strings.ToLower(path), ".ps1") {
				lang = "ps1"
			}

			req := &protocol.ScriptLoadRequest{
				Lang:   lang,
				Script: b64,
				Args:   c.Args.String("args"),
			}
			return sendRecvAndPrint(req)
		},
	})
}

