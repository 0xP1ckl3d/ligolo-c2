//go:build !agent
// +build !agent

package app

import (
	"encoding/base64"
	"os"

	"github.com/desertbit/grumble"
	"github.com/nicocha30/ligolo-ng/pkg/protocol"
)

func init() {
	App.AddCommand(&grumble.Command{
		Name: "loadasm",
		Help: "load a .NET assembly reflectively and call a static method",
		Args: func(a *grumble.Args) {
			a.String("dll", "assembly path")
			a.String("type", "Namespace.Type")
			a.String("method", "static method name")
			a.String("json", "JSON arg", grumble.Default("null"))
		},
		Run: func(c *grumble.Context) error {
			raw, err := os.ReadFile(c.Args.String("dll"))
			if err != nil {
				return err
			}
			b64 := make([]byte, base64.StdEncoding.EncodedLen(len(raw)))
			base64.StdEncoding.Encode(b64, raw)

			req := &protocol.AssemblyLoadRequest{
				DLL:     b64,
				Type:    c.Args.String("type"),
				Method:  c.Args.String("method"),
				JSONArg: c.Args.String("json"),
			}
			return sendRecvAndPrint(req)
		},
	})
}

