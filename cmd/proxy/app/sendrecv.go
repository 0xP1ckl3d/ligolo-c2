package app

import (
	"errors"
	"fmt"

	"github.com/nicocha30/ligolo-ng/pkg/protocol"
)

// sendRecvAndPrint opens a yamux stream on the current agent, sends `req`,
// waits for the response, and prints output to the console.
func sendRecvAndPrint(req interface{}) error {
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

	if err = enc.Encode(req); err != nil {
		return err
	}
	if err = dec.Decode(); err != nil {
		return err
	}

	switch v := dec.Payload.(type) {
	case *protocol.ScriptLoadResponse:
		fmt.Print(v.Output)
	case *protocol.AssemblyLoadResponse:
		fmt.Print(v.Return)
	default:
		return errors.New("unexpected response type")
	}
	return nil
}

