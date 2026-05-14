package ipc

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
)

const socketPath = "/var/run/fenrir/fenrir.sock"

type Command struct {
	Action string            `json:"action"`
	Args   map[string]string `json:"args,omitempty"`
}

type CommandResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

// CommandHandler is a callback that processes a received command.
type CommandHandler func(cmd Command) CommandResponse

type LocalControlChannel struct {
	listener net.Listener
	handlers map[string]CommandHandler
}

func NewLocalControlChannel() *LocalControlChannel {
	return &LocalControlChannel{
		handlers: make(map[string]CommandHandler),
	}
}

// Register adds a handler for a named action (e.g., "status", "quarantine-list").
func (l *LocalControlChannel) Register(action string, handler CommandHandler) {
	l.handlers[strings.ToLower(action)] = handler
}

func (l *LocalControlChannel) Start() error {
	if err := os.MkdirAll("/var/run/fenrir", 0700); err != nil {
		return fmt.Errorf("create socket dir: %w", err)
	}
	// Remove stale socket
	os.Remove(socketPath)

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("listen unix socket: %w", err)
	}
	// Only root should access the control socket
	if err := os.Chmod(socketPath, 0600); err != nil {
		log.Printf("[IPC] chmod warning: %v", err)
	}

	l.listener = ln
	log.Printf("[IPC] LocalControlChannel listening on %s", socketPath)

	go l.accept()
	return nil
}

func (l *LocalControlChannel) Stop() {
	if l.listener != nil {
		l.listener.Close()
		os.Remove(socketPath)
	}
}

func (l *LocalControlChannel) accept() {
	for {
		conn, err := l.listener.Accept()
		if err != nil {
			return // listener was closed
		}
		go l.handle(conn)
	}
}

func (l *LocalControlChannel) handle(conn net.Conn) {
	defer conn.Close()

	var cmd Command
	if err := json.NewDecoder(conn).Decode(&cmd); err != nil {
		l.reply(conn, CommandResponse{Success: false, Message: "invalid JSON"})
		return
	}

	action := strings.ToLower(cmd.Action)
	handler, ok := l.handlers[action]
	if !ok {
		l.reply(conn, CommandResponse{Success: false, Message: fmt.Sprintf("unknown action: %s", action)})
		return
	}

	resp := handler(cmd)
	l.reply(conn, resp)
}

func (l *LocalControlChannel) reply(conn net.Conn, resp CommandResponse) {
	data, _ := json.Marshal(resp)
	conn.Write(append(data, '\n'))
}
