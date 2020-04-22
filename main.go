package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/google/uuid"
	"github.com/kennylevinsen/sshmux"
	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"
)

type client struct {
	sshConn        ssh.Conn
	address        string
	name           string
	id             uuid.UUID
	connectionTime time.Time

	lastPingLock sync.Mutex
	lastPingTime time.Time
}

type user struct {
	PublicKey string `json:"publicKey"`
	Name      string `json:"name"`
}

type server struct {
	users     []*sshmux.User
	nodeUsers []*sshmux.User

	sshConfig *ssh.ServerConfig

	nodeLock sync.Mutex
	nodes    []*client

	anyNode   bool
	anyMaster bool

	nodeKeepAlive time.Duration

	clientWaiter *sync.Cond
}

func (s *server) auth(c ssh.ConnMetadata, key ssh.PublicKey) (*sshmux.User, error) {
	if s.anyMaster {
		return nil, nil
	}

	t := key.Type()
	k := key.Marshal()
	for i := range s.users {
		candidate := s.users[i].PublicKey
		if t == candidate.Type() && bytes.Compare(k, candidate.Marshal()) == 0 {
			return s.users[i], nil
		}
	}

	log.Printf("%s: access denied (username: %s)", c.RemoteAddr(), c.User())
	return nil, errors.New("access denied")
}

func (s *server) nodeAuth(c ssh.ConnMetadata, key ssh.PublicKey) (*sshmux.User, error) {
	if s.anyNode {
		return nil, nil
	}

	t := key.Type()
	k := key.Marshal()
	for i := range s.nodeUsers {
		candidate := s.nodeUsers[i].PublicKey
		if t == candidate.Type() && bytes.Compare(k, candidate.Marshal()) == 0 {
			return s.nodeUsers[i], nil
		}
	}

	log.Printf("%s: access denied (username: %s)", c.RemoteAddr(), c.User())
	return nil, errors.New("access denied")
}

func (s *server) setup(session *sshmux.Session) error {
	var username string
	if session.User != nil {
		username = session.User.Name
	} else {
		username = "unknown user"
	}
	log.Printf("%s: %s authorized (username: %s)", session.Conn.RemoteAddr(), username, session.Conn.User())

	s.nodeLock.Lock()
	defer s.nodeLock.Unlock()
	for _, c := range s.nodes {
		session.Remotes = append(session.Remotes, &sshmux.Remote{
			Names:       []string{c.id.String(), c.id.String() + ":22", c.sshConn.RemoteAddr().String(), c.sshConn.User(), c.sshConn.User() + ":22"},
			Description: fmt.Sprintf("%s (%s, %s)", c.id.String(), c.sshConn.User(), c.sshConn.RemoteAddr().String()),
			Address:     c.id.String() + ":22",
		})
	}
	return nil
}

func (s *server) interactive(comm io.ReadWriter, session *sshmux.Session) (*sshmux.Remote, error) {
	fmt.Fprintf(comm, "Welcome to sshfleet, %s\r\n\r\n", session.Conn.User())
	fmt.Fprintf(comm, "%d servers connected at the current time.\r\n\r\n", len(s.nodes))
	fmt.Fprintf(comm, "Type 'help' to see available commands\r\n")

	// Beware, nasty input parsing loop
	for {
		b := make([]byte, 1)
		var (
			user    string
			n       int
			err     error
			esc     []byte
			history [][]byte
		)
		history = append(history, []byte("> "))
		historyPos := len(history) - 1

		fmt.Fprintf(comm, "\r%s", history[historyPos])
		for {
			if err != nil {
				return nil, err
			}
			n, err = comm.Read(b)
			if n == 1 {
				ol := len(history[historyPos])

				// Escape codes (arrow up/down for history)
				if esc != nil {
					esc = append(esc, b[0])
					if len(esc) >= 2 {
						if esc[1] == 91 {
						} else {
							esc = nil
							continue
						}
					}
					if len(esc) >= 3 {
						switch esc[2] {
						case 65:
							if historyPos != 0 {
								historyPos -= 1
							}
						case 66:
							if historyPos < len(history)-1 {
								historyPos++
							}
						}
						esc = nil
						goto print
					}
					continue
				}
				switch b[0] {
				case 27:
					esc = []byte{27}
					continue
				case 0x7F, 0x08:
					if len(history[historyPos]) > 2 {
						history[historyPos] = history[historyPos][0 : len(history[historyPos])-1]
					}
				case '\r':
					fmt.Fprintf(comm, "\r\n")

					s.nodeLock.Lock()
					nodes := make([]*client, len(s.nodes))
					copy(nodes, s.nodes)
					s.nodeLock.Unlock()

					sort.Slice(nodes, func(i, j int) bool {
						if nodes[i].name == "" && nodes[j].name == "" {
							return bytes.Compare(nodes[i].id[:], nodes[j].id[:]) == -1
						}
						if nodes[i].name == "" {
							return true
						} else if nodes[j].name == "" {
							return false
						}

						return nodes[i].name < nodes[j].name
					})

					input := string(history[historyPos])[2:]
					sp := strings.Split(input, " ")
					switch sp[0] {
					case "":
					case "u", "user", "username":
						if len(sp) != 2 {
							fmt.Fprintf(comm, "error: command expects username as second parameter\r\n")
							goto addhistory
						}
						user = sp[1]
						fmt.Fprintf(comm, "username set to %s\r\n", user)
					case "l", "list":
						for i, v := range nodes {
							v.lastPingLock.Lock()
							t := v.lastPingTime
							v.lastPingLock.Unlock()
							fmt.Fprintf(comm, "    [%d] id: %s\r\n", i, v.id.String())
							fmt.Fprintf(comm, "        name: %s\r\n", v.sshConn.User())
							fmt.Fprintf(comm, "        addr: %s\r\n", v.sshConn.RemoteAddr().String())
							fmt.Fprintf(comm, "        connected: %s\r\n", v.connectionTime.String())
							fmt.Fprintf(comm, "        lastPing: %s\r\n\r\n", t.String())
						}
					case "c", "connect":
						if len(sp) != 2 {
							fmt.Fprintf(comm, "error: command expects server as second parameter\r\n")
							goto addhistory
						}
						num, err := strconv.ParseInt(sp[1], 10, 64)
						isNum := err == nil
						for idx, n := range nodes {
							if n.name == sp[1] || n.id.String() == sp[1] || (isNum && num == int64(idx)) {
								return &sshmux.Remote{
									Address: n.id.String() + ":22",
								}, nil
							}
						}

						fmt.Fprintf(comm, "No such server. Please try again\r\n")
					case "k", "kill":
						if len(sp) != 2 {
							fmt.Fprintf(comm, "error: command expects server as second parameter\r\n")
							goto addhistory
						}
						var c *client

						num, err := strconv.ParseInt(sp[1], 10, 64)
						isNum := err == nil
						for idx, n := range nodes {
							if n.name == input || n.id.String() == input || (isNum && num == int64(idx)) {
								c = n
								break
							}
						}

						if c == nil {
							fmt.Fprintf(comm, "No such server. Please try again\r\n")
						} else {
							fmt.Fprintf(comm, "Kicking %s\r\n", c.id.String())
							c.sshConn.Close()
						}
					case "m", "monitor":
						now := time.Now()
						fmt.Fprintf(comm, "Waiting for new connections\r\n")
						s.clientWaiter.L.Lock()
						s.clientWaiter.Wait()
						s.clientWaiter.L.Unlock()
						fmt.Fprintf(comm, "New connections received\r\n")

						s.nodeLock.Lock()
						nodes := make([]*client, len(s.nodes))
						copy(nodes, s.nodes)
						s.nodeLock.Unlock()

						sort.Slice(nodes, func(i, j int) bool {
							if nodes[i].name == "" && nodes[j].name == "" {
								return bytes.Compare(nodes[i].id[:], nodes[j].id[:]) == -1
							}
							if nodes[i].name == "" {
								return true
							} else if nodes[j].name == "" {
								return false
							}

							return nodes[i].name < nodes[j].name
						})
						newNodes := make([]*client, 0, len(nodes))
						for _, n := range nodes {
							if n.connectionTime.After(now) {
								newNodes = append(newNodes, n)
							}
						}
						for i, v := range newNodes {
							v.lastPingLock.Lock()
							t := v.lastPingTime
							v.lastPingLock.Unlock()
							fmt.Fprintf(comm, "    [%d] id: %s\r\n", i, v.id.String())
							fmt.Fprintf(comm, "        name: %s\r\n", v.sshConn.User())
							fmt.Fprintf(comm, "        addr: %s\r\n", v.sshConn.RemoteAddr().String())
							fmt.Fprintf(comm, "        connected: %s\r\n", v.connectionTime.String())
							fmt.Fprintf(comm, "        lastPing: %s\r\n\r\n", t.String())
						}
					case "h", "help":
						fmt.Fprintf(comm, "Available commands:\r\n")
						fmt.Fprintf(comm, "   u, user, username : Set username to the specified string\r\n")
						fmt.Fprintf(comm, "   l, list           : List known nodes\r\n")
						fmt.Fprintf(comm, "   c, connect        : Connect to the specified node\r\n")
						fmt.Fprintf(comm, "   k, kill           : Kill the specified node connection\r\n")
						fmt.Fprintf(comm, "   m, monitor        : Monitor client connections\r\n")
						fmt.Fprintf(comm, "   q, quit           : Disconnect\r\n")
					case "q", "quit":
						fmt.Fprintf(comm, "\r\nGoodbye\r\n")
						return nil, errors.New("user terminated session")
					default:
						fmt.Fprintf(comm, "Unknown command: %s\r\n", sp[0])
					}

				addhistory:
					if historyPos != len(history)-1 {
						history = append(history, history[historyPos])
					}
					history = append(history, []byte("> "))
					if len(history) > 100 {
						history = history[len(history)-100 : len(history)-1]
					}
					historyPos = len(history) - 1
					fmt.Fprintf(comm, "\r%s", history[historyPos])
					continue
				case 0x04, 0x03:
					fmt.Fprintf(comm, "\r\nGoodbye\r\n")
					return nil, errors.New("user terminated session")
				default:
					history[historyPos] = append(history[historyPos], b[0])
				}
			print:
				fmt.Fprintf(comm, "\r%s", history[historyPos])
				if ol > len(history[historyPos]) {
					padding := ""
					for i := ol; i > len(history[historyPos]); i-- {
						padding += " "
					}
					padding += fmt.Sprintf("\033[%dD", ol-len(history[historyPos]))
					fmt.Fprintf(comm, "%s", padding)
				}
			}
		}
	}
}

func (s *server) dialer(network, address string) (net.Conn, error) {
	log.Printf("Asking for %s %s", network, address)
	if network != "tcp" {
		return nil, fmt.Errorf("unknown network %s", network)
	}

	var c *client
	s.nodeLock.Lock()
	for _, node := range s.nodes {
		if address == (node.id.String() + ":22") {
			c = node
			break
		}
	}
	s.nodeLock.Unlock()
	if c == nil {
		return nil, fmt.Errorf("unknown node")
	}

	return s.connectTo(c.sshConn)
}

type fakeAddr struct{}

func (fakeAddr) Network() string { return "tcp" }
func (fakeAddr) String() string  { return "" }

type sshSortaConn struct {
	net.Conn
	sshChannel ssh.Channel
}

func (s *sshSortaConn) Read(data []byte) (int, error)  { return s.sshChannel.Read(data) }
func (s *sshSortaConn) Write(data []byte) (int, error) { return s.sshChannel.Write(data) }
func (s *sshSortaConn) Close() error                   { return s.sshChannel.Close() }
func (sshSortaConn) RemoteAddr() net.Addr              { return fakeAddr{} }
func (sshSortaConn) LocalAddr() net.Addr               { return fakeAddr{} }

// https://tools.ietf.org/html/rfc4254
type channelOpenForwardMsg struct {
	RAddr string
	RPort uint32
	LAddr string
	LPort uint32
}

func (s *server) connectTo(sshconn ssh.Conn) (net.Conn, error) {
	log.Printf("Connecting to node")
	ch, reqs, err := sshconn.OpenChannel("forwarded-tcpip", ssh.Marshal(
		channelOpenForwardMsg{
			RAddr: "sshfleet",
			RPort: 22,
			LAddr: "sshfleet",
			LPort: 22,
		}))
	if err != nil {
		log.Printf("connection failed: %+v", err)
		return nil, err
	}

	go ssh.DiscardRequests(reqs)

	return &sshSortaConn{sshChannel: ch}, nil
}

// https://tools.ietf.org/html/rfc4254
type forwardTcpMsg struct {
	Addr string
	Port uint32
}

func (s *server) NodeAuth(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	k := key.Marshal()
	t := key.Type()
	perm := &ssh.Permissions{
		Extensions: map[string]string{
			"pubKey":     string(k),
			"pubKeyType": t,
		},
	}

	_, err := s.nodeAuth(conn, key)
	if err == nil {
		return perm, nil
	}

	return nil, err
}

type publicKey struct {
	publicKey     []byte
	publicKeyType string
}

func (p *publicKey) Marshal() []byte {
	b := make([]byte, len(p.publicKey))
	copy(b, p.publicKey)
	return b
}

func (p *publicKey) Type() string {
	return p.publicKeyType
}

func (p *publicKey) Verify([]byte, *ssh.Signature) error {
	return errors.New("verify not implemented")
}

func (s *server) HandleConn(c net.Conn) error {
	sshConn, chans, reqs, err := ssh.NewServerConn(c, s.sshConfig)
	if err != nil {
		c.Close()
		return err
	}
	defer sshConn.Close()

	if !s.anyNode && (sshConn.Permissions == nil || sshConn.Permissions.Extensions == nil) {
		return fmt.Errorf("no permissions")
	}

	cl := &client{
		sshConn:        sshConn,
		address:        c.RemoteAddr().String(),
		name:           sshConn.User(),
		id:             uuid.New(),
		connectionTime: time.Now(),
		lastPingTime:   time.Now(),
	}

	s.nodeLock.Lock()
	s.nodes = append(s.nodes, cl)
	s.nodeLock.Unlock()

	s.clientWaiter.Broadcast()

	go func() {
		for req := range reqs {
			log.Printf("Request from %v: %s", cl.id, req.Type)
			switch req.Type {
			case "tcpip-forward":
				var msg forwardTcpMsg
				ssh.Unmarshal(req.Payload, &msg)
				if req.WantReply {
					req.Reply(msg.Addr == "sshfleet" && msg.Port == 22, []byte{})
				}
			case "keepalive@openssh.com":
				if req.WantReply {
					req.Reply(true, []byte{})
				}
			default:
				req.Reply(false, []byte{})
			}
		}
	}()

	go func() {
		for newChannel := range chans {
			log.Printf("Channel from %v: %s", cl.id, newChannel.ChannelType())
			newChannel.Reject(ssh.UnknownChannelType, "connection flow not supported by sshfleet")
		}
	}()

	if s.nodeKeepAlive > 0 {
		go func() {
			ticker := time.NewTicker(s.nodeKeepAlive)
			for range ticker.C {
				_, _, err := sshConn.SendRequest("keepalive@sshfleet", true, nil)
				if err != nil {
					sshConn.Close()
					break
				}

				cl.lastPingLock.Lock()
				cl.lastPingTime = time.Now()
				cl.lastPingLock.Unlock()
			}
		}()

		if tc, ok := c.(*net.TCPConn); ok {
			tc.SetKeepAlivePeriod(s.nodeKeepAlive)
			tc.SetKeepAlive(true)
		}
	}

	err = sshConn.Wait()

	s.nodeLock.Lock()
	for i := 0; i < len(s.nodes); i++ {
		if s.nodes[i] == cl {
			s.nodes = append(s.nodes[:i], s.nodes[i+1:]...)
			break
		}
	}
	s.nodeLock.Unlock()
	return err
}

func (s *server) Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}

		go s.HandleConn(conn)
	}
}

var configFile = flag.String("config", "", "User-supplied configuration file to use")

func parseUsers(key string) ([]*sshmux.User, error) {
	var users []*sshmux.User
	us := make([]user, 0)
	err := viper.UnmarshalKey(key, &us)
	if err != nil {
		return nil, err
	}
	for _, u := range us {
		encoded, err := base64.StdEncoding.DecodeString(u.PublicKey)
		if err != nil {
			return nil, errors.New("Could not decode key: " + u.Name)
		}

		pk, err := ssh.ParsePublicKey([]byte(encoded))
		if err != nil {
			return nil, errors.New(err.Error() + " for " + u.Name)
		}
		u := &sshmux.User{
			PublicKey: pk,
			Name:      u.Name,
		}
		users = append(users, u)
	}
	return users, nil
}

func main() {
	flag.Parse()
	viper.SetDefault("address", ":2200")
	viper.SetDefault("nodeAddress", ":2201")
	viper.SetDefault("hostkey", "hostkey")
	viper.SetDefault("authkeys", "authkeys")
	viper.SetDefault("anyNode", false)
	viper.SetDefault("anyMaster", false)
	viper.SetDefault("nodeKeepAlive", 30)

	viper.SetConfigName("sshfleet")
	viper.AddConfigPath(".")
	viper.AddConfigPath("$HOME/.sshfleet")
	viper.AddConfigPath("/etc/sshfleet/")

	viper.SetConfigFile(*configFile)

	err := viper.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("Error parsing the config file: %s\n", err))
	}
	log.Printf("Config File used: %s", viper.ConfigFileUsed())

	users, err := parseUsers("users")
	if err != nil {
		panic(fmt.Errorf("Error parsing the config file hosts list: %s\n", err))
	}

	nodeUsers, err := parseUsers("nodeUsers")
	if err != nil {
		panic(fmt.Errorf("Error parsing the config file hosts list: %s\n", err))
	}

	hostSigner, err := ssh.ParsePrivateKey([]byte(viper.GetString("hostkey")))
	if err != nil {
		panic(err)
	}

	fleetServer := server{
		users:         users,
		nodeUsers:     nodeUsers,
		anyNode:       viper.GetBool("anyNode"),
		anyMaster:     viper.GetBool("anyMaster"),
		nodeKeepAlive: time.Duration(viper.GetInt("nodeKeepAlive")) * time.Second,
		clientWaiter:  &sync.Cond{L: &sync.Mutex{}},
	}

	fleetServer.sshConfig = &ssh.ServerConfig{
		PublicKeyCallback: fleetServer.NodeAuth,
	}
	if viper.GetBool("anyNode") {
		fleetServer.sshConfig.NoClientAuth = true
	}
	fleetServer.sshConfig.AddHostKey(hostSigner)

	viper.WatchConfig()
	viper.OnConfigChange(func(e fsnotify.Event) {
		log.Println("Config file changed:", e.Name)
		if u, err := parseUsers("users"); err != nil {
			log.Printf("Error parsing the config file users list: %s\n"+
				"Keeping current users list", err)
		} else {
			fleetServer.users = u
		}
		if u, err := parseUsers("nodeUsers"); err != nil {
			log.Printf("Error parsing the config file node users list: %s\n"+
				"Keeping current users list", err)
		} else {
			fleetServer.nodeUsers = u
		}
		fleetServer.anyMaster = viper.GetBool("anyMaster")
		fleetServer.nodeKeepAlive = time.Duration(viper.GetInt("nodeKeepAlive")) * time.Second
	})

	// sshmux setup
	server := sshmux.New(hostSigner, fleetServer.auth, fleetServer.setup)
	server.Selected = func(session *sshmux.Session, remote string) error {
		var username string
		if session.User != nil {
			username = session.User.Name
		} else {
			username = "unknown user"
		}
		log.Printf("%s: %s connecting to %s", session.Conn.RemoteAddr(), username, remote)
		return nil
	}
	server.Dialer = fleetServer.dialer
	server.Interactive = fleetServer.interactive

	// Set up listener
	l1, err := net.Listen("tcp", viper.GetString("address"))
	if err != nil {
		panic(err)
	}
	l2, err := net.Listen("tcp", viper.GetString("nodeAddress"))
	if err != nil {
		panic(err)
	}

	go server.Serve(l1)
	fleetServer.Serve(l2)
}
