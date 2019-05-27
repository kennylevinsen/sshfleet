package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/kennylevinsen/sshmux"
	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"
	"github.com/google/uuid"
)

type Client struct {
	sshConn ssh.Conn
	address string
	name string
	id uuid.UUID
}

type User struct {
	PublicKey string `json:"publicKey"`
	Name      string `json:"name"`
}

type Server struct {
	users []*sshmux.User
	nodeUsers []*sshmux.User

	sshConfig *ssh.ServerConfig

	nodeLock sync.Mutex
	nodes []*Client

	anyNode bool
	anyMaster bool

	nodeKeepAlive time.Duration
}

func (s *Server) auth(c ssh.ConnMetadata, key ssh.PublicKey) (*sshmux.User, error) {
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

func (s *Server) nodeAuth(c ssh.ConnMetadata, key ssh.PublicKey) (*sshmux.User, error) {
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

func (s *Server) setup(session *sshmux.Session) error {
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
			Names: []string{c.id.String(), c.id.String() + ":22", c.sshConn.RemoteAddr().String(), c.sshConn.User(), c.sshConn.User() + ":22"},
			Description: fmt.Sprintf("%s (%s, %s)", c.id.String(), c.sshConn.User(), c.sshConn.RemoteAddr().String()),
			Address: c.id.String() + ":22",
		})
	}
	return nil
}

func (s *Server) dialer(network, address string) (net.Conn, error) {
	log.Printf("Asking for %s %s", network, address)
	if network != "tcp" {
		return nil, fmt.Errorf("unknown network %s", network)
	}

	var c *Client
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

type FakeAddr struct {}
func (FakeAddr) Network() string { return "tcp" }
func (FakeAddr) String() string { return "" }

type SSHSortaConn struct {
	net.Conn
	sshChannel ssh.Channel
}

func (s *SSHSortaConn) Read(data []byte) (int, error) { return s.sshChannel.Read(data) }
func (s *SSHSortaConn) Write(data []byte) (int, error) { return s.sshChannel.Write(data) }
func (s *SSHSortaConn) Close() error { return s.sshChannel.Close() }
func (SSHSortaConn) RemoteAddr() net.Addr { return FakeAddr{} }
func (SSHSortaConn) LocalAddr() net.Addr { return FakeAddr{} }

// https://tools.ietf.org/html/rfc4254
type channelOpenForwardMsg struct {
	RAddr string
	RPort uint32
	LAddr string
	LPort uint32
}

func (s *Server) connectTo(sshconn ssh.Conn) (net.Conn, error) {
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

	return &SSHSortaConn{sshChannel: ch}, nil
}

// https://tools.ietf.org/html/rfc4254
type forwardTcpMsg struct {
	Addr string
	Port uint32
}

func (s *Server) NodeAuth(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
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

func (s *Server) HandleConn(c net.Conn) error {
	sshConn, chans, reqs, err := ssh.NewServerConn(c, s.sshConfig)
	if err != nil {
		c.Close()
		return err
	}
	defer sshConn.Close()

	if !s.anyNode && (sshConn.Permissions == nil || sshConn.Permissions.Extensions == nil) {
		return fmt.Errorf("no permissions")
	}

	client := &Client{
		sshConn: sshConn,
		address: c.RemoteAddr().String(),
		name: sshConn.User(),
		id: uuid.New(),
	}

	s.nodeLock.Lock()
	s.nodes = append(s.nodes, client)
	s.nodeLock.Unlock()

	go func() {
		for req := range reqs {
			switch req.Type {
			case "tcpip-forward":
				var msg forwardTcpMsg
				ssh.Unmarshal(req.Payload, &msg)
				if msg.Addr != "sshfleet" && msg.Port != 22 {
					if req.WantReply {
						req.Reply(false, []byte{})
					}
					continue
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
			}
		}()
	}

	err = sshConn.Wait()

	s.nodeLock.Lock()
	for i := 0; i < len(s.nodes); i++ {
		if s.nodes[i] == client {
			s.nodes = append(s.nodes[:i], s.nodes[i+1:]...)
			break
		}
	}
	s.nodeLock.Unlock()
	return err
}

func (s *Server) Serve(l net.Listener) error {
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
	us := make([]User, 0)
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

	viper.SetConfigName("sshmuxd")
	viper.AddConfigPath(".")
	viper.AddConfigPath("$HOME/.sshmuxd")
	viper.AddConfigPath("/etc/sshmuxd/")

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

	fleetServer := Server{
		users: users,
		nodeUsers: nodeUsers,
		anyNode: viper.GetBool("anyNode"),
		anyMaster: viper.GetBool("anyMaster"),
		nodeKeepAlive: time.Duration(viper.GetInt("nodeKeepAlive")) * time.Second,
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
