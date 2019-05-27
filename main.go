package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/fsnotify/fsnotify"
	"github.com/kennylevinsen/sshmux"
	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"
)

type Client struct {

}

type Host struct {
	Address string   `json:"address"`
	Users   []string `json:"users"`
	NoAuth  bool     `json:"noAuth"`
}

type User struct {
	PublicKey string `json:"publicKey"`
	Name      string `json:"name"`
}

type Server struct {
	users []*sshmux.User
	hosts []Host
	hasDefaults bool
}

func (s *Server) auth(c ssh.ConnMetadata, key ssh.PublicKey) (*sshmux.User, error) {
	t := key.Type()
	k := key.Marshal()
	for i := range s.users {
		candidate := s.users[i].PublicKey
		if t == candidate.Type() && bytes.Compare(k, candidate.Marshal()) == 0 {
			return s.users[i], nil
		}
	}

	if s.hasDefaults {
		return nil, nil
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

outer:
	for _, h := range s.hosts {
		if h.NoAuth {
			session.Remotes = append(session.Remotes, h.Address)
			continue outer
		}

		if session.User == nil {
			continue
		}

		for _, u := range h.Users {
			if u == session.User.Name {
				session.Remotes = append(session.Remotes, h.Address)
				continue outer
			}
		}
	}
	return nil
}

func (s *Server) dialer(network, address string) (net.Conn, error) {
	return net.Dial(network, address)
}

func (s *Server) HandleConn(c net.Conn) {
	sshConn, chans, reqs, err := ssh.NewServerConn(c, s.sshConfig)
	if err != nil {
		c.Close()
		return
	}

	if sshConn.Permissions == nil || sshConn.Permissions.Extensions == nil {
		sshConn.Close()
		return
	}

	ext := sshConn.Permissions.Extensions
	pk := &publicKey{
		publicKey:     []byte(ext["pubKey"]),
		publicKeyType: ext["pubKeyType"],
	}

	user, err := s.Auther(sshConn, pk)

	session := &Session{
		Conn:      sshConn,
		User:      user,
		PublicKey: pk,
	}

	s.Setup(session)

	go ssh.DiscardRequests(reqs)
	newChannel := <-chans
	if newChannel == nil {
		sshConn.Close()
		return
	}

	switch newChannel.ChannelType() {
	case "direct-tcpip":
		s.ChannelForward(session, newChannel)
	default:
		newChannel.Reject(ssh.UnknownChannelType, "connection flow not supported by sshmux")
	}
}

var configFile = flag.String("config", "", "User-supplied configuration file to use")

func parseUsers() ([]*sshmux.User, error) {
	var users []*sshmux.User
	us := make([]User, 0)
	err := viper.UnmarshalKey("users", &us)
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
	viper.SetDefault("address", ":22")
	viper.SetDefault("hostkey", "hostkey")
	viper.SetDefault("authkeys", "authkeys")

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

	hosts := make([]Host, 0)
	err = viper.UnmarshalKey("hosts", &hosts)
	if err != nil {
		panic(fmt.Errorf("Error parsing the config file hosts list: %s\n", err))
	}

	users, err := parseUsers()
	if err != nil {
		panic(fmt.Errorf("Error parsing the config file hosts list: %s\n", err))
	}

	hostSigner, err := ssh.ParsePrivateKey([]byte(viper.GetString("hostkey")))
	if err != nil {
		panic(err)
	}

	viper.WatchConfig()
	viper.OnConfigChange(func(e fsnotify.Event) {
		log.Println("Config file changed:", e.Name)
		nh := make([]Host, 0)
		err = viper.UnmarshalKey("hosts", &nh)
		if err != nil {
			log.Printf("Error parsing the config file hosts list: %s\n"+
				"Keeping current host list", err)
		} else {
			hosts = nh
			log.Printf("New hosts list: %+v\n", hosts)
		}
		if u, err := parseUsers(); err != nil {
			log.Printf("Error parsing the config file users list: %s\n"+
				"Keeping current users list", err)
		} else {
			users = u
		}
		h, err := ssh.ParsePrivateKey([]byte(viper.GetString("hostkey")))
		if err != nil {
			log.Printf("Error parsing the config file hostkey: %s\n"+
				"Keeping current hostkey", err)
		} else {
			hostSigner = h
		}

	})

	hasDefaults := false
	for _, h := range hosts {
		if h.NoAuth {
			hasDefaults = true
			break
		}
	}

	fleetServer := Server{
		hosts: hosts,
		users: users,
		hasDefaults: hasDefaults,
	}

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
	l, err := net.Listen("tcp", viper.GetString("address"))
	if err != nil {
		panic(err)
	}

	server.Serve(l)
}
