package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/hashicorp/go-multierror"
)

type NTPClient struct {
	//log *logrus.Entry

	pairPackets  [4]*PairPacketNTP
	QueryOptions *QueryOptions
}

type PacketNTP struct {
	LiVnMode  uint8 // Leap indicator(2), Version number(3), Mode(3)
	Stratum   uint8 // Stratum level of the local clock (8)
	Poll      uint8 // Maximum interval between messages(8)
	Precision uint8 // Precision of local clock (8)

	RootDelay      uint32 // Total round trip delay time (32)
	RootDispersion uint32 // Max error aloud from primary clock source (32)
	ReferenceID    uint32 // Reference clock identifier (32)

	ReferenceTime uint64 // Reference time stamp (64)
	OriginTime    uint64 // Origin time stamp (64)
	ReceivedTime  uint64 // Received time stamp (64)
	TransmitTime  uint64 // Transmitted time stamp (64)
}

type PairPacketNTP struct {
	queryPacket   *PacketNTP
	recvPacket    *PacketNTP
	localAddress  *net.UDPAddr
	remoteAdderss *net.UDPAddr
	serverHost    string
}

type QueryOptions struct {
	Timeout      time.Duration // defaults to 5 seconds
	Version      int           // NTP protocol version, defaults to 4
	TTL          int           // IP TTL to use, defaults to system default
	Port         int           // Server port, defaults to 123
	LocalAddress string        // IP address to use for the client address, defaults to golang net
}

var (
	host     = "uk.pool.ntp.org"
	ntpEpoch = time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)
)

func NewNTPClient() *NTPClient {
	ntpClient := new(NTPClient)

	ntpClient.QueryOptions = NewQueryOptions()

	for i := 0; i < 4; i++ {
		ntpClient.pairPackets[i] = NewPairPacket(fmt.Sprintf("%d.%s", i, host))
	}

	return ntpClient
}

func (n *NTPClient) getTime() error {
	var result *multierror.Error

	for _, pair := range n.pairPackets {
		if err := pair.requestTime(n.QueryOptions); err != nil {
			result = multierror.Append(result, fmt.Errorf("error getting time from pair: %v", err))
		}
	}

	return result.ErrorOrNil()
}

func NewPairPacket(host string) *PairPacketNTP {
	pairPacket := &PairPacketNTP{
		recvPacket:   new(PacketNTP),
		localAddress: new(net.UDPAddr),
		serverHost:   host,
	}

	pairPacket.queryPacket = pairPacket.NewQueryPacket()

	return pairPacket
}

func NewQueryOptions() *QueryOptions {
	return &QueryOptions{
		Timeout: (time.Second * 5),
		Version: 4,
		Port:    123,
	}
}

func (p *PairPacketNTP) NewQueryPacket() *PacketNTP {
	packet := &PacketNTP{
		LiVnMode: 0x1b, // 00,100,011 leep indicator=0, version=4, mode=3 (client)
	}

	return packet
}

func (p *PairPacketNTP) requestTime(options *QueryOptions) error {
	var err error
	var result *multierror.Error

	if options.LocalAddress != "" {
		p.localAddress, err = net.ResolveUDPAddr("udp", net.JoinHostPort(options.LocalAddress, "0"))
		if err != nil {
			result = multierror.Append(result, fmt.Errorf("failed to resolve local address from options: %v", err))
		}
	}

	if options.Version < 2 || options.Version > 4 {
		result = multierror.Append(result, fmt.Errorf("requested ntp version number is not supported: %d", options.Version))
	}

	if result != nil {
		return result
	}

	p.setVersionNumber(options.Version)

	p.remoteAdderss, err = net.ResolveUDPAddr("udp", net.JoinHostPort(p.serverHost, strconv.Itoa(options.Port)))
	if err != nil {
		return fmt.Errorf("failed to resolve host address: %v", err)
	}

	con, err := net.DialUDP("udp", p.localAddress, p.remoteAdderss)
	if err != nil {
		return fmt.Errorf("failed to connect to remote server: %v", err)
	}
	defer con.Close()

	con.SetDeadline(time.Now().Add(options.Timeout))

	// Use a random transmit time in message to increase privacy and prevent spoofing
	randomBits := make([]byte, 8)
	if _, err := rand.Read(randomBits); err != nil {
		return fmt.Errorf("failed to generate random bits for transmit time: %v", err)
	}

	p.queryPacket.TransmitTime = uint64(binary.BigEndian.Uint64(randomBits))
	realTransmitTime := time.Now()

	// Send query
	if err := binary.Write(con, binary.BigEndian, p.queryPacket); err != nil {
		return fmt.Errorf("failed to send ntp query to server: %v", err)
	}

	// Receive response
	if err := binary.Read(con, binary.BigEndian, p.recvPacket); err != nil {
		return fmt.Errorf("responding network error: %v", err)
	}

	transmissionTime := time.Since(realTransmitTime)

	if err := p.verifyResponsePacket(); err != nil {
		return fmt.Errorf("error verifying response packet: %v", err)
	}

	fmt.Printf("(%s) transmission time: %v\n", p.serverHost, transmissionTime.String())

	return nil
}

func (p *PairPacketNTP) setVersionNumber(version int) {
	p.queryPacket.LiVnMode = (p.queryPacket.LiVnMode & 0xc7) | (uint8(version) << 3) // ( LiVnMode & 11000111) | 00VER111
}

func (p *PairPacketNTP) verifyResponsePacket() error {
	var result *multierror.Error

	//verify server mode in response
	if (p.recvPacket.LiVnMode & 0x07) != 0x04 {
		result = multierror.Append(result, errors.New("response packet did not respond with server mode"))
	}

	if p.recvPacket.OriginTime != p.queryPacket.TransmitTime {
		result = multierror.Append(result, errors.New("response transmit time did not match query's"))
	}

	if p.recvPacket.ReceivedTime > p.recvPacket.TransmitTime {
		result = multierror.Append(result, errors.New("server clock has ticked backwards"))
	}

	return result.ErrorOrNil()
}

func main() {

	ntp := NewNTPClient()
	if err := ntp.getTime(); err != nil {
		fmt.Printf("%v", err)
	}

	return
}
