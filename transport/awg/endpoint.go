package awg

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"

	"go4.org/netipx"
)

type Endpoint struct {
	options        EndpointOptions
	peers          []peerConfig
	ipcConf        string
	allowedAddress []netip.Prefix
	tunDevice      Device
	device         *device.Device
	pause          pause.Manager
	pauseCallback  *list.Element[pause.Callback]
}

func NewEndpoint(options EndpointOptions) (*Endpoint, error) {
	if options.PrivateKey == "" {
		return nil, E.New("missing private key")
	}
	privateKeyBytes, err := base64.StdEncoding.DecodeString(options.PrivateKey)
	if err != nil {
		return nil, E.Cause(err, "decode private key")
	}
	privateKey := hex.EncodeToString(privateKeyBytes)

	ipcConf := "private_key=" + privateKey
	if options.ListenPort != 0 {
		ipcConf += "\nlisten_port=" + F.ToString(options.ListenPort)
	}
	// Параметры обфускации обязаны идти до первого public_key=, иначе
	// amneziawg-go отправит их в обработчик пира и вернёт ошибку.
	ipcConf += options.buildAWGIpcLines()

	var peers []peerConfig
	for peerIndex, rawPeer := range options.Peers {
		peer := peerConfig{
			allowedIPs: rawPeer.AllowedIPs,
			keepalive:  rawPeer.PersistentKeepaliveInterval,
		}
		if rawPeer.Endpoint.Addr.IsValid() {
			peer.endpoint = rawPeer.Endpoint.AddrPort()
		} else if rawPeer.Endpoint.IsFqdn() {
			peer.destination = rawPeer.Endpoint
		}
		publicKeyBytes, err := base64.StdEncoding.DecodeString(rawPeer.PublicKey)
		if err != nil {
			return nil, E.Cause(err, "decode public key for peer ", peerIndex)
		}
		peer.publicKeyHex = hex.EncodeToString(publicKeyBytes)
		if rawPeer.PreSharedKey != "" {
			preSharedKeyBytes, err := base64.StdEncoding.DecodeString(rawPeer.PreSharedKey)
			if err != nil {
				return nil, E.Cause(err, "decode pre shared key for peer ", peerIndex)
			}
			peer.preSharedKeyHex = hex.EncodeToString(preSharedKeyBytes)
		}
		if len(rawPeer.AllowedIPs) == 0 {
			return nil, E.New("missing allowed ips for peer ", peerIndex)
		}
		peers = append(peers, peer)
	}

	var allowedPrefixBuilder netipx.IPSetBuilder
	for _, peer := range options.Peers {
		for _, prefix := range peer.AllowedIPs {
			allowedPrefixBuilder.AddPrefix(prefix)
		}
	}
	allowedIPSet, err := allowedPrefixBuilder.IPSet()
	if err != nil {
		return nil, err
	}
	allowedAddresses := allowedIPSet.Prefixes()
	if options.MTU == 0 {
		options.MTU = 1408
	}
	deviceOptions := DeviceOptions{
		Context:        options.Context,
		Logger:         options.Logger,
		System:         options.System,
		Handler:        options.Handler,
		UDPTimeout:     options.UDPTimeout,
		CreateDialer:   options.CreateDialer,
		Name:           options.Name,
		MTU:            options.MTU,
		Address:        options.Address,
		AllowedAddress: allowedAddresses,
	}
	tunDevice, err := NewDevice(deviceOptions)
	if err != nil {
		return nil, E.Cause(err, "create AmneziaWG device")
	}
	return &Endpoint{
		options:        options,
		peers:          peers,
		ipcConf:        ipcConf,
		allowedAddress: allowedAddresses,
		tunDevice:      tunDevice,
	}, nil
}

// buildAWGIpcLines собирает device-уровневые параметры обфускации AWG.
//
// Нулевые значения опускаются: в AWG отсутствие параметра и ноль —
// одно и то же, но явная пустая строка для диапазона («h1=») не
// распарсится, поэтому молчание здесь надёжнее.
func (options EndpointOptions) buildAWGIpcLines() string {
	var lines string
	addUint := func(key string, value uint32) {
		if value != 0 {
			lines += "\n" + key + "=" + F.ToString(value)
		}
	}
	addString := func(key, value string) {
		if value != "" {
			lines += "\n" + key + "=" + value
		}
	}
	addBool := func(key string, value *bool) {
		if value != nil && *value {
			lines += "\n" + key + "=true"
		}
	}

	// Мусорные пакеты перед хендшейком.
	addUint("jc", options.JunkCount)
	addUint("jmin", options.JunkMin)
	addUint("jmax", options.JunkMax)

	// Криптографические паддинги.
	addUint("s1", uint32(options.InitPadding))
	addUint("s2", uint32(options.ResponsePadding))
	addUint("s3", uint32(options.CookiePadding))
	addUint("s4", uint32(options.TransportPadding))

	// Заголовки: одно число либо диапазон «x-y».
	addString("h1", options.InitHeader)
	addString("h2", options.ResponseHeader)
	addString("h3", options.CookieHeader)
	addString("h4", options.TransportHeader)

	// Подписи из тегов <b 0x..>, <r N>, <rd N>, <rc N>, <t>.
	for index, signature := range options.Signature {
		addString("i"+F.ToString(index+1), signature)
	}

	addString("header_protection_key", options.HeaderProtectionKey)
	addString("content_padding_addition", options.ContentPaddingAddition)

	addBool("random_trailers", options.RandomTrailers)
	addBool("disable_cookies", options.DisableCookies)

	// Тайминги, если заданы, иначе остаются штатные для WireGuard.
	addString("rekey_after_time", options.RekeyAfterTime)
	addString("rekey_timeout", options.RekeyTimeout)
	addString("reject_after_time", options.RejectAfterTime)
	addString("keepalive_timeout", options.KeepaliveTimeout)
	addString("max_handshake_attempts", options.MaxHandshakeAttempts)

	return lines
}

func (e *Endpoint) Start(resolve bool) error {
	if common.Any(e.peers, func(peer peerConfig) bool {
		return !peer.endpoint.IsValid() && peer.destination.IsFqdn()
	}) {
		if !resolve {
			return nil
		}
		for peerIndex, peer := range e.peers {
			if peer.endpoint.IsValid() || !peer.destination.IsFqdn() {
				continue
			}
			destinationAddress, err := e.options.ResolvePeer(peer.destination.Fqdn)
			if err != nil {
				return E.Cause(err, "resolve endpoint domain for peer[", peerIndex, "]: ", peer.destination)
			}
			e.peers[peerIndex].endpoint = netip.AddrPortFrom(destinationAddress, peer.destination.Port)
		}
	} else if resolve {
		return nil
	}

	// У amneziawg-go конструктор conn.NewStdNetBind не принимает
	// посторонний слушатель, поэтому путь «диалер сам является UDP»,
	// который есть в transport/wireguard, недоступен. В приложении он
	// и не встречается: диалер всегда даёт ListenPacket.
	var (
		isConnect   bool
		connectAddr netip.AddrPort
	)
	if len(e.peers) == 1 && e.peers[0].endpoint.IsValid() {
		isConnect = true
		connectAddr = e.peers[0].endpoint
	}
	var bind conn.Bind = NewClientBind(e.options.Context, e.options.Logger, e.options.Dialer, isConnect, connectAddr)

	err := e.tunDevice.Start()
	if err != nil {
		return err
	}
	logger := &device.Logger{
		Verbosef: func(format string, args ...any) {
			e.options.Logger.Debug(fmt.Sprintf(strings.ToLower(format), args...))
		},
		Errorf: func(format string, args ...any) {
			e.options.Logger.Error(fmt.Sprintf(strings.ToLower(format), args...))
		},
	}
	wgDevice := device.NewDevice(e.tunDevice, bind, logger)
	e.tunDevice.SetDevice(wgDevice)
	ipcConf := e.ipcConf
	for _, peer := range e.peers {
		ipcConf += peer.GenerateIpcLines()
	}
	err = wgDevice.IpcSet(ipcConf)
	if err != nil {
		return E.Cause(err, "setup amneziawg: \n", ipcConf)
	}
	e.device = wgDevice
	e.pause = service.FromContext[pause.Manager](e.options.Context)
	if e.pause != nil {
		e.pauseCallback = e.pause.RegisterCallback(e.onPauseUpdated)
	}
	return nil
}

func (e *Endpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if !destination.Addr.IsValid() {
		return nil, E.Cause(os.ErrInvalid, "invalid non-IP destination")
	}
	return e.tunDevice.DialContext(ctx, network, destination)
}

func (e *Endpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if !destination.Addr.IsValid() {
		return nil, E.Cause(os.ErrInvalid, "invalid non-IP destination")
	}
	return e.tunDevice.ListenPacket(ctx, destination)
}

func (e *Endpoint) Close() error {
	if e.device != nil {
		e.device.Close()
	}
	if e.pauseCallback != nil {
		e.pause.UnregisterCallback(e.pauseCallback)
	}
	return nil
}

func (e *Endpoint) onPauseUpdated(event int) {
	switch event {
	case pause.EventDevicePaused, pause.EventNetworkPause:
		e.device.Down()
	case pause.EventDeviceWake, pause.EventNetworkWake:
		e.device.Up()
	}
}

type peerConfig struct {
	destination     M.Socksaddr
	endpoint        netip.AddrPort
	publicKeyHex    string
	preSharedKeyHex string
	allowedIPs      []netip.Prefix
	keepalive       uint16
}

func (c peerConfig) GenerateIpcLines() string {
	ipcLines := "\npublic_key=" + c.publicKeyHex
	if c.endpoint.IsValid() {
		ipcLines += "\nendpoint=" + c.endpoint.String()
	}
	if c.preSharedKeyHex != "" {
		ipcLines += "\npreshared_key=" + c.preSharedKeyHex
	}
	for _, allowedIP := range c.allowedIPs {
		ipcLines += "\nallowed_ip=" + allowedIP.String()
	}
	if c.keepalive > 0 {
		ipcLines += "\npersistent_keepalive_interval=" + F.ToString(c.keepalive)
	}
	return ipcLines
}