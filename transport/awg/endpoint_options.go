package awg

import (
	"context"
	"net/netip"
	"time"

	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// EndpointOptions описывает всё, из чего собирается AWG-эндпоинт.
//
// Отличие от WireGuard: поля Reserved нет вовсе, зато есть набор
// параметров обфускации, которые в UAPI устройства передаются как
// jc/jmin/jmax, s1-s4, h1-h4, i1-i5 и header_protection_key.
type EndpointOptions struct {
	Context      context.Context
	Logger       logger.ContextLogger
	System       bool
	Handler      tun.Handler
	UDPTimeout   time.Duration
	Dialer       N.Dialer
	CreateDialer func(interfaceName string) N.Dialer
	Name         string
	MTU          uint32
	Address      []netip.Prefix
	PrivateKey   string
	ListenPort   uint16
	ResolvePeer  func(domain string) (netip.Addr, error)
	Peers        []PeerOptions

	// AWG-specific, device-wide. Пустое значение означает «не задавать»,
	// и соответствующая строка в UAPI просто не попадает в конфигурацию.

	// Мусорные пакеты перед каждым хендшейком.
	JunkCount uint32
	JunkMin   uint32
	JunkMax   uint32

	// Криптографические паддинги сообщений.
	InitPadding     uint16
	ResponsePadding uint16
	CookiePadding   uint16
	TransportPadding uint16

	// Заголовки сообщений, каждый либо одно число, либо диапазон «x-y».
	InitHeader     string
	ResponseHeader string
	CookieHeader   string
	TransportHeader string

	// Подписи из тегов <b 0x..>, <r N>, <rd N>, <rc N>, <t>.
	Signature [5]string

	// Шифрование заголовков. Ключ общий для клиента и сервера.
	HeaderProtectionKey string

	// Дополнительное паддингование содержимого, диапазон.
	ContentPaddingAddition string

	// Случайные хвосты у транспортных сообщений.
	RandomTrailers *bool

	// Полностью выключить cookie-механику.
	DisableCookies *bool

	// Тайминги в виде диапазонов, пустое значение — стандарт WireGuard.
	RekeyAfterTime       string
	RekeyTimeout         string
	RejectAfterTime      string
	KeepaliveTimeout     string
	MaxHandshakeAttempts string
}

type PeerOptions struct {
	Endpoint                    M.Socksaddr
	PublicKey                   string
	PreSharedKey                string
	AllowedIPs                  []netip.Prefix
	PersistentKeepaliveInterval uint16
}