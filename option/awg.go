package option

import (
	"net/netip"

	"github.com/sagernet/sing/common/json/badoption"
)

// AWGOutboundOptions — настройки исходящего AmneziaWG.
//
// Модель пира взята у legacy WireGuard (один сервер, один пир), потому
// что редактор профилей работает именно с такой конфигурацией: сервер,
// порт, один публичный ключ.
//
// Поля reserved здесь отсутствуют намеренно: в amneziawg-go у сообщений
// нет такого поля, и UAPI его не принимает.
type AWGOutboundOptions struct {
	ServerOptions
	LocalAddress  badoption.Listable[netip.Prefix] `json:"local_address"`
	PrivateKey    string                           `json:"private_key"`
	PeerPublicKey string                           `json:"peer_public_key"`
	PreSharedKey  string                           `json:"pre_shared_key,omitempty"`
	MTU           uint32                           `json:"mtu,omitempty"`
	UDPTimeout    badoption.Duration               `json:"udp_timeout,omitempty"`

	// PersistentKeepaliveInterval в секундах. В конфигурации AWG поле
	// называется PersistentKeepalive и принимает диапазон, но одиночное
	// число тоже допустимый диапазон, поэтому здесь обычное целое.
	PersistentKeepaliveInterval uint16 `json:"persistent_keepalive_interval,omitempty"`

	// Мусорные пакеты, отправляются перед каждым хендшейком.
	// По документации amneziawg-go менять их на сервере не нужно,
	// рекомендуемое значение Jc — 4-12.
	JunkCount uint32 `json:"junk_count,omitempty"`
	JunkMin   uint32 `json:"junk_min,omitempty"`
	JunkMax   uint32 `json:"junk_max,omitempty"`

	// Криптографические паддинги сообщений. Значения обязаны совпадать
	// с серверными; при включённой защите заголовков все четыре должны
	// быть не меньше 12.
	InitPadding      uint16 `json:"init_padding,omitempty"`
	ResponsePadding  uint16 `json:"response_padding,omitempty"`
	CookiePadding    uint16 `json:"cookie_padding,omitempty"`
	TransportPadding uint16 `json:"transport_padding,omitempty"`

	// Заголовки сообщений: одно число либо диапазон «x-y».
	InitHeader      string `json:"init_header,omitempty"`
	ResponseHeader  string `json:"response_header,omitempty"`
	CookieHeader    string `json:"cookie_header,omitempty"`
	TransportHeader string `json:"transport_header,omitempty"`

	// Подписи из тегов <b 0x..>, <r N>, <rd N>, <rc N>, <t>.
	// Отправляются перед хендшейком в порядке I1-I5.
	Signature1 string `json:"signature_1,omitempty"`
	Signature2 string `json:"signature_2,omitempty"`
	Signature3 string `json:"signature_3,omitempty"`
	Signature4 string `json:"signature_4,omitempty"`
	Signature5 string `json:"signature_5,omitempty"`

	// Ключ шифрования заголовков, общий для клиента и сервера.
	HeaderProtectionKey string `json:"header_protection_key,omitempty"`

	// Дополнительное паддингование содержимого, диапазон.
	ContentPaddingAddition string `json:"content_padding_addition,omitempty"`

	RandomTrailers *bool `json:"random_trailers,omitempty"`
	DisableCookies *bool `json:"disable_cookies,omitempty"`

	DialerOptions
}

// AWGSignatures собирает пять подписей в порядке, который требует
// amneziawg-go: I1, I2, I3, I4, I5.
func (o AWGOutboundOptions) AWGSignatures() [5]string {
	return [5]string{o.Signature1, o.Signature2, o.Signature3, o.Signature4, o.Signature5}
}