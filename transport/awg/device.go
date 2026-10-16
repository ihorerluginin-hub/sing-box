package awg

import (
	"context"
	"net/netip"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	wgTun "github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

type Device interface {
	wgTun.Device
	N.Dialer
	Start() error
	SetDevice(device *device.Device)
}

type DeviceOptions struct {
	Context        context.Context
	Logger         logger.ContextLogger
	System         bool
	Handler        tun.Handler
	UDPTimeout     time.Duration
	CreateDialer   func(interfaceName string) N.Dialer
	Name           string
	MTU            uint32
	Address        []netip.Prefix
	AllowedAddress []netip.Prefix
}

func NewDevice(options DeviceOptions) (Device, error) {
	if !options.System {
		return newStackDevice(options)
	} else if options.Handler == nil {
		return newSystemDevice(options)
	} else {
		// Вариант «настоящий TUN плюс обработчик пакетов» в amneziawg-go
		// не собирается. Он сбрасывает пакеты из сетевого стека прямо
		// в устройство, а device.allowedips и device.queue у amneziawg-go
		// неэкспортируемые: снаружи пакета не подложить. У sagernet в
		// wireguard-go для этого есть метод InputPacket, здесь — нет.
		//
		// В приложении этот путь и не нужен: NekoBox оставляет
		// system_interface пустым и работает через пользовательский
		// стек, то есть попадает в newStackDevice.
		return nil, E.New("AmneziaWG does not support a system interface with a packet handler")
	}
}
