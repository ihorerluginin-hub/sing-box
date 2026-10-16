package awg

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	awgTransport "github.com/sagernet/sing-box/transport/awg"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.AWGOutboundOptions](registry, C.TypeAWG, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	ctx            context.Context
	dnsRouter      adapter.DNSRouter
	logger         logger.ContextLogger
	localAddresses []netip.Prefix
	endpoint       *awgTransport.Endpoint
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.AWGOutboundOptions) (adapter.Outbound, error) {
	outbound := &Outbound{
		Adapter:        outbound.NewAdapterWithDialerOptions(C.TypeAWG, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		ctx:            ctx,
		dnsRouter:      service.FromContext[adapter.DNSRouter](ctx),
		logger:         logger,
		localAddresses: options.LocalAddress,
	}
	outboundDialer, err := dialer.NewWithOptions(dialer.Options{
		Context:          ctx,
		Options:          options.DialerOptions,
		RemoteIsDomain:   options.ServerIsDomain(),
		ResolverOnDetour: true,
	})
	if err != nil {
		return nil, err
	}
	endpointOptions := awgTransport.EndpointOptions{
		Context: ctx,
		Logger:  logger,
		// Пользовательский сетевой стек, а не системный интерфейс.
		// Так же, как у WireGuard в этом приложении: NekoBox не
		// передаёт system_interface, весь трафик идёт через стек
		// sing-box. У amneziawg-go нет другого рабочего пути — сброс
		// пакетов прямо в устройство снаружи невозможен, поля
		// allowedips и queue неэкспортируемые.
		System: false,
		Dialer: outboundDialer,
		CreateDialer: func(interfaceName string) N.Dialer {
			return common.Must1(dialer.NewDefault(ctx, option.DialerOptions{
				BindInterface: interfaceName,
			}))
		},
		MTU:        options.MTU,
		Address:    options.LocalAddress,
		PrivateKey: options.PrivateKey,
		UDPTimeout: time.Duration(options.UDPTimeout),
		ResolvePeer: func(domain string) (netip.Addr, error) {
			endpointAddresses, lookupErr := outbound.dnsRouter.Lookup(ctx, domain, outboundDialer.(dialer.ResolveDialer).QueryOptions())
			if lookupErr != nil {
				return netip.Addr{}, lookupErr
			}
			return endpointAddresses[0], nil
		},
		Peers: []awgTransport.PeerOptions{{
			Endpoint:     options.ServerOptions.Build(),
			PublicKey:    options.PeerPublicKey,
			PreSharedKey: options.PreSharedKey,
			AllowedIPs: []netip.Prefix{
				netip.PrefixFrom(netip.IPv4Unspecified(), 0),
				netip.PrefixFrom(netip.IPv6Unspecified(), 0),
			},
		}},
		Workers: options.Workers,

		// Обфускация AWG, единая на весь интерфейс.
		JunkCount:               options.JunkCount,
		JunkMin:                 options.JunkMin,
		JunkMax:                 options.JunkMax,
		InitPadding:             options.InitPadding,
		ResponsePadding:         options.ResponsePadding,
		CookiePadding:           options.CookiePadding,
		TransportPadding:        options.TransportPadding,
		InitHeader:              options.InitHeader,
		ResponseHeader:          options.ResponseHeader,
		CookieHeader:            options.CookieHeader,
		TransportHeader:         options.TransportHeader,
		Signature:               options.AWGSignatures(),
		HeaderProtectionKey:     options.HeaderProtectionKey,
		ContentPaddingAddition:  options.ContentPaddingAddition,
		RandomTrailers:          options.RandomTrailers,
		DisableCookies:          options.DisableCookies,
	}
	if endpointOptions.MTU == 0 {
		endpointOptions.MTU = 1408
	}
	awgEndpoint, err := awgTransport.NewEndpoint(endpointOptions)
	if err != nil {
		return nil, err
	}
	outbound.endpoint = awgEndpoint
	return outbound, nil
}

func (o *Outbound) Start(stage adapter.StartStage) error {
	switch stage {
	case adapter.StartStateStart:
		return o.endpoint.Start(false)
	case adapter.StartStatePostStart:
		return o.endpoint.Start(true)
	}
	return nil
}

func (o *Outbound) Close() error {
	return o.endpoint.Close()
}

func (o *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch network {
	case N.NetworkTCP:
		o.logger.InfoContext(ctx, "outbound connection to ", destination)
	case N.NetworkUDP:
		o.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	}
	if destination.IsFqdn() {
		destinationAddresses, err := o.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, err
		}
		return N.DialSerial(ctx, o.endpoint, network, destination, destinationAddresses)
	} else if !destination.Addr.IsValid() {
		return nil, E.New("invalid destination: ", destination)
	}
	return o.endpoint.DialContext(ctx, network, destination)
}

func (o *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	o.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	if destination.IsFqdn() {
		destinationAddresses, err := o.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, err
		}
		packetConn, _, err := N.ListenSerial(ctx, o.endpoint, destination, destinationAddresses)
		if err != nil {
			return nil, err
		}
		return packetConn, err
	}
	return o.endpoint.ListenPacket(ctx, destination)
}