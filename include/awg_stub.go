//go:build !with_awg

package include

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func registerAWGOutbound(registry *outbound.Registry) {
	outbound.Register[option.AWGOutboundOptions](registry, C.TypeAWG, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.AWGOutboundOptions) (adapter.Outbound, error) {
		return nil, E.New(`AmneziaWG is not included in this build, rebuild with -tags with_awg`)
	})
}