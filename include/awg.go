//go:build with_awg

package include

import (
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/protocol/awg"
)

func registerAWGOutbound(registry *outbound.Registry) {
	awg.RegisterOutbound(registry)
}