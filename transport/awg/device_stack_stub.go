//go:build !with_gvisor

package awg

import "github.com/sagernet/sing-tun"

// newSystemStackDevice отсутствует намеренно: вариант «настоящий TUN
// плюс обработчик пакетов» у amneziawg-go не собирается, см. NewDevice
// в device.go.

func newStackDevice(options DeviceOptions) (Device, error) {
	return nil, tun.ErrGVisorNotIncluded
}