package logic

import (
	"testing"

	"github.com/m-mizutani/gt"
)

func TestDecodeNetBIOSName(t *testing.T) {
	// Encode "WORKSTATION" in NetBIOS format
	// Each byte is split into two nibbles, each nibble + 'A'
	source := "WORKSTATION     " // 15 chars + suffix byte
	var encoded []byte
	for i := 0; i < 16; i++ {
		var ch byte
		if i < len(source) {
			ch = source[i]
		}
		encoded = append(encoded, (ch>>4)+'A', (ch&0x0F)+'A')
	}

	name := decodeNetBIOSName(string(encoded))
	gt.V(t, name).Equal("WORKSTATION")
}
