package app

import "testing"

func TestFormatIPv4FromKernelNetworkOrderValue(t *testing.T) {
	const raw uint32 = 0xA104A8C0

	if got, want := formatIPv4(raw), "192.168.4.161"; got != want {
		t.Fatalf("formatIPv4 mismatch: got %q want %q", got, want)
	}
}

func TestCaptureSourceName(t *testing.T) {
	cases := map[uint8]string{
		0: "unknown",
		1: "sock_sendmsg",
		2: "tcp_sendmsg",
		3: "sock_recvmsg",
		4: "tcp_recvmsg",
		5: "tcp_close",
	}

	for raw, want := range cases {
		if got := captureSourceName(raw); got != want {
			t.Fatalf("captureSourceName(%d) = %q want %q", raw, got, want)
		}
	}
}
