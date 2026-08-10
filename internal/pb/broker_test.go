package pb

import "testing"

func TestConnectionListenerTypeCourierIsStable(t *testing.T) {
	const want = int32(3)
	if got := int32(ConnectionListenerType_CONNECTION_LISTENER_TYPE_COURIER); got != want {
		t.Fatalf("courier value = %d, want %d", got, want)
	}
	if got := ConnectionListenerType_CONNECTION_LISTENER_TYPE_COURIER.String(); got != "CONNECTION_LISTENER_TYPE_COURIER" {
		t.Fatalf("courier name = %q", got)
	}
}
