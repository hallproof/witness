package adapter

import (
	"context"
	"testing"
)

func reset(t *testing.T) {
	t.Helper()
	mu.Lock()
	saved := registry
	registry = map[string]Adapter{}
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		registry = saved
		mu.Unlock()
	})
}

func attachNothing(context.Context, Host) (bool, error) { return false, nil }

func TestRegisterAndList(t *testing.T) {
	reset(t)
	Register(Adapter{Name: "warden", Attach: attachNothing})
	Register(Adapter{Name: "authsome", Attach: attachNothing})
	Register(Adapter{Name: "keysmith", Attach: attachNothing})
	got := Adapters()
	if len(got) != 3 || got[0].Name != "authsome" || got[1].Name != "keysmith" || got[2].Name != "warden" {
		t.Fatalf("Adapters() = %v, want authsome, keysmith, warden", got)
	}
}

func mustPanic(t *testing.T, what string, f func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatalf("%s didn't panic", what)
		}
	}()
	f()
}

func TestRegisterPanicsOnDuplicate(t *testing.T) {
	reset(t)
	Register(Adapter{Name: "vault", Attach: attachNothing})
	mustPanic(t, "a second vault adapter", func() { Register(Adapter{Name: "vault", Attach: attachNothing}) })
}

func TestRegisterPanicsOnEmptyNameOrAttach(t *testing.T) {
	reset(t)
	mustPanic(t, "an adapter with no name", func() { Register(Adapter{Attach: attachNothing}) })
	mustPanic(t, "an adapter with no Attach", func() { Register(Adapter{Name: "grove"}) })
}

func TestDecode(t *testing.T) {
	var opts struct {
		Apps        []string `json:"apps"`
		EventProofs bool     `json:"event_proofs"`
		Every       int      `json:"every"`
	}
	src := map[string]any{"apps": []any{"a", "b"}, "event_proofs": true, "every": 30, "unknown": "ignored"}
	if err := Decode(src, &opts); err != nil {
		t.Fatal(err)
	}
	if len(opts.Apps) != 2 || opts.Apps[1] != "b" || !opts.EventProofs || opts.Every != 30 {
		t.Fatalf("Decode gave %+v", opts)
	}
	if err := Decode(nil, &opts); err != nil {
		t.Fatalf("Decode(nil) = %v, want nil", err)
	}
	if err := Decode(map[string]any{"every": "soon"}, &opts); err == nil {
		t.Fatal("a string for an int field was accepted")
	}
}

func TestStaffRolesDefault(t *testing.T) {
	if got := (Scope{}).Roles(); len(got) != 2 || got[0] != "platform-owner" || got[1] != "platform-admin" {
		t.Fatalf("default staff roles = %v", got)
	}
	if got := (Scope{StaffRoles: []string{"ops"}}).Roles(); len(got) != 1 || got[0] != "ops" {
		t.Fatalf("configured staff roles = %v", got)
	}
}

func TestWidened(t *testing.T) {
	Host{}.Widened("all_tenants") // no Widen set: no panic
	var got []string
	Host{Widen: func(r string) { got = append(got, r) }}.Widened("all_tenants")
	if len(got) != 1 || got[0] != "all_tenants" {
		t.Fatalf("Widen got %v", got)
	}
}
