package adapter

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/hallproof/witness"
	"github.com/hallproof/witness/collect"
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

func TestExtension(t *testing.T) {
	if x, ok := (Host{}).Ext("dispatch"); ok || x != nil {
		t.Fatalf("Ext with no lookup = %v, %v; want nil, false", x, ok)
	}
	h := Host{Extension: func(name string) (any, bool) {
		if name == "dispatch" {
			return "the dispatch extension", true
		}
		return nil, false
	}}
	if x, ok := h.Ext("dispatch"); !ok || x != "the dispatch extension" {
		t.Fatalf("Ext(dispatch) = %v, %v", x, ok)
	}
	if _, ok := h.Ext("cortex"); ok {
		t.Fatal("Ext(cortex) found an extension the app doesn't run")
	}
}

func newWitness(t *testing.T) *witness.Witness {
	t.Helper()
	w, err := witness.New(witness.Options{
		Endpoint:  "http://localhost:1",
		IngestKey: "hpk_test",
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func snap(key string) collect.Snapshot {
	return collect.Snapshot{Key: key, Title: "t", Collect: func(context.Context) (map[string]any, error) { return nil, nil }}
}

func pop(key string) collect.Population {
	return collect.Population{Key: key, Title: "t", Source: key, Collect: func(context.Context) ([]map[string]any, error) { return nil, nil }}
}

func proof(key string) collect.EventProof {
	return collect.EventProof{Key: key, Title: "t", Stream: Platform, Actions: []string{"user.login"}}
}

// registered reports which of keys w holds, removing them as it checks.
func registered(w *witness.Witness, keys ...string) []string {
	var out []string
	for _, k := range keys {
		if w.Remove(k) {
			out = append(out, k)
		}
	}
	return out
}

func TestSetRegistersEverything(t *testing.T) {
	w := newWitness(t)
	var s Set
	s.Snapshot(snap("a"))
	s.Population(pop("b"), pop("c"))
	s.EventProof(proof("d"))
	if s.Len() != 4 {
		t.Fatalf("Len() = %d, want 4", s.Len())
	}
	if err := s.Register(w); err != nil {
		t.Fatal(err)
	}
	if got := registered(w, "a", "b", "c", "d"); len(got) != 4 {
		t.Fatalf("registered %v, want a, b, c and d", got)
	}
}

func TestSetRollsBackWhenOneFails(t *testing.T) {
	cases := map[string]func(w *witness.Witness, s *Set){
		"key the witness already has": func(w *witness.Witness, s *Set) {
			if err := w.Snapshot(snap("taken")); err != nil {
				t.Fatal(err)
			}
			s.EventProof(proof("taken"))
		},
		"bad title": func(_ *witness.Witness, s *Set) {
			bad := snap("bad")
			bad.Title = " "
			s.Snapshot(bad)
		},
		"key used twice in the set": func(_ *witness.Witness, s *Set) {
			s.Population(pop("a"))
		},
		"event proof without actions": func(_ *witness.Witness, s *Set) {
			e := proof("e")
			e.Actions = nil
			s.EventProof(e)
		},
	}
	for name, last := range cases {
		t.Run(name, func(t *testing.T) {
			w := newWitness(t)
			var s Set
			s.Snapshot(snap("a"))
			s.Population(pop("b"))
			s.EventProof(proof("c"))
			last(w, &s)
			if err := s.Register(w); err == nil {
				t.Fatal("Register = nil, want the failing collector's error")
			}
			if got := registered(w, "a", "b", "c", "bad", "e"); len(got) != 0 {
				t.Fatalf("still registered after a failed Register: %v", got)
			}
			if name == "key the witness already has" && len(registered(w, "taken")) != 1 {
				t.Fatal("Register removed a collector it didn't add")
			}
		})
	}
}

func TestSetNeedsAWitness(t *testing.T) {
	var s Set
	s.Snapshot(snap("a"))
	if err := s.Register(nil); err == nil {
		t.Fatal("Register(nil) = nil, want an error")
	}
}
