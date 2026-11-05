package witness_test

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/hallproof/witness"
	"github.com/hallproof/witness/collect"
	"github.com/hallproof/witness/httpmw"
)

// An app reports its authentication settings and its staff accounts, and
// records what staff change over HTTP.
func ExampleNew() {
	w, err := witness.New(witness.Options{
		Endpoint:  "https://hallproof.example.com",
		IngestKey: os.Getenv("HALLPROOF_INGEST_KEY"),
	})
	if err != nil {
		log.Fatal(err)
	}

	err = w.Snapshot(collect.Snapshot{
		Key:   "auth-settings",
		Title: "Authentication settings",
		Tests: []string{"mfa-enforced"},
		Every: 15 * time.Minute,
		Collect: func(context.Context) (map[string]any, error) {
			return map[string]any{"mfa": "required", "session_hours": 12}, nil
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	err = w.Population(collect.Population{
		Key:    "staff-users",
		Title:  "Staff accounts",
		Source: "staff-users",
		Tests:  []string{"access-reviewed"},
		Every:  time.Hour,
		Collect: func(context.Context) ([]map[string]any, error) {
			// Read these from your user store. Send who has access, never
			// passwords or tokens.
			return []map[string]any{
				{"id": "usr_1", "email": "ada@example.com", "role": "admin", "mfa": true},
			}, nil
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /settings", func(http.ResponseWriter, *http.Request) {})
	handler := w.Middleware(httpmw.Options{
		Actor: func(r *http.Request) (httpmw.Actor, bool) {
			// Read the signed-in user from your own auth.
			id := r.Header.Get("X-User-ID")
			return httpmw.Actor{ID: id, Staff: true}, id != ""
		},
	})(mux)

	ctx := context.Background()
	if err := w.Start(ctx); err != nil {
		log.Fatal(err)
	}
	defer func() {
		stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := w.Stop(stop); err != nil {
			log.Print(err)
		}
	}()

	// Serve handler the way you already do, with your http.Server.
	_ = handler
}
