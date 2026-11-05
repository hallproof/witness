// Package witness reports evidence from a Go app to Hallproof.
//
// You register collectors once, at start-up, and witness runs them on a
// schedule. Each one returns what the app knows about itself (its settings,
// who has access, what exists), and witness pushes it to Hallproof when it
// changes, with a heartbeat in between so Hallproof can tell a quiet
// collector from a dead one:
//
//	w, err := witness.New(witness.Options{
//		Endpoint:  "https://hallproof.example.com",
//		IngestKey: os.Getenv("HALLPROOF_INGEST_KEY"),
//	})
//	if err != nil {
//		return err
//	}
//	err = w.Snapshot(collect.Snapshot{
//		Key:   "auth-settings",
//		Title: "Authentication settings",
//		Tests: []string{"mfa-enforced"},
//		Every: 15 * time.Minute,
//		Collect: func(ctx context.Context) (map[string]any, error) {
//			return map[string]any{"mfa": cfg.MFA, "session_hours": cfg.SessionHours}, nil
//		},
//	})
//	if err != nil {
//		return err
//	}
//	if err := w.Start(ctx); err != nil {
//		return err
//	}
//	defer w.Stop(context.Background())
//
// Witness sends metadata, never content. It never makes the app wait on
// Hallproof: if Hallproof is down, evidence queues (up to a limit, oldest
// dropped first) and goes out when it's back.
//
// The wire protocol is in package push and in spec/protocol.md.
package witness
