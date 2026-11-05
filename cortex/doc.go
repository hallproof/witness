// Package cortex sends evidence about your AI agents to Hallproof, read
// from a github.com/xraph/cortex engine.
//
// # Collectors
//
// cortex.agents is a population of every agent in scope: its ID, name,
// scope, whether it's enabled, model, reasoning loop, step limit, tool
// names, persona and inline skill, trait and behaviour names, the keys of
// its guardrails (never their values), its owner and principal ID, when it
// was created and updated, and when its newest run started. It runs every
// 15 minutes and supports the agent-has-owner, agent-owner-active and
// no-orphaned-agents tests. An agent with no owner goes with an empty
// owner_id, so Hallproof sees "no owner" and not a missing field.
//
// cortex.tools is a snapshot of the tool catalog the engine can offer a
// model: each tool's name, where it comes from (builtin, registered or
// external), whether it's marked safe to retry, and whether a host
// authorizer gates the engine at all. It runs hourly. Give it a risk
// classifier with WithRiskClass and each tool also gets a risk, and the
// snapshot then supports the high-risk-approved test.
//
// cortex.personas is a population of the personas in scope, with the names
// of the skills, traits and behaviours each one composes. It runs hourly
// and has no test yet; it's inventory for ISO 42001 documentation.
//
// cortex.pending-approvals is a population of checkpoints where a run is
// paused for a person to approve it: the checkpoint, run and agent IDs,
// scope, state, step and when it was opened. It runs every 15 minutes and
// supports high-risk-approved.
//
// Two event proofs come from the platform stream, and they're off until
// you turn on event proofs. cortex.oversight cites cortex.checkpoint.created
// and cortex.checkpoint.resolved, for high-risk-approved.
// cortex.agent-activity cites the run, tool and publication events, for
// agent-events-chained. Both only prove something once your app wires
// cortex's audit_hook plugin to the chain witness proves from.
//
// Never sent: system prompts and prompt sections, agent and persona
// descriptions, guardrail values, agent metadata other than the two owner
// keys, a persona's identity and styles, temperature and token limits,
// anything a run holds (input, output, error, metadata, principal), tool
// descriptions and parameter schemas, a checkpoint's reason and metadata,
// and decisions (reason, who decided, the decider's principal). The adapter
// reads runs only for their start time.
//
// # Scope
//
// Cortex scopes are the host's own hierarchy. The adapter reads one root,
// org=<your platform org> by default, and everything beneath it, so your
// org's projects and environments are included. You name the org in Org
// (config org). If you don't, the adapter collects nothing. It won't guess
// a scope, since cortex refuses a read without one anyway. Register returns
// ErrNoOrg, and in a Forge app the adapter logs a warning and registers
// nothing.
//
// In an app where agents run inside customer workspaces, like Loomplane
// Cloud, staff scope may hold no agents at all. You can add customer orgs
// with Orgs (config orgs), and their IDs then go to Hallproof. There's no
// all-tenants mode: cortex can't list agents across scopes, so the
// witness scope's AllTenants only logs a warning here.
//
// Each row's scope is checked again after the store returns it, so a
// store that ignores the scope still can't hand you a customer's agents.
// A scope that holds more than push.MaxItems agents, personas or pending
// checkpoints fails the run with ErrTooMany, and the heartbeat reports the
// collector unhealthy, because a cut-off list would read as the full set.
//
// # Options
//
// In a Forge app these come from extensions.witness.adapters.cortex:
//
//	org: org_...                # required: your platform org's ID
//	scope_key: org              # the key of the scope's first level
//	orgs: []                    # more orgs to read, customers included
//	owner_key: owner_id         # agent metadata key holding the owner
//	principal_key: principal_id # agent metadata key holding the principal ID
//	event_proofs: false
//
// Outside Forge the same settings are Options: WithOrg, WithScopeKey,
// WithOrgs, WithOwnerKeys and WithEventProofs. Three more exist only in
// code. WithScope reads whole cortex scopes, for a host whose scopes aren't
// org-shaped. WithOwner says who owns each agent, for a host that keeps
// ownership outside cortex, and replaces the metadata keys. WithRiskClass
// names each tool's risk class.
//
// The principal ID is how Hallproof joins a cortex agent to the same actor
// in Authsome, so set it to the agent's Authsome principal when it has one.
//
// # Using it
//
// With Forge, import the package for its side effect, and the witness
// extension finds *engine.Engine in the container:
//
//	import _ "github.com/hallproof/witness/cortex"
//
// Cortex's own Forge extension provides the engine. If you build it
// yourself, provide it with forge.ProvideValue(c, eng).
//
// Without Forge, build the adapter and register it before you start
// witness:
//
//	a := cortex.New(eng,
//		cortex.WithOrg("org_..."),
//		cortex.WithOwner(func(c *agent.Config) (string, string) {
//			return ownerOf(c.Name), principalOf(c.Name)
//		}),
//	)
//	if err := a.Register(w); err != nil {
//		return err
//	}
//
// # Library gaps
//
// These are things cortex (v1.10.4 here) doesn't do yet that would make
// this adapter cheaper or more accurate:
//
//   - agent.Config has no owner. The adapter reads one from metadata keys
//     or your WithOwner func until cortex grows an Owner field.
//   - checkpoint.Store lists pending checkpoints only. There's no read for
//     decided ones, so approved and rejected counts per agent can't be a
//     population, and the oversight proof is the only record of decisions.
//   - Every read needs a scope, and there's no operator read across
//     scopes, so a fleet-wide inventory needs the host to name each org.
//   - There's no cheap "last run" read. The adapter asks for each agent's
//     newest run, which is one query per agent and loads that run's input
//     and output into memory (they're never sent).
//   - Lists page by offset, which can skip or repeat a row when rows are
//     created during a scan. The adapter drops repeats, and a skipped row
//     shows up on the next run.
//   - audit_hook puts error text into run.failed and tool.failed events,
//     and the host's own approval reason into checkpoint.created. An event
//     proof sends cited events as they are, so turn proofs on only when
//     you're happy for that text to reach Hallproof. An error type in
//     place of the text would fix it.
//   - audit_hook has no action for a denied tool call or for an agent being
//     created, updated or deleted, and checkpoint.resolved doesn't say who
//     decided.
//   - Cortex's Forge extension doesn't wire audit_hook to Chronicle, so
//     cortex.* events reach the chain only when your app adds the plugin.
//     Loomplane Cloud doesn't today.
//   - A tool has no risk class in cortex. Risk is the host's call, which is
//     why WithRiskClass exists.
package cortex
