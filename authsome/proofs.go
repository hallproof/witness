package authsome

import (
	"github.com/xraph/authsome/hook"

	"github.com/hallproof/witness/adapter"
	"github.com/hallproof/witness/collect"
)

// actionIssueAgentSession is agentauth's audit action for an agent session.
// agentauth writes it as a literal; hook has no constant for it.
const actionIssueAgentSession = "issue_agent_session"

// eventProofs prove Authsome's audit events on the platform stream. They
// are off unless you turn them on: see the package doc.
func eventProofs() []collect.EventProof {
	return []collect.EventProof{
		{
			Key:         "authsome.mfa-proof",
			Title:       "Sign-in and MFA events",
			Description: "Signed proof of staff sign-ins and of MFA challenges, enrolments and removals.",
			Tests:       []string{"mfa-enforced"},
			Every:       every,
			Stream:      adapter.Platform,
			Actions:     []string{hook.ActionSignIn, hook.ActionMFAChallenge, hook.ActionMFAEnroll, hook.ActionMFADisable},
		},
		{
			Key:         "authsome.access-change-proof",
			Title:       "Access change events",
			Description: "Signed proof of platform role grants and removals, organisation membership changes and impersonation.",
			Tests:       []string{"privileged-reviewed"},
			Every:       every,
			Stream:      adapter.Platform,
			Actions:     []string{hook.ActionRoleAssign, hook.ActionRoleUnassign, hook.ActionMemberRemove, hook.ActionMemberRoleChange, hook.ActionImpersonate},
		},
		{
			Key:         "authsome.deprovision-proof",
			Title:       "Deprovisioning events",
			Description: "Signed proof of accounts deleted or banned and sessions revoked.",
			Tests:       []string{"no-active-leavers"},
			Every:       every,
			Stream:      adapter.Platform,
			Actions:     []string{hook.ActionAdminDeleteUser, hook.ActionAdminBanUser, hook.ActionSessionRevoke, hook.ActionAdminBulkRevokeSessions},
		},
		{
			Key:         "authsome.agent-proof",
			Title:       "Agent delegation events",
			Description: "Signed proof of delegations granted to and revoked from agents, and of agent sessions issued.",
			Tests:       []string{"agent-events-chained"},
			Every:       every,
			Stream:      adapter.Platform,
			Actions:     []string{hook.ActionDelegationGrant, hook.ActionDelegationRevoke, actionIssueAgentSession},
		},
	}
}
