# Example Analyst Investigation — Identity Access Review

**Context:** Offline training simulation. Review date: 2026-11-02.

## Case: sarah.jones

**Observed:** Active identity has `mfa_active=false`, and the simulated policy field shows `AdministratorAccess` with no recorded approval.

**Risk:** The account may be inadequately protected and have broader access than its role requires. This is a potential risk, not evidence of account compromise.

**Validation steps:**
1. Confirm whether the identity is still employed and who owns it.
2. Verify actual sign-in method and MFA enforcement (including any federated authentication).
3. Review effective permissions, policy attachments, and the approved job function.
4. Look for change tickets and access approvals.
5. Coordinate remediation through the established change-management process.

**Recommendation:** Enforce the organization's MFA requirements and reduce privileges to least necessary access if administrator access is not approved.

**Status:** Open for verification — no real-world changes performed.

## Case: mike.brown

**Observed:** Last recorded console login and active-key usage are older than the 90-day training threshold.

**Risk:** Credentials may be unnecessary or abandoned.

**Validation steps:** Confirm owner and job need; check all credential types and relevant activity before deciding the identity is inactive.

**Recommendation:** Remove or disable unused credentials only after approval and impact assessment.

**Status:** Open for verification — no real-world changes performed.
