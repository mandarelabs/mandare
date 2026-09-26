import { formatAmount, ledgerDbPath, readApprovals, readSnapshot } from '@/lib/data';
import { verifyBadge } from '@/lib/verify';
import { killAgentAction } from '@/lib/kill';

export const dynamic = 'force-dynamic';

export default async function FleetPage() {
  const dbPath = ledgerDbPath();
  const [snapshot, badge] = await Promise.all([
    Promise.resolve(readSnapshot(dbPath)),
    verifyBadge(),
  ]);

  if (snapshot === null) {
    return (
      <>
        <h1>Fleet</h1>
        <div className="empty">
          No ledger at <code>{dbPath}</code> yet. Start the gateway (or{' '}
          <code>docker compose up</code>) and this page fills itself — every row
          here is derived from the ledger, nothing else.
        </div>
      </>
    );
  }

  return (
    <>
      <h1>
        Fleet <span className="dead">· door {snapshot.doorId ?? 'unknown'}</span>
      </h1>

      {snapshot.unreadableRows > 0 ? (
        <div className="empty">
          <strong className="bad">
            {snapshot.unreadableRows} ledger row{snapshot.unreadableRows === 1 ? '' : 's'} failed the
            stored-row check
          </strong>{' '}
          — their stored text can be read more than one way (tampering signature). They are left out of
          every figure below; run <code>mandare verify</code> for the seq numbers.
        </div>
      ) : null}

      <div className="badge-row">
        <div className="badge">
          <div className="label">Chain</div>
          <div className={`value ${badge.chainOk ? 'ok' : 'bad'}`}>
            {badge.chainOk ? 'VALID' : 'INVALID'}
          </div>
          <div className="sub">
            {badge.failure ?? `${badge.entries} entries, every one hash-linked + door-signed`}
          </div>
        </div>
        <div className="badge">
          <div className="label">Budget counters</div>
          <div
            className={`value ${
              badge.countersConsistent === null ? '' : badge.countersConsistent ? 'ok' : 'bad'
            }`}
          >
            {badge.countersConsistent === null
              ? 'n/a'
              : badge.countersConsistent
                ? 'CONSISTENT'
                : 'DIVERGENT'}
          </div>
          <div className="sub">live counters == fresh replay of the ledger</div>
        </div>
        <div className="badge">
          <div className="label">Witness</div>
          {badge.witness.configured ? (
            <>
              <div className={`value ${badge.witness.consistent ? 'ok' : 'bad'}`}>
                {badge.witness.consistent ? 'CONSISTENT' : 'CHECK FAILED'}
              </div>
              <div className="sub">
                {!badge.witness.consistent
                  ? badge.witness.detail
                  : badge.anchor === 'self-anchored'
                    ? 'SELF-ANCHORED — checked against the source the ledger file names; set MANDARE_DOOR_PUBLIC_KEY to bind it to the door key'
                    : 'external head history of the out-of-band door key covers this chain'}
              </div>
            </>
          ) : (
            <>
              <div className="value dead">not configured</div>
              <div className="sub">truncation/rewrite detection needs a witness</div>
            </>
          )}
        </div>
        <div className="badge">
          <div className="label">Tree head</div>
          <div className="value mono">{badge.treeSize ?? '—'}</div>
          <div className="sub mono">{badge.treeRoot ? `${badge.treeRoot.slice(0, 16)}…` : ''}</div>
        </div>
      </div>

      <h2>Agents under management</h2>
      {snapshot.agents.length === 0 ? (
        <div className="empty">No agent activity on the ledger yet.</div>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Agent</th>
              <th>Status</th>
              <th className="num">Settled spend</th>
              <th className="num">Refusals</th>
              <th className="num">Entries</th>
              <th>Last seen</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {snapshot.agents.map((agent) => (
              <tr key={agent.actor}>
                <td className="mono">{agent.actor}</td>
                <td>
                  {agent.revoked ? (
                    <span className="chip revoke">KILLED {agent.revokedAt?.slice(0, 16)}</span>
                  ) : (
                    <span className="chip result">active</span>
                  )}
                </td>
                <td className="num">{formatAmount(agent.settledMicros, agent.currency)}</td>
                <td className="num">{agent.refusals}</td>
                <td className="num">{agent.entryCount}</td>
                <td className="mono">{agent.lastSeen.slice(0, 19)}Z</td>
                <td>
                  {agent.revoked || !agent.actor.startsWith('did:') ? null : (
                    <form action={killAgentAction}>
                      <input type="hidden" name="agent" value={agent.actor} />
                      <button className="kill-button" type="submit">
                        kill
                      </button>
                    </form>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <p className="hint">
        Kill writes an <code>agent.revoke</code> entry through the same local authority as{' '}
        <code>mandare kill</code> — the gateway refuses the agent on its next request. Reinstating
        is deliberately terminal-only.
      </p>

      <h2>Mandate budgets</h2>
      {snapshot.mandates.length === 0 ? (
        <div className="empty">No spend recorded against any mandate yet.</div>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Mandate</th>
              <th className="num">Settled today</th>
              <th className="num">Reserved (in flight)</th>
              <th className="num">Settled total</th>
              <th className="num">Intents</th>
            </tr>
          </thead>
          <tbody>
            {snapshot.mandates.map((mandate) => (
              <tr key={mandate.mandateId}>
                <td className="mono">{mandate.mandateId}</td>
                <td className="num">{formatAmount(mandate.todaySettledMicros, 'EUR')}</td>
                <td className="num">{formatAmount(mandate.todayReservedMicros, 'EUR')}</td>
                <td className="num">{formatAmount(mandate.totalSettledMicros, 'EUR')}</td>
                <td className="num">{mandate.intents}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <ApprovalsSection dbPath={dbPath} />

      {snapshot.revokedSubjects.length > 0 ? (
        <>
          <h2>Revoked subjects</h2>
          <table>
            <thead>
              <tr>
                <th>Subject</th>
                <th>Since</th>
              </tr>
            </thead>
            <tbody>
              {snapshot.revokedSubjects.map((subject) => (
                <tr key={subject.subject}>
                  <td className="mono">{subject.subject}</td>
                  <td className="mono">{subject.updatedAt.slice(0, 19)}Z</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      ) : null}
    </>
  );
}

function ApprovalsSection({ dbPath }: { dbPath: string }) {
  const approvals = readApprovals(dbPath, 15);
  if (approvals.length === 0) {
    return null;
  }
  return (
    <>
      <h2>Approval trail</h2>
      <table>
        <thead>
          <tr>
            <th>Seq</th>
            <th>When</th>
            <th>Event</th>
            <th>Decided by / held for</th>
          </tr>
        </thead>
        <tbody>
          {approvals.map((approval) => (
            <tr key={approval.seq}>
              <td className="num">{approval.seq}</td>
              <td className="mono">{approval.ts.slice(0, 19)}Z</td>
              <td>
                <span className="chip approval">{approval.actionType}</span>
              </td>
              <td className="mono">{approval.actor}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}
