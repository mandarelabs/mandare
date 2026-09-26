import Link from 'next/link';

import { formatAmount, ledgerDbPath, readTrail } from '@/lib/data';

export const dynamic = 'force-dynamic';

function chipClass(actionType: string): string {
  if (actionType === 'storage mismatch') return 'chip denied';
  if (actionType.endsWith('.intent')) return 'chip intent';
  if (actionType.endsWith('.result')) return 'chip result';
  if (actionType.endsWith('.denied') || actionType.endsWith('.failed')) return 'chip denied';
  if (actionType === 'agent.revoke') return 'chip revoke';
  if (actionType === 'agent.reinstate' || actionType === 'subject.register') return 'chip register';
  if (actionType.startsWith('approval.')) return 'chip approval';
  return 'chip';
}

export default async function TrailPage({
  searchParams,
}: {
  searchParams: Promise<{ before?: string }>;
}) {
  const params = await searchParams;
  const beforeSeq = params.before === undefined ? undefined : Number.parseInt(params.before, 10);
  const dbPath = ledgerDbPath();
  const rows = readTrail(
    dbPath,
    50,
    beforeSeq !== undefined && Number.isInteger(beforeSeq) && beforeSeq > 0 ? beforeSeq : undefined
  );
  const oldest = rows.at(-1)?.seq;

  return (
    <>
      <h1>Ledger trail</h1>
      {rows.length === 0 ? (
        <div className="empty">
          Nothing here{beforeSeq !== undefined ? ' before that point' : ''} — the ledger at{' '}
          <code>{dbPath}</code> has no entries yet.
        </div>
      ) : (
        <>
          <table>
            <thead>
              <tr>
                <th className="num">Seq</th>
                <th>When</th>
                <th>Action</th>
                <th>Actor</th>
                <th className="num">Amount</th>
                <th>Entry hash</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.seq}>
                  <td className="num">{row.seq}</td>
                  <td className="mono">{row.storageOk ? `${row.ts.slice(0, 19)}Z` : '—'}</td>
                  <td>
                    <span className={chipClass(row.actionType)}>{row.actionType}</span>
                    {row.storageOk ? null : (
                      <div className="dead">stored text has more than one reading — run mandare verify</div>
                    )}
                    {row.target !== null && row.actionType.startsWith('agent.') ? (
                      <div className="mono dead">{row.target}</div>
                    ) : null}
                  </td>
                  <td className="mono">{row.actor}</td>
                  <td className="num">
                    {row.amountMicros > 0 ? formatAmount(row.amountMicros, row.currency) : '—'}
                  </td>
                  <td className="mono">{row.entryHash.slice(0, 16)}…</td>
                </tr>
              ))}
            </tbody>
          </table>
          {oldest !== undefined && oldest > 1 ? (
            <p>
              <Link className="plain" href={`/trail?before=${oldest}`}>
                ← older entries
              </Link>
            </p>
          ) : null}
        </>
      )}
      <p className="hint">
        Every row is an append-only, door-signed ledger entry. Intents reserve budget BEFORE the
        action runs; results settle the true cost; DENIED rows are refusals — recorded no's.
      </p>
    </>
  );
}
