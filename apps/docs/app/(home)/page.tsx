import Link from 'next/link';

export default function HomePage() {
  return (
    <main
      style={{
        flex: 1,
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'center',
        alignItems: 'center',
        textAlign: 'center',
        padding: '4rem 1.5rem',
        gap: '1.2rem',
      }}
    >
      <h1 style={{ fontSize: '2rem', fontWeight: 700, maxWidth: '38rem' }}>
        Give your agents a budget they cannot talk their way out of.
      </h1>
      <p style={{ maxWidth: '40rem', color: 'var(--color-fd-muted-foreground)' }}>
        Mandare is the accountability stack for AI agent fleets: signed agent identity
        (Passport), signed machine-readable authority (Mandate), a tamper-evident ledger of what
        actually happened, an offline kill switch — and external witnessing so even the operator
        cannot rewrite history. Local-first. Open source.
      </p>
      <pre
        style={{
          background: 'var(--color-fd-secondary)',
          padding: '1rem 1.4rem',
          borderRadius: '0.6rem',
          textAlign: 'left',
          fontSize: '0.85rem',
        }}
      >
        {`git clone https://github.com/mandarelabs/mandare && cd mandare
docker compose up -d --wait
docker compose run --rm demo   # a runaway loop dies at the cap, with proof`}
      </pre>
      <div style={{ display: 'flex', gap: '0.8rem' }}>
        <Link
          href="/docs/quickstart"
          style={{
            background: 'var(--color-fd-primary)',
            color: 'var(--color-fd-primary-foreground)',
            padding: '0.55rem 1.1rem',
            borderRadius: '0.5rem',
            fontWeight: 600,
          }}
        >
          Quickstart
        </Link>
        <Link
          href="/docs"
          style={{
            border: '1px solid var(--color-fd-border)',
            padding: '0.55rem 1.1rem',
            borderRadius: '0.5rem',
            fontWeight: 600,
          }}
        >
          Documentation
        </Link>
      </div>
    </main>
  );
}
