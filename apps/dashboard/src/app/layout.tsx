import type { Metadata } from 'next';
import Link from 'next/link';
import './globals.css';

export const metadata: Metadata = {
  title: 'Mandare — fleet view',
  description: 'Local-first accountability dashboard: agents, spend, the ledger trail, and the kill switch.',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <header className="topbar">
          <div className="topbar-inner">
            <Link href="/" className="brand">
              <span className="brand-mark">▣</span> mandare
            </Link>
            <nav>
              <Link href="/">Fleet</Link>
              <Link href="/trail">Ledger trail</Link>
            </nav>
            <span className="topbar-note">local-first · no telemetry</span>
          </div>
        </header>
        <main className="page">{children}</main>
        <footer className="footer">
          Everything on this page is derived from the ledger — the same
          <code> mandare verify</code> an auditor runs. Reads are read-only; the
          only write is the kill switch.
        </footer>
      </body>
    </html>
  );
}
