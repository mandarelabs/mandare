import type { Metadata } from 'next';
import { RootProvider } from 'fumadocs-ui/provider';
import './global.css';

export const metadata: Metadata = {
  title: {
    template: '%s — Mandare',
    default: 'Mandare — the accountability stack for AI agent fleets',
  },
  description:
    'Verified agent identity, signed spending mandates, a tamper-evident action ledger, and a kill switch that works offline. Local-first, open source.',
};

export default function Layout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body style={{ display: 'flex', flexDirection: 'column', minHeight: '100vh' }}>
        <RootProvider>{children}</RootProvider>
      </body>
    </html>
  );
}
