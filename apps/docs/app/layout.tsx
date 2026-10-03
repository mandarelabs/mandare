import type { Metadata } from 'next';
import { RootProvider } from 'fumadocs-ui/provider';
import { SITE_DESCRIPTION, SITE_NAME, SITE_ORIGIN, SITE_TITLE, shareMetadata } from '@/lib/site';
import './global.css';

export const metadata: Metadata = {
  metadataBase: new URL(SITE_ORIGIN),
  title: {
    template: `%s — ${SITE_NAME}`,
    default: SITE_TITLE,
  },
  description: SITE_DESCRIPTION,
  ...shareMetadata({ title: SITE_TITLE, description: SITE_DESCRIPTION }),
};

export default function Layout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body style={{ display: 'flex', flexDirection: 'column', minHeight: '100vh' }}>
        <RootProvider search={{ options: { api: '/docs/api/search' } }}>{children}</RootProvider>
      </body>
    </html>
  );
}
