import type { Metadata } from 'next';

/**
 * The docs are served at mandarelabs.com/docs through a proxy rewrite, so
 * every absolute URL this app emits (canonicals, share tags, sitemap,
 * llms.txt) is on that origin, never on the deployment's own host.
 */
export const SITE_ORIGIN = 'https://mandarelabs.com';
export const SITE_NAME = 'Mandare';
export const SITE_TITLE = 'Mandare — the accountability stack for AI agent fleets';
export const SITE_DESCRIPTION =
  'Signed agent identity, signed spending mandates, a tamper-evident action ledger, and a kill switch that works offline. Local-first, open source.';

// Hosted by the marketing site, outside this app.
const SHARE_IMAGE = { url: `${SITE_ORIGIN}/og.png`, width: 1200, height: 630 };

export function absoluteUrl(path: string): string {
  return `${SITE_ORIGIN}${path}`;
}

interface ShareInput {
  title: string;
  description?: string | undefined;
  /** The page's canonical path. Omit where no single page is meant (the root layout's defaults). */
  path?: string;
  type?: 'website' | 'article';
}

/**
 * Open Graph + Twitter tags. Next replaces `openGraph`/`twitter` wholesale
 * per segment instead of merging them, so each page builds the complete set.
 */
export function shareMetadata(input: ShareInput): Pick<Metadata, 'openGraph' | 'twitter'> {
  const { title, description, path, type = 'website' } = input;
  const text = description === undefined ? {} : { description };
  return {
    openGraph: {
      title,
      ...text,
      ...(path === undefined ? {} : { url: absoluteUrl(path) }),
      siteName: SITE_NAME,
      type,
      images: [SHARE_IMAGE],
    },
    twitter: {
      card: 'summary_large_image',
      title,
      ...text,
      images: [SHARE_IMAGE.url],
    },
  };
}
