import type { MetadataRoute } from 'next';

import { lastCommitDate } from '@/lib/last-commit';
import { absoluteUrl } from '@/lib/site';
import { pagesInNavOrder } from '@/lib/source';

// Rendered once, at build time: that is where git history is available.
export const dynamic = 'force-static';

/**
 * Served at /docs/sitemap.xml. It has to live under /docs: the marketing
 * site proxies only that prefix, so a root-level sitemap would be
 * unreachable on mandarelabs.com.
 */
export default function sitemap(): MetadataRoute.Sitemap {
  return pagesInNavOrder().map((page) => {
    const lastModified = lastCommitDate(page.absolutePath);
    return {
      url: absoluteUrl(page.url),
      ...(lastModified === undefined ? {} : { lastModified }),
    };
  });
}
