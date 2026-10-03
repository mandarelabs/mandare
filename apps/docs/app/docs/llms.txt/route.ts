import { llmsIndex } from '@/lib/llms';
import { SITE_NAME } from '@/lib/site';
import { pagesInNavOrder, source } from '@/lib/source';

export const dynamic = 'force-static';

export function GET(): Response {
  // The summary is the index page's own description, so it cannot drift from the docs.
  const summary = source.getPage([])?.data.description;
  if (summary === undefined) {
    throw new Error('llms.txt: content/docs/index.mdx needs a description');
  }
  const pages = pagesInNavOrder().map((page) => ({
    title: page.data.title,
    description: page.data.description,
    url: page.url,
  }));
  const body = llmsIndex(
    { title: `${SITE_NAME} documentation`, summary, fullTextUrl: '/docs/llms-full.txt' },
    pages
  );
  return new Response(body, { headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
}
