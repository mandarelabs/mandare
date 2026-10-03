import { llmsFull, llmsPageText } from '@/lib/llms';
import { pagesInNavOrder } from '@/lib/source';

// Built once: `page.data.content` reads the page's source file from disk.
export const dynamic = 'force-static';

export function GET(): Response {
  const pages = pagesInNavOrder().map((page) =>
    llmsPageText(
      { title: page.data.title, description: page.data.description, url: page.url },
      page.data.content
    )
  );
  return new Response(llmsFull(pages), { headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
}
