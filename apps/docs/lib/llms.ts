import { SITE_ORIGIN, absoluteUrl } from './site';

export interface LlmsPage {
  title: string;
  description?: string | undefined;
  /** Site-relative URL, e.g. `/docs/quickstart`. */
  url: string;
}

interface LlmsSite {
  title: string;
  summary: string;
  /** Site-relative URL of the single-file version (llms-full.txt). */
  fullTextUrl: string;
}

const FRONTMATTER = /^---\r?\n[\s\S]*?\r?\n---\r?\n/;
const CALLOUT = /^<Callout\b([^>]*)>\n([\s\S]*?)\n<\/Callout>\n*/gm;

/** `<Callout>` is the one MDX component the pages use; in Markdown it is a labelled blockquote. */
function calloutsToBlockquotes(markdown: string): string {
  return markdown.replace(CALLOUT, (_match, attributes: string, inner: string) => {
    const type = /\btype="(\w+)"/.exec(attributes)?.[1];
    const label = type === 'warn' || type === 'warning' ? 'Warning' : type === 'error' ? 'Error' : 'Note';
    const quoted = `**${label}:** ${inner}`
      .split('\n')
      .map((line) => (line === '' ? '>' : `> ${line}`))
      .join('\n');
    return `${quoted}\n\n`;
  });
}

/** llms.txt in the llmstxt.org shape: H1, blockquote summary, one link line per page. */
export function llmsIndex(site: LlmsSite, pages: readonly LlmsPage[]): string {
  const lines = pages.map((page) => {
    const link = `- [${page.title}](${absoluteUrl(page.url)})`;
    return page.description === undefined ? link : `${link}: ${page.description}`;
  });
  return [
    `# ${site.title}`,
    '',
    `> ${site.summary}`,
    '',
    `Every page below as one Markdown file: ${absoluteUrl(site.fullTextUrl)}`,
    '',
    '## Docs',
    '',
    ...lines,
    '',
  ].join('\n');
}

/**
 * One page of llms-full.txt: title, canonical URL and description, then the
 * page's Markdown. fumadocs-mdx 11 exposes no Markdown export, and the pages
 * are Markdown/GFM plus `<Callout>`, so the source file is converted here:
 * frontmatter dropped, callouts turned into blockquotes, site-relative links
 * made absolute (the file is read out of context). test/llms.test.ts runs
 * this over every real page and fails if any other MDX syntax survives.
 */
export function llmsPageText(page: LlmsPage, fileContent: string): string {
  const body = calloutsToBlockquotes(fileContent.replace(FRONTMATTER, ''))
    .replaceAll('](/docs', `](${SITE_ORIGIN}/docs`)
    .trim();
  const head = [`# ${page.title}`, `URL: ${absoluteUrl(page.url)}`];
  if (page.description !== undefined) {
    head.push(page.description);
  }
  return [...head, body].join('\n\n');
}

export function llmsFull(pages: readonly string[]): string {
  return `${pages.join('\n\n---\n\n')}\n`;
}
