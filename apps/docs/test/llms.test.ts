import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

import { llmsFull, llmsIndex, llmsPageText } from '../lib/llms';

const contentDir = join(dirname(fileURLToPath(import.meta.url)), '..', 'content', 'docs');

describe('llms.txt', () => {
  it('lists every page with an absolute URL and its description', () => {
    const text = llmsIndex(
      { title: 'Mandare documentation', summary: 'A summary.', fullTextUrl: '/docs/llms-full.txt' },
      [
        { title: 'What is Mandare?', description: 'The overview.', url: '/docs' },
        { title: 'Quickstart', url: '/docs/quickstart' },
      ]
    );
    expect(text.startsWith('# Mandare documentation\n\n> A summary.\n')).toBe(true);
    expect(text).toContain('https://mandarelabs.com/docs/llms-full.txt');
    expect(text).toContain('- [What is Mandare?](https://mandarelabs.com/docs): The overview.');
    expect(text).toContain('- [Quickstart](https://mandarelabs.com/docs/quickstart)\n');
  });
});

describe('llms-full.txt', () => {
  const page = { title: 'Concepts', description: 'The model.', url: '/docs/concepts' };

  it('drops the frontmatter and heads the page with title, URL and description', () => {
    const text = llmsPageText(page, '---\ntitle: Concepts\ndescription: The model.\n---\n\n## Door\n\nBody.\n');
    expect(text).toBe(
      '# Concepts\n\nURL: https://mandarelabs.com/docs/concepts\n\nThe model.\n\n## Door\n\nBody.'
    );
  });

  it('makes site-relative links absolute and leaves others alone', () => {
    const text = llmsPageText(
      page,
      '---\ntitle: Concepts\n---\nSee the [threat model](/docs/threat-model) and [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421).\n'
    );
    expect(text).toContain('[threat model](https://mandarelabs.com/docs/threat-model)');
    expect(text).toContain('[RFC 9421](https://www.rfc-editor.org/rfc/rfc9421)');
  });

  it('separates pages with a rule', () => {
    expect(llmsFull(['# A', '# B'])).toBe('# A\n\n---\n\n# B\n');
  });

  it('turns a Callout into a labelled blockquote, set off from the next paragraph', () => {
    const text = llmsPageText(
      page,
      '---\ntitle: Concepts\n---\nBefore.\n\n<Callout type="warn">\nFirst line\nsecond line.\n</Callout>\nAfter.\n'
    );
    expect(text).toContain('Before.\n\n> **Warning:** First line\n> second line.\n\nAfter.');
  });

  /**
   * llms-full.txt is built from each page's source, not from a Markdown
   * export. That only yields Markdown while the pages use nothing beyond
   * Markdown/GFM and `<Callout>`. If this fails, teach llmsPageText the new
   * syntax (or move to a remark pipeline) instead of loosening the test.
   */
  it('leaves no MDX-only syntax in any real page', () => {
    const files = readdirSync(contentDir, { recursive: true, encoding: 'utf8' }).filter((file) =>
      file.endsWith('.mdx')
    );
    expect(files.length).toBeGreaterThan(0);
    for (const file of files) {
      const prose = llmsPageText(page, readFileSync(join(contentDir, file), 'utf8'))
        .replace(/^(```|~~~)[\s\S]*?^\1/gm, '')
        .replace(/`[^`\n]*`/g, '');
      expect(prose, file).not.toMatch(/^(import|export)\s/m);
      expect(prose, file).not.toMatch(/<\/?[A-Z][A-Za-z0-9.]*[\s/>]/);
    }
  });
});
