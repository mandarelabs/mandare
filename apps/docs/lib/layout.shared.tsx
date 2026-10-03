import type { BaseLayoutProps } from 'fumadocs-ui/layouts/shared';

export function baseOptions(): BaseLayoutProps {
  return {
    nav: {
      // The site is served at mandarelabs.com/docs; "/" there is the static
      // marketing page, which the Next router cannot client-navigate into.
      url: '/docs',
      title: (
        <>
          <span style={{ color: 'var(--color-fd-primary)' }}>▣</span>&nbsp;mandare
        </>
      ),
    },
    githubUrl: 'https://github.com/mandarelabs/mandare',
    links: [
      { text: 'Quickstart', url: '/docs/quickstart' },
      { text: 'Threat model', url: '/docs/threat-model' },
      // Absolute on purpose: the journal is a static page outside this app,
      // like "/" above.
      { text: 'Journal', url: 'https://mandarelabs.com/journal' },
    ],
  };
}
