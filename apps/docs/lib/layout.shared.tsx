import type { BaseLayoutProps } from 'fumadocs-ui/layouts/shared';

export function baseOptions(): BaseLayoutProps {
  return {
    nav: {
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
    ],
  };
}
