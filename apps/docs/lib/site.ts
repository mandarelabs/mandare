/**
 * The docs are served at mandarelabs.com/docs through a proxy rewrite, so
 * every absolute URL this app emits (canonicals, share tags, sitemap,
 * llms.txt) is on that origin, never on the deployment's own host.
 */
export const SITE_ORIGIN = 'https://mandarelabs.com';
export const SITE_NAME = 'Mandare';

export function absoluteUrl(path: string): string {
  return `${SITE_ORIGIN}${path}`;
}
