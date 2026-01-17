import type { BaseLayoutProps } from 'fumadocs-ui/layouts/shared'

export function baseOptions(): BaseLayoutProps {
  return {
    nav: {
      title: 'BetterAuthGoServer',
    },
    links: [
      {
        text: 'GitHub',
        url: 'https://github.com/webdeveloperben/BetterAuthGoServer',
      },
    ],
  }
}
