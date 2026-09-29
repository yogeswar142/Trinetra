import type { NextConfig } from 'next';

const apiOrigin = process.env.API_INTERNAL_URL ?? 'http://127.0.0.1:8765';

const nextConfig: NextConfig = {
  async redirects() {
    return [
      { source: '/threats', destination: '/alerts', permanent: false },
      { source: '/hunt', destination: '/alerts', permanent: false },
      { source: '/detectors', destination: '/sensor', permanent: false },
      { source: '/models', destination: '/sensor', permanent: false },
      { source: '/exports', destination: '/ledger', permanent: false },
    ];
  },
  async rewrites() {
    return [
      {
        source: '/api/:path*',
        destination: `${apiOrigin}/api/:path*`,
      },
      {
        source: '/openapi.json',
        destination: `${apiOrigin}/api/openapi.json`,
      },
    ];
  },
  output: 'standalone',
};

export default nextConfig;
