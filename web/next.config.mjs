import createNextIntlPlugin from "next-intl/plugin";

import { fileURLToPath } from "node:url";

// Static export: `NEXT_EXPORT=1 next build` produces a pure static directory in web/out that can be dropped
// straight into the nginx web root. Development (next dev) does not set this variable, keeping the /api proxy and hot reload.
const isExport = process.env.NEXT_EXPORT === "1";

/** @type {import('next').NextConfig} */
const nextConfig = {
  // Prevents a lockfile in a parent directory from affecting root inference and asset path generation.
  turbopack: { root: fileURLToPath(new URL(".", import.meta.url)) },
  reactCompiler: true,
  compiler: {
    removeConsole: process.env.NODE_ENV === "production",
  },
  ...(isExport
    ? {
        // Pure static export: no Node runtime; images are not optimized; each route produces <route>/index.html.
        output: "export",
        images: { unoptimized: true },
        trailingSlash: true,
      }
    : {
        // Development: proxy /api/* to the Go backend (default :8787, overridable with AUTOPENTEST_API).
        async rewrites() {
          const backend = process.env.AUTOPENTEST_API ?? "http://localhost:8787";
          return [{ source: "/api/:path*", destination: `${backend}/api/:path*` }];
        },
      }),
};

// next-intl plugin. Request config lives in src/i18n/request.ts. Since i18n path routing
// is not used, no middleware is added (compatible with static export output: "export").
const withNextIntl = createNextIntlPlugin("./src/i18n/request.ts");

export default withNextIntl(nextConfig);
