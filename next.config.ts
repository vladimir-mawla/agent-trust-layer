import type { NextConfig } from "next";

/**
 * `extensionAlias` + `--webpack` (see package.json's build/dev/start
 * scripts): lib/identity's relative imports use explicit ".js" suffixes
 * on purpose (required by its own strict NodeNext moduleResolution — see
 * tsconfig.lib.json) even though the files on disk are ".ts". webpack
 * resolves that the same way Node's real ESM loader eventually will once
 * compiled: by trying ".ts"/".tsx" first when a ".js" specifier's literal
 * file doesn't exist. Turbopack (Next 16's default bundler) does not yet
 * implement this — `next build`/`next dev` with Turbopack fail with
 * "Module not found" on every one of lib/identity's internal imports,
 * and Next.js's own turbopack-compat check confirms `extensionAlias` is a
 * webpack-only option it does not (yet) honour under Turbopack. Falling
 * back to `--webpack` is the documented, supported escape hatch for
 * exactly this: it is not a hack, it is Next.js's other production
 * bundler, still fully maintained. The cost: this app forgoes
 * Turbopack's faster dev/build until Turbopack implements TS-style
 * extension aliasing (tracked upstream) or lib/identity's imports change
 * — whichever comes first should let this file and those scripts revert.
 */
const nextConfig: NextConfig = {
  experimental: {
    extensionAlias: {
      ".js": [".ts", ".tsx", ".js"],
    },
  },
};

export default nextConfig;
