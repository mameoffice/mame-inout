FROM node:24.22.3-bookworm-slim AS build
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
COPY package.json package-lock.json .npmrc ./
COPY apps/api/package.json apps/api/package.json
COPY apps/web/package.json apps/web/package.json
COPY packages/contracts/package.json packages/contracts/package.json
RUN npm ci --no-audit --no-fund
COPY tsconfig.base.json ./
COPY eslint.config.mjs vitest.config.ts ./
COPY apps apps
COPY packages packages
COPY scripts scripts
COPY tests tests
RUN npm run generate && npm run build && npm run typecheck && npm run lint && npm test

FROM node:24.22.3-bookworm-slim AS api-dependencies
WORKDIR /app
COPY package.json package-lock.json .npmrc ./
COPY apps/api/package.json apps/api/package.json
COPY packages/contracts/package.json packages/contracts/package.json
# 同じロックで検証したキャッシュを使い、APIに必要な依存だけを別に組み立てる。
COPY --from=build /root/.npm /root/.npm
# 任意のpeer経由でテストツールが残るため、devだけでなくpeer・optionalも除く。
# Prismaの生成はbuild段階で済ませ、実行時にCLIやインストールスクリプトを要求しない。
RUN npm ci --offline --workspace=@mame/api --workspace=@mame/contracts \
    --omit=dev --omit=peer --omit=optional --ignore-scripts --no-audit --no-fund
COPY scripts/check-api-runtime.mjs scripts/check-api-runtime.mjs
RUN node scripts/check-api-runtime.mjs

FROM node:24.22.3-bookworm-slim AS runtime
# 実行時はNodeだけを使う。同梱npmの依存を攻撃対象へ残さず、ビルド段階とは分離する。
RUN rm -rf /usr/local/lib/node_modules/npm \
    && rm -f /usr/local/bin/npm /usr/local/bin/npx

FROM runtime AS api
WORKDIR /app
ENV NODE_ENV=production
COPY --from=api-dependencies /app/node_modules ./node_modules
COPY --from=build /app/packages/contracts/package.json ./packages/contracts/package.json
COPY --from=build /app/packages/contracts/dist ./packages/contracts/dist
COPY --from=build /app/apps/api/package.json ./apps/api/package.json
COPY --from=build /app/apps/api/dist ./apps/api/dist
COPY --from=build /app/apps/api/prisma ./apps/api/prisma
USER 1000:1000
WORKDIR /app/apps/api
CMD ["node", "dist/server.js"]

FROM runtime AS web
WORKDIR /app
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 HOSTNAME=0.0.0.0 PORT=3000
COPY --from=build --chown=1000:1000 /app/apps/web/.next/standalone ./
COPY --from=build --chown=1000:1000 /app/apps/web/.next/static ./apps/web/.next/static
COPY --from=build --chown=1000:1000 /app/apps/web/public ./apps/web/public
USER 1000:1000
CMD ["node", "apps/web/server.js"]

FROM build AS tests
COPY tests tests
COPY vitest.integration.config.ts ./
USER 1000:1000
CMD ["npm", "run", "test:integration"]
