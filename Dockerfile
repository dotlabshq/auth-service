# DEPRECATED — use Dockerfile.workspace, built from the monorepo root.
#
# auth-service now depends on workspace packages (@baseworks/auth, @baseworks/core)
# and `npm ci` cannot resolve `workspace:*`. This file is kept for reference only;
# it builds a release whose @baseworks dependencies all came from the registry.
#
FROM node:22-alpine AS builder
WORKDIR /app

# package-lock.json da kopyalanır ve npm ci kullanılır: lock'suz `npm install` her
# build'de registry'yi yeniden çözüyordu; 2026-09-08'de npm 10.9 bir @baseworks sürümünde
# 'Cannot read properties of null (reading edgesOut)' ile çöktü ve imaj üretilemedi.
# 0.2.2 aylardır cache'ten geçtiği için görünmemişti.
COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json ./
COPY tsup.config.ts ./
COPY src ./src
RUN npm run build


FROM node:22-alpine
WORKDIR /app

RUN npm install --prefix /app ioredis@^5.0.0 libsodium-wrappers@^0.7.16 libsodium@^0.7.16 --omit=dev && \
    cp /app/node_modules/libsodium/dist/modules-esm/libsodium.mjs \
       /app/node_modules/libsodium-wrappers/dist/modules-esm/libsodium.mjs

RUN echo '{"type":"module"}' > package.json

COPY --from=builder /app/dist ./dist

ENV NODE_ENV=production
ENV PORT=3000

EXPOSE 3000

CMD ["node", "dist/index.js"]
