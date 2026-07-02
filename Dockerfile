FROM node:22-alpine AS builder
WORKDIR /app

COPY package.json ./
RUN npm install

COPY tsconfig.json ./
COPY tsup.config.ts ./
COPY src ./src
RUN npm run build


FROM node:22-alpine
WORKDIR /app

RUN npm install --prefix /app @libsql/client@^0.14.0 ioredis@^5.0.0 --omit=dev

RUN echo '{"type":"module"}' > package.json

COPY --from=builder /app/dist ./dist

ENV NODE_ENV=production
ENV PORT=3000

EXPOSE 3000

CMD ["node", "dist/index.js"]
