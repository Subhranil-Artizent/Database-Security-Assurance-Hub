# syntax=docker/dockerfile:1.7

ARG NODE_VERSION=22.13.0

FROM node:${NODE_VERSION}-alpine AS dependencies
WORKDIR /workspace
COPY package.json package-lock.json ./
COPY vendor ./vendor
RUN npm ci --ignore-scripts

FROM node:${NODE_VERSION}-alpine AS builder
ARG CONSOLE_DATA_MODE=api
ARG ASSURANCE_API_BASE_URL=http://api:8000
ENV NEXT_TELEMETRY_DISABLED=1 \
    CONSOLE_DATA_MODE=${CONSOLE_DATA_MODE} \
    ASSURANCE_API_BASE_URL=${ASSURANCE_API_BASE_URL}
WORKDIR /workspace
COPY --from=dependencies /workspace/node_modules ./node_modules
COPY --from=dependencies /workspace/vendor ./vendor
COPY package.json package-lock.json ./
COPY app ./app
COPY components ./components
COPY public ./public
COPY worker ./worker
COPY build ./build
COPY .openai ./.openai
COPY scripts/local-console-auth.mjs scripts/local-synthetic-collection.mjs ./scripts/
COPY next.config.ts next-env.d.ts postcss.config.mjs tsconfig.json vite.config.ts ./
RUN npm run build

FROM node:${NODE_VERSION}-alpine AS runtime

# This image is a reproducible, scan-ready web build artifact. The protected
# console is intentionally not deployed from this image: only private Sites
# dispatch provides the trusted sign-in and identity-header boundary.
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    HOST=0.0.0.0 \
    PORT=3000
WORKDIR /workspace

COPY --from=dependencies --chown=node:node /workspace/node_modules ./node_modules
COPY --from=dependencies --chown=node:node /workspace/vendor ./vendor
COPY --from=builder --chown=node:node /workspace/dist ./dist
COPY --from=builder --chown=node:node /workspace/package.json ./package.json

USER node
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:3000/').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"]

CMD ["npm", "run", "start", "--", "--host", "0.0.0.0", "--port", "3000"]
