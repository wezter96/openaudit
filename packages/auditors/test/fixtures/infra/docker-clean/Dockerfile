FROM node:22.11-alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci && npm run build

FROM gcr.io/distroless/nodejs22-debian12:nonroot@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
COPY --from=build /app/dist /app
USER 65532
HEALTHCHECK CMD ["/nodejs/bin/node", "/app/health.js"]
CMD ["/app/server.js"]
