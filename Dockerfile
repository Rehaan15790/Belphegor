# syntax=docker/dockerfile:1
# Everything is built from this checkout, so the image contains only the source you reviewed.

FROM node:22-bookworm-slim AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY web/ ./
RUN npm run build:static

FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
COPY --from=web /src/web/out server/webui/dist
RUN CGO_ENABLED=0 go build -tags embedui -trimpath -ldflags "-s -w" -o /belphegor ./cmd/belphegor

FROM node:22-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates python3 ripgrep curl wget vim git jq unzip tini \
      dnsutils netcat-openbsd inetutils-telnet whois nmap \
    && rm -rf /var/lib/apt/lists/*
# Pinned, and installed at build time so agents never download browsers or packages at run time.
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright
# Only Chromium is installed; the Playwright CLI and MCP otherwise look for Google Chrome.
ENV PLAYWRIGHT_MCP_BROWSER=chromium
RUN npm install -g @playwright/mcp@0.0.86 @playwright/cli@0.1.25 playwright@1.65.1 \
    && playwright install --with-deps chromium \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /belphegor /app/belphegor
COPY docker-entrypoint.sh /app/docker-entrypoint.sh
COPY skills/ /app/skills/
# Agents must not be able to replace the program that receives the secrets on the next start, so /app is
# sticky and root-owned: node can add jwt.key but not touch root's files.
RUN sed -i 's/\r$//' /app/docker-entrypoint.sh && chmod 755 /app/docker-entrypoint.sh \
    && mkdir -p /app/data && chown -R node:node /app/data /app/skills && chown root:node /app && chmod 1775 /app
# Agents run shell commands as this user, so it must not be root.
USER node
EXPOSE 8787
ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["-addr", ":8787", "-proxy", "127.0.0.1:8788"]
