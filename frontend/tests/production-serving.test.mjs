import assert from 'node:assert/strict'
import fs from 'node:fs'
import test from 'node:test'

function source(path) {
  return fs.readFileSync(
    new URL(`../${path}`, import.meta.url),
    'utf8',
  )
}

test(
  'frontend Dockerfile builds with Node and runs with Nginx',
  () => {
    const dockerfile = source('Dockerfile')

    assert.match(
      dockerfile,
      /FROM node:22-alpine@sha256:[a-f0-9]{64} AS build/,
    )

    assert.match(
      dockerfile,
      /RUN npm ci/,
    )

    assert.match(
      dockerfile,
      /RUN npm run build/,
    )

    assert.match(
      dockerfile,
      /FROM nginx:alpine@sha256:[a-f0-9]{64} AS runtime/,
    )

    assert.match(
      dockerfile,
      /COPY --from=build \/app\/dist \/usr\/share\/nginx\/html/,
    )

    assert.match(
      dockerfile,
      /COPY nginx\.conf \/etc\/nginx\/conf\.d\/default\.conf/,
    )

    assert.match(
      dockerfile,
      /EXPOSE 80/,
    )

    assert.doesNotMatch(
      dockerfile,
      /npm.*run.*dev/,
    )

    assert.doesNotMatch(
      dockerfile,
      /EXPOSE 5173/,
    )
  },
)

test(
  'frontend runtime Nginx serves the SPA and proxies backend traffic',
  () => {
    const nginxUrl =
      new URL('../nginx.conf', import.meta.url)

    assert.equal(
      fs.existsSync(nginxUrl),
      true,
      'frontend/nginx.conf must exist',
    )

    const nginx = source('nginx.conf')

    assert.match(
      nginx,
      /listen 80;/,
    )

    assert.match(
      nginx,
      /root \/usr\/share\/nginx\/html;/,
    )

    assert.match(
      nginx,
      /try_files \$uri \$uri\/ \/index\.html;/,
    )

    assert.match(
      nginx,
      /location \/api\//,
    )

    assert.match(
      nginx,
      /location = \/health/,
    )

    const backendProxyMatches =
      nginx.match(
        /proxy_pass http:\/\/\$backend_upstream;/g,
      ) ?? []

    assert.equal(
      backendProxyMatches.length,
      2,
    )
  },
)

test(
  'frontend Nginx re-resolves backend through Docker DNS',
  () => {
    const nginx = source('nginx.conf')

    assert.match(
      nginx,
      /resolver\s+127\.0\.0\.11\s+valid=5s\s+ipv6=off;/,
    )

    assert.match(
      nginx,
      /resolver_timeout\s+2s;/,
    )

    assert.match(
      nginx,
      /set\s+\$backend_upstream\s+backend:8000;/,
    )

    const dynamicProxyMatches =
      nginx.match(
        /proxy_pass\s+http:\/\/\$backend_upstream;/g,
      ) ?? []

    assert.equal(
      dynamicProxyMatches.length,
      2,
    )

    assert.doesNotMatch(
      nginx,
      /proxy_pass\s+http:\/\/backend:8000;/,
    )
  },
)
