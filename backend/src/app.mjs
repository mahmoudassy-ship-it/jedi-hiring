import fs from 'node:fs'
import http from 'node:http'
import path from 'node:path'
import { createRepository } from './database.mjs'

const contentTypes = {
  '.css': 'text/css; charset=utf-8',
  '.html': 'text/html; charset=utf-8',
  '.ico': 'image/x-icon',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.map': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.woff2': 'font/woff2',
}

function commonHeaders(contentType) {
  return {
    'Content-Type': contentType,
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'X-Content-Type-Options': 'nosniff',
  }
}

function send(response, status, body, contentType, extraHeaders = {}) {
  response.writeHead(status, { ...commonHeaders(contentType), ...extraHeaders })
  response.end(body)
}

function sendJson(response, status, value) {
  send(response, status, JSON.stringify(value), contentTypes['.json'], { 'Cache-Control': 'no-store' })
}

function serveFile(response, file) {
  fs.readFile(file, (error, content) => {
    if (error) return send(response, 404, 'Not found', 'text/plain; charset=utf-8')
    const immutable = /\/assets\/[^/]+-[A-Za-z0-9_-]+\.[^.]+$/.test(file)
    send(response, 200, content, contentTypes[path.extname(file)] || 'application/octet-stream', {
      'Cache-Control': immutable ? 'public, max-age=31536000, immutable' : 'no-cache',
    })
  })
}

function positiveInteger(value, fallback) {
  const parsed = Number(value)
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback
}

export function createApplication({ databasePath, frontendDirectory }) {
  const repository = createRepository(databasePath)
  const server = http.createServer((request, response) => {
    try {
      const url = new URL(request.url || '/', `http://${request.headers.host || 'localhost'}`)

      if (url.pathname.startsWith('/api/') && request.method !== 'GET') {
        return sendJson(response, 405, { error: 'Method not allowed' })
      }

      if (url.pathname === '/health') {
        return sendJson(response, 200, { status: 'ok' })
      }

      if (url.pathname === '/api/overview') {
        return sendJson(response, 200, repository.getOverview())
      }

      if (url.pathname === '/api/taxonomies') {
        return sendJson(response, 200, repository.getTaxonomies())
      }

      if (url.pathname === '/api/requirements') {
        return sendJson(response, 200, repository.listRequirements({
          q: url.searchParams.get('q') || '',
          stage: url.searchParams.get('stage') || '',
          lens: url.searchParams.get('lens') || '',
          effect: url.searchParams.get('effect') || '',
          status: url.searchParams.get('status') || '',
          page: positiveInteger(url.searchParams.get('page'), 1),
          pageSize: positiveInteger(url.searchParams.get('page_size'), 25),
        }))
      }

      const requirementMatch = url.pathname.match(/^\/api\/requirements\/([a-z0-9-]+)$/)
      if (requirementMatch) {
        const requirement = repository.getRequirement(requirementMatch[1])
        return requirement
          ? sendJson(response, 200, requirement)
          : sendJson(response, 404, { error: 'Requirement not found' })
      }

      if (url.pathname === '/api/instruments') {
        return sendJson(response, 200, repository.listInstruments())
      }

      if (url.pathname === '/api/jurisdictions') {
        return sendJson(response, 200, repository.listJurisdictions())
      }

      if (url.pathname.startsWith('/api/')) {
        return sendJson(response, 404, { error: 'Not found' })
      }

      let decodedPath
      try {
        decodedPath = decodeURIComponent(url.pathname)
      } catch {
        return send(response, 400, 'Bad request', 'text/plain; charset=utf-8')
      }

      const requestedFile = path.resolve(frontendDirectory, `.${decodedPath}`)
      if (
        requestedFile.startsWith(`${frontendDirectory}${path.sep}`)
        && fs.existsSync(requestedFile)
        && fs.statSync(requestedFile).isFile()
      ) {
        return serveFile(response, requestedFile)
      }

      const indexFile = path.join(frontendDirectory, 'index.html')
      if (fs.existsSync(indexFile)) return serveFile(response, indexFile)
      return send(response, 404, 'Frontend is not built', 'text/plain; charset=utf-8')
    } catch (error) {
      console.error(error)
      return sendJson(response, 500, { error: 'Internal server error' })
    }
  })

  async function close() {
    if (server.listening) {
      await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()))
    }
    repository.close()
  }

  return { close, server }
}
