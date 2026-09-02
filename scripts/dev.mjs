import { spawn } from 'node:child_process'

const children = [
  spawn('npm', ['run', 'dev', '--workspace', 'backend'], {
    env: { ...process.env, HOST: '127.0.0.1', PORT: '3101' },
    stdio: 'inherit',
  }),
  spawn('npm', ['run', 'dev', '--workspace', 'frontend'], {
    env: process.env,
    stdio: 'inherit',
  }),
]

let stopping = false

function stop(signal = 'SIGTERM') {
  if (stopping) return
  stopping = true
  for (const child of children) {
    if (!child.killed) child.kill(signal)
  }
}

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.once(signal, () => stop(signal))
}

for (const child of children) {
  child.once('exit', (code) => {
    if (!stopping) {
      stop()
      process.exitCode = code || 0
    }
  })
}
