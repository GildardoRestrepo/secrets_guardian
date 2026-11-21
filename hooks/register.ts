import type { EngineInterface, Register } from 'claude-code'
import {
  ALLOW_FILE,
  formatFindings,
  parseGitAction,
  scanDiff,
  scanFile,
  withoutAllowed,
  type Finding,
  type GitAction,
} from './scan'

const MAX_UNTRACKED_BYTES = 512 * 1024

async function git($: EngineInterface, args: string[], cwd?: string) {
  return $.process.run(['git', '-c', 'core.quotePath=false', ...args], { cwd, timeoutMs: 60_000 })
}

async function readAllowList($: EngineInterface, top: string): Promise<string | undefined> {
  try {
    return await $.fs.read(`${top}/${ALLOW_FILE}`)
  } catch {
    return undefined // el repo no tiene lista de permitidos
  }
}

/** Busca secretos en lo que el comando git va a guardar o publicar. */
async function collectFindings($: EngineInterface, action: GitAction): Promise<Finding[] | undefined> {
  const inRepo = await git($, ['rev-parse', '--show-toplevel'], action.cwd)
  if (inRepo.exitCode !== 0) return undefined // no es un repo: que git mismo responda
  const top = inRepo.stdout.trim()

  const found: Finding[] = []

  if (action.kind === 'push') {
    // Todo lo que aún no está en ningún remoto (en el primer push, toda la historia).
    const log = await git($, ['log', '-p', '--format=', '--no-color', '--no-ext-diff', 'HEAD', '--not', '--remotes'], action.cwd)
    if (log.exitCode === 0) found.push(...scanDiff(log.stdout))
  } else {
    const staged = await git($, ['diff', '--cached', '--no-color', '--no-ext-diff'], action.cwd)
    if (staged.exitCode === 0) found.push(...scanDiff(staged.stdout))

    if (action.includesUnstaged) {
      const unstaged = await git($, ['diff', '--no-color', '--no-ext-diff'], action.cwd)
      if (unstaged.exitCode === 0) found.push(...scanDiff(unstaged.stdout))

      // Desde la raíz, para que las rutas sean relativas a ella.
      const others = await git($, ['ls-files', '--others', '--exclude-standard', '-z'], top)
      for (const rel of others.stdout.split('\0').filter(Boolean)) {
        try {
          const content = await $.fs.read(`${top}/${rel}`, { length: MAX_UNTRACKED_BYTES })
          if (content.includes('\0')) continue // binario
          found.push(...scanFile(rel, content))
        } catch {
          // ilegible: lo ignoramos
        }
      }
    }
  }

  const seen = new Set<string>()
  return withoutAllowed(found, await readAllowList($, top)).filter(f => {
    const key = `${f.file}:${f.line}:${f.kind}`
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}

function denyMessage(action: GitAction, findings: Finding[]): string {
  const verb = action.kind === 'push' ? 'publicar (push)' : 'hacer commit de'
  return [
    `guardian-secretos bloqueó este git ${action.kind}: estás a punto de ${verb} lo que parecen secretos.`,
    formatFindings(findings),
    '',
    'Qué hacer:',
    '  1. Mover el valor a un archivo ignorado por git (p. ej. secrets.h / .env en .gitignore) o a una variable de entorno, y dejar un placeholder en el código.',
    action.kind === 'push'
      ? '  2. Si ya quedó en un commit, hay que reescribir ese commit antes de hacer push (y rotar la credencial si ya se publicó antes).'
      : '  2. Sacarlo del área de preparación (git restore --staged <archivo>) si no debía ir.',
    '  3. Si es un falso positivo, la persona puede confirmarlo; entonces se agrega el comentario `secret-guard: allow` en esa línea.',
    `  4. Si el equipo decidió versionar ese secreto a propósito, la persona puede agregar la ruta a ${ALLOW_FILE} en la raíz del repo.`,
    'No reintentes el mismo comando sin cambiar nada ni intentes esquivar el guardián: pregúntale a la persona.',
  ].join('\n')
}

async function guard($: EngineInterface, command: string) {
  const action = parseGitAction(command)
  if (!action) return undefined

  $.ui.status(`🔒 revisando git ${action.kind}…`)
  try {
    const findings = await collectFindings($, action)
    if (!findings || findings.length === 0) return undefined

    const n = findings.length
    $.ui.toast(`🔒 guardián: git ${action.kind} bloqueado (${n} posible${n === 1 ? '' : 's'} secreto${n === 1 ? '' : 's'})`, { timeoutMs: 8000 })
    return { deny: denyMessage(action, findings) }
  } finally {
    $.ui.status(undefined)
  }
}

const FAILED = {
  deny: 'guardian-secretos: no pude revisar este comando git, así que lo detuve por seguridad. Pídele a la persona que lo revise o lo ejecute ella misma.',
}

export const register: Register = on => {
  on('tool.call', { tool: 'Bash' }, async ($, e, next) => (await guard($, e.command)) ?? next(e))
    .catch(($, e, next) => (next.called ? next(e) : FAILED))

  on('tool.call', { tool: 'PowerShell' }, async ($, e, next) => (await guard($, e.command)) ?? next(e))
    .catch(($, e, next) => (next.called ? next(e) : FAILED))
}
