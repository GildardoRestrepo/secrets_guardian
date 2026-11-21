// Revisión para los hooks de git (commits y pushes hechos a mano).
// Usa las mismas reglas que el mod de Claude: ../hooks/scan.ts
// Uso: node check.ts pre-commit   |   node check.ts pre-push  (refs por stdin)
import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { ALLOW_FILE, formatFindings, scanDiff, withoutAllowed, type Finding } from '../hooks/scan.ts'

const ZERO = /^0+$/

function git(args: string[]): string {
  return execFileSync('git', ['-c', 'core.quotePath=false', ...args], { encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 })
}

function allowList(): string | undefined {
  try {
    return readFileSync(join(git(['rev-parse', '--show-toplevel']).trim(), ALLOW_FILE), 'utf8')
  } catch {
    return undefined // el repo no tiene lista de permitidos
  }
}

function preCommit(): Finding[] {
  return scanDiff(git(['diff', '--cached', '--no-color', '--no-ext-diff']))
}

function prePush(): Finding[] {
  const found: Finding[] = []
  for (const line of readFileSync(0, 'utf8').split('\n')) {
    const [, localSha, , remoteSha] = line.trim().split(/\s+/)
    if (!localSha || ZERO.test(localSha)) continue // borrar una rama: nada que revisar
    const range = !remoteSha || ZERO.test(remoteSha)
      ? [localSha, '--not', '--remotes'] // rama nueva: lo que aún no está en ningún remoto
      : [`${remoteSha}..${localSha}`]
    found.push(...scanDiff(git(['log', '-p', '--format=', '--no-color', '--no-ext-diff', ...range])))
  }
  return found
}

const mode = process.argv[2]
const findings = withoutAllowed(mode === 'pre-push' ? prePush() : preCommit(), allowList())

if (findings.length > 0) {
  const what = mode === 'pre-push' ? 'push' : 'commit'
  console.error(`\n🔒 secrets_guardian bloqueó este ${what}: hay lo que parecen secretos.\n`)
  console.error(formatFindings(findings, 20))
  console.error(`
Qué hacer:
  - Mueve el valor a un archivo ignorado (secrets.h, .env) o a una variable de entorno y deja un placeholder.
  - Falso positivo: agrega el comentario  secret-guard: allow  en esa línea.
  - Secreto versionado a propósito por el equipo: agrega la ruta a ${ALLOW_FILE} en la raíz del repo.
  - Si estás seguro y quieres saltarte la revisión una vez:  git ${what} --no-verify
`)
  process.exit(1)
}
