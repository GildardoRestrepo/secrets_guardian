// Lógica pura del guardián: qué comando git es, y qué líneas de un diff
// parecen secretos. Sin acceso a $, para poder probarla aislada.

export type GitAction = {
  kind: 'commit' | 'push'
  /** Carpeta del repo si el comando la indica (`cd X &&` o `git -C X`). */
  cwd?: string
  /** El commit también toma cambios no preparados (`-a`, o `git add` antes). */
  includesUnstaged: boolean
}

export type Finding = {
  file: string
  line: number
  kind: string
  preview: string
}

/** Marca para ignorar una línea a propósito (p. ej. un valor de ejemplo). */
export const ALLOW_MARKER = /secret-guard:\s*allow|pragma:\s*allowlist secret/i

const unquote = (s: string) => s.replace(/^["']|["']$/g, '')

/** Detecta `git commit` / `git push` dentro de un comando de shell. */
export function parseGitAction(command: string): GitAction | undefined {
  const parts = command.split(/&&|\|\||;|\n/).map(p => p.trim())
  let cwd: string | undefined
  let sawAdd = false

  for (const part of parts) {
    const cd = part.match(/^(?:cd|Set-Location|sl|pushd)\s+(?:-Path\s+)?("[^"]+"|'[^']+'|\S+)/i)
    if (cd) {
      cwd = unquote(cd[1] ?? '')
      continue
    }

    const git = part.match(/^git(?:\.exe)?\s+(.*)$/i)
    if (!git) continue

    let rest = git[1] ?? ''
    const dashC = rest.match(/^-C\s+("[^"]+"|'[^']+'|\S+)\s+(.*)$/)
    if (dashC) {
      cwd = unquote(dashC[1] ?? '')
      rest = dashC[2] ?? ''
    }
    // Saltar opciones globales tipo `-c user.name=x`.
    rest = rest.replace(/^(?:-c\s+\S+\s+)+/, '')

    const sub = rest.split(/\s+/)[0] ?? ''
    if (sub === 'add') sawAdd = true
    if (sub === 'commit') {
      const args = rest.slice('commit'.length)
      const includesUnstaged = sawAdd || /(^|\s)(-[a-zA-Z]*a[a-zA-Z]*|--all)(\s|$)/.test(args)
      return { kind: 'commit', cwd, includesUnstaged }
    }
    if (sub === 'push') return { kind: 'push', cwd, includesUnstaged: false }
  }
  return undefined
}

type Rule = { kind: string; re: RegExp; placeholderCheck?: number }

// placeholderCheck: índice del grupo con el valor, para descartar ejemplos.
const RULES: Rule[] = [
  { kind: 'llave privada', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY( BLOCK)?-----/ },
  { kind: 'llave AWS', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { kind: 'token GitHub', re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b/ },
  { kind: 'token Slack', re: /\bxox[abprs]-[A-Za-z0-9-]{10,}/ },
  { kind: 'llave Google API', re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { kind: 'llave Anthropic', re: /\bsk-ant-[A-Za-z0-9_-]{20,}/ },
  { kind: 'llave OpenAI', re: /\bsk-(?:proj-)?[A-Za-z0-9]{32,}\b/ },
  { kind: 'llave Stripe', re: /\b[sr]k_live_[A-Za-z0-9]{20,}\b/ },
  {
    kind: 'URL con usuario:contraseña',
    re: /\b[a-z][a-z0-9+.-]*:\/\/[^\s/:@"']+:([^\s/:@"']{3,})@/i,
    placeholderCheck: 1,
  },
  {
    // uint8_t appKey[] = { 0x2B, 0x7E, ... }  (RadioLib / LMIC)
    // #define LORAWAN_APP_KEY 0x2B, 0x7E, ...
    kind: 'llave LoRaWAN (bytes)',
    re: /\b\w*?(?:app_?s?key|nwk_?s?key|nwk_?key|app_?key)\w*\s*(?:\[\s*\d*\s*\])?\s*(?:=\s*)?\{?\s*(0x[0-9a-f]{2}(?:\s*,\s*0x[0-9a-f]{2}){7,})/i,
    placeholderCheck: 1,
  },
  {
    kind: 'llave LoRaWAN (hex)',
    re: /\b\w*?(?:app_?s?key|nwk_?s?key|nwk_?key|app_?key)\w*\W{1,6}["']?([0-9a-f]{32})\b/i,
    placeholderCheck: 1,
  },
  {
    // #define WIFI_PASSWORD "algo"   |   const char* mqtt_pass = "algo";   |   password: "algo"  (secret-guard: allow)
    kind: 'credencial en texto plano',
    re: /\b\w*(?:passw(?:or)?d|passwd|pwd|_pass|pass_|psk|secret|token|api_?key|apikey|auth_?key|access_?key|private_?key|client_?secret)\w*["']?\s*(?:=|:|\s)\s*(?:\(?\s*(?:const\s+)?(?:char\s*\*?|String|str)?\s*\)?\s*)?(?:F\()?["']([^"'\s][^"']{3,})["']/i,
    placeholderCheck: 1,
  },
]

const PLACEHOLDER = /^(?:x+|\*+|\.+|-+|0+|(?:0x00\s*,?\s*)+|changeme|change_me|your[_-].*|tu[_-].*|<.*>|\$\{.*\}|\{\{.*\}\}|todo|tbd|placeholder|example|ejemplo|dummy|test|password|secret|null|none|undefined|redacted|\.\.\.)$/i

function isPlaceholder(value: string): boolean {
  const v = value.trim()
  if (PLACEHOLDER.test(v)) return true
  if (/^(?:YOUR|TU|MY|INSERT|PUT|SET)_/i.test(v)) return true
  // Variables de entorno o referencias, no valores: getenv("X"), process.env.X
  if (/^[A-Z][A-Z0-9_]+$/.test(v) && v.length < 40 && !/\d/.test(v)) return true
  return false
}

/** Muestra el inicio y el final del valor, nunca el secreto entero. */
export function mask(text: string): string {
  const t = text.trim()
  if (t.length <= 8) return t[0] + '…'
  return `${t.slice(0, 4)}…${t.slice(-2)}`
}

export function scanLine(text: string): { kind: string; preview: string } | undefined {
  if (ALLOW_MARKER.test(text)) return undefined
  for (const rule of RULES) {
    const m = text.match(rule.re)
    if (!m) continue
    const value = (rule.placeholderCheck !== undefined ? m[rule.placeholderCheck] : m[0]) ?? ''
    if (rule.placeholderCheck !== undefined && isPlaceholder(value)) continue
    return { kind: rule.kind, preview: mask(value) }
  }
  return undefined
}

/** Recorre un diff unificado y revisa solo las líneas agregadas (`+`). */
export function scanDiff(diff: string): Finding[] {
  const findings: Finding[] = []
  let file = '?'
  let line = 0
  for (const raw of diff.split('\n')) {
    if (raw.startsWith('+++ ')) {
      file = raw.slice(4).trim().replace(/^"(.*)"$/, '$1').replace(/^b\//, '')
      continue
    }
    if (raw.startsWith('--- ')) continue
    const hunk = raw.match(/^@@ -\d+(?:,\d+)? \+(\d+)/)
    if (hunk) {
      line = Number(hunk[1])
      continue
    }
    if (raw.startsWith('+')) {
      const hit = scanLine(raw.slice(1))
      if (hit) findings.push({ file, line, ...hit })
      line++
    } else if (!raw.startsWith('-') && !raw.startsWith('\\')) {
      line++
    }
  }
  return findings
}

/** Revisa un archivo nuevo completo (aún sin seguimiento en git). */
export function scanFile(file: string, content: string): Finding[] {
  const findings: Finding[] = []
  content.split('\n').forEach((text, i) => {
    const hit = scanLine(text)
    if (hit) findings.push({ file, line: i + 1, ...hit })
  })
  return findings
}

export function formatFindings(findings: Finding[], max = 10): string {
  const lines = findings.slice(0, max).map(f => `  - ${f.file}:${f.line} — ${f.kind} (${f.preview})`)
  if (findings.length > max) lines.push(`  - …y ${findings.length - max} más`)
  return lines.join('\n')
}

/** Archivo, en la raíz del repo, con las rutas donde un secreto es intencional. */
export const ALLOW_FILE = '.secret-guard-allow'

function globToRegExp(glob: string): RegExp {
  let g = glob.replace(/\\/g, '/').replace(/^\.?\//, '')
  // Como en .gitignore: con "/" al inicio o en medio, la ruta es desde la raíz del repo.
  const anchored = g.replace(/\/$/, '').includes('/') || glob.startsWith('/')
  if (g.endsWith('/')) g += '**'
  let re = ''
  for (let i = 0; i < g.length; i++) {
    const c = g[i] ?? ''
    if (c === '*' && g[i + 1] === '*') {
      if (g[i + 2] === '/') {
        re += '(?:.*/)?'
        i += 2
      } else {
        re += '.*'
        i += 1
      }
    } else if (c === '*') re += '[^/]*'
    else if (c === '?') re += '[^/]'
    else re += c.replace(/[.+^${}()|[\]\\]/g, '\\$&')
  }
  return new RegExp(anchored ? `^${re}$` : `(?:^|/)${re}$`)
}

/** Lee .secret-guard-allow: una ruta o patrón por línea, estilo .gitignore (sin "!"). */
export function parseAllowList(text: string): (path: string) => boolean {
  const patterns = text
    .split(/\r?\n/)
    .map(l => l.replace(/(^|\s)#.*$/, '').trim())
    .filter(Boolean)
    .map(globToRegExp)
  return path => {
    const p = path.replace(/\\/g, '/').replace(/^\.\//, '')
    return patterns.some(re => re.test(p))
  }
}

export function withoutAllowed(findings: Finding[], allowText: string | undefined): Finding[] {
  if (!allowText) return findings
  const isAllowed = parseAllowList(allowText)
  return findings.filter(f => !isAllowed(f.file))
}
