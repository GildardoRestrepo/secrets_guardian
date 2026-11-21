import { describe, expect, test, type TestBody } from 'claude-code/testing'
import { parseAllowList, parseGitAction, scanDiff, scanLine, withoutAllowed } from './scan'

// Valores inventados para las pruebas: no son credenciales reales.
const FAKE_WIFI = 'Invernadero#2026!' // secret-guard: allow
const FAKE_GH = 'ghp_' + 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8'

const diffWith = (...added: string[]) =>
  [
    'diff --git a/src/config.h b/src/config.h',
    '--- a/src/config.h',
    '+++ b/src/config.h',
    '@@ -10,2 +10,4 @@',
    ' #pragma once',
    ...added.map(l => '+' + l),
    ' #define LED 2',
  ].join('\n')

describe('parseGitAction', () => {
  test('reconoce commit, push, cd y -C', async () => {
    expect(parseGitAction('git status')).toBeUndefined()
    expect(parseGitAction('git commit -m "x"')).toEqual({ kind: 'commit', cwd: undefined, includesUnstaged: false })
    expect(parseGitAction('git commit -am "x"')?.includesUnstaged).toBe(true)
    expect(parseGitAction('git add . && git commit -m x')?.includesUnstaged).toBe(true)
    expect(parseGitAction('cd "C:/repo x" && git push origin main')).toEqual({ kind: 'push', cwd: 'C:/repo x', includesUnstaged: false })
    expect(parseGitAction('git -C ../fw push')?.cwd).toBe('../fw')
    expect(parseGitAction('echo "git commit"')).toBeUndefined()
  })
})

describe('scanLine', () => {
  test('detecta credenciales típicas de firmware', async () => {
    expect(scanLine(`#define WIFI_PASSWORD "${FAKE_WIFI}"`)?.kind).toBe('credencial en texto plano')
    expect(scanLine('const char* mqtt_pass = "s3creto-mqtt";')?.kind).toBe('credencial en texto plano') // secret-guard: allow
    expect(scanLine('uint8_t appKey[] = { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB };')?.kind).toBe('llave LoRaWAN (bytes)') // secret-guard: allow
    expect(scanLine('mqtt://nodo:clave123@broker.local:1883')?.kind).toBe('URL con usuario:contraseña') // secret-guard: allow
    expect(scanLine(`token = "${FAKE_GH}"`)).toBeDefined()
  })

  test('ignora placeholders, variables y la marca de permiso', async () => {
    expect(scanLine('#define WIFI_PASSWORD ""')).toBeUndefined()
    expect(scanLine('#define WIFI_PASSWORD "YOUR_PASSWORD"')).toBeUndefined()
    expect(scanLine('#define WIFI_PASSWORD "xxxxxxxx"')).toBeUndefined()
    expect(scanLine('password = os.getenv("WIFI_PASS")')).toBeUndefined()
    expect(scanLine('uint8_t appKey[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };')).toBeUndefined()
    expect(scanLine('#define WIFI_PASSWORD "demo1234" // secret-guard: allow')).toBeUndefined()
  })

  test('nunca muestra el secreto completo', async () => {
    const hit = scanLine('const char* mqtt_pass = "s3creto-mqtt";') // secret-guard: allow
    expect(hit?.preview).toBe('s3cr…tt')
  })
})

describe('scanDiff', () => {
  test('solo mira líneas agregadas y da archivo:línea', async () => {
    const diff = diffWith('#define SSID "lab"', 'const char* mqtt_pass = "s3creto-mqtt";').concat('\n-#define OLD_PASSWORD "viejo-valor"') // secret-guard: allow
    expect(scanDiff(diff)).toEqual([
      { file: 'src/config.h', line: 12, kind: 'credencial en texto plano', preview: 's3cr…tt' },
    ])
  })
})

describe('hook sobre git', () => {
  const ok = (stdout: string) => ({
    value: { exitCode: 0, stdout, stderr: '', isStdoutTruncated: false, isStderrTruncated: false },
  })

  const toasts: string[] = []
  const fakeGit = (on: Parameters<TestBody>[1], stagedDiff: string) => {
    toasts.length = 0
    on('ui.status', async () => ({ value: undefined }))
    on('ui.toast', async (_, e) => {
      toasts.push(e.text)
      return { value: undefined }
    })
    on('process.run', async (_, e) => {
      const args = e.argv.slice(1).join(' ')
      if (args.includes('rev-parse')) return ok('C:/repo\n')
      if (args.includes('diff --cached')) return ok(stagedDiff)
      return ok('')
    })
  }

  test('bloquea un commit con una contraseña', async ($, on) => {
    fakeGit(on, diffWith('const char* mqtt_pass = "s3creto-mqtt";')) // secret-guard: allow
    let ran = false
    on('tool.call', async () => {
      ran = true
      return { result: { stdout: '', stderr: '', interrupted: false } }
    })

    const res = await $.tool.call({ tool: 'Bash', command: 'git commit -m "config"' })

    expect(ran).toBe(false)
    // Desde el $ de una prueba, un rechazo llega como { deny }.
    const msg = res.deny ?? res.text ?? ''
    expect(msg).toContain('guardian-secretos bloqueó')
    expect(msg).toContain('src/config.h:11')
    expect(msg).not.toContain('s3creto-mqtt')
    expect(toasts[0]).toContain('bloqueado')
    expect(toasts[0]).toContain('bloqueado')
  })

  test('deja pasar un commit limpio y otros comandos', async ($, on) => {
    fakeGit(on, diffWith('#define LED_PIN 2'))
    let ran = 0
    on('tool.call', async () => {
      ran++
      return { result: { stdout: 'ok', stderr: '', interrupted: false } }
    })

    await $.tool.call({ tool: 'Bash', command: 'git commit -m "led"' })
    await $.tool.call({ tool: 'Bash', command: 'ls' })

    expect(ran).toBe(2)
    expect(toasts).toEqual([])
    expect(toasts).toEqual([])
  })
})

describe('llaves LoRaWAN en firmware', () => {
  test('detecta #define LORAWAN_APP_KEY con bytes y respeta llaves en cero', async () => {
    const real = '#define LORAWAN_APP_KEY 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C' // secret-guard: allow
    const zero = '#define LORAWAN_NWK_KEY 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00'
    expect(scanLine(real)?.kind).toBe('llave LoRaWAN (bytes)')
    expect(scanLine(zero)).toBeUndefined()
    expect(scanLine('| AppKey | `2b7e151628aed2a6abf7158809cf4f3c` |')?.kind).toBe('llave LoRaWAN (hex)') // secret-guard: allow
  })
})

describe('.secret-guard-allow', () => {
  const allow = parseAllowList(
    [
      '# credenciales versionadas a propósito',
      '01_firmware/nodes/',
      '00_docs/03_nodes_cards/*.md',
      'secrets.example.h   # en cualquier carpeta',
      '**/examples/',
    ].join('\n'),
  )

  test('carpetas, globs, nombres sueltos y **', async () => {
    expect(allow('01_firmware/nodes/bigos.h')).toBe(true)
    expect(allow('01_firmware/nodes/sub/x.h')).toBe(true)
    expect(allow('00_docs/03_nodes_cards/bigos.md')).toBe(true)
    expect(allow('00_docs/03_nodes_cards/sub/bigos.md')).toBe(false)
    expect(allow('a/b/secrets.example.h')).toBe(true)
    expect(allow('01_firmware/lib/X/examples/Demo/Demo.ino')).toBe(true)
    expect(allow('01_firmware/src/main.cpp')).toBe(false)
    expect(allow('otro/01_firmware/nodes/bigos.h')).toBe(false)
  })

  test('sin archivo no filtra nada', async () => {
    const f = [{ file: 'a.h', line: 1, kind: 'x', preview: 'y' }]
    expect(withoutAllowed(f, undefined)).toEqual(f)
    expect(withoutAllowed(f, '\n# vacío\n')).toEqual(f)
    expect(withoutAllowed(f, 'a.h')).toEqual([])
  })

  test('el mod deja pasar un commit cuyo secreto está en una ruta permitida', async ($, on) => {
    const nodeDiff = [
      'diff --git a/01_firmware/nodes/bigos.h b/01_firmware/nodes/bigos.h',
      '--- a/01_firmware/nodes/bigos.h',
      '+++ b/01_firmware/nodes/bigos.h',
      '@@ -5,0 +5,1 @@',
      '+#define LORAWAN_APP_KEY 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C', // secret-guard: allow
    ].join('\n')
    on('ui.status', async () => ({ value: undefined }))
    on('ui.toast', async () => ({ value: undefined }))
    on('process.run', async (_, e) => {
      const args = e.argv.slice(1).join(' ')
      const out = args.includes('rev-parse') ? 'C:/repo\n' : args.includes('diff --cached') ? nodeDiff : ''
      return { value: { exitCode: 0, stdout: out, stderr: '', isStdoutTruncated: false, isStderrTruncated: false } }
    })
    let allowText = ''
    on('fs.read', async (_, e) =>
      e.path.replace(/\\/g, '/').endsWith('/.secret-guard-allow') ? { value: allowText } : { deny: 'no existe' },
    )
    let ran = 0
    on('tool.call', async () => {
      ran++
      return { result: { stdout: '', stderr: '', interrupted: false } }
    })

    const blocked = await $.tool.call({ tool: 'Bash', command: 'git commit -m "llaves bigos"' })
    expect(blocked.deny ?? blocked.text ?? '').toContain('01_firmware/nodes/bigos.h:5')

    allowText = '01_firmware/nodes/\n'
    await $.tool.call({ tool: 'Bash', command: 'git commit -m "llaves bigos"' })
    expect(ran).toBe(1)
  })
})
