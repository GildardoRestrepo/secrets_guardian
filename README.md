# secrets_guardian

Bloquea `git commit` y `git push` cuando los cambios contienen lo que parece un secreto. Funciona en dos capas que comparten las mismas reglas (`hooks/scan.ts`):

1. **Mod de Claude (`guardian-secretos`)**: revisa los commits y pushes que ejecuta Claude Code (Bash o PowerShell) antes de que corran, y le explica a Claude qué corregir.
2. **Hooks de git globales (`git-hooks/`)**: revisan los commits y pushes que haces tú a mano, en todos tus repos.

## Qué detecta

- Contraseñas y PSK en texto plano (`#define WIFI_PASSWORD "..."`, `mqtt_pass = "..."`)
- Llaves LoRaWAN (AppKey/NwkSKey/AppSKey en bytes `0x..` o hex de 32 caracteres)
- URLs con `usuario:contraseña@`
- Llaves privadas, tokens de GitHub/Slack, llaves de AWS, Google, Anthropic, OpenAI y Stripe

Solo mira líneas agregadas, ignora placeholders (`""`, `YOUR_...`, `xxxx`, llaves en ceros) y nunca muestra el secreto completo.

- `git commit`: lo preparado (staged). En el mod, con `-a` o un `git add` en el mismo comando, también lo no preparado y los archivos nuevos.
- `git push`: los commits que aún no están en el remoto.

**Falso positivo:** agrega el comentario `secret-guard: allow` en esa línea.

## Instalar el mod de Claude

En una sesión de terminal de Claude Code:

```
/plugin install guardian-secretos --marketplace GildardoRestrepo/secrets_guardian
```

Responde `y` para agregar el marketplace y elige el alcance de usuario (`user`) para que aplique en todos tus repos.

Desde una shell:

```
claude plugin install guardian-secretos --marketplace GildardoRestrepo/secrets_guardian
```

En la app de escritorio, donde `/plugin` no funciona: haz clic en **+** junto al cuadro de texto, luego **Plugins**, **Add marketplace** con `GildardoRestrepo/secrets_guardian` y después **Add plugin**.

## Activar los hooks de git (commits manuales)

Requiere Node 23.6 o superior (ejecuta TypeScript directamente).

```
git clone https://github.com/GildardoRestrepo/secrets_guardian.git
git config --global core.hooksPath "<ruta>/secrets_guardian/git-hooks"
```

Desde ese momento aplica a **todos** los repos, incluidos los que crees o clones después. Si un repo tiene sus propios hooks en `.git/hooks`, se siguen ejecutando después de la revisión.

- Saltar la revisión una vez: `git commit --no-verify` (o `git push --no-verify`).
- Desactivarlo: `git config --global --unset core.hooksPath`.
- Si `node` no está instalado, el hook avisa y deja pasar el commit sin revisarlo.

## Desarrollo

```
claude plugin validate .
claude plugin test .
```

Licencia MIT.
