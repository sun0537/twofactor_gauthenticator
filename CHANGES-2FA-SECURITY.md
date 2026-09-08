# Cambios de seguridade no plugin twofactor_gauthenticator (2FA)

**Data:** 2026-09-07 · **Change SDD:** `harden-2fa-authentication` · **Base:** Roundcube 1.6.9 · plugin v2.0.0

Documento de rexistro dos cambios aplicados para corrixir os catro achados de seguridade
V-1, V-2, V-3 e V-4 no fluxo de verificación 2FA. Tódolos fragmentos de código citados
corresponden ao estado actual de `twofactor_gauthenticator.php`.

Índice de estado:

| Achado | Problema | Estado |
|---|---|---|
| V-1 | Verificación de código sen rate limiting | **Resolto** (contador persistente + espera física + logout) |
| V-2 | A sesión non se destrúe ao fallar a 2FA | **Resolto** (teardown server-side completo) |
| V-3 | Bypass de 2FA por cabeceiras suplantadas | **Resolto** (whitelist con `REMOTE_ADDR` + opt-in de proxy) |
| V-4 | Defecto de precedencia de operadores | **Resolto** (helper único `__is2FAFresh()`) |

---

## V-1 — Code check without rate limiting

### Problema
As dúas vías de verificación (`check_2FAlogin()` no login e o endpoint AJAX
`plugin.twofactor_gauthenticator-checkcode`) permitían probar códigos TOTP/códigos de
recuperación sen ningún límite de intentos.

### Solución final
- **Logout en cada fallo** (comportamento orixinal restaurado): un fallo nunca queda en
  "reintento" — destrúe a sesión.
- **Contador persistente** por (IP, usuario) en ficheiro JSON en `log_dir`
  (`twofactor_gauth_fail_<md5(ip|usuario)>.json`), que sobrevive a logouts e re-logins.
- **Espera física incremental**: cada fallo atrasa a resposta `delay(level)` segundos antes
  de evictar, co navegador en estado "cargando".
- **Bloqueo vixente**: mentres `blocked_until > now`, calquera envío (mesmo o código
  correcto) espera o restante e sae sen verificar.
- **Sen canle oracle**: o self-test AJAX require un `secret` explícito e non dá veredicto
  mentres o bloqueo está vixente.

### Apuntes de código

Estado do contador (nivel, último fallo, desbloqueo):

```php
$state = array(
    'level'         => $level,
    'last'          => $now,
    'blocked_until' => $blocked_until,
);
```

Espera física (tope de 600 s ≡ máximo da escala):

```php
private function __waitSeconds(int $seconds): void
{
    $seconds = min(max(0, $seconds), 600);
    if ($seconds > 0) {
        usleep($seconds * 1000000);
    }
}
```

Rexistro do fallo (devolve os segundos de espera que o caller aplicará):

```php
private function __registerFailedAttempt(): int   // returns the applied wait (seconds)
{
    // ... le/crea o estado, incrementa level (reseta se pasou twofactor_lockout) ...
    $blocked_until = $now + $this->__failureDelay($level);
    $this->__writeFailState($key, array(
        'level'         => $level,
        'last'          => $now,
        'blocked_until' => $blocked_until,
    ));
    return max(0, $blocked_until - $now);
}
```

Fío no login (`check_2FAlogin()`): bloqueado → esperar e saír; fallo → rexistrar, esperar,
teardown; acerto → limpar contador:

```php
if ($code) {
    if ($this->__isLockedOut()) {
        $this->__waitSeconds($this->__blockedRemaining());   // sentir o bloqueo restante
        $this->__exitSession();                              // teardown
    }
    if (self::__checkCode($code) || self::__isRecoveryCode($code)) {
        $this->__clearFailedAttempts();
        // ... recuperación / remember-me / redirect a mail ...
    } else {
        $wait = $this->__registerFailedAttempt();   // rexistro persistente
        $this->__waitSeconds($wait);                // DELAY FÍSICO antes de saír
        $this->__exitSession();                     // calquera fallo -> teardown
    }
}
```

Self-test AJAX (EMENDA 4 — peche do oracle):

```php
if (!$secret) {                              // secret explícito obrigatorio
    echo $this->gettext('code_ko');          // nunca verificar contra o secret real
    exit;
}
if ($this->__isLockedOut()) {                // bloqueado: sen veredicto
    $this->__waitSeconds($this->__blockedRemaining());
    echo $this->gettext('code_ko');
    exit;
}
```

### Secuencia real de esperas (escala por defecto)

| Fallo acumulado | Espera física |
|---|---|
| 1º | 1 s |
| 2º | 2 s |
| 3º | 5 s |
| 4º | 20 s |
| 5º | 60 s (1 min) |
| 6º | 300 s (5 min) |
| 7º+ | 600 s (10 min, tope) |

Notas:
- O contador resécase cun acerto (bórrase o ficheiro) e expira se pasan
  `twofactor_lockout` (900 s) sen fallos.
- Unha falla mentres bloqueado non incrementa (sen dobre penalización).
- O almacén en ficheiro foi elixido porque a cache per-user de Roundcube non persistía no
  contorno MAMP (o bloqueo degradaba en silencio).

---

## V-2 — Session not destroyed on failed 2FA

### Problema
`__exitSession()` só facía `unset()` de dúas claves do plugin e redirixía a
`?_task=logout`: a sesión autenticada de Roundcube (xa establecida pola contrasinal)
seguía viva no servidor.

### Solución
Teardown completo server-side en `__exitSession()`:

```php
// 1. Limpar o cookie "remember me" de 30 días (nome derivado igual que __cookie())
$this->__clearRememberMeCookie();

// 2. Destrución real da sesión: destrúe o almacén, invalida o ID (non resumible),
//    limpa o cookie de sesión de Roundcube e resetea $_SESSION
$rcmail->kill_session();

// 3. Belt-and-suspenders: botar os marcadores do plugin
unset($_SESSION['twofactor_gauthenticator_login']);
unset($_SESSION['twofactor_gauthenticator_2FA_login']);

// 4. Redirección ao login como cortesía (o teardown xa é server-side)
header('Location: ?_task=login');
exit;
```

- O redirect xa non é o mecanismo de destrución nin precisa token.
- Aplícase **uniformemente** aos tres callers: fallo de código (V-1), rama de evicción
  parcial (V-4) e o gate anti-bypass de `twofactor_gauthenticator_save()` (incidente
  2022-04-02 preservado).
- O contador V-1 vive no ficheiro, intencionadamente **fóra da sesión**: o teardown non o
  borra, así o rate limiting segue acumulando entre logins.

---

## V-3 — 2FA bypass via spoofed headers

### Problema
O whitelist de IP en `check_2FAlogin()` confiaba en `HTTP_CLIENT_IP` e no primeiro valor
de `HTTP_X_FORWARDED_FOR` (ambos suplantables): un atacante podía enviar
`X-Forwarded-For: <IP-whitelist>` e saltarse a 2FA.

### Solución
Un único resolvedor de IP de confianza, `__getClientIP()`:

```php
private function __getClientIP(): string
{
    $rcmail  = rcmail::get_instance();
    $remote  = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $trusted = $rcmail->config->get('twofactor_trusted_proxies', array());

    if (is_array($trusted) && count($trusted) > 0 && $this->__isTrustedProxy($remote, $trusted)) {
        $xff = filter_input(INPUT_SERVER, 'HTTP_X_FORWARDED_FOR');
        if (is_string($xff) && $xff !== '') {
            $hops = array_map('trim', explode(',', $xff));
            // scan RIGHT->LEFT: o primeiro salto que NON é un proxy confiado é o cliente real.
            // Un valor á esquerda inxectado polo cliente nunca se usa a menos que todos os
            // saltos á dereita sexan proxies confiados explicitamente.
            for ($i = count($hops) - 1; $i >= 0; $i--) {
                if ($hops[$i] === '') {
                    continue;
                }
                if (!$this->__isTrustedProxy($hops[$i], $trusted)) {
                    return $hops[$i];
                }
            }
        }
    }
    return $remote;
}
```

- Por defecto: **só `REMOTE_ADDR`** (o peer TCP real).
- `HTTP_CLIENT_IP` eliminado por completo da ruta de decisión (0 ocorrencias).
- `X-Forwarded-For` só se honra cando o peer directo está na nova lista opt-in
  `twofactor_trusted_proxies` (IP/CIDR, validada con `CIDR::match`), parseada de
  dereita a esquerda.
- **Nota de migración:** despregues que whitelistan clientes tras un proxy deben engadir o
  proxy a `twofactor_trusted_proxies` ou o whitelist deixa de coincidir (seguro por defecto).

---

## V-4 — Operator precedence defect

### Problema
A comprobación de frescura da sesión no `elseif` de `check_2FAlogin()` usaba

```php
! $_SESSION['twofactor_gauthenticator_2FA_login'] >= $_SESSION['twofactor_gauthenticator_login']
```

En PHP `!` ten precedencia sobre `>=`, así que a expresión parsea como `(!$x) >= $y`, con
`!$x` en `false`/`true` → a rama quedaba morta (nunca evictaba).

### Solución
Comprobación centralizada e correcta nun único helper, reutilizado polos tres puntos:

```php
/**
 * Invariante compartido: a 2FA está completa só cando o marcador 2FA_login está
 * definido e é >= ao marcador de login por contrasinal. Con isset() para PHP 8.
 */
private function __is2FAFresh(): bool
{
    if (!isset($_SESSION['twofactor_gauthenticator_login'])) {
        return false;
    }
    if (!isset($_SESSION['twofactor_gauthenticator_2FA_login'])) {
        return false;
    }
    return $_SESSION['twofactor_gauthenticator_2FA_login']
        >= $_SESSION['twofactor_gauthenticator_login'];
}
```

Callers:
- `init()` — garda AJAX de autenticación parcial.
- `check_2FAlogin()` — rama de evicción parcial (o antigo `elseif` morto, agora vivo e
  parentesizado como `! $this->__is2FAFresh()`).
- `twofactor_gauthenticator_save()` — gate anti-bypass 2022-04-02
  (`$config_2FA['activate'] && !$this->__is2FAFresh()`).

Garantía anti falsos positivos: os usuarios con whitelist ou cookie remain-me que saltan a
2FA lexitimamente teñen `return $p` **antes** da rama de frescura → nunca son evictados por
erro.

---

## Configuración nova (`config.inc.php.dist`)

```php
// Esperas incrementais (segundos) tras o N-ésimo fallo; clampeadas a >=1;
// niveis máis aló da lista usan o ÚLTIMO valor.
$rcmail_config['twofactor_lockout_delays'] = array(1, 2, 5, 20, 60, 300, 600);

// Fiestra de expiración do contador (segundos): se o último fallo é máis vello,
// o nivel resécase a 0 antes de contar o seguinte. (15 min)
$rcmail_config['twofactor_lockout'] = 900;

// Lista de proxies de confianza (IPs/CIDR) cuxo X-Forwarded-For se honra para o
// whitelist e a chave do rate limit. Baleira = só REMOTE_ADDR. HTTP_CLIENT_IP nunca se usa.
$rcmail_config['twofactor_trusted_proxies'] = array();
```

A chave obsoleta `twofactor_max_attempts` quedou **eliminada** (o limiar plano non existe);
se aínda existe no teu `config.inc.php`, o código ignóraa.

---

## Ficheiros tocados

| Ficheiro | Cambio |
|---|---|
| `twofactor_gauthenticator.php` | +14 métodos privados novos, rewiring de auth/teardown (V-1..V-4) |
| `config.inc.php.dist` | 3 opcións novas; `twofactor_max_attempts` eliminada |
| `README.md` | táboa de variables + sección de seguridade (V-1..V-4 + nota de proxy) |
| `openspec/` (gitignored) | artefactos SDD do change `harden-2fa-authentication` (proposal/specs/design/tasks) |

Non se tocou: `twofactor_gauthenticator.js`, `PHPGangsta/`, `CIDR.php`, `localization/`
(e os cambios locais previos de `.js`/`.gitignore` son alleos a este SDD).

---

## Estado

- [x] Implementación (16 tarefas do change) e verificación estática: `php -l` limpo,
  0 ocorrencias de `HTTP_CLIENT_IP`/`twofactor_max_attempts`/cache contador no PHP.

Aclaracións do diagnóstico que levaron ás emendas:
- O contador en `$_SESSION` era inútil (o teardown destrúe a sesión en cada fallo):
  nunca pasaría de 1.
- A cache per-user de Roundcube non persistía no MAMP: o bloqueo degradaba en silencio
  (emenda 2 → ficheiro JSON en `log_dir`, visible e debuggable con `cat`).
- O bloqueo funcionaba pero era imperceptible: emenda 3 → `usleep` físico por nivel.
- Un curl podía usar o self-test sen `secret` como oráculo de verificación contra o secret
  real: emenda 4 → secret explícito obrigatorio e sen veredicto mentres bloqueado.
