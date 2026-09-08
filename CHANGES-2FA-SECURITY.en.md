# Security changes in the twofactor_gauthenticator plugin (2FA)

**Date:** 2026-09-07 · **SDD change:** `harden-2fa-authentication` · **Base:** Roundcube 1.6.9 · plugin v2.0.0

Change log for the fixes applied to the four security findings V-1, V-2, V-3 and V-4 in
the 2FA verification flow. Every code fragment quoted reflects the current state of
`twofactor_gauthenticator.php`.

Status overview:

| Finding | Issue | Status |
|---|---|---|
| V-1 | Code check without rate limiting | **Fixed** (persistent counter + physical wait + logout) |
| V-2 | Session not destroyed on failed 2FA | **Fixed** (full server-side teardown) |
| V-3 | 2FA bypass via spoofed headers | **Fixed** (whitelist uses `REMOTE_ADDR` + proxy opt-in) |
| V-4 | Operator precedence defect | **Fixed** (single `__is2FAFresh()` helper) |

---

## V-1 — Code check without rate limiting

### Problem
Both verification paths (`check_2FAlogin()` on login and the AJAX endpoint
`plugin.twofactor_gauthenticator-checkcode`) allowed unlimited TOTP / recovery-code
guessing.

### Final solution
- **Logout on every failure** (original behavior restored): a failed code never falls back
  to a "retry" state — it destroys the session.
- **Persistent counter** per (IP, username) in a JSON file under `log_dir`
  (`twofactor_gauth_fail_<md5(ip|user)>.json`), surviving logouts and re-logins.
- **Incremental physical wait**: every failure delays the response `delay(level)` seconds
  before eviction (browser shows a loading state).
- **Active block**: while `blocked_until > now`, any submission (even the correct code)
  waits the remaining time and exits without verification.
- **No oracle channel**: the AJAX self-test requires an explicit `secret` and returns no
  verdict while the block is active.

### Code notes

Counter state (level, last failure, unlock time):

```php
$state = array(
    'level'         => $level,
    'last'          => $now,
    'blocked_until' => $blocked_until,
);
```

Physical wait (capped at 600 s, the scale maximum):

```php
private function __waitSeconds(int $seconds): void
{
    $seconds = min(max(0, $seconds), 600);
    if ($seconds > 0) {
        usleep($seconds * 1000000);
    }
}
```

Failure recording (returns the wait seconds the caller must apply):

```php
private function __registerFailedAttempt(): int   // returns the applied wait (seconds)
{
    // ... read/create state, increment level (reset when past twofactor_lockout) ...
    $blocked_until = $now + $this->__failureDelay($level);
    $this->__writeFailState($key, array(
        'level'         => $level,
        'last'          => $now,
        'blocked_until' => $blocked_until,
    ));
    return max(0, $blocked_until - $now);
}
```

Login wiring (`check_2FAlogin()`): blocked → wait and exit; failure → record, wait,
teardown; success → clear counter:

```php
if ($code) {
    if ($this->__isLockedOut()) {
        $this->__waitSeconds($this->__blockedRemaining());   // feel the remaining block
        $this->__exitSession();                              // teardown
    }
    if (self::__checkCode($code) || self::__isRecoveryCode($code)) {
        $this->__clearFailedAttempts();
        // ... recovery / remember-me / redirect to mail ...
    } else {
        $wait = $this->__registerFailedAttempt();   // persistent record
        $this->__waitSeconds($wait);                // FELT delay before leaving
        $this->__exitSession();                     // every failure -> teardown
    }
}
```

AJAX self-test (EMENDA 4 — oracle closed):

```php
if (!$secret) {                              // explicit secret required
    echo $this->gettext('code_ko');          // never verify against the real secret
    exit;
}
if ($this->__isLockedOut()) {                // blocked: no verdict
    $this->__waitSeconds($this->__blockedRemaining());
    echo $this->gettext('code_ko');
    exit;
}
```

### Actual wait sequence (default scale)

| Accumulated failure | Physical wait |
|---|---|
| 1st | 1 s |
| 2nd | 2 s |
| 3rd | 5 s |
| 4th | 20 s |
| 5th | 60 s (1 min) |
| 6th | 300 s (5 min) |
| 7th+ | 600 s (10 min, cap) |

Notes:
- The counter resets on success (state file removed) and expires when
  `twofactor_lockout` (900 s) passes without failures.
- A failure while blocked does not increment (no double penalty).
- File-based storage was chosen because the Roundcube per-user cache did not persist in the
  MAMP environment (the lockout silently degraded).

---

## V-2 — Session not destroyed on failed 2FA

### Problem
`__exitSession()` only `unset()` two plugin keys and redirected to `?_task=logout`: the
authenticated Roundcube session (already established by the password) stayed alive
server-side.

### Solution
Full server-side teardown in `__exitSession()`:

```php
// 1. Clear the 30-day "remember me" cookie (name derived as in __cookie())
$this->__clearRememberMeCookie();

// 2. Real session destruction: destroys the store, invalidates the ID (not resumable),
//    clears the Roundcube session cookie and resets $_SESSION
$rcmail->kill_session();

// 3. Belt-and-suspenders: drop the plugin markers
unset($_SESSION['twofactor_gauthenticator_login']);
unset($_SESSION['twofactor_gauthenticator_2FA_login']);

// 4. Redirect to login as UI courtesy (teardown is already server-side)
header('Location: ?_task=login');
exit;
```

- The redirect is no longer the destruction mechanism and needs no token.
- Applied **uniformly** to all three callers: failed code (V-1), the partial-auth eviction
  branch (V-4) and the `twofactor_gauthenticator_save()` anti-bypass gate (2022-04-02
  incident preserved).
- The V-1 counter lives in its file, intentionally **outside the session**: teardown does
  not clear it, so rate limiting keeps accumulating across logins.

---

## V-3 — 2FA bypass via spoofed headers

### Problem
The IP whitelist in `check_2FAlogin()` trusted `HTTP_CLIENT_IP` and the first value of
`HTTP_X_FORWARDED_FOR` (both spoofable): an attacker could send
`X-Forwarded-For: <whitelisted-IP>` and bypass 2FA.

### Solution
A single trusted IP resolver, `__getClientIP()`:

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
            // scan RIGHT->LEFT: the first hop that is NOT a trusted proxy is the real client.
            // A client-injected leading (left) value is never used unless every hop to its
            // right is an explicitly trusted proxy.
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

- Default: **only `REMOTE_ADDR`** (the real TCP peer).
- `HTTP_CLIENT_IP` removed entirely from the decision path (0 occurrences).
- `X-Forwarded-For` is honored only when the direct peer is in the new opt-in list
  `twofactor_trusted_proxies` (IP/CIDR, validated via `CIDR::match`), parsed right-to-left.
- **Migration note:** deployments whitelisting clients behind a proxy must add that proxy
  to `twofactor_trusted_proxies` or their whitelist stops matching (secure by default).

---

## V-4 — Operator precedence defect

### Problem
The session-freshness check in the `check_2FAlogin()` `elseif` used

```php
! $_SESSION['twofactor_gauthenticator_2FA_login'] >= $_SESSION['twofactor_gauthenticator_login']
```

In PHP `!` binds tighter than `>=`, so the expression parses as `(!$x) >= $y`, with `!$x`
being `false`/`true` → the branch was dead (never evicted).

### Solution
Centralized, correct check in a single helper reused by all three spots:

```php
/**
 * Shared invariant: 2FA is complete only when the 2FA login marker is set
 * and >= the password-auth login marker. Isset-guarded for PHP 8.
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
- `init()` — the AJAX partial-auth guard.
- `check_2FAlogin()` — the partial-auth eviction branch (the previously dead `elseif`, now
  alive as `! $this->__is2FAFresh()`).
- `twofactor_gauthenticator_save()` — the 2022-04-02 anti-bypass gate
  (`$config_2FA['activate'] && !$this->__is2FAFresh()`).

False-positive guarantee: whitelisted / remember-me users who legitimately skip 2FA have
their `return $p` **before** the freshness branch, so they are never evicted by mistake.

---

## New configuration (`config.inc.php.dist`)

```php
// Incremental waits (seconds) applied after the N-th failure; clamped to >=1;
// levels beyond the list use the LAST value.
$rcmail_config['twofactor_lockout_delays'] = array(1, 2, 5, 20, 60, 300, 600);

// Counter-expiry window (seconds): if the last failure is older than this,
// the level resets to 0 before counting the next one. (15 min)
$rcmail_config['twofactor_lockout'] = 900;

// Trusted reverse-proxies (IPs/CIDR) whose X-Forwarded-For is honored for the
// whitelist and the rate-limit key. Empty = REMOTE_ADDR only. HTTP_CLIENT_IP is never used.
$rcmail_config['twofactor_trusted_proxies'] = array();
```

The obsolete `twofactor_max_attempts` key was **removed** (no flat threshold anymore); if it
still exists in your `config.inc.php`, the code ignores it.

---

## Touched files

| File | Change |
|---|---|
| `twofactor_gauthenticator.php` | +14 new private methods, auth/teardown rewiring (V-1..V-4) |
| `config.inc.php.dist` | 3 new options; `twofactor_max_attempts` removed |
| `README.md` | variables table + security section (V-1..V-4 + proxy note) |
| `openspec/` (gitignored) | SDD artifacts of change `harden-2fa-authentication` (proposal/specs/design/tasks) |

Not touched: `twofactor_gauthenticator.js`, `PHPGangsta/`, `CIDR.php`, `localization/`
(pre-existing local changes in `.js`/`.gitignore` are unrelated to this SDD).

---

## Status 

- [x] Implementation (16 change tasks) and static verification: `php -l` clean,
  0 occurrences of `HTTP_CLIENT_IP` / `twofactor_max_attempts` / session counter in the PHP.

Diagnostic findings that drove the emendas:
- A `$_SESSION` counter was useless (teardown destroys the session on every failure): it
  could never exceed 1.
- The Roundcube per-user cache did not persist in MAMP: the lockout silently degraded
  (emenda 2 → JSON file in `log_dir`, visible and debuggable with `cat`).
- The lockout worked but was imperceptible: emenda 3 → physical `usleep` per level.
- A scripted caller could use the self-test without `secret` as a verification oracle
  against the real secret: emenda 4 → explicit secret required and no verdict while
  blocked.
