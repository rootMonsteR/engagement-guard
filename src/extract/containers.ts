import type { OpaqueKind } from './tokenizer.js'
import { type KnownToolSpec, lookupTool } from './tools-table.js'

// Option lists from the Docker CLI reference (`docker`, `docker container run|create|exec`,
// `docker image pull`) and the podman man pages (podman(1), podman-run(1), podman-exec(1),
// podman-pull(1)). `run` and `create` share one list. An option in neither list of a command makes
// the image position unknown, which fails closed (`nested-command-unresolved`).

interface OptionSet {
  value: ReadonlySet<string>
  switches: ReadonlySet<string>
}

/** Global options that take a value (docker; podman). */
const GLOBAL_VALUE: ReadonlySet<string> = new Set([
  // docker
  '--config',
  '-c',
  '--context',
  '-H',
  '--host',
  '-l',
  '--log-level',
  '--tlscacert',
  '--tlscert',
  '--tlskey',
  // podman
  '--cdi-spec-dir',
  '--cgroup-manager',
  '--conmon',
  '--connection',
  '--events-backend',
  '--hooks-dir',
  '--identity',
  '--imagestore',
  '--module',
  '--network-config-dir',
  '--out',
  '--root',
  '--runroot',
  '--runtime',
  '--runtime-flag',
  '--ssh',
  '--storage-driver',
  '--storage-opt',
  '--tls-ca',
  '--tls-cert',
  '--tls-details',
  '--tls-key',
  '--tmpdir',
  '--url',
  '--volumepath',
])

/** Global switches (docker; podman). */
const GLOBAL_SWITCH: ReadonlySet<string> = new Set([
  // docker
  '-D',
  '--debug',
  '--tls',
  '--tlsverify',
  '-v',
  '--version',
  '-h',
  '--help',
  // podman
  '-r',
  '--remote',
  '--syslog',
  '--transient-store',
])

// Docker Compose CLI reference (`docker compose`, `compose run`, `compose exec`); also used for the
// standalone `docker-compose` and `podman-compose` front ends.
const COMPOSE_GLOBAL_VALUE: ReadonlySet<string> = new Set([
  '--ansi',
  '--env-file',
  '-f',
  '--file',
  '--parallel',
  '--profile',
  '--progress',
  '--project-directory',
  '-p',
  '--project-name',
])
const COMPOSE_GLOBAL_SWITCH: ReadonlySet<string> = new Set([
  '--all-resources',
  '--compatibility',
  '--dry-run',
  '-h',
  '--help',
])
const COMPOSE_RUN: OptionSet = {
  value: new Set([
    '--cap-add',
    '--cap-drop',
    '--entrypoint',
    '-e',
    '--env',
    '--env-from-file',
    '-l',
    '--label',
    '--name',
    '-p',
    '--publish',
    '--pull',
    '-u',
    '--user',
    '-v',
    '--volume',
    '-w',
    '--workdir',
  ]),
  switches: new Set([
    '--build',
    '-d',
    '--detach',
    '-i',
    '--interactive',
    '--no-deps',
    '-T',
    '--no-tty',
    '-q',
    '--quiet',
    '--quiet-build',
    '--quiet-pull',
    '--remove-orphans',
    '--rm',
    '-P',
    '--service-ports',
    '--use-aliases',
  ]),
}
const COMPOSE_EXEC: OptionSet = {
  value: new Set(['-e', '--env', '--index', '-u', '--user', '-w', '--workdir']),
  switches: new Set([
    '-d',
    '--detach',
    '-T',
    '--no-tty',
    '--privileged',
    '-i',
    '--interactive',
    '-t',
    '--tty',
  ]),
}

const RUN_VALUE: ReadonlySet<string> = new Set([
  // docker container run / create
  '--add-host',
  '--annotation',
  '-a',
  '--attach',
  '--blkio-weight',
  '--blkio-weight-device',
  '--cap-add',
  '--cap-drop',
  '--cgroup-parent',
  '--cgroupns',
  '--cidfile',
  '--cpu-count',
  '--cpu-percent',
  '--cpu-period',
  '--cpu-quota',
  '--cpu-rt-period',
  '--cpu-rt-runtime',
  '-c',
  '--cpu-shares',
  '--cpus',
  '--cpuset-cpus',
  '--cpuset-mems',
  '--detach-keys',
  '--device',
  '--device-cgroup-rule',
  '--device-read-bps',
  '--device-read-iops',
  '--device-write-bps',
  '--device-write-iops',
  '--dns',
  '--dns-option',
  '--dns-search',
  '--domainname',
  '--entrypoint',
  '-e',
  '--env',
  '--env-file',
  '--expose',
  '--gpus',
  '--group-add',
  '--health-cmd',
  '--health-interval',
  '--health-retries',
  '--health-start-interval',
  '--health-start-period',
  '--health-timeout',
  '-h',
  '--hostname',
  '--io-maxbandwidth',
  '--io-maxiops',
  '--ip',
  '--ip6',
  '--ipc',
  '--isolation',
  '-l',
  '--label',
  '--label-file',
  '--link',
  '--link-local-ip',
  '--log-driver',
  '--log-opt',
  '--mac-address',
  '-m',
  '--memory',
  '--memory-reservation',
  '--memory-swap',
  '--memory-swappiness',
  '--mount',
  '--name',
  '--network',
  '--net',
  '--network-alias',
  '--oom-score-adj',
  '--pid',
  '--pids-limit',
  '--platform',
  '-p',
  '--publish',
  '--pull',
  '--restart',
  '--runtime',
  '--security-opt',
  '--shm-size',
  '--stop-signal',
  '--stop-timeout',
  '--storage-opt',
  '--sysctl',
  '--tmpfs',
  '--ulimit',
  '--umask',
  '-u',
  '--user',
  '--userns',
  '--uts',
  '-v',
  '--volume',
  '--volume-driver',
  '--volumes-from',
  '-w',
  '--workdir',
  // podman run / create (in addition)
  '--creds',
  '--arch',
  '--authfile',
  '--cert-dir',
  '--cgroup-conf',
  '--cgroups',
  '--chrootdirs',
  '--conmon-pidfile',
  '--decryption-key',
  '--env-merge',
  '--gidmap',
  '--group-entry',
  '--health-log-destination',
  '--health-max-log-count',
  '--health-max-log-size',
  '--health-on-failure',
  '--health-startup-cmd',
  '--health-startup-interval',
  '--health-startup-retries',
  '--health-startup-success',
  '--health-startup-timeout',
  '--hosts-file',
  '--hostuser',
  '--image-volume',
  '--init-path',
  '--os',
  '--passwd-entry',
  '--personality',
  '--pidfile',
  '--pod',
  '--pod-id-file',
  '--preserve-fd',
  '--preserve-fds',
  '--rdt-class',
  '--requires',
  '--retry',
  '--retry-delay',
  '--sdnotify',
  '--seccomp-policy',
  '--secret',
  '--shm-size-systemd',
  '--subgidname',
  '--subuidname',
  '--timeout',
  '--tz',
  '--uidmap',
  '--unsetenv',
  '--variant',
])

const RUN_SWITCH: ReadonlySet<string> = new Set([
  // docker
  '-d',
  '--detach',
  '--help',
  '--init',
  '-i',
  '--interactive',
  '--no-healthcheck',
  '--oom-kill-disable',
  '--privileged',
  '-P',
  '--publish-all',
  '-q',
  '--quiet',
  '--read-only',
  '--rm',
  '--sig-proxy',
  '-t',
  '--tty',
  '--use-api-socket',
  // podman (`--http-proxy`, `--read-only-tmpfs`, `--tls-verify` take a value only as `=v`)
  '--disable-content-trust',
  '--env-host',
  '--no-hostname',
  '--no-hosts',
  '--passwd',
  '--replace',
  '--rmi',
  '--rootfs',
  '--unsetenv-all',
  '--http-proxy',
  '--read-only-tmpfs',
  '--tls-verify',
])

const EXEC_VALUE: ReadonlySet<string> = new Set([
  '--detach-keys',
  '-e',
  '--env',
  '--env-file',
  '-u',
  '--user',
  '-w',
  '--workdir',
  // podman exec
  '--cidfile',
  '--preserve-fd',
  '--preserve-fds',
])

const EXEC_SWITCH: ReadonlySet<string> = new Set([
  '-d',
  '--detach',
  '-i',
  '--interactive',
  '--privileged',
  '-t',
  '--tty',
  // podman exec
  '-l',
  '--latest',
  '--no-session',
])

const PULL_VALUE: ReadonlySet<string> = new Set([
  '--platform',
  // podman pull
  '--arch',
  '--authfile',
  '--cert-dir',
  '--creds',
  '--decryption-key',
  '--os',
  '--policy',
  '--retry',
  '--retry-delay',
  '--tls-verify',
  '--variant',
])

const PULL_SWITCH: ReadonlySet<string> = new Set([
  '-a',
  '--all-tags',
  '-q',
  '--quiet',
  '--disable-content-trust',
  '-h',
  '--help',
])

const OPTIONS: Readonly<Record<string, OptionSet>> = {
  run: { value: RUN_VALUE, switches: RUN_SWITCH },
  create: { value: RUN_VALUE, switches: RUN_SWITCH },
  exec: { value: EXEC_VALUE, switches: EXEC_SWITCH },
  pull: { value: PULL_VALUE, switches: PULL_SWITCH },
}

/**
 * True when `name` is the Docker Compose `--no-TTY` switch under any casing. The reference spells it
 * `--no-TTY`; our tables carry `--no-tty`. Only this one flag is matched case-insensitively.
 */
const isNoTty = (name: string, set: OptionSet): boolean =>
  name.toLowerCase() === '--no-tty' && set.switches.has('--no-tty')

/**
 * Words one option occupies, or `undefined` when the option is not documented. `onOption` is called
 * once with every recognised option name (a long `--name`, or each short letter of a bare/clustered
 * `-abc`); it is never called for an option's value, so a value that looks like a flag (`-e -l`)
 * cannot be mistaken for the option itself.
 */
function optionWidth(
  tok: string,
  set: OptionSet,
  onOption?: (name: string, inlineValue?: string) => void,
): number | undefined {
  if (tok.startsWith('--')) {
    const eq = tok.indexOf('=')
    const name = eq > 0 ? tok.slice(0, eq) : tok
    onOption?.(name, eq > 0 ? tok.slice(eq + 1) : undefined)
    if (set.switches.has(name) || isNoTty(name, set)) return 1
    if (set.value.has(name)) return eq > 0 ? 1 : 2
    return undefined
  }
  if (set.value.has(tok)) {
    onOption?.(tok)
    return 2
  }
  if (set.switches.has(tok)) {
    onOption?.(tok)
    return 1
  }
  // `-p8080:80` (attached value) or a cluster such as `-it`, `-dit`, `-itp 80:80`.
  if (set.value.has(tok.slice(0, 2))) {
    onOption?.(tok.slice(0, 2))
    return 1
  }
  const letters = tok.slice(1).split('')
  for (let k = 0; k < letters.length; k++) {
    const f = `-${letters[k]}`
    if (set.value.has(f)) {
      onOption?.(f)
      return k === letters.length - 1 ? 2 : 1
    }
    if (!set.switches.has(f)) return undefined
    onOption?.(f)
  }
  return 1
}

/** `registry.acme.example/x/y:1` → `registry.acme.example`; `nginx` / `library/nginx` → none. */
export function imageRegistry(image: string): string | undefined {
  const slash = image.indexOf('/')
  if (slash < 0) return undefined
  const first = image.slice(0, slash)
  return first.includes('.') || first.includes(':') || first === 'localhost' ? first : undefined
}

/** `instrumentisto/nmap:7.94` → `nmap`. */
function imageBasename(image: string): string {
  const last = image.slice(image.lastIndexOf('/') + 1)
  return last.replace(/[@:].*$/, '')
}

export interface ContainerForm {
  opaque: OpaqueKind[]
  /** argv to parse with the docker/podman table entry (global options, subcommand, image). */
  outer: string[]
  /** Commands the container runs (the one after the image, plus fail-closed guesses). */
  nestedArgvs: string[][]
  /** Registry hosts named by the image. */
  targets: string[]
}

const CONTAINER_SUBCOMMANDS: ReadonlySet<string> = new Set([
  'run',
  'create',
  'exec',
  'pull',
  'compose',
  'container',
  'image',
])

/** Skips options from `start`; returns the next index and whether an option was undocumented. */
function skipOptions(
  argv: string[],
  start: number,
  set: OptionSet,
  onValue?: (name: string, value: string) => void,
  onOption?: (name: string, inlineValue?: string) => void,
): { next: number; unresolved: boolean } {
  let i = start
  let unresolved = false
  while (i < argv.length) {
    const tok = argv[i] as string
    if (tok === '--') return { next: i + 1, unresolved }
    if (!tok.startsWith('-') || tok === '-') break
    const width = optionWidth(tok, set, onOption)
    if (width === undefined) unresolved = true
    if (onValue && tok.startsWith('--') && tok.includes('=')) {
      onValue(tok.slice(0, tok.indexOf('=')), tok.slice(tok.indexOf('=') + 1))
    } else if (onValue && width === 2 && argv[i + 1] !== undefined) {
      onValue(tok, argv[i + 1] as string)
    }
    i += width ?? 1
  }
  return { next: i, unresolved }
}

/** Fail-closed guess: from the first word after `from` that names a known tool. */
function firstToolArgv(
  argv: string[],
  from: number,
  skip: number,
  tools: readonly KnownToolSpec[],
): string[] | undefined {
  const k = argv.findIndex((t, n) => n > from && n !== skip && lookupTool(t, tools) !== undefined)
  if (k < 0) return undefined
  // A tool word before the image (an entrypoint value) runs with the words after the image.
  return k < skip ? [argv[k] as string, ...argv.slice(skip + 1)] : argv.slice(k)
}

const pushUnique = (list: string[][], argv: string[] | undefined) => {
  if (argv && argv.length > 0 && !list.some((x) => x.join('\u0000') === argv.join('\u0000'))) {
    list.push(argv)
  }
}

/**
 * The command after the image or service: `--entrypoint X` runs X with the words after it; a
 * first word starting with `-` goes to the image's own entrypoint (unknown: fail closed, and try
 * the image's basename, `instrumentisto/nmap`).
 */
function innerCommands(
  form: ContainerForm,
  inner: string[],
  entrypoint: string | undefined,
  image: string,
  tools: readonly KnownToolSpec[],
): boolean {
  if (entrypoint !== undefined && entrypoint.trim() !== '') {
    pushUnique(form.nestedArgvs, [...entrypoint.trim().split(/\s+/), ...inner])
    return false
  }
  if (inner.length === 0) return false
  if (!(inner[0] as string).startsWith('-')) {
    pushUnique(form.nestedArgvs, inner)
    return false
  }
  const base = imageBasename(image)
  if (lookupTool(base, tools)) pushUnique(form.nestedArgvs, [base, ...inner])
  return true
}

/** `compose [globals] run|exec [opts] SERVICE [CMD…]` starting at `start`. */
function composeForm(
  argv: string[],
  start: number,
  unresolvedBefore: boolean,
  tools: readonly KnownToolSpec[],
): ContainerForm | undefined {
  const globals = skipOptions(argv, start, {
    value: COMPOSE_GLOBAL_VALUE,
    switches: COMPOSE_GLOBAL_SWITCH,
  })
  let unresolved = unresolvedBefore || globals.unresolved
  const subIndex = globals.next
  const sub = argv[subIndex]
  const set = sub === 'run' ? COMPOSE_RUN : sub === 'exec' ? COMPOSE_EXEC : undefined
  if (set === undefined) {
    return unresolved
      ? {
          opaque: ['nested-command-unresolved'],
          outer: argv,
          nestedArgvs: [firstToolArgv(argv, 0, -1, tools) ?? []].filter((a) => a.length > 0),
          targets: [],
        }
      : undefined
  }
  let entrypoint: string | undefined
  const opts = skipOptions(argv, subIndex + 1, set, (name, value) => {
    if (name === '--entrypoint') entrypoint = value
  })
  unresolved ||= opts.unresolved
  const serviceIndex = opts.next
  const service = argv[serviceIndex]
  const form: ContainerForm = {
    opaque: [],
    outer: argv.slice(0, Math.min(serviceIndex + 1, argv.length)),
    nestedArgvs: [],
    targets: [],
  }
  if (service !== undefined) {
    unresolved =
      innerCommands(form, argv.slice(serviceIndex + 1), entrypoint, service, tools) || unresolved
  }
  if (unresolved) {
    form.opaque.push('nested-command-unresolved')
    pushUnique(form.nestedArgvs, firstToolArgv(argv, subIndex, serviceIndex, tools))
  }
  return form
}

/**
 * `docker|podman [global opts] [container|image] run|create|exec|pull [opts] IMAGE [CMD…]`,
 * `docker|podman compose …`, and `docker-compose|podman-compose …`. The words after the image (or
 * service) are the nested command. Fails closed: an undocumented option (global or not), or a
 * command that starts with `-`, raises `nested-command-unresolved`, and the first word naming a
 * known tool (or the image's basename) is analysed as the command too.
 */
export function containerForm(
  argv: string[],
  tools: readonly KnownToolSpec[],
): ContainerForm | undefined {
  const program = (argv[0] ?? '')
    .split(/[\\/]/)
    .pop()
    ?.replace(/\.exe$/i, '')
    .toLowerCase()
  if (program === 'docker-compose' || program === 'podman-compose') {
    return composeForm(argv, 1, false, tools)
  }
  const globals = skipOptions(argv, 1, { value: GLOBAL_VALUE, switches: GLOBAL_SWITCH })
  let unresolved = globals.unresolved
  let i = globals.next
  if (unresolved && !CONTAINER_SUBCOMMANDS.has(argv[i] ?? '')) {
    // An undocumented global may have taken the next word: find the subcommand, or give up.
    const k = argv.findIndex((t, n) => n >= i && CONTAINER_SUBCOMMANDS.has(t))
    if (k < 0) {
      return {
        opaque: ['nested-command-unresolved'],
        outer: argv,
        nestedArgvs: [firstToolArgv(argv, 0, -1, tools) ?? []].filter((a) => a.length > 0),
        targets: [],
      }
    }
    i = k
  }
  if (argv[i] === 'compose') return composeForm(argv, i + 1, unresolved, tools)
  let skip = -1
  if (argv[i] === 'container' || argv[i] === 'image') {
    skip = i
    i++
  }
  const sub = argv[i]
  const set = sub === undefined ? undefined : OPTIONS[sub]
  if (sub === undefined || set === undefined) {
    return unresolved
      ? {
          opaque: ['nested-command-unresolved'],
          outer: argv,
          nestedArgvs: [firstToolArgv(argv, 0, -1, tools) ?? []].filter((a) => a.length > 0),
          targets: [],
        }
      : undefined
  }
  const subIndex = i
  let entrypoint: string | undefined
  // `-l`/`--latest` (podman exec, no container argument) read from the option letters only — never
  // from an option's value, so `exec -e -l ctr …` keeps `ctr` as the container.
  let latest = false
  // pflag booleans accept `--latest=false|0|f`: only a true value selects the latest container; a
  // false value keeps the container argument; anything else is unknown and fails closed.
  let latestUnresolved = false
  const opts = skipOptions(
    argv,
    i + 1,
    set,
    (name, value) => {
      if (name === '--entrypoint') entrypoint = value
    },
    (name, inlineValue) => {
      if (sub !== 'exec' || (name !== '-l' && name !== '--latest')) return
      if (inlineValue === undefined || /^(true|t|1)$/i.test(inlineValue)) latest = true
      else if (!/^(false|f|0)$/i.test(inlineValue)) latestUnresolved = true
    },
  )
  unresolved ||= opts.unresolved || latestUnresolved
  i = opts.next
  const keep = (_: string, k: number) => k !== skip
  // `podman exec -l/--latest` has no container argument: the command starts right away.
  if (latest) {
    const form: ContainerForm = {
      opaque: [],
      outer: argv.slice(0, i).filter(keep),
      nestedArgvs: [],
      targets: [],
    }
    pushUnique(form.nestedArgvs, argv.slice(i))
    if (unresolved) {
      form.opaque.push('nested-command-unresolved')
      pushUnique(form.nestedArgvs, firstToolArgv(argv, subIndex, -1, tools))
    }
    return form
  }
  const image = argv[i]
  const outer = argv.slice(0, Math.min(i + 1, argv.length)).filter(keep)
  const form: ContainerForm = { opaque: [], outer, nestedArgvs: [], targets: [] }
  if (image === undefined) return form
  const registry = sub === 'exec' ? undefined : imageRegistry(image)
  if (registry !== undefined) form.targets.push(registry)
  if (sub === 'pull') {
    // `pull` runs no nested command, but an undocumented global may have swallowed a word and left
    // the real subcommand (and its argv) past the `pull` token: fail closed and still sweep it.
    if (unresolved) {
      form.opaque.push('nested-command-unresolved')
      pushUnique(form.nestedArgvs, firstToolArgv(argv, subIndex, i, tools))
    }
    return form
  }
  unresolved = innerCommands(form, argv.slice(i + 1), entrypoint, image, tools) || unresolved
  if (unresolved) {
    form.opaque.push('nested-command-unresolved')
    pushUnique(form.nestedArgvs, firstToolArgv(argv, subIndex, i, tools))
  }
  return form
}
