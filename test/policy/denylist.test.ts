import { describe, expect, it } from 'vitest'
import { checkDenylist, DENYLIST } from '../../src/policy/denylist.js'
import { analyze } from './helpers.js'

type Shell = 'posix' | 'powershell'
interface Case {
  command: string
  shell: Shell
}
const c = (command: string, shell: Shell = 'posix'): Case => ({ command, shell })

/** Per entry: commands it must refuse, and near misses that no entry may refuse. */
const TABLE: Record<string, { hits: Case[]; misses: Case[] }> = {
  'dos-tools': {
    hits: [
      c('aireplay-ng -00 -a 00:11:22:33:44:55 wlan0mon'),
      c('hping3 --flood -S -p 80 192.0.2.10'),
      c('sudo hping3 -S -p 80 -i u1000 192.0.2.10'),
      c('hping3 -S -p 80 -iu100 192.0.2.10'),
      c('hping3 -S --interval u10 192.0.2.10'),
      c('slowloris 192.0.2.10'),
      c('python3 slowloris.py 192.0.2.10'),
      c('slowhttptest -c 1000 -H -u https://acme.example'),
      c('t50 192.0.2.10 --flood'),
      c('thc-ssl-dos 192.0.2.10 443'),
      c('goldeneye https://acme.example'),
      c('python hulk.py https://acme.example'),
      c('mdk4 wlan0mon d'),
      c('mdk3 wlan0mon a'),
      c('aireplay-ng --deauth 10 -a 00:11:22:33:44:55 wlan0mon'),
      c('aireplay-ng -0 5 -a 00:11:22:33:44:55 wlan0mon'),
      c("bash -c 'hping3 --flood 192.0.2.10'"),
      c("ssh pivot.acme.example 'hping3 --flood 192.0.2.10'"),
    ],
    misses: [
      c('hping3 -S -p 80 -c 3 192.0.2.10'),
      c('hping3 -S -p 80 -i 1 -c 3 192.0.2.10'),
      c('aireplay-ng -9 wlan0mon'),
      c('apt-get install slowhttptest'),
      c('grep -r slowloris notes/'),
    ],
  },
  'nmap-script-dos': {
    hits: [
      c('nmap --script vuln 192.0.2.10'),
      c('nmap --script exploit -p 445 192.0.2.10'),
      c('nmap --script intrusive 192.0.2.10'),
      c('nmap --script "*" 192.0.2.10'),
      c('nmap --script "default,vuln" 192.0.2.10'),
      c('nmap --script "vuln or exploit" 192.0.2.10'),
      c('nmap --script "http-slowloris and not dos" 192.0.2.10'),
      c('nmap --script dos 192.0.2.10'),
      c('nmap --script=http-slowloris -p 80 192.0.2.10'),
      c('nmap --script "default,dos" 192.0.2.10'),
      c('nmap --script smb-vuln-regsvc-dos -p 445 192.0.2.10'),
      c('nmap --script all 192.0.2.10'),
      c('nmap --script "smb-*" -p 445 192.0.2.10'),
      c('nmap -script ipv6-ra-flood -6 2001:db8::1'),
    ],
    misses: [
      c('nmap --script safe 192.0.2.10'),
      c('nmap --script "default or safe" 192.0.2.10'),
      c('nmap --script ssl-enum-ciphers -p 443 192.0.2.10'),
      c('nmap --script "vuln and not dos" 192.0.2.10'),
      c('nmap --script "(vuln or exploit) and not dos" 192.0.2.10'),
      c('nmap --script "all and not dos" 192.0.2.10'),
      c('nmap --script default 192.0.2.10'),
      c('nmap --script "default and not dos" 192.0.2.10'),
      c('nmap --script http-slowloris-check -p 80 192.0.2.10'),
      c('nmap --script "http-title,ssl-*" -p 443 192.0.2.10'),
      c('nmap -sC -sV 192.0.2.10'),
    ],
  },
  'random-targeting': {
    hits: [
      c('nmap -iR 100 -p 80'),
      c('nmap -sS -iR 0'),
      c('hping3 --rand-dest -S -p 80 192.0.2.x'),
      c('zmap -p 80'),
      c('zmap -p 443 -N 1000 -o out.csv'),
      c('masscan -p80 --rate 100'),
      c('masscan -p80 --exclude 192.0.2.5 --rate 100'),
      c('zmap -p 80 -c 8 -o out.csv'),
    ],
    misses: [
      c('masscan -p80 --range=192.0.2.0/25 --rate 100'),
      c('masscan -p80 --ranges=192.0.2.0/25 --rate 100'),
      c('masscan -p80 --dst=192.0.2.0/25 --rate 100'),
      c('masscan 192.0.2.0/25 --rate 100'),
      c('zmap -p 80 192.0.2.0/25'),
      c('zmap -p 80 -w allow.txt'),
      c('masscan -p80 -iL targets-in.txt --rate 100'),
      c('zmap --help'),
      c('masscan -c scan.conf'),
      c('nmap -iL targets-in.txt'),
    ],
  },
  'global-range': {
    hits: [
      c('nmap 0/0'),
      c('nmap -sn 64/7'),
      c('masscan -p80 0/0 --rate 100'),
      c('masscan -p80 --range=0.0.0.0/0 --rate 100'),
      c('nmap 0.0.0.0/0'),
      c('nmap -sn 64.0.0.0/7'),
      c('nmap -6 ::/0'),
      c('nmap 0.0.0.0-255.255.255.255'),
      c('masscan 0.0.0.0/0 -p443 --rate 100'),
      c("ssh pivot.acme.example 'nmap -sn 0.0.0.0/0'"),
      c('fping -a -g 0.0.0.0/1'),
    ],
    misses: [
      c('nmap 10/8'),
      c('nmap -sn 192.0.2/24'),
      c('nmap 10.0.0.0/8'),
      c('nmap 192.0.2.0/24'),
      c('nmap -6 2001:db8::/32'),
      c('iptables -A INPUT -s 0.0.0.0/0 -j DROP'),
      c('echo 0.0.0.0/0'),
      c("ssh pivot.acme.example 'ip route add 0.0.0.0/0 via 192.0.2.1'"),
    ],
  },
  'log-wipe': {
    hits: [
      c('> /var/log/auth.log'),
      c('>| /var/log/wtmp'),
      c('echo >| /var/log/wtmp'),
      c('ssh root@192.0.2.10 ">/var/log/auth.log"'),
      c('ssh root@192.0.2.10 "echo >| /var/log/wtmp"'),
      c('Get-EventLog -List | ForEach-Object { Clear-EventLog $_.Log }', 'powershell'),
      c('wevtutil el | ForEach-Object { wevtutil cl $_ }', 'powershell'),
      c('wevtutil el | % { wevtutil cl $_ }', 'powershell'),
      c(
        'Get-ChildItem C:\\Windows\\System32\\winevt\\Logs\\*.evtx | Remove-Item -Force',
        'powershell',
      ),
      c('shred -u /var/log/auth.log'),
      c('sudo truncate -s 0 /var/log/syslog'),
      c('rm -rf /var/log/*'),
      c('rm -f /var//log/apache2/access.log'),
      c('cat /dev/null > /var/log/wtmp'),
      c('find /var/log -type f -delete'),
      c('wevtutil cl Security'),
      c('wevtutil.exe clear-log System'),
      c('Clear-EventLog -LogName Security', 'powershell'),
      c('Remove-EventLog -LogName Application', 'powershell'),
      c('Remove-Item C:\\Windows\\System32\\winevt\\Logs\\Security.evtx', 'powershell'),
      c("ssh root@192.0.2.10 'rm -rf /var/log/*'"),
      c("nxc smb 192.0.2.10 -u admin -p pw -x 'wevtutil cl Security'"),
    ],
    misses: [
      c('Get-ChildItem C:\\Windows\\System32\\winevt\\Logs', 'powershell'),
      c('Copy-Item C:\\Windows\\System32\\winevt\\Logs\\Security.evtx .\\evidence\\', 'powershell'),
      c('wevtutil qe Security /c:5', 'powershell'),
      c('wevtutil el | ForEach-Object { wevtutil gli $_ }', 'powershell'),
      c('> ./notes.txt'),
      c('echo done >| ./build.log'),
      c('shred -u ./tmp/key.pem'),
      c('wevtutil qe Security'),
      c('rm -rf ./var/log/build'),
      c('cat /var/log/auth.log'),
      c('tail -n 50 /var/log/syslog > ./syslog-tail.txt'),
      c('Get-EventLog -LogName Security -Newest 10', 'powershell'),
      c("ssh root@192.0.2.10 'tail /var/log/auth.log'"),
    ],
  },
  'audit-disable': {
    hits: [
      c('auditctl -D'),
      c('sudo auditctl -e 0'),
      c('auditctl -e0'),
      c('systemctl stop auditd'),
      c('service auditd stop'),
      c('auditpol /clear /y'),
      c("ssh root@192.0.2.10 'auditctl -D'"),
    ],
    misses: [
      c('auditctl -l'),
      c('auditctl -e 1'),
      c('systemctl status auditd'),
      c('auditpol /get /category:*'),
    ],
  },
  'history-wipe': {
    hits: [
      c("ssh 192.0.2.10 -p 2222 'history -c'"),
      c("ssh 192.0.2.10 -- 'history -c'"),
      c("ssh -- 192.0.2.10 'history -c'"),
      c(`ssh 192.0.2.10 "id; echo don't; history -c"`),
      c("sshpass -p pw ssh root@192.0.2.10 'history -c'"),
      c("sshpass -f pass.txt -e ssh -p 2222 root@192.0.2.10 'history -c'"),
      c("ssh user@192.0.2.10 'history -c'"),
      c('ssh user@192.0.2.10 history -c'),
      c("ssh -p 2222 -i id_ed25519 user@192.0.2.10 'id; history -cw'"),
      c("ssh 192.0.2.10 'unset HISTFILE'"),
      c("ssh 192.0.2.10 'export HISTFILE=/dev/null'"),
      c("ssh 192.0.2.10 'rm -f ~/.bash_history'"),
      c("ssh 192.0.2.10 'cat /dev/null > ~/.bash_history'"),
      c("ssh 192.0.2.10 'set +o history'"),
      c(`ssh 192.0.2.10 'sudo bash -c "history -c"'`),
    ],
    misses: [
      c("ssh 192.0.2.10 'echo history -c'; id"),
      c('sshpass -p pw ssh root@192.0.2.10 id; history -c'),
      c('history -c'),
      c("ssh user@192.0.2.10 'cat ~/.bash_history'"),
      c('ssh user@192.0.2.10 history'),
      c("ssh -o 'ProxyCommand=history -c' 192.0.2.10 id"),
    ],
  },
  timestomp: {
    hits: [
      c('timestomp evil.exe -z "01/01/2020 00:00:00"'),
      c(`msfconsole -q -x 'sessions -i 1 -c "timestomp C:\\x.exe -b"'`),
      c(`ssh 192.0.2.10 'touch -d "2020-01-01 00:00" /usr/bin/backdoor'`),
      c("ssh 192.0.2.10 'touch -r /bin/ls /tmp/implant'"),
      c("(Get-Item C:\\x.exe).LastWriteTime = '01/01/2020'", 'powershell'),
      c('Set-ItemProperty -Path C:\\x.exe -Name CreationTime -Value "01/01/2020"', 'powershell'),
    ],
    misses: [
      c('touch -d "2026-01-01" build.stamp'),
      c("ssh 192.0.2.10 'touch /tmp/marker'"),
      c('Get-Item C:\\x.exe | Select-Object LastWriteTime', 'powershell'),
      c("if ((Get-Item C:\\x.exe).LastWriteTime -eq $d) { 'same' }", 'powershell'),
    ],
  },
  'remote-root-wipe': {
    hits: [
      c("ssh 192.0.2.10 -p 2222 'rm -rf /'"),
      c("ssh 192.0.2.10 -- 'rm -rf /'"),
      c("ssh root@192.0.2.10 'rm -rf /'"),
      c("ssh root@192.0.2.10 'rm -rf --no-preserve-root /'"),
      c("ssh root@192.0.2.10 'sudo rm -fr /*'"),
      c("ssh user@192.0.2.10 'rm -rf ~'"),
      c("ssh user@192.0.2.10 'rm -r -f $HOME/'"),
      c("ssh root@192.0.2.10 'dd if=/dev/zero of=/dev/sda bs=1M'"),
      c("ssh root@192.0.2.10 'mkfs.ext4 /dev/sda1'"),
    ],
    misses: [
      c("ssh root@192.0.2.10 'rm -rf /tmp/guard-upload'"),
      c("ssh user@192.0.2.10 'rm -rf ~/scratch'"),
      c("ssh root@192.0.2.10 'dd if=/dev/sda of=/tmp/mbr.bin bs=512 count=1'"),
      c('rm -rf ./dist'),
    ],
  },
  'defence-disable': {
    hits: [
      c("ssh 192.0.2.10 -l root -p 2222 'ufw disable'"),
      c(`ssh 192.0.2.10 'id; echo "x; ufw disable'`),
      c("ssh admin@192.0.2.10 'netsh advfirewall set allprofiles state off'"),
      c("ssh admin@192.0.2.10 'sudo ufw disable'"),
      c("ssh root@192.0.2.10 'iptables -F'"),
      c("ssh root@192.0.2.10 'iptables --flush INPUT'"),
      c("ssh root@192.0.2.10 'systemctl stop firewalld'"),
      c("nxc smb 192.0.2.10 -u admin -p pw -X 'Set-MpPreference -DisableRealtimeMonitoring $true'"),
      c("nxc smb 192.0.2.10 -u admin -p pw -x 'netsh advfirewall set currentprofile state off'"),
    ],
    misses: [
      c(`ssh 192.0.2.10 "echo it's"; iptables -F`),
      c(`ssh 192.0.2.10 'echo "hi'; sudo ufw disable`),
      c("ssh admin@192.0.2.10 'netsh advfirewall show allprofiles'"),
      c("ssh admin@192.0.2.10 'ufw status verbose'"),
      c("ssh root@192.0.2.10 'iptables -L -n'"),
      c('sudo ufw disable'),
      c('iptables -F'),
    ],
  },
}

describe('DENYLIST', () => {
  it('has unique ids, each with a description and a fixture table', () => {
    const ids = DENYLIST.map((e) => e.id)
    expect(new Set(ids).size).toBe(ids.length)
    for (const e of DENYLIST) expect(e.description.length).toBeGreaterThan(10)
    expect(Object.keys(TABLE).sort()).toEqual([...ids].sort())
  })

  for (const [id, { hits, misses }] of Object.entries(TABLE)) {
    describe(id, () => {
      it('has at least one positive and one near-miss negative', () => {
        expect(hits.length).toBeGreaterThan(0)
        expect(misses.length).toBeGreaterThan(0)
      })
      for (const h of hits) {
        it(`refuses: ${h.command}`, async () => {
          const a = await analyze(h.command, h.shell)
          expect(checkDenylist(a)?.id).toBe(id)
        })
      }
      for (const m of misses) {
        it(`passes near miss: ${m.command}`, async () => {
          const a = await analyze(m.command, m.shell)
          expect(checkDenylist(a)).toBeUndefined()
        })
      }
    })
  }

  it('entry tests are pure: the same analysis gives the same answer twice', async () => {
    const a = await analyze("ssh root@192.0.2.10 'history -c'; nmap --script dos 192.0.2.10")
    const first = DENYLIST.map((e) => e.test(a))
    expect(first.filter(Boolean).length).toBe(2)
    expect(DENYLIST.map((e) => e.test(a))).toEqual(first)
  })

  it('stays fast on long hostile input', async () => {
    const hostile = [
      `nmap --script ${'a*'.repeat(5_000)}b 192.0.2.10`,
      `ssh 192.0.2.10 '${'rm -rf ; '.repeat(5_000)}'`,
      `rm ${'/'.repeat(50_000)}x`,
    ]
    for (const cmd of hostile) {
      const a = await analyze(cmd)
      const t0 = performance.now()
      checkDenylist(a)
      expect(performance.now() - t0).toBeLessThan(500)
    }
  })

  it('ordinary developer and recon commands pass', async () => {
    for (const cmd of [
      'git clone https://github.com/acme/app.git',
      'pnpm install',
      'nmap -sV -T3 192.0.2.10',
      'curl -s https://acme.example/robots.txt',
      'ls -la /var/log',
      'ssh user@192.0.2.10 id',
      'constructor __proto__ toString',
      "ssh 192.0.2.10 'constructor; __proto__ -x'",
    ]) {
      expect(checkDenylist(await analyze(cmd)), cmd).toBeUndefined()
    }
  })
})

describe('nmap-script-dos suggestion', () => {
  const entry = DENYLIST.find((e) => e.id === 'nmap-script-dos')
  const suggest = async (command: string) => entry?.suggest?.(await analyze(command)) ?? null

  it('keeps the operator category and excludes dos', async () => {
    expect(await suggest('nmap --script vuln 192.0.2.10')).toBe('--script "vuln and not dos"')
    expect(await suggest('nmap --script=exploit 192.0.2.10')).toBe('--script "exploit and not dos"')
  })

  it('applies per comma element and brackets boolean expressions', async () => {
    expect(await suggest('nmap --script "default,vuln" 192.0.2.10')).toBe(
      '--script "default,vuln and not dos"',
    )
    expect(await suggest('nmap --script "vuln or exploit" 192.0.2.10')).toBe(
      '--script "(vuln or exploit) and not dos"',
    )
  })

  it('drops explicitly named DoS scripts, or offers nothing when none remain', async () => {
    expect(await suggest('nmap --script "default,http-slowloris" 192.0.2.10')).toBe(
      '--script "default"',
    )
    expect(await suggest('nmap --script dos 192.0.2.10')).toBeNull()
  })

  it('entries without a compliant alternative have no suggest', () => {
    for (const e of DENYLIST) if (e.id !== 'nmap-script-dos') expect(e.suggest).toBeUndefined()
  })
})

/** Fix round 2: ANSI-C quoting, sound --script logic, PowerShell bodies across split segments, ssh hops. */
const ROUND2: Record<string, { hits: Case[]; misses: Case[] }> = {
  'history-wipe': {
    hits: [
      c("ssh 192.0.2.10 $'id \\'x\\'; history -c'"),
      c("ssh 192.0.2.10 $'\\'\\'; history -c'"),
      c(`ssh pivot.acme.example 'ssh root@192.0.2.10 "history -c"'`),
      c(`ssh pivot.acme.example 'sshpass -p pw ssh root@192.0.2.10 "history -c"'`),
      c(`ssh pivot.acme.example 'ssh -p 2222 jump.acme.example "ssh root@192.0.2.10 history -c"'`),
    ],
    misses: [c("ssh pivot.acme.example 'ssh root@192.0.2.10 id'")],
  },
  'defence-disable': {
    hits: [],
    misses: [c("ssh 192.0.2.10 'echo \\'; ufw disable"), c("echo $'it\\'s'; ufw status")],
  },
  'nmap-script-dos': {
    hits: [
      c("nmap --script 'not safe' 192.0.2.10"),
      c('nmap --script "not default" 192.0.2.10'),
      c('nmap --script "vuln or not dos" 192.0.2.10'),
      c('nmap --script "(vuln and not dos) or exploit" 192.0.2.10'),
      c('nmap --script "not (dos or safe) or vuln" 192.0.2.10'),
      c('nmap --script broadcast 192.0.2.10'),
      c('nmap --script "vul*" 192.0.2.10'),
      c('nmap --script "((vuln and not dos)" 192.0.2.10'),
      c('nmap --script "vuln and not" 192.0.2.10'),
      c('nmap --script /usr/share/nmap/scripts/ 192.0.2.10'),
      c('nmap --script /usr/share/nmap/scripts 192.0.2.10'),
      c('nmap --script ./scripts/ 192.0.2.10'),
      c('nmap --script "default,./scripts/" 192.0.2.10'),
    ],
    misses: [
      c('nmap --script "vuln and not dos" 192.0.2.10'),
      c("nmap --script 'safe and not dos' 192.0.2.10"),
      c('nmap --script "not dos and vuln" 192.0.2.10'),
      c('nmap --script "all and not dos" 192.0.2.10'),
      c('nmap --script "vuln and (not dos)" 192.0.2.10'),
      c('nmap --script "(default or vuln) and not dos" 192.0.2.10'),
      c('nmap --script "not dos" 192.0.2.10'),
      c('nmap --script default 192.0.2.10'),
      c('nmap --script safe 192.0.2.10'),
      c('nmap --script "default or safe" 192.0.2.10'),
      c('nmap --script vulners -sV 192.0.2.10'),
      c('nmap --script ssl-enum-ciphers -p 443 192.0.2.10'),
      c('nmap --script ./custom/http-title2.nse 192.0.2.10'),
    ],
  },
  'log-wipe': {
    hits: [
      c("pwsh -c 'Get-EventLog -List | % { Clear-EventLog $_.Log }'"),
      c(`powershell -Command "wevtutil el | ForEach-Object { wevtutil cl $_ }"`),
      c("nxc smb 203.0.113.5 -u a -p b -X 'Get-EventLog -List | % { Clear-EventLog $_.Log }'"),
      c("nxc smb 203.0.113.5 -u a -p b -X 'wevtutil el | % { wevtutil cl $_ }'"),
      c("iex 'Clear-EventLog Security'", 'powershell'),
      c('Get-Help about_Logs | % { Clear-EventLog Security }', 'powershell'),
    ],
    misses: [
      c(
        "nxc smb 203.0.113.5 -u a -p b -X 'Get-ChildItem C:\\Windows\\System32\\winevt\\Logs | Format-Table'",
      ),
      c("pwsh -c 'Get-EventLog -List | Format-Table'"),
      c('Get-Help Clear-EventLog', 'powershell'),
      c('Get-Help Clear-EventLog -Full | more', 'powershell'),
      c('Get-Command Remove-EventLog', 'powershell'),
      c('gcm Clear-EventLog; man Remove-EventLog', 'powershell'),
    ],
  },
}

describe('DENYLIST fix round 2', () => {
  for (const [id, { hits, misses }] of Object.entries(ROUND2)) {
    describe(id, () => {
      for (const h of hits) {
        it(`refuses: ${h.command}`, async () => {
          expect(checkDenylist(await analyze(h.command, h.shell))?.id).toBe(id)
        })
      }
      for (const m of misses) {
        it(`passes near miss: ${m.command}`, async () => {
          expect(checkDenylist(await analyze(m.command, m.shell))).toBeUndefined()
        })
      }
    })
  }

  it('every nmap-script-dos suggestion is itself accepted', async () => {
    const entry = DENYLIST.find((e) => e.id === 'nmap-script-dos')
    const hits = [...(TABLE['nmap-script-dos']?.hits ?? []), ...ROUND2['nmap-script-dos']!.hits]
    let suggested = 0
    for (const h of hits) {
      const s = entry?.suggest?.(await analyze(h.command)) ?? null
      if (s === null) continue
      suggested++
      expect(
        checkDenylist(await analyze(`nmap ${s} 192.0.2.10`)),
        `${h.command} → ${s}`,
      ).toBeUndefined()
    }
    expect(suggested).toBeGreaterThan(5)
  })

  it('suggestions for negations and directories', async () => {
    const entry = DENYLIST.find((e) => e.id === 'nmap-script-dos')
    const suggest = async (cmd: string) => entry?.suggest?.(await analyze(cmd)) ?? null
    expect(await suggest("nmap --script 'not safe' 192.0.2.10")).toBe(
      '--script "(not safe) and not dos"',
    )
    expect(await suggest('nmap --script /usr/share/nmap/scripts/ 192.0.2.10')).toBeNull()
    expect(await suggest('nmap --script "default,./scripts/" 192.0.2.10')).toBe(
      '--script "default"',
    )
  })

  it('deeply nested --script parentheses fail closed without throwing', async () => {
    const deep = `nmap --script "${'('.repeat(5000)}safe${')'.repeat(5000)}" 192.0.2.10`
    expect(checkDenylist(await analyze(deep))?.id).toBe('nmap-script-dos')
  })
})

/** Fix round 3: negated script paths, strict help-head exemption, remote PowerShell bodies. */
const ROUND3: Record<string, { hits: Case[]; misses: Case[] }> = {
  'nmap-script-dos': {
    hits: [
      c('nmap --script "not ./scripts/" 192.0.2.10'),
      c('nmap --script "not /usr/share/nmap/scripts" 192.0.2.10'),
      c('nmap --script "not ./custom/" 192.0.2.10'),
      c('nmap --script /opt/my-nse 192.0.2.10'),
      c('nmap --script "safe or not ./custom" 192.0.2.10'),
    ],
    misses: [
      c('nmap --script ./my-check.nse 192.0.2.10'),
      c('nmap --script /opt/nse/http-title2.nse 192.0.2.10'),
    ],
  },
  'log-wipe': {
    hits: [
      c('& (gcm Clear-EventLog) Security', 'powershell'),
      c('& (Get-Command Clear-EventLog) -LogName Security', 'powershell'),
      c("(Get-Command Clear-EventLog).Invoke('Security')", 'powershell'),
      c('Get-Help (Clear-EventLog Security)', 'powershell'),
      c('gcm Clear-EventLog | % { & $_ Security }', 'powershell'),
      c('gcm Clear-EventLog | ForEach-Object { & $PSItem Security }', 'powershell'),
      c('. (gcm wevtutil) cl Security', 'powershell'),
      c('& wevtutil.exe cl Security', 'powershell'),
      c(`ssh 192.0.2.10 "pwsh -c 'Get-EventLog -List | % { Clear-EventLog \\$_.Log }'"`),
      c(`ssh 192.0.2.10 "powershell -Command 'wevtutil el | % { wevtutil cl \\$_ }'"`),
    ],
    misses: [
      c('Get-Help Clear-EventLog', 'powershell'),
      c('Get-Help Clear-EventLog -Full', 'powershell'),
      c('Get-Help Clear-EventLog -Parameter LogName', 'powershell'),
      c('man Clear-EventLog', 'powershell'),
      c("pwsh -c 'Get-Help Clear-EventLog | more'"),
      c("nxc smb 203.0.113.5 -u a -p b -X 'Get-Help Clear-EventLog | Out-String'"),
      c('wevtutil qe Security /c:5 | Select-String cl', 'powershell'),
    ],
  },
  'defence-disable': {
    hits: [c("ssh 192.0.2.10 echo $$'a; ufw disable'")],
    misses: [c("ssh 192.0.2.10 echo $$'\\'; ufw disable")],
  },
}

describe('DENYLIST fix round 3', () => {
  for (const [id, { hits, misses }] of Object.entries(ROUND3)) {
    describe(id, () => {
      for (const h of hits) {
        it(`refuses: ${h.command}`, async () => {
          expect(checkDenylist(await analyze(h.command, h.shell))?.id).toBe(id)
        })
      }
      for (const m of misses) {
        it(`passes near miss: ${m.command}`, async () => {
          expect(checkDenylist(await analyze(m.command, m.shell))).toBeUndefined()
        })
      }
    })
  }

  it('the help-head exemption stays linear on hostile option runs', async () => {
    const hostile = `Get-Help Clear-EventLog ${'-a '.repeat(20_000)}!`
    const a = await analyze(hostile, 'powershell')
    const t0 = performance.now()
    expect(checkDenylist(a)?.id).toBe('log-wipe')
    expect(performance.now() - t0).toBeLessThan(500)
  })
})

/** Fix round 4: help exemption over the whole pipeline, capture switches, PowerShell bodies after remote statements. */
const ROUND4: Record<string, { hits: Case[]; misses: Case[] }> = {
  'log-wipe': {
    hits: [
      c('gcm Clear-EventLog | Where-Object Name | % { & $_ Security }', 'powershell'),
      c('gcm Clear-EventLog | Select-Object -First 1 | % { & $_ Security }', 'powershell'),
      c('gcm Clear-EventLog | % Name | % { & $_ Security }', 'powershell'),
      c(`ssh h "pwsh -c 'gcm Clear-EventLog | sort | % { & \\$_ Security }'"`),
      c('gcm Clear-EventLog -OutVariable c; & $c[0] Security', 'powershell'),
      c('gcm Clear-EventLog -ov c; & $c[0] Security', 'powershell'),
      c('Get-Command Clear-EventLog -PipelineVariable p | % { & $p Security }', 'powershell'),
      c('gcm Remove-EventLog -ov c; & $c[0] Security', 'powershell'),
      c("pwsh -c 'gcm Clear-EventLog -ov c; & $c[0] Security'"),
      c(`ssh 192.0.2.10 "cd /; pwsh -c 'Get-EventLog -List | % { Clear-EventLog \\$_.Log }'"`),
      c(`ssh 192.0.2.10 "id && pwsh -c 'Get-EventLog -List | % { Clear-EventLog \\$_.Log }'"`),
      c(`bash -c "id; pwsh -c 'Get-EventLog -List | % { Clear-EventLog \\$_.Log }'"`),
    ],
    misses: [
      c('Get-Help Clear-EventLog', 'powershell'),
      c('Get-Help Clear-EventLog -Full', 'powershell'),
      c('man Clear-EventLog', 'powershell'),
      c('Get-Help Clear-EventLog | more', 'powershell'),
      c('gcm Clear-EventLog | Format-List', 'powershell'),
      c(`ssh h "pwsh -c 'Get-Date'" | grep x`),
      c(`ssh h "pwsh -c 'Get-Date'; echo 'a | b'"`),
    ],
  },
  'nmap-script-dos': {
    hits: [
      c('nmap --script /usr/share/nmap/scripts/http-title 192.0.2.10'),
      c('nmap --script ~/nse/http-title 192.0.2.10'),
    ],
    misses: [
      c('nmap --script /usr/share/nmap/scripts/http-title.nse 192.0.2.10'),
      c('nmap --script ~/nse/http-title.nse 192.0.2.10'),
    ],
  },
}

describe('DENYLIST fix round 4', () => {
  for (const [id, { hits, misses }] of Object.entries(ROUND4)) {
    describe(id, () => {
      for (const h of hits) {
        it(`refuses: ${h.command}`, async () => {
          expect(checkDenylist(await analyze(h.command, h.shell))?.id).toBe(id)
        })
      }
      for (const m of misses) {
        it(`passes near miss: ${m.command}`, async () => {
          expect(checkDenylist(await analyze(m.command, m.shell))).toBeUndefined()
        })
      }
    })
  }

  it('suggests appending .nse to an extensionless --script path, and the suggestion passes', async () => {
    const entry = DENYLIST.find((e) => e.id === 'nmap-script-dos')
    const suggest = async (cmd: string) => entry?.suggest?.(await analyze(cmd)) ?? null
    expect(await suggest('nmap --script /usr/share/nmap/scripts/http-title 192.0.2.10')).toBe(
      '--script "/usr/share/nmap/scripts/http-title.nse"',
    )
    expect(await suggest('nmap --script ~/nse/http-title 192.0.2.10')).toBe(
      '--script "~/nse/http-title.nse"',
    )
    // A genuine directory (trailing slash or a `scripts` leaf) still has no file suggestion.
    expect(await suggest('nmap --script /usr/share/nmap/scripts 192.0.2.10')).toBeNull()
    expect(await suggest('nmap --script ./scripts/ 192.0.2.10')).toBeNull()
    // The suggestion itself passes the denylist.
    expect(
      checkDenylist(
        await analyze('nmap --script "/usr/share/nmap/scripts/http-title.nse" 192.0.2.10'),
      ),
    ).toBeUndefined()
    expect(
      checkDenylist(await analyze('nmap --script "~/nse/http-title.nse" 192.0.2.10')),
    ).toBeUndefined()
  })
})

/** Fix round 5 (final): positive help allowlist, invoke-expression, re-checked suggestions, gated body carry. */
const ROUND5: Record<string, { hits: Case[]; misses: Case[] }> = {
  'log-wipe': {
    hits: [
      c('gcm Clear-EventLog | Set-Variable c; & $c Security', 'powershell'),
      c('gcm Clear-EventLog | sv c; & $c Security', 'powershell'),
      c('gcm Clear-EventLog | New-Variable c; & $c Security', 'powershell'),
      c('gcm Clear-EventLog | Tee-Object -Variable c; & $c Security', 'powershell'),
      c("gcm Clear-EventLog | % { 'x'; & $_ Security }", 'powershell'),
      c('gcm Clear-EventLog | % { ;& $_ Security }', 'powershell'),
      c("gcm Clear-EventLog | % { 'a;b' | Out-Null; & $_ Security }", 'powershell'),
      c('filter f { & $_ Security }; gcm Clear-EventLog | f', 'powershell'),
      c(
        "gcm Clear-EventLog | Select-Object -ExpandProperty Name | % Insert 14 ' Security' | Invoke-Expression",
        'powershell',
      ),
      c(`ssh h "pwsh -c 'gcm Clear-EventLog | Set-Variable c; & \\$c Security'"`),
    ],
    misses: [
      c('Get-Help Clear-EventLog', 'powershell'),
      c('Get-Help Clear-EventLog -Full', 'powershell'),
      c('man Clear-EventLog', 'powershell'),
      c('Get-Help Clear-EventLog | more', 'powershell'),
      c('gcm Clear-EventLog | Format-List', 'powershell'),
      c('Get-Help Clear-EventLog -Full | Out-String', 'powershell'),
      c('gcm Clear-EventLog | Select-Object Name, Source', 'powershell'),
      c('gcm Clear-EventLog | Format-List *', 'powershell'),
      // `git commit -m "note; pwsh -c '…'"` and `echo "x; pwsh -c '…'"` are accepted fail-closed
      // over-blocks until core's chain splitter is quote-aware (controller adjudication, ruling P28).
    ],
  },
  'nmap-script-dos': {
    hits: [
      c('nmap --script /usr/share/nmap/scripts/http-slowloris 192.0.2.10'),
      c('nmap --script /usr/share/nmap/scripts/smb-vuln-regsvc-dos 192.0.2.10'),
      c('nmap --script ./x/flood-thing 192.0.2.10'),
      c('nmap --script "(/opt/x/y)" 192.0.2.10'),
      c('nmap --script "./x/y and not dos" 192.0.2.10'),
      c('nmap --script "/opt/x/*" 192.0.2.10'),
      c('nmap --script /usr/share/nmap/scripts/.. 192.0.2.10'),
      c('nmap --script /opt/my-nse 192.0.2.10'),
    ],
    misses: [
      c('nmap --script /usr/share/nmap/scripts/http-title.nse 192.0.2.10'),
      c('nmap --script ~/nse/http-title.nse 192.0.2.10'),
    ],
  },
}

// Controller adjudication after round 5 (ruling P28): every segment keeps its local view and nested
// analysis. The round-5 "phantom segment" gate dropped segments the quote scanner judged to be string
// content, which switched the whole denylist off whenever the scanner fell out of step with the shell
// (an apostrophe in a `#` comment, a heredoc, `$(…)` inside a string, `eval`, runners outside the
// carry set). Each hit below was refused before round 5 and must stay refused.
const ADJUDICATION: Record<string, { hits: Case[]; misses: Case[] }> = {
  'dos-tools': {
    hits: [
      c(`# don't run this on prod\nhping3 --flood 203.0.113.5`),
      c(`echo "a; $(hping3 --flood 203.0.113.5)"`),
      c(`eval "id; hping3 --flood 203.0.113.5"`),
      c(`echo "$(echo "it's")"; hping3 --flood 203.0.113.5`),
    ],
    misses: [c(`echo "a; hping3 is a tool"`)],
  },
  'log-wipe': {
    hits: [
      c(`echo hi # it's\n> /var/log/auth.log`),
      c(`eval "id; > /var/log/auth.log"`),
      c(`git commit -m "x; $(> /var/log/auth.log)"`),
      c('gcm Clear-EventLog | Sort-Object -OutVariable c; & $c[0] Security', 'powershell'),
      c('gcm Clear-EventLog | sort -ov c; & $c[0] Security', 'powershell'),
      c('gcm Clear-EventLog | Format-List -PipelineVariable p | % { & $p Security }', 'powershell'),
      // PowerShell accepts unambiguous parameter prefixes and any dash character.
      c('gcm Clear-EventLog | Sort-Object -OutVar c; & $c[0] Security', 'powershell'),
      c('gcm Clear-EventLog | Sort-Object -Outv c; & $c[0] Security', 'powershell'),
      c('Get-Help Clear-EventLog | Out-String -OutVa c; & $c Security', 'powershell'),
      c('gcm Clear-EventLog | Measure-Object -OutV m; & $m Security', 'powershell'),
      c('gcm Clear-EventLog | Sort-Object –ov c; & $c[0] Security', 'powershell'),
      c('gcm Clear-EventLog | Sort-Object -OV:c; & $c[0] Security', 'powershell'),
    ],
    misses: [
      c('gcm Clear-EventLog | Sort-Object', 'powershell'),
      c('Get-Help Clear-EventLog -Examples | Sort-Object', 'powershell'),
      c('gcm Clear-EventLog | Format-List -Property Name, Source', 'powershell'),
      c('gcm Clear-EventLog | Sort-Object -Property Name -Descending', 'powershell'),
      c('Get-Help Clear-EventLog | Out-String -Width 120', 'powershell'),
    ],
  },
  'global-range': {
    hits: [c(`echo "starting" # let's go\nnmap 0/0`), c(`eval "id; nmap 0/0"`)],
    misses: [],
  },
  'nmap-script-dos': { hits: [c(`echo "x; $(nmap --script dos 192.0.2.10)"`)], misses: [] },
}

describe('DENYLIST adjudication after round 5 (P28)', () => {
  for (const [id, { hits, misses }] of Object.entries(ADJUDICATION)) {
    describe(id, () => {
      for (const h of hits) {
        it(`refuses: ${JSON.stringify(h.command)}`, async () => {
          expect(checkDenylist(await analyze(h.command, h.shell))?.id).toBe(id)
        })
      }
      for (const m of misses) {
        it(`passes near miss: ${JSON.stringify(m.command)}`, async () => {
          expect(checkDenylist(await analyze(m.command, m.shell))).toBeUndefined()
        })
      }
    })
  }
})

describe('DENYLIST fix round 5', () => {
  for (const [id, { hits, misses }] of Object.entries(ROUND5)) {
    describe(id, () => {
      for (const h of hits) {
        it(`refuses: ${h.command}`, async () => {
          expect(checkDenylist(await analyze(h.command, h.shell))?.id).toBe(id)
        })
      }
      for (const m of misses) {
        it(`passes near miss: ${m.command}`, async () => {
          expect(checkDenylist(await analyze(m.command, m.shell))).toBeUndefined()
        })
      }
    })
  }

  const entry = DENYLIST.find((e) => e.id === 'nmap-script-dos')
  const suggest = async (cmd: string) => entry?.suggest?.(await analyze(cmd)) ?? null

  it('suggests .nse only for a bare script path under a known NSE directory', async () => {
    expect(await suggest('nmap --script /usr/share/nmap/scripts/http-title 192.0.2.10')).toBe(
      '--script "/usr/share/nmap/scripts/http-title.nse"',
    )
    expect(await suggest('nmap --script ~/nse/http-title 192.0.2.10')).toBe(
      '--script "~/nse/http-title.nse"',
    )
    for (const cmd of [
      'nmap --script /opt/my-nse 192.0.2.10',
      'nmap --script /usr/share/nmap/scripts/http-slowloris 192.0.2.10',
      'nmap --script /usr/share/nmap/scripts/smb-vuln-regsvc-dos 192.0.2.10',
      'nmap --script ./x/flood-thing 192.0.2.10',
      'nmap --script "(/opt/x/y)" 192.0.2.10',
      'nmap --script "./x/y and not dos" 192.0.2.10',
      'nmap --script "/opt/x/*" 192.0.2.10',
      'nmap --script /usr/share/nmap/scripts/.. 192.0.2.10',
    ]) {
      expect(await suggest(cmd), cmd).toBeNull()
    }
  })

  it('every suggestion from the round 3-5 script tables is itself accepted', async () => {
    const hits = [
      ...(ROUND3['nmap-script-dos']?.hits ?? []),
      ...(ROUND4['nmap-script-dos']?.hits ?? []),
      ...(ROUND5['nmap-script-dos']?.hits ?? []),
    ]
    for (const h of hits) {
      const s = await suggest(h.command)
      if (s === null) continue
      expect(
        checkDenylist(await analyze(`nmap ${s} 192.0.2.10`)),
        `${h.command} -> ${s}`,
      ).toBeUndefined()
    }
  })
})
