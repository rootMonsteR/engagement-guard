import type { Engagement } from '../engagement/schema.js'

export type TimeCheck =
  | { ok: true }
  | { ok: false; reason: 'OUTSIDE_WINDOW' | 'BLACKOUT'; message: string }

type Day = 'mon' | 'tue' | 'wed' | 'thu' | 'fri' | 'sat' | 'sun'
type Blackout = Engagement['roe']['blackout_hours'][number]

const DAYS: readonly Day[] = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat']
const WEEKDAY_SHORT: Readonly<Record<string, Day>> = {
  Sun: 'sun',
  Mon: 'mon',
  Tue: 'tue',
  Wed: 'wed',
  Thu: 'thu',
  Fri: 'fri',
  Sat: 'sat',
}

const formatters = new Map<string, Intl.DateTimeFormat>()

function formatterFor(timeZone: string): Intl.DateTimeFormat {
  let f = formatters.get(timeZone)
  if (f === undefined) {
    f = new Intl.DateTimeFormat('en-US', {
      timeZone,
      weekday: 'short',
      hour: '2-digit',
      minute: '2-digit',
      hourCycle: 'h23',
    })
    formatters.set(timeZone, f)
  }
  return f
}

/** Weekday and minute of the day on the wall clock of `timeZone` at `now`. */
function wallClock(now: Date, timeZone: string): { day: Day; minute: number; text: string } {
  const parts = formatterFor(timeZone).formatToParts(now)
  const part = (type: Intl.DateTimeFormatPartTypes) => parts.find((p) => p.type === type)?.value
  const day = WEEKDAY_SHORT[part('weekday') ?? '']
  const hour = Number(part('hour'))
  const minute = Number(part('minute'))
  if (day === undefined || !Number.isInteger(hour) || !Number.isInteger(minute)) {
    throw new Error(`cannot read the wall clock in ${timeZone}`)
  }
  // Some ICU builds print midnight as 24 even with h23.
  const h = hour % 24
  const text = `${part('weekday')} ${String(h).padStart(2, '0')}:${String(minute).padStart(2, '0')}`
  return { day, minute: h * 60 + minute, text }
}

const toMinutes = (hhmm: string) => Number(hhmm.slice(0, 2)) * 60 + Number(hhmm.slice(3, 5))

const previousDay = (d: Day): Day => DAYS[(DAYS.indexOf(d) + 6) % 7] as Day

/**
 * True when the wall-clock `minute` on `day` falls in `b` (start inclusive, end exclusive).
 * `start > end` crosses midnight; `days` name the day the blackout starts, so the part after
 * midnight belongs to the previous day's entry.
 */
function inBlackout(b: Blackout, day: Day, minute: number): boolean {
  const start = toMinutes(b.start)
  const end = toMinutes(b.end)
  const on = (d: Day) => b.days === undefined || b.days.includes(d)
  if (start < end) return on(day) && minute >= start && minute < end
  return (on(day) && minute >= start) || (on(previousDay(day)) && minute < end)
}

function describeBlackout(b: Blackout): string {
  const days = b.days === undefined ? 'daily' : b.days.join(',')
  return `${days} ${b.start}–${b.end}`
}

/**
 * Time checks for a network action (§6.4). The window is `[start, end)`; blackout hours are read
 * on the wall clock of `e.window.timezone`. There is no override (Global Constraints): an invalid
 * clock fails closed as OUTSIDE_WINDOW.
 */
export function checkTime(e: Engagement, now: Date): TimeCheck {
  const t = now.getTime()
  const start = Date.parse(e.window.start)
  const end = Date.parse(e.window.end)
  if (!(t >= start && t < end)) {
    return {
      ok: false,
      reason: 'OUTSIDE_WINDOW',
      message: `outside the testing window [${e.window.start}, ${e.window.end})`,
    }
  }
  const tz = e.window.timezone
  const clock = wallClock(now, tz)
  for (const b of e.roe.blackout_hours) {
    if (inBlackout(b, clock.day, clock.minute)) {
      return {
        ok: false,
        reason: 'BLACKOUT',
        message: `inside blackout hours ${describeBlackout(b)} (${tz}; now ${clock.text})`,
      }
    }
  }
  return { ok: true }
}
