import type { EventSource, GuardEvent } from '../../src/types.js'

/** `Omit` applied to each member of a union (plain `Omit` would keep only the shared keys). */
type Unstamped<E> = E extends unknown ? Omit<E, 'ts'> : never

export interface FakeEvents extends EventSource {
  /** Stamps `ts: Date.now()` and delivers to the listeners of its type, then to `'*'` listeners. */
  emit(e: Unstamped<GuardEvent>): void
}

export function createFakeEvents(): FakeEvents {
  const listeners = new Map<GuardEvent['type'] | '*', Set<(e: GuardEvent) => void>>()
  return {
    on(type, fn) {
      let set = listeners.get(type)
      if (set === undefined) {
        set = new Set()
        listeners.set(type, set)
      }
      // A fresh wrapper per subscription, so the same function can be subscribed twice.
      const entry = (e: GuardEvent) => fn(e)
      set.add(entry)
      return () => {
        set.delete(entry)
      }
    },
    emit(e) {
      const event = { ...e, ts: Date.now() } as GuardEvent
      for (const fn of [...(listeners.get(event.type) ?? [])]) fn(event)
      for (const fn of [...(listeners.get('*') ?? [])]) fn(event)
    },
  }
}
