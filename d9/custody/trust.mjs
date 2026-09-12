import { failD931 } from './errors.mjs'

const journalBrokers = new WeakSet()

export function registerProtectedJournalBroker(value) {
  journalBrokers.add(value)
  return value
}

export function assertProtectedJournalBroker(value) {
  if (!journalBrokers.has(value)) failD931('D931_BROKER_UNTRUSTED', 'journal broker was not produced by the protected constructor')
  return value
}
