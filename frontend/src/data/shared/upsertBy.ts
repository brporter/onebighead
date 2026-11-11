/** Replace one identified record in place, or append it without introducing duplicates. */
export function upsertBy<T>(values: T[], incoming: T, key: keyof T): T[] {
  return values.some(value => value[key] === incoming[key])
    ? values.map(value => value[key] === incoming[key] ? incoming : value)
    : [...values, incoming];
}
