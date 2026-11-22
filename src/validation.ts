import { types } from 'node:util';

export function record(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || types.isProxy(value) || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) return false;
  // Inspect descriptors before reading values: reject executable or hidden fields.
  return Reflect.ownKeys(value).every(key => {
    const descriptor = Object.getOwnPropertyDescriptor(value, key)!;
    return typeof key === 'string' && descriptor.enumerable && Object.hasOwn(descriptor, 'value');
  });
}

export function keys(value: Record<string, unknown>, allowed: string[], required: string[] = []): boolean {
  return Object.keys(value).every(key => allowed.includes(key))
    && required.every(key => Object.hasOwn(value, key));
}

export function stringList(value: unknown): value is string[] {
  if (value === null || typeof value !== 'object' || types.isProxy(value)
    || !Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) return false;
  const names = Reflect.ownKeys(value);
  if (names.length !== value.length + 1) return false;
  return names.every(key => {
    if (key === 'length') return true;
    const descriptor = Object.getOwnPropertyDescriptor(value, key)!;
    return typeof key === 'string' && /^(0|[1-9][0-9]*)$/.test(key)
      && Number(key) < value.length && descriptor.enumerable
      && Object.hasOwn(descriptor, 'value') && typeof descriptor.value === 'string';
  });
}
