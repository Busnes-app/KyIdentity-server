type Persistable = Pick<StorageManager, 'persisted' | 'persist'>;

/**
 * Asks the browser not to clear this site's storage on its own (to free space, or after Safari's
 * days without a visit), since it holds this browser's keyring device key. Firefox asks the user;
 * Chromium and Safari decide silently. Best effort: true only when storage is kept.
 */
export async function keepStorage(storage: Partial<Persistable> | undefined = globalThis.navigator?.storage): Promise<boolean> {
  if (!storage?.persisted || !storage.persist) return false;
  try {
    return (await storage.persisted()) || (await storage.persist());
  } catch {
    return false;
  }
}
