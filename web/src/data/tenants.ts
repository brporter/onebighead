import type { Tenant } from '../types';

const tenants = [
  { tenantId: 1, name: 'Retro Vault', owner: 'bryan@bryanporter.com' },
  { tenantId: 2, name: 'Patchterest', owner: 'bob@bryanporter.com' },
] as const satisfies readonly Tenant[];

export default tenants;

