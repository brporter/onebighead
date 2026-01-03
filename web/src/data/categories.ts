import type { Category } from '../types';

const categories = [
  { tenantId: 1, categoryId: 1, name: 'Motorola 68000 Computers', description: 'Some long descriptive text about this particular category.', parentCategoryId: null },
  { tenantId: 1, categoryId: 2, name: 'Compact Macintosh', description: 'Some long descriptive text about this particular category.', parentCategoryId: 1 },
  { tenantId: 1, categoryId: 3, name: 'Sun Workstations', description: 'Some long descriptive text about this particular category.', parentCategoryId: 1 },
  { tenantId: 1, categoryId: 4, name: 'Desktop Macintosh', description: 'Some long descriptive text about this particular category.', parentCategoryId: 1 },
  { tenantId: 1, categoryId: 5, name: 'Intel x86', description: 'Some long descriptive text about this particular category.', parentCategoryId: null },
  { tenantId: 1, categoryId: 6, name: '80386', description: 'Some long descriptive text about this particular category.', parentCategoryId: 5 },
  { tenantId: 1, categoryId: 7, name: 'Pentium and Later', description: 'Some long descriptive text about this particular category.', parentCategoryId: 5 },
] as const satisfies readonly Category[];

export default categories;

