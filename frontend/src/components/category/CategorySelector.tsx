import type { Category, CategoryNode } from '../../utils/types';

interface CategorySelectorProps {
  categories: Category[];
  selectedCategoryId: number | null;
  onChange: (categoryId: number | null) => void;
  label?: string;
  allowNull?: boolean;
  nullLabel?: string;
}

function buildCategoryTree(categories: Category[]): CategoryNode[] {
  const map = new Map<number, CategoryNode>();
  const roots: CategoryNode[] = [];

  for (const cat of categories) {
    map.set(cat.categoryId, { ...cat, children: [] });
  }

  for (const cat of categories) {
    const node = map.get(cat.categoryId)!;
    if (cat.parentCategoryId === null) {
      roots.push(node);
    } else {
      const parent = map.get(cat.parentCategoryId);
      if (parent) {
        parent.children.push(node);
      } else {
        roots.push(node);
      }
    }
  }

  return roots;
}

function flattenWithIndent(nodes: CategoryNode[], depth = 0): { category: Category; depth: number }[] {
  const result: { category: Category; depth: number }[] = [];
  for (const node of nodes) {
    result.push({ category: node, depth });
    if (node.children.length > 0) {
      result.push(...flattenWithIndent(node.children, depth + 1));
    }
  }
  return result;
}

function CategorySelector({
  categories,
  selectedCategoryId,
  onChange,
  label = 'Category',
  allowNull = true,
  nullLabel = 'No category',
}: CategorySelectorProps) {
  const tree = buildCategoryTree(categories);
  const flatList = flattenWithIndent(tree);

  return (
    <div className="detail__field">
      <label htmlFor="category-selector" className="detail__label">{label}</label>
      <select
        id="category-selector"
        className="detail__input"
        value={selectedCategoryId ?? ''}
        onChange={(e) => onChange(e.target.value ? Number(e.target.value) : null)}
      >
        {allowNull && <option value="">{nullLabel}</option>}
        {flatList.map(({ category, depth }) => (
          <option key={category.categoryId} value={category.categoryId}>
            {'  '.repeat(depth)}{depth > 0 ? '└ ' : ''}{category.name}
          </option>
        ))}
      </select>
    </div>
  );
}

export default CategorySelector;
