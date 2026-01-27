import type { CollectionTheme, ThemeCategory } from './types';

interface ThemePreviewProps {
  theme: CollectionTheme;
}

interface CategoryNode extends ThemeCategory {
  children: CategoryNode[];
}

function buildCategoryTree(categories: ThemeCategory[]): CategoryNode[] {
  const rootCategories: CategoryNode[] = [];
  const childMap = new Map<string, CategoryNode[]>();

  // First pass: organize children by parent name
  for (const cat of categories) {
    const node: CategoryNode = { ...cat, children: [] };
    if (cat.parentName) {
      const siblings = childMap.get(cat.parentName) || [];
      siblings.push(node);
      childMap.set(cat.parentName, siblings);
    } else {
      rootCategories.push(node);
    }
  }

  // Second pass: attach children to parents
  const attachChildren = (nodes: CategoryNode[]) => {
    for (const node of nodes) {
      const children = childMap.get(node.name) || [];
      children.sort((a, b) => a.sortOrder - b.sortOrder);
      node.children = children;
      attachChildren(children);
    }
  };

  rootCategories.sort((a, b) => a.sortOrder - b.sortOrder);
  attachChildren(rootCategories);

  return rootCategories;
}

function CategoryTreePreview({ categories }: { categories: CategoryNode[] }) {
  if (categories.length === 0) return null;

  return (
    <ul className="themePreview__categoryList">
      {categories.map((cat) => (
        <li key={cat.name} className="themePreview__categoryItem">
          {cat.name}
          {cat.children.length > 0 && (
            <CategoryTreePreview categories={cat.children} />
          )}
        </li>
      ))}
    </ul>
  );
}

function ThemePreview({ theme }: ThemePreviewProps) {
  const categoryTree = buildCategoryTree(theme.categories);

  return (
    <div className="themePreview">
      <div className="themePreview__section">
        <h4 className="themePreview__sectionTitle">Templates</h4>
        {theme.templates.length === 0 ? (
          <p className="themePreview__empty">No templates included</p>
        ) : (
          <div className="themePreview__templates">
            {theme.templates.map((template) => (
              <div key={template.itemTemplateId} className="themePreview__template">
                <span className="themePreview__templateName">{template.name}</span>
                <div className="themePreview__templateProperties">
                  {template.properties.map((prop, i) => (
                    <span key={i} className="themePreview__propertyTag">
                      {prop.category}: {prop.name}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="themePreview__section">
        <h4 className="themePreview__sectionTitle">Categories</h4>
        {categoryTree.length === 0 ? (
          <p className="themePreview__empty">No categories included</p>
        ) : (
          <CategoryTreePreview categories={categoryTree} />
        )}
      </div>
    </div>
  );
}

export default ThemePreview;
