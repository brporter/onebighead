import { useId, useMemo, type CSSProperties } from 'react';
import type { CollectionTheme } from '../../utils/types';
import { themeCategoryPreview } from '../../data/themes/themeCategoryPreview';
import '../../styles/components/ThemePreview.css';

interface ThemePreviewProps {
  theme: CollectionTheme;
}

function ThemePreview({ theme }: ThemePreviewProps) {
  const id = useId();
  const { rows, hierarchyAvailable } = useMemo(() => themeCategoryPreview(theme.categories), [theme.categories]);

  return <div className="themePreview">
    <section className="themePreview__section" aria-labelledby={`${id}-templates`}>
      <h4 id={`${id}-templates`} className="themePreview__sectionTitle">Templates <span className="themePreview__count">{theme.templates.length}</span></h4>
      {theme.templates.length === 0 ? <p className="themePreview__empty">No templates included</p> :
        <ul className="themePreview__templates">
          {theme.templates.map(template => <li key={template.itemTemplateId} className="themePreview__template">
            <h5 className="themePreview__templateName">{template.name}</h5>
            {template.description && <p className="themePreview__description">{template.description}</p>}
            {template.properties.length === 0 ? <p className="themePreview__empty">No preset properties</p> :
              <ul className="themePreview__templateProperties" aria-label={`${template.name} properties`}>
                {template.properties.map((property, index) => <li key={index} className="themePreview__propertyTag">
                  {property.category ? `${property.category}: ${property.name}` : property.name}
                </li>)}
              </ul>}
          </li>)}
        </ul>}
    </section>
    <section className="themePreview__section" aria-labelledby={`${id}-categories`}>
      <h4 id={`${id}-categories`} className="themePreview__sectionTitle">Categories <span className="themePreview__count">{rows.length}</span></h4>
      {!hierarchyAvailable && <p className="themePreview__notice" role="status">Category hierarchy unavailable. All category names are listed below.</p>}
      {rows.length === 0 ? <p className="themePreview__empty">No categories included</p> :
        <ul className="themePreview__categoryList">
          {rows.map(({ category, sourceIndex, depth }) => <li key={sourceIndex} className="themePreview__categoryItem"
            style={{ '--theme-depth': Math.min(depth, 4) } as CSSProperties}>
            <span className="themePreview__categoryName">{category.name}</span>
            {category.parentName && <span className="themePreview__parent">Parent: {category.parentName}</span>}
            {category.description && <p className="themePreview__description">{category.description}</p>}
          </li>)}
        </ul>}
    </section>
  </div>;
}

export default ThemePreview;
