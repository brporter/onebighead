import type { ItemProperty } from './types';

interface PropertyRenderProps {
  properties?: ItemProperty[];
}

function groupPropertiesByCategory(properties: ItemProperty[] | undefined): [string, ItemProperty[]][] {
  const groups = new Map<string, ItemProperty[]>();

  for (const prop of properties ?? []) {
    const category = prop.category?.trim() || 'Other';
    if (!groups.has(category)) groups.set(category, []);
    groups.get(category)!.push(prop);
  }

  return Array.from(groups.entries());
}

function PropertyRender({ properties }: PropertyRenderProps) {
  const propertyGroups = groupPropertiesByCategory(properties);

  if (!propertyGroups.length) {
    return null;
  }

  return (
    <div className="detail__properties">
      {propertyGroups.map(([category, props]) => (
        <section key={category} className="detail__property-group">
          <h3 className="detail__property-group-title">{category}</h3>
          <dl className="detail__property-group-list">
            {props.map(({ name, value }) => (
              <div key={`${category}:${name}`} className="detail__property-row">
                <dt className="detail__property-name">{name}</dt>
                <dd className="detail__property-value">{value}</dd>
              </div>
            ))}
          </dl>
        </section>
      ))}
    </div>
  );
}

export default PropertyRender;

