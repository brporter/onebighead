import PropTypes from 'prop-types'
import ImageGallery from './ImageGallery.jsx'

function groupPropertiesByCategory(properties) {
  const groups = new Map()

  for (const prop of properties ?? []) {
    const category = prop.category?.trim() || 'Other'
    if (!groups.has(category)) groups.set(category, [])
    groups.get(category).push(prop)
  }

  return Array.from(groups.entries())
}

function ItemDetail({ item, onClose }) {
  if (!item) {
    return (
      <section className="detail detail--empty">
        <p className="detail__placeholder">Select an item</p>
      </section>
    )
  }

  const propertyGroups = groupPropertiesByCategory(item.properties)

  return (
    <section className="detail">
      <div className="detail__header">
        <h2 className="detail__title">{item.name}</h2>
        {onClose ? (
          <button type="button" className="detail__close" onClick={onClose}>
            Back to list
          </button>
        ) : null}
      </div>

      <p className="detail__description">{item.description}</p>

      <ImageGallery key={item.id} images={item.images} title={item.name} />

      {propertyGroups.length ? (
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
      ) : null}
    </section>
  )
}

ItemDetail.propTypes = {
  item: PropTypes.shape({
    id: PropTypes.number.isRequired,
    name: PropTypes.string.isRequired,
    description: PropTypes.string.isRequired,
    properties: PropTypes.arrayOf(
      PropTypes.shape({
        category: PropTypes.string,
        name: PropTypes.string.isRequired,
        value: PropTypes.string.isRequired,
      }),
    ),
    images: PropTypes.arrayOf(
      PropTypes.oneOfType([
        PropTypes.string,
        PropTypes.shape({
          url: PropTypes.string.isRequired,
          alt: PropTypes.string,
        }),
      ]),
    ),
  }),
  onClose: PropTypes.func,
}

ItemDetail.defaultProps = {
  item: null,
  onClose: null,
}

export default ItemDetail
