import PropTypes from 'prop-types'

function SubcategoryDropdown({ subcategories, selectedId, onChange }) {
  if (!subcategories?.length) return null

  return (
    <div className="subcategoryDropdown">
      <label htmlFor="subcategory-filter" className="subcategoryDropdown__label">
        Filter by subcategory:
      </label>
      <select
        id="subcategory-filter"
        className="subcategoryDropdown__select"
        value={selectedId ?? ''}
        onChange={(e) => onChange(e.target.value ? Number(e.target.value) : null)}
      >
        <option value="">All items</option>
        {subcategories.map((cat) => (
          <option key={cat.categoryId} value={cat.categoryId}>
            {cat.name}
          </option>
        ))}
      </select>
    </div>
  )
}

SubcategoryDropdown.propTypes = {
  subcategories: PropTypes.arrayOf(
    PropTypes.shape({
      categoryId: PropTypes.number.isRequired,
      name: PropTypes.string.isRequired,
    })
  ),
  selectedId: PropTypes.number,
  onChange: PropTypes.func.isRequired,
}

SubcategoryDropdown.defaultProps = {
  subcategories: [],
  selectedId: null,
}

export default SubcategoryDropdown

