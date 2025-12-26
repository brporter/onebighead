import PropTypes from 'prop-types'

const PAGE_SIZE = 25

function ItemList({ items, selectedId, onSelect, pageIndex, onPageChange }) {
  const totalCount = items.length
  const totalPages = Math.max(1, Math.ceil(totalCount / PAGE_SIZE))
  const safePageIndex = Math.min(Math.max(0, pageIndex), totalPages - 1)
  const start = safePageIndex * PAGE_SIZE
  const pageItems = items.slice(start, start + PAGE_SIZE)

  const canPrev = safePageIndex > 0
  const canNext = safePageIndex < totalPages - 1

  function handleRowKeyDown(e, id) {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault()
      onSelect(id)
    }
  }

  return (
    <aside className="list">
      <div className="list__header">
        <h2 className="list__title">Items</h2>
        <div className="list__count" aria-label="Item count">
          {totalCount} total
        </div>
      </div>

      <div className="list__tableWrap">
        <table className="list__table">
          <thead>
            <tr>
              <th scope="col" className="list__th list__th--name">
                Name
              </th>
              <th scope="col" className="list__th">
                Summary
              </th>
            </tr>
          </thead>
          <tbody>
            {pageItems.length ? (
              pageItems.map((item) => {
                const isSelected = item.id === selectedId
                return (
                  <tr
                    key={item.id}
                    className={`list__tr list__tr--clickable${
                      isSelected ? ' list__tr--active' : ''
                    }`}
                    tabIndex={0}
                    role="button"
                    aria-label={`Select ${item.name}`}
                    onClick={() => onSelect(item.id)}
                    onKeyDown={(e) => handleRowKeyDown(e, item.id)}
                  >
                    <td className="list__td list__td--name">{item.name}</td>
                    <td className="list__td list__td--summary">{item.summary ?? ''}</td>
                  </tr>
                )
              })
            ) : (
              <tr>
                <td className="list__td" colSpan={2}>
                  <p className="list__empty">No items</p>
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="list__pager" aria-label="Pagination">
        <button
          type="button"
          className="list__pagerButton"
          onClick={() => onPageChange(safePageIndex - 1)}
          disabled={!canPrev}
        >
          Previous
        </button>
        <div className="list__pagerStatus">
          Page {safePageIndex + 1} of {totalPages}
        </div>
        <button
          type="button"
          className="list__pagerButton"
          onClick={() => onPageChange(safePageIndex + 1)}
          disabled={!canNext}
        >
          Next
        </button>
      </div>
    </aside>
  )
}

ItemList.propTypes = {
  items: PropTypes.arrayOf(
    PropTypes.shape({
      id: PropTypes.number.isRequired,
      name: PropTypes.string.isRequired,
      summary: PropTypes.string,
    }),
  ).isRequired,
  selectedId: PropTypes.number,
  onSelect: PropTypes.func.isRequired,
  pageIndex: PropTypes.number.isRequired,
  onPageChange: PropTypes.func.isRequired,
}

ItemList.defaultProps = {
  selectedId: null,
}

export default ItemList
