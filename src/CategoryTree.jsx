import { useMemo, useState } from 'react'
import PropTypes from 'prop-types'

function buildTree(categories) {
  const byId = new Map()
  const roots = []

  for (const cat of categories ?? []) {
    byId.set(cat.categoryId, { ...cat, children: [] })
  }

  for (const node of byId.values()) {
    if (node.parentCategoryId == null) {
      roots.push(node)
      continue
    }

    const parent = byId.get(node.parentCategoryId)
    if (parent) parent.children.push(node)
    else roots.push(node)
  }

  return roots
}

function CategoryNode({ node, level, selectedCategoryId, onSelect, expandedIds, onToggle }) {
  const isSelected = node.categoryId === selectedCategoryId
  const hasChildren = node.children.length > 0
  const isExpanded = expandedIds.has(node.categoryId)

  return (
    <li className="categoryTree__node">
      <div className="categoryTree__row" style={{ paddingLeft: `${level * 14}px` }}>
        {hasChildren ? (
          <button
            type="button"
            className="categoryTree__toggle"
            aria-label={isExpanded ? `Collapse ${node.name}` : `Expand ${node.name}`}
            onClick={() => onToggle(node.categoryId)}
          >
            {isExpanded ? '▾' : '▸'}
          </button>
        ) : (
          <span className="categoryTree__toggle-spacer" aria-hidden="true">
            ▸
          </span>
        )}

        <button
          type="button"
          className={`categoryTree__item${isSelected ? ' categoryTree__item--active' : ''}`}
          onClick={() => onSelect(node.categoryId)}
        >
          {node.name}
        </button>
      </div>

      {hasChildren && isExpanded ? (
        <ul className="categoryTree__children">
          {node.children.map((child) => (
            <CategoryNode
              key={child.categoryId}
              node={child}
              level={level + 1}
              selectedCategoryId={selectedCategoryId}
              onSelect={onSelect}
              expandedIds={expandedIds}
              onToggle={onToggle}
            />
          ))}
        </ul>
      ) : null}
    </li>
  )
}

CategoryNode.propTypes = {
  node: PropTypes.shape({
    categoryId: PropTypes.number.isRequired,
    name: PropTypes.string.isRequired,
    parentCategoryId: PropTypes.number,
    children: PropTypes.array,
  }).isRequired,
  level: PropTypes.number.isRequired,
  selectedCategoryId: PropTypes.number,
  onSelect: PropTypes.func.isRequired,
  expandedIds: PropTypes.instanceOf(Set).isRequired,
  onToggle: PropTypes.func.isRequired,
}

CategoryNode.defaultProps = {
  selectedCategoryId: null,
}

function CategoryTree({ categories, selectedCategoryId, onSelect }) {
  const tree = useMemo(() => buildTree(categories), [categories])
  const [expandedIds, setExpandedIds] = useState(() => {
    const rootIds = (categories ?? [])
      .filter((c) => c.parentCategoryId == null)
      .map((c) => c.categoryId)
    return new Set(rootIds)
  })

  function toggle(id) {
    setExpandedIds((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  return (
    <aside className="categoryTree">
      <h2 className="categoryTree__title">Categories</h2>
      <ul className="categoryTree__list">
        {tree.map((node) => (
          <CategoryNode
            key={node.categoryId}
            node={node}
            level={0}
            selectedCategoryId={selectedCategoryId}
            onSelect={onSelect}
            expandedIds={expandedIds}
            onToggle={toggle}
          />
        ))}
      </ul>
    </aside>
  )
}

CategoryTree.propTypes = {
  categories: PropTypes.arrayOf(
    PropTypes.shape({
      categoryId: PropTypes.number.isRequired,
      name: PropTypes.string.isRequired,
      parentCategoryId: PropTypes.number,
    }),
  ).isRequired,
  selectedCategoryId: PropTypes.number,
  onSelect: PropTypes.func.isRequired,
}

CategoryTree.defaultProps = {
  selectedCategoryId: null,
}

export { CategoryTree }
export default CategoryTree
