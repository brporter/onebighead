import { useMemo, useState } from 'react'
import './App.css'
import categories from './categories.mjs'
import items from './data.mjs'
import CategoryTree from './CategoryTree.jsx'
import ItemList from './ItemList.jsx'
import ItemDetail from './ItemDetail.jsx'
import SubcategoryDropdown from './SubcategoryDropdown.jsx'
import { getCategoryAndDescendantIds } from './categoryUtils.mjs'

function App() {
  const [selectedCategoryId, setSelectedCategoryId] = useState(null)
  const [selectedItemId, setSelectedItemId] = useState(null)
  const [pageIndex, setPageIndex] = useState(0)
  // Mobile navigation: 'categories' | 'items' | 'detail'
  const [mobileView, setMobileView] = useState('categories')
  // Subcategory filter for dropdown
  const [subcategoryFilter, setSubcategoryFilter] = useState(null)

  // Get direct child subcategories of the selected category
  const directSubcategories = useMemo(() => {
    if (selectedCategoryId == null) return []
    return categories.filter((cat) => cat.parentCategoryId === selectedCategoryId)
  }, [selectedCategoryId])

  // Show dropdown when category has subcategories
  const showSubcategoryDropdown = directSubcategories.length > 0

  // Compute eligible category IDs based on subcategory filter
  const eligibleCategoryIds = useMemo(() => {
    if (selectedCategoryId == null) return new Set()
    // If a subcategory filter is active, use that subtree
    if (subcategoryFilter != null) {
      return getCategoryAndDescendantIds(categories, subcategoryFilter)
    }
    return getCategoryAndDescendantIds(categories, selectedCategoryId)
  }, [selectedCategoryId, subcategoryFilter])

  const filteredItems = useMemo(() => {
    if (selectedCategoryId == null) return []
    return items.filter((item) => eligibleCategoryIds.has(item.categoryId))
  }, [eligibleCategoryIds, selectedCategoryId])

  const totalPages = useMemo(() => {
    const pageSize = 25
    return Math.max(1, Math.ceil(filteredItems.length / pageSize))
  }, [filteredItems.length])

  const safePageIndex = useMemo(() => {
    return Math.min(Math.max(0, pageIndex), totalPages - 1)
  }, [pageIndex, totalPages])

  const selectedItem = useMemo(() => {
    if (selectedItemId == null) return null
    return filteredItems.find((item) => item.id === selectedItemId) || null
  }, [filteredItems, selectedItemId])

  function handleSelectCategory(categoryId) {
    setSelectedCategoryId(categoryId)
    setSelectedItemId(null)
    setPageIndex(0)
    setSubcategoryFilter(null)
    setMobileView('items')
  }

  function handleSelectItem(itemId) {
    setSelectedItemId(itemId)
    setMobileView('detail')
  }

  function handleBackToCategories() {
    setMobileView('categories')
  }

  function handleBackToItems() {
    setSelectedItemId(null)
    setMobileView('items')
  }

  function handlePageChange(next) {
    const clamped = Math.min(Math.max(0, next), totalPages - 1)
    setPageIndex(clamped)
  }

  return (
    <div className="app" data-mobile-view={mobileView}>
      <header className="app__header">
        <h1>Vintage Macintosh Models</h1>
        <p className="app__subtitle">Browse categories, then view items and details.</p>
      </header>

      <div className="app__layout">
        <nav className="app__sidebar" aria-label="Category navigation">
          <CategoryTree
            categories={categories}
            selectedCategoryId={selectedCategoryId}
            onSelect={handleSelectCategory}
          />
        </nav>

        <main className="app__content">
          {selectedCategoryId == null ? (
            <section className="placeholder">
              <p className="placeholder__text">Select a category to browse items</p>
            </section>
          ) : selectedItem ? (
            <article className="app__detail">
              <nav className="mobileNav">
                <button
                  type="button"
                  className="mobileNav__back"
                  onClick={handleBackToItems}
                >
                  ← Back to items
                </button>
              </nav>
              <ItemDetail item={selectedItem} onClose={handleBackToItems} />
            </article>
          ) : (
            <section className="app__items">
              <nav className="mobileNav">
                <button
                  type="button"
                  className="mobileNav__back"
                  onClick={handleBackToCategories}
                >
                  ← Categories
                </button>
              </nav>
              {showSubcategoryDropdown && (
                <SubcategoryDropdown
                  subcategories={directSubcategories}
                  selectedId={subcategoryFilter}
                  onChange={setSubcategoryFilter}
                />
              )}
              <ItemList
                items={filteredItems}
                selectedId={null}
                onSelect={handleSelectItem}
                pageIndex={safePageIndex}
                onPageChange={handlePageChange}
              />
            </section>
          )}
        </main>
      </div>
    </div>
  )
}

export default App
