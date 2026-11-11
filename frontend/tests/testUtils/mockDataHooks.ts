/** One component fixture can supply the domain hooks used by its child components. */
export function mockDataHooks<T extends { useData: () => unknown }>(mock: T) {
  return { ...mock,
    useCollectionsData: mock.useData,
    useCategoriesData: mock.useData,
    useItemsData: mock.useData,
    useTemplatesData: mock.useData,
    useSuggestionsData: mock.useData,
    useThemesData: mock.useData,
    useImagesData: mock.useData,
  };
}
