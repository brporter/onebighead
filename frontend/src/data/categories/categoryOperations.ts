import type { useCategories } from './useCategories';
import type { Category } from '../../utils/types';
import type { CategoryDraft } from './categoryDraft';
import type { CategoryMove } from './categoryDrop';

export type CategoryManagerPort = Pick<ReturnType<typeof useCategories>, 'categories' | 'loadCategoriesForCollection' |
  'addCategory' | 'updateCategory' | 'deleteCategory' | 'reorderCategories'>;
export type CategoryCommand = CategoryMove | { type: 'quick-create'; name: string } |
  { type: 'save'; categoryId: number | null; draft: CategoryDraft } | { type: 'delete'; categoryId: number };

/** Checkpoints confirmed responses. A failed reorder/refresh never repeats a confirmed write. */
export function categoryOperation(port: CategoryManagerPort, collectionId: number, categories: Category[], command: CategoryCommand) {
  const steps: Array<() => Promise<unknown>> = [];
  const scoped = categories.filter(category => category.collectionId === collectionId && !category.isSystem);
  switch (command.type) {
    case 'quick-create': {
      let createdId: number;
      steps.push(async () => { createdId = await port.addCategory({ collectionId, name: command.name, description: '', parentCategoryId: null, itemTemplateIds: [] }); });
      steps.push(() => port.reorderCategories([createdId, ...scoped.filter(category => category.parentCategoryId === null)
        .sort((a, b) => a.sortOrder - b.sortOrder).map(category => category.categoryId)]
        .map((categoryId, sortOrder) => ({ categoryId, sortOrder }))));
      break;
    }
    case 'save':
      steps.push(() => command.categoryId === null ? port.addCategory({ collectionId, ...command.draft }) : port.updateCategory(command.categoryId, command.draft));
      break;
    case 'delete':
      steps.push(() => port.deleteCategory(command.categoryId));
      break;
    case 'reorder':
      steps.push(() => port.reorderCategories(command.updates));
      break;
    case 'reparent': {
      const category = scoped.find(candidate => candidate.categoryId === command.categoryId);
      if (!category) {
        steps.push(async () => { throw new Error('This category is no longer available. Reload categories and try again.'); });
        break;
      }
      const siblings = scoped.filter(candidate => candidate.parentCategoryId === command.parentId && candidate.categoryId !== category.categoryId)
        .sort((a, b) => a.sortOrder - b.sortOrder);
      const targetIndex = siblings.findIndex(candidate => candidate.categoryId === command.insertAtCategoryId);
      const index = targetIndex < 0 ? siblings.length : targetIndex + (command.insertAfter ? 1 : 0);
      siblings.splice(index, 0, category);
      steps.push(() => port.updateCategory(category.categoryId, { name: category.name, description: category.description,
        parentCategoryId: command.parentId, itemTemplateIds: category.itemTemplateIds }));
      steps.push(() => port.reorderCategories(siblings.map((sibling, sortOrder) => ({ categoryId: sibling.categoryId, sortOrder }))));
      break;
    }
  }
  steps.push(() => port.loadCategoriesForCollection(collectionId, { throwOnError: true }));
  let completed = 0;
  return {
    get hasSaved() { return completed > 0; },
    async run() { while (completed < steps.length) { await steps[completed](); completed++; } },
  };
}
