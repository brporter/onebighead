import { describe, it, expect } from 'vitest';
import { router } from '../src/router';

describe('router', () => {
  it('should have root route', () => {
    const rootRoute = router.routes[0];
    expect(rootRoute.path).toBe('/');
  });

  it('should have collections route', () => {
    const rootRoute = router.routes[0];
    const collectionsRoute = rootRoute.children?.find(r => r.path === 'collections');
    expect(collectionsRoute).toBeDefined();
  });

  it('should have collection detail route', () => {
    const rootRoute = router.routes[0];
    const collectionRoute = rootRoute.children?.find(r => r.path === 'collections/:collectionId');
    expect(collectionRoute).toBeDefined();
  });

  it('should have category route', () => {
    const rootRoute = router.routes[0];
    const categoryRoute = rootRoute.children?.find(r => r.path === 'collections/:collectionId/categories/:categoryId');
    expect(categoryRoute).toBeDefined();
  });

  it('should have item route', () => {
    const rootRoute = router.routes[0];
    const itemRoute = rootRoute.children?.find(r => r.path === 'collections/:collectionId/items/:itemId');
    expect(itemRoute).toBeDefined();
  });

  it('should redirect index to collections', () => {
    const rootRoute = router.routes[0];
    const indexRoute = rootRoute.children?.find(r => r.index === true);
    expect(indexRoute).toBeDefined();
  });
});
