import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';

// Vitest can replace CSS imports with empty modules, including ?raw imports.
const styles = Object.fromEntries(Object.keys(import.meta.glob('../src/**/*.css')).map(path =>
  [path, readFileSync(new URL(path, import.meta.url), 'utf8')]));
const components = import.meta.glob('../src/components/**/*.tsx', { query: '?raw', import: 'default', eager: true });

describe('design system', () => {
  it('gives deletion counts enough room for complete labels in narrow dialogs', () => {
    const css = styles['../src/styles/components/DeletionStatsGrid.css'];
    expect(css).toContain('grid-template-columns: repeat(auto-fit, minmax(min(100%, 8rem), 1fr))');
    expect(css).not.toContain('minmax(80px, 1fr)');
  });
  it('keeps theme choices and previews self-contained, readable, and responsive', () => {
    const card = styles['../src/styles/components/ThemeCard.css'];
    const preview = styles['../src/styles/components/ThemePreview.css'];
    for (const name of ['ThemeCard', 'ThemePreview']) {
      expect(components[`../src/components/collection/${name}.tsx`]).toContain(`import '../../styles/components/${name}.css'`);
    }
    for (const css of [card, preview]) {
      expect(css).toContain('min-width: 0');
      expect(css).toContain('overflow-wrap: anywhere');
    }
    expect(card).toContain('min-height: 44px');
    expect(card).toContain(':focus-visible');
    expect(card).toContain('prefers-reduced-motion: reduce');
    expect(preview).toContain('flex-wrap: wrap');
    expect(preview).toContain('@media (max-width: 520px)');
    expect(styles['../src/styles/App.css']).not.toMatch(/\.themeCard|\.themePreview/);
  });
  it('keeps category navigation targets usable and selection borders from shifting content', () => {
    const css = styles['../src/components/category/CategoryNav.css'];
    expect(css).toContain('min-height: 44px');
    expect(css).toContain('min-width: 44px');
    expect(css).toContain('min-width: 0');
    expect(css).toContain('overflow-wrap: anywhere');
    expect(css).toContain(':focus-visible');
    expect(css).not.toContain('border-left: 3px');
  });
  it('keeps the category manager in one responsive panel and gives tree controls usable targets', () => {
    const tree = styles['../src/styles/components/CategoryManagerTree.css'];
    const modal = styles['../src/components/category/CategoryManagerModal.css'];
    expect(components['../src/components/category/CategoryManagerTree.tsx']).toContain("import '../../styles/components/CategoryManagerTree.css'");
    for (const css of [tree, modal]) {
      expect(css).toContain('min-height: 44px');
      expect(css).toContain('min-width: 0');
      expect(css).toContain('overflow-wrap: anywhere');
      expect(css).toContain(':focus-visible');
    }
    expect(modal).toContain('90dvh');
    expect(modal).toContain('.modal.categoryManager');
    expect(modal).toContain('grid-column: 1 / -1');
    expect(modal).toContain('.category-manager-form .content-state { min-height: 0;');
    expect(modal).toContain('flex-shrink: 0');
    expect(modal).not.toContain('width: 200%');
    expect(modal).not.toContain('min-width: 300px');
    expect(tree).toContain('touch-action: none');
  });
  it('keeps workspace recovery usable without nested scrolling and fits long names', () => {
    const css = styles['../src/styles/components/WorkspaceRestorationModal.css'];
    expect(components['../src/components/workspace/WorkspaceRestorationModal.tsx']).toContain("import '../../styles/components/WorkspaceRestorationModal.css'");
    expect(css).toContain('width: min(100%, 34rem)');
    expect(css).toContain('min-height: 44px');
    expect(css).toContain('min-width: 0');
    expect(css).toContain('overflow-wrap: anywhere');
    expect(css).toContain('flex-wrap: wrap');
    expect(css).toContain(':focus-within');
    expect(css).toContain(':focus-visible');
    expect(css).not.toContain('max-height: 200px');
  });
  it('keeps the shared workspace wizard responsive and owns its styles', () => {
    const css = styles['../src/styles/components/WorkspaceSetupWizard.css'];
    expect(components['../src/components/wizard/WorkspaceSetupWizard.tsx']).toContain("import '../../styles/components/WorkspaceSetupWizard.css'");
    expect(css).toContain('min-height: 44px');
    expect(css).toContain('flex-wrap: wrap');
    expect(css).toContain('min-width: 0');
    expect(css).toContain('minmax(min(100%, 12rem), 1fr)');
    expect(css).toContain('overflow-wrap: anywhere');
    expect(css).toContain(':focus-visible');
    expect(css).toContain('font: inherit');
    expect(css).toContain('min-height: 0');
    expect(css).toContain('flex-shrink: 0');
    expect(css).toContain('position: sticky');
    expect(css).toContain('@media (max-width: 520px)');
    expect(css).toContain('grid-template-columns: minmax(0, 1fr)');
  });
  it('keeps support controls and conversations flexible without relying on settings or admin page styles', () => {
    const css = styles['../src/styles/components/SupportPanel.css'];
    expect(css).toContain('min-height: 44px');
    expect(css).toContain('flex-wrap: wrap');
    expect(css).toContain('overflow-wrap: anywhere');
    expect(css).toContain('min-width: 0');
    expect(css).toContain(':focus-visible');
    expect(styles['../src/styles/components/AdminSupportSection.css']).toContain('overflow-x: auto');
    expect(styles['../src/styles/components/AdminSupportSection.css']).not.toContain('.systemAdmin__');
    expect(styles['../src/styles/Support.css']).not.toMatch(/\.support-detail|\.support-request-card/);
    for (const component of ['SupportSection', 'SupportRequestList', 'SupportRequestSession', 'SupportConversation', 'SupportPresentation']) {
      expect(components[`../src/components/support/${component}.tsx`]).toContain("import '../../styles/components/SupportPanel.css'");
    }
  });
  it('keeps workspace modal styles local, with usable controls and wrapping gallery URLs', () => {
    const css = styles['../src/styles/components/WorkspaceEditModal.css'];
    expect(components['../src/components/workspace/WorkspaceEditModal.tsx']).toContain("import '../../styles/components/WorkspaceEditModal.css'");
    expect(css).toContain('min-height: 44px');
    expect(css).toContain('min-width: 0');
    expect(css).toContain('flex-wrap: wrap');
    expect(css).toContain('overflow-wrap: anywhere');
    expect(css).not.toMatch(/^\.modal__/m);
  });
  it('keeps collection forms and actions usable at narrow widths', () => {
    expect(components['../src/components/collection/CollectionEditor.tsx']).toContain("import '../../styles/components/CollectionEditor.css'");
    expect(components['../src/components/collection/CollectionSettings.tsx']).toContain("import '../../styles/components/CollectionSettings.css'");
    expect(components['../src/components/collection/CollectionSetupWizard.tsx']).toContain("import '../../styles/components/CollectionSetupWizard.css'");
    expect(styles['../src/styles/components/CollectionEditor.css']).toContain('min-height: 44px');
    expect(styles['../src/styles/components/CollectionEditor.css']).toContain('flex-wrap: wrap');
    expect(styles['../src/styles/components/CollectionSettings.css']).toContain('minmax(min(100%, 20rem), 1fr)');
    expect(styles['../src/styles/components/CollectionSettings.css']).toContain('overflow-wrap: anywhere');
    expect(styles['../src/styles/components/CollectionSetupWizard.css']).toContain('minmax(min(100%, 12rem), 1fr)');
    expect(styles['../src/styles/SettingsView.css']).not.toMatch(/\.settings-form|\.settings-collection/);
  });
  it('keeps dashboard charts readable at narrow widths and honors reduced motion', () => {
    const css = styles['../src/styles/components/DashboardSection.css'];
    expect(css).toContain('minmax(min(100%, 12rem), 1fr)');
    expect(css).toContain('min-width: 0');
    expect(css).toContain('overflow-wrap: anywhere');
    expect(css).toContain('prefers-reduced-motion: reduce');
    expect(css).not.toContain('min-height: 2px');
    expect(styles['../src/styles/SettingsView.css']).not.toContain('.dashboard-chart');
    expect(components['../src/components/settings/DashboardSection.tsx']).toContain("import '../../styles/components/DashboardSection.css'");
    expect(styles['../src/styles/SettingsView.css']).toContain('.app__sidebar.settings-sidebar {\n  display: block;');
    expect(styles['../src/styles/SettingsView.css']).toContain('minmax(min(100%, 9rem), 1fr)');
    expect(styles['../src/styles/SettingsView.css']).toContain('min-height: 44px');
  });
  it('keeps account actions large enough to use and allows actions and feedback to wrap', () => {
    expect(styles['../src/styles/UserButton.css']).toContain('min-height: 44px');
    expect(styles['../src/styles/UserButton.css']).toContain('flex-wrap: wrap');
    expect(styles['../src/styles/UserButton.css']).toContain('overflow-wrap: anywhere');
    expect(styles['../src/styles/TermsAcceptance.css']).toContain('min-height: 44px');
    expect(styles['../src/styles/TermsAcceptance.css']).toContain('flex-wrap: wrap');
    expect(styles['../src/styles/components/WorkspaceSettings.css']).toContain('min-height: 44px');
    expect(styles['../src/styles/components/WorkspaceSettings.css']).toContain('flex-wrap: wrap');
    expect(styles['../src/styles/components/WorkspaceSettings.css']).toContain('overflow-wrap: anywhere');
    expect(components['../src/components/workspace/WorkspaceSettings.tsx']).toContain("import '../../styles/components/WorkspaceSettings.css'");
    expect(components['../src/components/workspace/DataExportSection.tsx']).toContain("import '../../styles/components/DataExportSection.css'");
    for (const [component, stylesheet] of [['common/DeletionConfirmationModal', 'DeletionConfirmationModal'], ['common/DeletionStatsGrid', 'DeletionStatsGrid'], ['user/AccountDeletionSection', 'AccountDeletionSection']]) {
      expect(components[`../src/components/${component}.tsx`]).toContain(`import '../../styles/components/${stylesheet}.css'`);
    }
    expect(styles['../src/styles/SettingsView.css']).not.toMatch(/\.deletion-modal|\.deletion-stats-grid|\.settings-workspace-card|\.settings-export-card/);
  });
  it('defines every CSS token used without a fallback', () => {
    const css = Object.values(styles).join('\n');
    const definitions = new Set([...css.matchAll(/(--[\w-]+)\s*:/g)].map(match => match[1]));
    const missing = Object.entries(styles).flatMap(([path, text]) =>
      [...String(text).matchAll(/var\((--[\w-]+)\)/g)]
        .filter(match => !definitions.has(match[1]))
        .map(match => `${path}: ${match[1]}`));
    expect(missing).toEqual([]);
  });

  it('loads template and modal styles without depending on an image gallery', () => {
    expect(components['../src/components/template/TemplateSelector.tsx']).toContain("import '../../styles/components/TemplateSelector.css'");
    expect(components['../src/components/template/TemplateChecklist.tsx']).toContain("import '../../styles/components/TemplateChecklist.css'");
    expect(components['../src/components/common/ModalDialog.tsx']).toContain("import '../../styles/components/ModalDialog.css'");
    for (const [component, stylesheet] of [['item/PropertyEditor', 'PropertyEditor'], ['common/ImageEditor', 'ImageEditor'], ['common/DragHandle', 'DragHandle'], ['template/TemplateCard', 'TemplateCard'], ['template/TemplateDefinitionForm', 'TemplateDefinitionForm'], ['template/TemplateDraftForm', 'TemplateDefinitionForm'], ['admin/AdminResource', 'AdminPanel'], ['support/AdminSupportSection', 'AdminSupportSection']]) {
      expect(components[`../src/components/${component}.tsx`]).toContain(`import '../../styles/components/${stylesheet}.css'`);
    }
    expect(styles['../src/styles/components/ImageGallery.css']).not.toMatch(/\.templateSelector|\.modal-dialog|\.propertyEditor|\.imageEditor|\.drag-handle/);
  });

  it('keeps administration navigation flexible and wide tables inside scrollable regions', () => {
    expect(styles['../src/styles/SystemAdmin.css']).toContain('.system-admin__navigation');
    expect(styles['../src/styles/SystemAdmin.css']).toContain('flex-wrap: wrap');
    expect(styles['../src/styles/components/AdminPanel.css']).toContain('.admin-panel__table-scroll { overflow-x: auto; max-width: 100%');
    expect(styles['../src/styles/SystemAdmin.css']).not.toContain('.systemAdmin__');
  });

  it('allows template cards and property rows to shrink and stack on narrow screens', () => {
    expect(styles['../src/styles/ItemTemplateEditor.css']).toContain('minmax(min(100%, 20rem), 1fr)');
    expect(styles['../src/styles/components/TemplateDefinitionForm.css']).toContain('grid-template-columns: 32px minmax(0, 1fr) 40px');
    expect(styles['../src/styles/components/TemplateDefinitionForm.css']).toContain('.template-form__legend');
    expect(styles['../src/styles/components/TemplateCard.css']).toContain('overflow-wrap: anywhere');
  });
});


it('keeps support composer and notification styles local with reachable controls and bounded scrolling', () => {
  const modal = styles['../src/styles/components/SupportModal.css'];
  const banner = styles['../src/styles/components/UnreadSupportBanner.css'];
  expect(banner).toContain('color: var(--color-text);');
  expect(modal).toContain('.support-modal__hint { margin: 0; color: var(--color-text-secondary);');
  expect(modal).toContain('max-height: 90dvh');
  expect(modal).toContain('overflow-y: auto');
  expect(modal).toContain('.support-modal__scroll { min-height: 0;');
  expect(modal).toContain('grid-template-columns: repeat(auto-fit, minmax(min(9rem, 100%), 1fr))');
  expect(modal).toContain('flex-shrink: 0');
  for (const css of [modal, banner]) {
    expect(css).toContain('min-height: 44px');
    expect(css).toContain('min-width: 44px');
    expect(css).toContain(':focus-visible');
    expect(css).toContain('overflow-wrap: anywhere');
  }
  expect(styles['../src/styles/Support.css']).not.toMatch(/\.support-modal|\.support-banner/);
  expect(components['../src/components/support/SupportModal.tsx']).toContain("import '../../styles/components/SupportModal.css'");
  expect(components['../src/components/support/UnreadSupportBanner.tsx']).toContain("import '../../styles/components/UnreadSupportBanner.css'");
});


it('keeps team actions reachable and member identities readable on narrow screens', () => {
  const css = styles['../src/styles/components/TeamManagement.css'];
  for (const rule of ['min-height: 44px', 'min-width: 44px', ':focus-visible', 'overflow-wrap: anywhere', 'flex-wrap: wrap', '@media (max-width: 480px)', 'grid-template-columns: minmax(0, 1fr)']) expect(css).toContain(rule);
  expect(css).toContain('grid-template-columns: minmax(0, 1fr) minmax(0, 1.4fr)');
  expect(css).not.toContain('max-width: 700px');
  expect(components['../src/components/user/TeamManagement.tsx']).toContain("import '../../styles/components/TeamManagement.css'");
  expect(Object.values(components).join('\n')).not.toContain("styles/UserManagement.css");
});


it('keeps image previews complete and image controls visible, labelled and usable on narrow screens', () => {
  const css = styles['../src/styles/components/ImageEditor.css'];
  for (const rule of ['min-height: 44px', 'min-width: 44px', ':focus-visible', 'overflow-wrap: anywhere', 'minmax(min(100%, 12rem), 1fr)', 'object-fit: contain']) expect(css).toContain(rule);
  expect(css).not.toContain('opacity: 0;');
});


it('aligns item fields and actions to the image controls and stacks mobile actions', () => {
  const css = styles['../src/styles/components/ItemEditor.css'];
  for (const rule of ['.detail__input', '.subcategoryDropdown__select', '.detail__btn', '.propertyEditor__add', 'min-height: 44px', 'min-width: 44px', 'overflow-wrap: anywhere', '@media (max-width: 480px)', 'grid-template-columns: minmax(0, 1fr)', '.detail--editing { padding: var(--space-md); }']) expect(css).toContain(rule);
});

it('gives property rows shrinkable fields, visible focus and reachable mobile controls', () => {
  const css = styles['../src/styles/components/PropertyEditor.css'];
  for (const rule of ['min-height: 44px', 'width: 44px', 'height: 44px', ':focus-visible', 'overflow-wrap: anywhere',
    'repeat(3, minmax(0, 1fr))', '44px minmax(0, 1fr) 44px', 'grid-row: 1 / 4', 'min-width: 0', 'font-size: 1rem']) expect(css).toContain(rule);
  expect(css).toContain('.propertyEditor .drag-handle { width: 44px; height: 44px; }');
});

it('keeps session recovery and workspace choices readable and reachable on narrow screens', () => {
  const feedback = styles['../src/styles/components/SessionChangeFeedback.css'];
  const switcher = styles['../src/components/common/WorkspaceSwitcher.css'];
  for (const css of [feedback, switcher]) {
    for (const rule of ['min-height: 44px', ':focus-visible', 'overflow-wrap: anywhere', 'min-width: 0', 'calc(100vw - 2rem)']) expect(css).toContain(rule);
  }
  expect(feedback).toContain('.modal.session-change');
  expect(feedback).toContain('max-height: 90dvh');
  expect(switcher).toContain('max-height: min(32rem, 60dvh)');
  expect(switcher).toContain('left: var(--space-md)');
  expect(switcher).toContain('right: var(--space-md)');
  expect(switcher).not.toContain('right: anchor(right)');
  expect(switcher).toContain('overflow-y: auto');
});
