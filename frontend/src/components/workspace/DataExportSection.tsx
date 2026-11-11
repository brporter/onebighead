import { exportApi } from '../../api';
import { useAsyncAction } from '../../utils/useAsyncAction';
import { saveDownload } from '../../utils/saveDownload';
import '../../styles/components/DataExportSection.css';

export function DataExportSection() {
  const action = useAsyncAction();
  return <div className="settings-section">
    <div className="settings-section__header">
      <div>
        <h2 className="settings-section__title">Data Export</h2>
        <p className="settings-section__description">Download the active workspace’s collections, categories, items, and templates as a ZIP file for backup.</p>
      </div>
    </div>
    <div className="settings-export-card">
      <div className="settings-export-card__icon" aria-hidden="true">📦</div>
      <div className="settings-export-card__content">
        <h3 className="settings-export-card__title">Export All Data</h3>
        <p className="settings-export-card__description">Creates a ZIP archive containing JSON files with your collection metadata and item properties.</p>
      </div>
      {action.error && <div className="settings-section__error" role="alert">{action.error}</div>}
      <button type="button" className="settings-export-card__button" disabled={action.pending} onClick={() => {
        void action.run(async () => saveDownload(await exportApi.downloadExport()), 'Failed to export data');
      }}>{action.pending ? 'Exporting...' : 'Download Export'}</button>
    </div>
  </div>;
}
