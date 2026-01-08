import './styles/Settings.css';
import BackNav from './BackNav';

interface SettingsProps {
  onBack: () => void;
}

function Settings({ onBack }: SettingsProps) {
  return (
    <div className="settings">
      <BackNav label="Back" onClick={onBack} />
      <div className="settings__content">
        <h2 className="settings__title">Settings</h2>
        <p className="settings__placeholder">Settings options coming soon.</p>
      </div>
    </div>
  );
}

export default Settings;
