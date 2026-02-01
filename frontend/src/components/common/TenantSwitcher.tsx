import { useState, useRef, useEffect } from 'react';
import { useUser } from '../../contexts/UserContext';
import { tenantsApi } from '../../api';
import type { TenantMembership } from '../../utils/types';

import './TenantSwitcher.css';

export function TenantSwitcher() {
  const { user, refetch } = useUser();
  const [isOpen, setIsOpen] = useState(false);
  const [isSwitching, setIsSwitching] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  // Don't render if user has only one tenant
  if (!user || user.tenants.length <= 1) {
    return null;
  }

  const activeTenant = user.activeTenant;
  const otherTenants = user.tenants.filter(t => t.tenantId !== activeTenant.tenantId);

  // Close dropdown when clicking outside
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    }

    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
      return () => document.removeEventListener('mousedown', handleClickOutside);
    }
  }, [isOpen]);

  const handleSwitch = async (tenant: TenantMembership) => {
    if (isSwitching) return;

    setIsSwitching(true);
    try {
      await tenantsApi.switch(tenant.tenantId);
      // Reload the page to refresh all data for the new tenant context
      window.location.reload();
    } catch (error) {
      console.error('Failed to switch tenant:', error);
      setIsSwitching(false);
      await refetch();
    }
  };

  return (
    <div className="tenant-switcher" ref={dropdownRef}>
      <button
        className="tenant-switcher__trigger"
        onClick={() => setIsOpen(!isOpen)}
        aria-expanded={isOpen}
        aria-haspopup="listbox"
        disabled={isSwitching}
      >
        <span className="tenant-switcher__name">{activeTenant.tenantName}</span>
        <span className="tenant-switcher__icon" aria-hidden="true">
          {isOpen ? '\u25B2' : '\u25BC'}
        </span>
      </button>

      {isOpen && (
        <div className="tenant-switcher__dropdown" role="listbox">
          <div className="tenant-switcher__current">
            <span className="tenant-switcher__label">Current</span>
            <div className="tenant-switcher__item tenant-switcher__item--active">
              <span className="tenant-switcher__item-name">{activeTenant.tenantName}</span>
              <span className="tenant-switcher__item-role">
                {activeTenant.tenantRole === 'TenantAdmin' ? 'Admin' : 'Member'}
              </span>
            </div>
          </div>

          {otherTenants.length > 0 && (
            <div className="tenant-switcher__others">
              <span className="tenant-switcher__label">Switch to</span>
              {otherTenants.map(tenant => (
                <button
                  key={tenant.tenantId}
                  className="tenant-switcher__item"
                  onClick={() => handleSwitch(tenant)}
                  disabled={isSwitching}
                  role="option"
                >
                  <span className="tenant-switcher__item-name">{tenant.tenantName}</span>
                  <span className="tenant-switcher__item-role">
                    {tenant.tenantRole === 'TenantAdmin' ? 'Admin' : 'Member'}
                  </span>
                </button>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default TenantSwitcher;
