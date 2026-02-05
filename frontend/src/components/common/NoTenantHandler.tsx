import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { useUser } from '../../contexts/UserContext';
import { tenantsApi } from '../../api';
import { TenantRestorationModal } from '../tenant';

interface NoTenantHandlerProps {
  children: React.ReactNode;
}

/**
 * Handles the case where a user has no active tenant.
 * Shows restoration modal if user has restorable tenants,
 * otherwise redirects to tenant creation.
 */
export function NoTenantHandler({ children }: NoTenantHandlerProps) {
  const { user, loading, refetch } = useUser();
  const navigate = useNavigate();
  const [showRestorationModal, setShowRestorationModal] = useState(false);
  const [hasCheckedTenants, setHasCheckedTenants] = useState(false);
  const [isCheckingTenants, setIsCheckingTenants] = useState(false);
  const isCheckingRef = useRef(false);

  useEffect(() => {
    const checkTenantStatus = async () => {
      console.log('[NoTenantHandler] checkTenantStatus:', {
        loading,
        hasUser: !!user,
        hasCheckedTenants,
        isChecking: isCheckingRef.current
      });
      if (loading || !user || hasCheckedTenants || isCheckingRef.current) return;

      // Check if user has no active tenants (all tenants array is empty or all deleted)
      const activeTenants = user.tenants || [];
      console.log('[NoTenantHandler] User tenants:', activeTenants);

      if (activeTenants.length === 0) {
        // Check for restorable tenants
        console.log('[NoTenantHandler] No active tenants, checking for restorable tenants...');
        isCheckingRef.current = true;
        setIsCheckingTenants(true);
        try {
          const restorable = await tenantsApi.getRestorableTenants();
          console.log('[NoTenantHandler] Restorable tenants response:', restorable);
          if (restorable.length > 0) {
            console.log('[NoTenantHandler] Found restorable tenants, showing modal');
            setShowRestorationModal(true);
          } else {
            // No restorable tenants - redirect to tenant creation
            console.log('[NoTenantHandler] No restorable tenants, redirecting to /tenants/new');
            navigate('/tenants/new');
          }
        } catch (error) {
          // On error, redirect to tenant creation
          console.error('[NoTenantHandler] Error fetching restorable tenants:', error);
          navigate('/tenants/new');
        } finally {
          isCheckingRef.current = false;
          setIsCheckingTenants(false);
        }
      }
      setHasCheckedTenants(true);
    };

    checkTenantStatus();
  }, [user, loading, hasCheckedTenants, navigate]);

  const handleRestoreComplete = () => {
    setShowRestorationModal(false);
    refetch();
    navigate('/collections');
  };

  const handleCreateNew = () => {
    setShowRestorationModal(false);
    navigate('/tenants/new');
  };

  // While checking for restorable tenants with no active tenants, show loading
  // This prevents children from rendering and navigating away
  const hasNoTenants = user && (!user.tenants || user.tenants.length === 0);
  if (hasNoTenants && (isCheckingTenants || (!hasCheckedTenants && !showRestorationModal))) {
    return <div className="app__loading">Loading...</div>;
  }

  // If showing restoration modal, don't render children (prevent navigation)
  if (showRestorationModal) {
    return (
      <TenantRestorationModal
        isOpen={true}
        onRestoreComplete={handleRestoreComplete}
        onCreateNew={handleCreateNew}
      />
    );
  }

  return <>{children}</>;
}

export default NoTenantHandler;
