-- Bootstrap System Administrators
-- This script should be run after initial deployment to set up system administrators.
-- It updates existing users to be system administrators based on their email address.

-- Add bryan@bryanporter.com as a system administrator
UPDATE "Users"
SET "IsSystemAdministrator" = TRUE
WHERE "Email" = 'bryan@bryanporter.com';

-- Verify the update
SELECT "Id", "Email", "IsSystemAdministrator", "CreatedAt"
FROM "Users"
WHERE "IsSystemAdministrator" = TRUE;
