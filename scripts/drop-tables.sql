-- Drop all tables and reset migration history (Azure SQL compatible)
-- This allows migrations to re-run and recreate tables from scratch

-- ============================================================================
-- STEP 1: Drop all foreign key constraints
-- ============================================================================

DECLARE @sql NVARCHAR(MAX) = N'';

SELECT @sql += N'ALTER TABLE ' + QUOTENAME(OBJECT_SCHEMA_NAME(parent_object_id))
    + '.' + QUOTENAME(OBJECT_NAME(parent_object_id))
    + ' DROP CONSTRAINT ' + QUOTENAME(name) + ';' + CHAR(13)
FROM sys.foreign_keys;

EXEC sp_executesql @sql;

PRINT 'All foreign key constraints dropped.';
GO

-- ============================================================================
-- STEP 2: Drop all application tables
-- Tables are listed in dependency order (leaf tables first) for clarity,
-- but with FK constraints removed, order is no longer critical.
-- ============================================================================

-- Level 1: Leaf tables
IF OBJECT_ID('dbo.SupportReplies', 'U') IS NOT NULL DROP TABLE dbo.SupportReplies;
IF OBJECT_ID('dbo.StoredImages', 'U') IS NOT NULL DROP TABLE dbo.StoredImages;
IF OBJECT_ID('dbo.ItemTemplateProperties', 'U') IS NOT NULL DROP TABLE dbo.ItemTemplateProperties;
IF OBJECT_ID('dbo.CollectionThemeTemplates', 'U') IS NOT NULL DROP TABLE dbo.CollectionThemeTemplates;
IF OBJECT_ID('dbo.CollectionThemeCategories', 'U') IS NOT NULL DROP TABLE dbo.CollectionThemeCategories;
IF OBJECT_ID('dbo.ContentScanLogs', 'U') IS NOT NULL DROP TABLE dbo.ContentScanLogs;
IF OBJECT_ID('dbo.CollectionItemHighlights', 'U') IS NOT NULL DROP TABLE dbo.CollectionItemHighlights;

-- Level 2: Junction tables and tables referencing Categories/Collections
IF OBJECT_ID('dbo.CategoryItemTemplates', 'U') IS NOT NULL DROP TABLE dbo.CategoryItemTemplates;
IF OBJECT_ID('dbo.CollectionItemTemplates', 'U') IS NOT NULL DROP TABLE dbo.CollectionItemTemplates;
IF OBJECT_ID('dbo.PropertySuggestions', 'U') IS NOT NULL DROP TABLE dbo.PropertySuggestions;
IF OBJECT_ID('dbo.Items', 'U') IS NOT NULL DROP TABLE dbo.Items;

-- Level 3: Categories (self-referencing hierarchy)
IF OBJECT_ID('dbo.Categories', 'U') IS NOT NULL DROP TABLE dbo.Categories;

-- Level 4: Collections, SupportRequests, and Collection statistics
IF OBJECT_ID('dbo.CollectionStatistics', 'U') IS NOT NULL DROP TABLE dbo.CollectionStatistics;
IF OBJECT_ID('dbo.Collections', 'U') IS NOT NULL DROP TABLE dbo.Collections;
IF OBJECT_ID('dbo.SupportRequests', 'U') IS NOT NULL DROP TABLE dbo.SupportRequests;

-- Level 5: ItemTemplates
IF OBJECT_ID('dbo.ItemTemplates', 'U') IS NOT NULL DROP TABLE dbo.ItemTemplates;

-- Level 6: User-related tables
IF OBJECT_ID('dbo.WorkspaceUsers', 'U') IS NOT NULL DROP TABLE dbo.WorkspaceUsers;
IF OBJECT_ID('dbo.Users', 'U') IS NOT NULL DROP TABLE dbo.Users;

-- Level 7: Root tables
IF OBJECT_ID('dbo.WorkspaceStatistics', 'U') IS NOT NULL DROP TABLE dbo.WorkspaceStatistics;
IF OBJECT_ID('dbo.Workspaces', 'U') IS NOT NULL DROP TABLE dbo.Workspaces;
IF OBJECT_ID('dbo.CollectionThemes', 'U') IS NOT NULL DROP TABLE dbo.CollectionThemes;

PRINT 'All application tables dropped.';
GO

-- ============================================================================
-- STEP 3: Clear migration history so migrations will re-run
-- ============================================================================

IF OBJECT_ID('dbo.__EFMigrationsHistory', 'U') IS NOT NULL
BEGIN
    TRUNCATE TABLE dbo.__EFMigrationsHistory;
    PRINT 'Migration history cleared.';
END
GO

PRINT 'Ready for fresh migration.';
GO
