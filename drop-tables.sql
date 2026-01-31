-- Drop all tables and reset migration history
-- This allows migrations to re-run and recreate tables from scratch
-- Tables are dropped in reverse dependency order (leaf tables first)

-- Disable all foreign key constraints first (makes drop order less critical)
EXEC sp_MSforeachtable 'ALTER TABLE ? NOCHECK CONSTRAINT ALL'
GO

-- Drop tables in dependency order
IF OBJECT_ID('dbo.SupportReplies', 'U') IS NOT NULL DROP TABLE dbo.SupportReplies;
IF OBJECT_ID('dbo.StoredImages', 'U') IS NOT NULL DROP TABLE dbo.StoredImages;
IF OBJECT_ID('dbo.Items', 'U') IS NOT NULL DROP TABLE dbo.Items;
IF OBJECT_ID('dbo.CategoryItemTemplates', 'U') IS NOT NULL DROP TABLE dbo.CategoryItemTemplates;
IF OBJECT_ID('dbo.CollectionItemTemplates', 'U') IS NOT NULL DROP TABLE dbo.CollectionItemTemplates;
IF OBJECT_ID('dbo.PropertySuggestions', 'U') IS NOT NULL DROP TABLE dbo.PropertySuggestions;
IF OBJECT_ID('dbo.Categories', 'U') IS NOT NULL DROP TABLE dbo.Categories;
IF OBJECT_ID('dbo.Collections', 'U') IS NOT NULL DROP TABLE dbo.Collections;
IF OBJECT_ID('dbo.SupportRequests', 'U') IS NOT NULL DROP TABLE dbo.SupportRequests;
IF OBJECT_ID('dbo.Users', 'U') IS NOT NULL DROP TABLE dbo.Users;
IF OBJECT_ID('dbo.Tenants', 'U') IS NOT NULL DROP TABLE dbo.Tenants;
IF OBJECT_ID('dbo.ItemTemplateProperties', 'U') IS NOT NULL DROP TABLE dbo.ItemTemplateProperties;
IF OBJECT_ID('dbo.CollectionThemeTemplates', 'U') IS NOT NULL DROP TABLE dbo.CollectionThemeTemplates;
IF OBJECT_ID('dbo.CollectionThemeCategories', 'U') IS NOT NULL DROP TABLE dbo.CollectionThemeCategories;
IF OBJECT_ID('dbo.ItemTemplates', 'U') IS NOT NULL DROP TABLE dbo.ItemTemplates;
IF OBJECT_ID('dbo.CollectionThemes', 'U') IS NOT NULL DROP TABLE dbo.CollectionThemes;
GO

-- Clear migration history so idempotent migrations will re-run
-- The idempotent script checks this table to decide what to apply
IF OBJECT_ID('dbo.__EFMigrationsHistory', 'U') IS NOT NULL
BEGIN
    TRUNCATE TABLE dbo.__EFMigrationsHistory;
    PRINT 'Migration history cleared.';
END
GO

PRINT 'All application tables dropped. Ready for fresh migration.';
GO
