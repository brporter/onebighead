using System.Text.Json;
using OneBigHead.Server.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;

namespace OneBigHead.Server.Data;

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
    {
    }

    public DbSet<Category> Categories => Set<Category>();
    public DbSet<Collection> Collections => Set<Collection>();
    public DbSet<Workspace> Workspaces => Set<Workspace>();
    public DbSet<User> Users => Set<User>();
    public DbSet<Item> Items => Set<Item>();
    public DbSet<PropertySuggestion> PropertySuggestions => Set<PropertySuggestion>();
    public DbSet<ItemTemplate> ItemTemplates => Set<ItemTemplate>();
    public DbSet<ItemTemplateProperty> ItemTemplateProperties => Set<ItemTemplateProperty>();
    public DbSet<CollectionItemTemplate> CollectionItemTemplates => Set<CollectionItemTemplate>();
    public DbSet<CategoryItemTemplate> CategoryItemTemplates => Set<CategoryItemTemplate>();
    public DbSet<StoredImage> StoredImages => Set<StoredImage>();
    public DbSet<CollectionTheme> CollectionThemes => Set<CollectionTheme>();
    public DbSet<CollectionThemeTemplate> CollectionThemeTemplates => Set<CollectionThemeTemplate>();
    public DbSet<CollectionThemeCategory> CollectionThemeCategories => Set<CollectionThemeCategory>();
    public DbSet<SupportRequest> SupportRequests => Set<SupportRequest>();
    public DbSet<SupportReply> SupportReplies => Set<SupportReply>();
    public DbSet<WorkspaceUser> WorkspaceUsers => Set<WorkspaceUser>();
    public DbSet<WorkspaceStatistic> WorkspaceStatistics => Set<WorkspaceStatistic>();
    public DbSet<CollectionStatistic> CollectionStatistics => Set<CollectionStatistic>();
    public DbSet<CollectionItemHighlight> CollectionItemHighlights => Set<CollectionItemHighlight>();
    public DbSet<ContentScanLog> ContentScanLogs => Set<ContentScanLog>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<Workspace>(entity =>
        {
            entity.HasKey(w => w.Id);
            entity.HasIndex(w => w.Name);
            entity.HasIndex(w => w.IsDeleted);
            entity.HasIndex(w => w.Slug)
                .IsUnique()
                .HasFilter("\"Slug\" IS NOT NULL");
        });

        modelBuilder.Entity<User>(entity =>
        {
            entity.HasKey(u => u.Id);

            entity.HasIndex(u => u.Email);
            entity.HasIndex(u => new { u.IdentityProvider, u.ProviderSubjectId }).IsUnique();

            entity.HasOne(u => u.ActiveWorkspace)
                .WithMany(w => w.ActiveUsers)
                .HasForeignKey(u => u.ActiveWorkspaceId)
                .OnDelete(DeleteBehavior.Restrict);
        });

        modelBuilder.Entity<WorkspaceUser>(entity =>
        {
            entity.HasKey(wu => new { wu.UserId, wu.WorkspaceId });

            entity.HasOne(wu => wu.User)
                .WithMany(u => u.WorkspaceMemberships)
                .HasForeignKey(wu => wu.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            entity.HasOne(wu => wu.Workspace)
                .WithMany(w => w.WorkspaceUsers)
                .HasForeignKey(wu => wu.WorkspaceId)
                .OnDelete(DeleteBehavior.Cascade);

            entity.HasIndex(wu => wu.WorkspaceId);
        });

        modelBuilder.Entity<Collection>(entity =>
        {
            entity.HasKey(c => c.Id);

            entity.HasOne(c => c.Workspace)
                .WithMany(w => w.Collections)
                .HasForeignKey(c => c.WorkspaceId)
                .OnDelete(DeleteBehavior.Cascade);

            entity.HasIndex(c => c.WorkspaceId);
            entity.HasIndex(c => new { c.WorkspaceId, c.Slug }).IsUnique();
        });

        modelBuilder.Entity<Category>(entity =>
        {
            entity.HasKey(c => c.Id);

            // Self-referencing FK uses Restrict to avoid delete cycles
            entity.HasOne(c => c.ParentCategory)
                .WithMany(c => c.ChildCategories)
                .HasForeignKey(c => c.ParentCategoryId)
                .OnDelete(DeleteBehavior.Restrict);

            // Use Restrict to avoid multiple cascade paths
            entity.HasOne(c => c.Workspace)
                .WithMany(w => w.Categories)
                .HasForeignKey(c => c.WorkspaceId)
                .OnDelete(DeleteBehavior.Restrict);

            entity.HasOne(c => c.Collection)
                .WithMany(col => col.Categories)
                .HasForeignKey(c => c.CollectionId)
                .OnDelete(DeleteBehavior.Cascade);

            entity.HasIndex(c => c.WorkspaceId);
            entity.HasIndex(c => c.CollectionId);
            entity.HasIndex(c => c.ParentCategoryId);
        });

        modelBuilder.Entity<Item>(entity =>
        {
            entity.HasKey(i => i.Id);

            // Use Restrict to avoid multiple cascade paths
            entity.HasOne(i => i.Workspace)
                .WithMany()
                .HasForeignKey(i => i.WorkspaceId)
                .OnDelete(DeleteBehavior.Restrict);

            // Use Restrict to avoid multiple cascade paths
            // (Collections → Categories → Items via SetNull creates a second path)
            entity.HasOne(i => i.Collection)
                .WithMany(c => c.Items)
                .HasForeignKey(i => i.CollectionId)
                .OnDelete(DeleteBehavior.Restrict);

            entity.HasOne(i => i.Category)
                .WithMany()
                .HasForeignKey(i => i.CategoryId)
                .OnDelete(DeleteBehavior.SetNull);

            entity.HasIndex(i => i.WorkspaceId);
            entity.HasIndex(i => i.CollectionId);
            entity.HasIndex(i => i.CategoryId);

            // Composite index for workspace-scoped template key queries (bulk updates)
            entity.HasIndex(i => new { i.WorkspaceId, i.TemplateKey });

            // Index for user flag queries (finding items by Have/Want/Trade status)
            entity.HasIndex(i => i.UserFlag);
            // Composite index for workspace-scoped flag queries (most common use case)
            entity.HasIndex(i => new { i.WorkspaceId, i.UserFlag });

            // Composite index for collection-scoped recently-added queries
            entity.HasIndex(i => new { i.CollectionId, i.CreatedAt });

            // Configure JSON columns for Properties and Images
            var jsonOptions = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
            
            entity.Property(i => i.Properties)
                .HasConversion(
                    v => JsonSerializer.Serialize(v, jsonOptions),
                    v => JsonSerializer.Deserialize<List<ItemProperty>>(v, jsonOptions) ?? new List<ItemProperty>()
                )
                .Metadata.SetValueComparer(new ValueComparer<List<ItemProperty>>(
                    (c1, c2) => JsonSerializer.Serialize(c1, jsonOptions) == JsonSerializer.Serialize(c2, jsonOptions),
                    c => c == null ? 0 : JsonSerializer.Serialize(c, jsonOptions).GetHashCode(),
                    c => JsonSerializer.Deserialize<List<ItemProperty>>(JsonSerializer.Serialize(c, jsonOptions), jsonOptions)!
                ));

            entity.Property(i => i.Images)
                .HasConversion(
                    v => JsonSerializer.Serialize(v, jsonOptions),
                    v => JsonSerializer.Deserialize<List<ItemImage>>(v, jsonOptions) ?? new List<ItemImage>()
                )
                .Metadata.SetValueComparer(new ValueComparer<List<ItemImage>>(
                    (c1, c2) => JsonSerializer.Serialize(c1, jsonOptions) == JsonSerializer.Serialize(c2, jsonOptions),
                    c => c == null ? 0 : JsonSerializer.Serialize(c, jsonOptions).GetHashCode(),
                    c => JsonSerializer.Deserialize<List<ItemImage>>(JsonSerializer.Serialize(c, jsonOptions), jsonOptions)!
                ));
        });

        modelBuilder.Entity<PropertySuggestion>(entity =>
        {
            entity.HasKey(p => p.Id);

            // Use Restrict to avoid multiple cascade paths
            entity.HasOne(p => p.Workspace)
                .WithMany()
                .HasForeignKey(p => p.WorkspaceId)
                .OnDelete(DeleteBehavior.Restrict);

            entity.HasOne(p => p.Collection)
                .WithMany()
                .HasForeignKey(p => p.CollectionId)
                .OnDelete(DeleteBehavior.Cascade);

            entity.HasIndex(p => new { p.CollectionId, p.Type });
            entity.HasIndex(p => new { p.CollectionId, p.Type, p.Value }).IsUnique();
        });

        modelBuilder.Entity<ItemTemplate>(entity =>
        {
            entity.HasKey(t => t.Id);

            entity.HasOne(t => t.Workspace)
                .WithMany()
                .HasForeignKey(t => t.WorkspaceId)
                .OnDelete(DeleteBehavior.Cascade);

            entity.HasIndex(t => t.WorkspaceId);
        });

        modelBuilder.Entity<ItemTemplateProperty>(entity =>
        {
            entity.HasKey(p => p.Id);

            entity.HasOne(p => p.ItemTemplate)
                .WithMany(t => t.Properties)
                .HasForeignKey(p => p.ItemTemplateId)
                .OnDelete(DeleteBehavior.Cascade);

            entity.HasIndex(p => p.ItemTemplateId);
        });

        modelBuilder.Entity<CollectionItemTemplate>(entity =>
        {
            entity.HasKey(ct => new { ct.CollectionId, ct.ItemTemplateId });

            entity.HasOne(ct => ct.Collection)
                .WithMany(c => c.CollectionItemTemplates)
                .HasForeignKey(ct => ct.CollectionId)
                .OnDelete(DeleteBehavior.Cascade);

            // Use Restrict to avoid multiple cascade paths
            entity.HasOne(ct => ct.ItemTemplate)
                .WithMany(t => t.CollectionItemTemplates)
                .HasForeignKey(ct => ct.ItemTemplateId)
                .OnDelete(DeleteBehavior.Restrict);
        });

        modelBuilder.Entity<CategoryItemTemplate>(entity =>
        {
            entity.HasKey(ct => new { ct.CategoryId, ct.ItemTemplateId });

            entity.HasOne(ct => ct.Category)
                .WithMany(c => c.CategoryItemTemplates)
                .HasForeignKey(ct => ct.CategoryId)
                .OnDelete(DeleteBehavior.Cascade);

            // Use Restrict to avoid multiple cascade paths
            entity.HasOne(ct => ct.ItemTemplate)
                .WithMany(t => t.CategoryItemTemplates)
                .HasForeignKey(ct => ct.ItemTemplateId)
                .OnDelete(DeleteBehavior.Restrict);

            entity.HasIndex(ct => ct.CategoryId);
        });

        modelBuilder.Entity<StoredImage>(entity =>
        {
            entity.HasKey(s => s.Id);

            entity.HasOne(s => s.Workspace)
                .WithMany()
                .HasForeignKey(s => s.WorkspaceId)
                .OnDelete(DeleteBehavior.Cascade);

            entity.HasIndex(s => s.WorkspaceId);
        });

        modelBuilder.Entity<CollectionTheme>(entity =>
        {
            entity.HasKey(t => t.Id);
            entity.HasIndex(t => t.SortOrder);
        });

        modelBuilder.Entity<CollectionThemeTemplate>(entity =>
        {
            entity.HasKey(tt => new { tt.ThemeId, tt.ItemTemplateId });

            entity.HasOne(tt => tt.Theme)
                .WithMany(t => t.ThemeTemplates)
                .HasForeignKey(tt => tt.ThemeId)
                .OnDelete(DeleteBehavior.Cascade);

            entity.HasOne(tt => tt.ItemTemplate)
                .WithMany()
                .HasForeignKey(tt => tt.ItemTemplateId)
                .OnDelete(DeleteBehavior.Cascade);

            entity.HasIndex(tt => tt.ThemeId);
        });

        modelBuilder.Entity<CollectionThemeCategory>(entity =>
        {
            entity.HasKey(tc => tc.Id);

            entity.HasOne(tc => tc.Theme)
                .WithMany(t => t.ThemeCategories)
                .HasForeignKey(tc => tc.ThemeId)
                .OnDelete(DeleteBehavior.Cascade);

            entity.HasIndex(tc => tc.ThemeId);
        });

        modelBuilder.Entity<SupportRequest>(entity =>
        {
            entity.HasKey(sr => sr.Id);

            entity.HasOne(sr => sr.User)
                .WithMany()
                .HasForeignKey(sr => sr.UserId)
                .OnDelete(DeleteBehavior.SetNull);

            entity.HasIndex(sr => sr.UserId);
            entity.HasIndex(sr => sr.Email);
            entity.HasIndex(sr => sr.Status);
            entity.HasIndex(sr => sr.CreatedAt);
            entity.HasIndex(sr => sr.IsDeleted);
        });

        modelBuilder.Entity<SupportReply>(entity =>
        {
            entity.HasKey(r => r.Id);

            entity.HasOne(r => r.SupportRequest)
                .WithMany(sr => sr.Replies)
                .HasForeignKey(r => r.SupportRequestId)
                .OnDelete(DeleteBehavior.Cascade);

            entity.HasOne(r => r.User)
                .WithMany()
                .HasForeignKey(r => r.UserId)
                .OnDelete(DeleteBehavior.SetNull);

            entity.HasIndex(r => r.SupportRequestId);
            entity.HasIndex(r => new { r.SupportRequestId, r.IsFromAdmin, r.IsRead });
        });

        modelBuilder.Entity<WorkspaceStatistic>(entity =>
        {
            entity.HasKey(s => s.Id);

            entity.Property(s => s.StatisticType)
                .HasConversion<int>();

            entity.HasIndex(s => new { s.WorkspaceId, s.StatisticType, s.Date }).IsUnique();
            entity.HasIndex(s => s.WorkspaceId);
        });

        modelBuilder.Entity<CollectionStatistic>(entity =>
        {
            entity.HasKey(s => s.Id);

            entity.Property(s => s.StatisticType)
                .HasConversion<int>();

            entity.HasOne<Collection>()
                .WithMany()
                .HasForeignKey(s => s.CollectionId)
                .OnDelete(DeleteBehavior.Cascade);

            entity.HasIndex(s => new { s.CollectionId, s.StatisticType }).IsUnique();
            entity.HasIndex(s => s.CollectionId);
        });

        modelBuilder.Entity<CollectionItemHighlight>(entity =>
        {
            entity.HasKey(h => h.Id);

            entity.HasOne<Collection>()
                .WithMany()
                .HasForeignKey(h => h.CollectionId)
                .OnDelete(DeleteBehavior.Cascade);

            entity.HasOne(h => h.Item)
                .WithMany()
                .HasForeignKey(h => h.ItemId)
                .OnDelete(DeleteBehavior.Restrict);

            entity.HasIndex(h => new { h.CollectionId, h.ItemId }).IsUnique();
            entity.HasIndex(h => new { h.CollectionId, h.ViewCount });
        });

        // ContentScanLog intentionally has no foreign key relationships to Workspace or User.
        // Scan logs are compliance/audit records that must survive workspace or user deletion.
        modelBuilder.Entity<ContentScanLog>(entity =>
        {
            entity.HasKey(l => l.Id);

            entity.HasIndex(l => l.WorkspaceId);
            entity.HasIndex(l => l.IsMatch);
            entity.HasIndex(l => l.ScannedAt);
        });
    }
}

