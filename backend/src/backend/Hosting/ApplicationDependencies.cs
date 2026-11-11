using OneBigHead.Server.Services.Email;
using OneBigHead.Server.Services.Support;
using OneBigHead.Server.Services.Collections;
using OneBigHead.Server.Data;
using OneBigHead.Server.Services;
using OneBigHead.Server.Services.Publishing;
using OneBigHead.Server.Services.BulkUpdate;
using OneBigHead.Server.Services.Categories;
using OneBigHead.Server.Services.Items;
using OneBigHead.Server.Services.Images;
using OneBigHead.Server.Services.PublicCatalog;
using OneBigHead.Server.Services.Workspaces;
using OneBigHead.Server.Services.Templates;
using OneBigHead.Server.Services.Administration;
using OneBigHead.Server.Services.Accounts;
using OneBigHead.Server.Services.Memberships;
using OneBigHead.Server.Services.Invitations;
using OneBigHead.Server.Services.Exports;
using OneBigHead.Server.Telemetry;

namespace OneBigHead.Server.Hosting;

internal static class ApplicationDependencies
{
    public static IServiceCollection AddApplicationDependencies(this IServiceCollection services, IConfiguration configuration)
    {
        // A single registration list keeps test and production dependency graphs aligned.
        var repoSource = DiagnosticsConfig.RepositoryActivitySource;
        var appSource = DiagnosticsConfig.AppActivitySource;

        services.AddTracingDecorator<ICategoryRepository, CategoryRepository>(repoSource);
        services.AddTracingDecorator<ICollectionRepository, CollectionRepository>(repoSource);
        services.AddTracingDecorator<IItemRepository, ItemRepository>(repoSource);
        services.AddTracingDecorator<IUserRepository, UserRepository>(repoSource);
        services.AddTracingDecorator<IWorkspaceRepository, WorkspaceRepository>(repoSource);
        services.AddTracingDecorator<IWorkspaceUserRepository, WorkspaceUserRepository>(repoSource);
        services.AddTracingDecorator<IPropertySuggestionRepository, PropertySuggestionRepository>(repoSource);
        services.AddTracingDecorator<IItemTemplateRepository, ItemTemplateRepository>(repoSource);
        services.AddTracingDecorator<IThemeRepository, ThemeRepository>(repoSource);
        services.AddTracingDecorator<ISupportRepository, SupportRepository>(repoSource);
        services.AddTracingDecorator<IImageProvider, DatabaseImageProvider>(repoSource);
        services.AddTracingDecorator<IImageReader, ImageReader>(repoSource);
        services.AddTracingDecorator<IPublicCatalogReader, PublicCatalogReader>(repoSource);
        services.AddTracingDecorator<IWorkspaceStatisticsRepository, WorkspaceStatisticsRepository>(repoSource);
        services.AddTracingDecorator<ICollectionStatisticsRepository, CollectionStatisticsRepository>(repoSource);
        services.AddTracingDecorator<IPublicationService, PublicationService>(appSource);
        services.AddSingleton<IVisibilityService, VisibilityService>();
        services.AddTracingDecorator<IWorkspaceAccessService, WorkspaceAccessService>(appSource);
        services.AddTracingDecorator<IWorkspaceSummaryService, WorkspaceSummaryService>(appSource);
        services.AddTracingDecorator<IWorkspaceDeletionService, WorkspaceDeletionService>(appSource);
        services.AddSingleton<IAccountDeletionReader, AccountDeletionReader>();
        services.AddSingleton<IAccountDeletion, AccountDeletion>();
        services.AddSingleton<IAccountTerms, AccountTerms>();
        services.AddSingleton<IWorkspaceAdminTransfer, WorkspaceAdminTransfer>();
        services.AddSingleton<IWorkspaceLeave, WorkspaceLeave>();
        services.AddSingleton<IWorkspaceSwitch, WorkspaceSwitch>();
        services.AddSingleton<IWorkspaceCreation, WorkspaceCreation>();
        services.AddSingleton<IWorkspaceDetails, WorkspaceDetails>();
        services.AddSingleton<IWorkspaceWelcome, WorkspaceWelcome>();
        services.AddSingleton<IWorkspaceSetup, WorkspaceSetup>();
        services.AddSingleton<ISupportReplies, SupportReplies>();
        services.AddSingleton<ISupportRequestCreator, SupportRequestCreator>();
        services.AddSingleton<ISupportRequests, SupportRequests>();
        services.AddSingleton<IWorkspaceExportService, WorkspaceExportService>();
        services.AddSingleton<ITeamDirectory, TeamDirectory>();
        services.AddSingleton<ITeamInvitations, TeamInvitations>();
        services.AddSingleton<IInvitationDirectory, InvitationDirectory>();
        services.AddSingleton<IInvitationCancellation, InvitationCancellation>();
        services.AddSingleton<IInvitationPreview, InvitationPreview>();
        services.AddSingleton<IInvitationAcceptance, InvitationAcceptance>();
        services.AddSingleton<TeamMembershipChanges>();
        services.AddSingleton<ITeamRoleChanges>(services => services.GetRequiredService<TeamMembershipChanges>());
        services.AddSingleton<ITeamMemberRemoval>(services => services.GetRequiredService<TeamMembershipChanges>());
        services.Configure<EmailSettings>(configuration.GetSection("Email"));
        services.AddEmailDelivery();
        services.AddTracingDecorator<IEmailService, SupportEmailService>(appSource);
        services.AddTracingDecorator<IContentScanLogRepository, ContentScanLogRepository>(repoSource);
        services.AddTracingDecorator<IContentScanner, NoOpContentScanner>(appSource);
        services.AddTracingDecorator<ICsamReportingService, NoOpCsamReportingService>(appSource);
        services.AddTracingDecorator<ITokenRevocationRepository, TokenRevocationRepository>(repoSource);

        services.AddSingleton<ICategoryReadService, CategoryReadService>();
        services.AddSingleton<IItemReadService, ItemReadService>();
        services.AddSingleton<IItemWriteService, ItemWriteService>();
        services.AddSingleton<IItemViewRecorder, ItemViewRecorder>();
        services.AddSingleton<ICategoryWriteService, CategoryWriteService>();
        services.AddSingleton<WorkspaceStatisticsWriter>();
        services.AddSingleton<IWorkspaceStatisticsWriter>(services => services.GetRequiredService<WorkspaceStatisticsWriter>());
        services.AddSingleton<IWorkspaceStatisticsDecrementer>(services => services.GetRequiredService<WorkspaceStatisticsWriter>());
        services.AddSingleton<ICollectionSetupService, CollectionSetupService>();
        services.AddSingleton<ICollectionDetails, CollectionDetails>();
        services.AddSingleton<ICollectionDeletion, CollectionDeletion>();
        services.AddSingleton<IWorkspaceRestorationService, WorkspaceRestorationService>();
        services.AddSingleton<ISystemTemplateService, SystemTemplateService>();
        services.AddSingleton<IWorkspaceTemplateEditor, WorkspaceTemplateEditor>();
        services.AddSingleton<IAdministratorAccessService, AdministratorAccessService>();
        services.AddSingleton<IAdministratorDirectory, AdministratorDirectory>();
        services.AddSingleton<IAdministratorUsers, AdministratorUsers>();
        services.AddSingleton<IAdministratorWorkspaceDeletion, AdministratorWorkspaceDeletion>();

        services.AddSingleton<IRasterImageCodec, SkiaRasterImageCodec>();
        services.AddSingleton<IImageProcessor, ImageProcessor>();
        services.AddSingleton<IImageFormatDetector, SkiaImageFormatDetector>();
        services.AddSingleton<IImageUploadService, ImageUploadService>();
        services.AddSingleton<IPropertyDiffService, PropertyDiffService>();
        services.AddSingleton<BulkUpdateQueue>();
        services.AddSingleton<IBulkUpdateQueue>(services => services.GetRequiredService<BulkUpdateQueue>());
        services.AddSingleton<IBulkUpdateJobs>(services => services.GetRequiredService<BulkUpdateQueue>());
        services.AddSingleton<IBulkUpdateCollectionLocks>(services => services.GetRequiredService<BulkUpdateQueue>());
        services.AddSingleton<BulkUpdateItemStore>();
        services.AddSingleton<IBulkUpdateTargets>(services => services.GetRequiredService<BulkUpdateItemStore>());
        services.AddSingleton<IBulkUpdateProperties>(services => services.GetRequiredService<BulkUpdateItemStore>());
        services.AddSingleton<IBulkUpdateProcessor, BulkUpdateProcessor>();
        services.AddHostedService<BulkUpdateWorker>();

        return services;
    }
}
