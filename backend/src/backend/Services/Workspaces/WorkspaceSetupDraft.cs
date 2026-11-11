using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Utilities;

namespace OneBigHead.Server.Services.Workspaces;

/// <summary>One normalization contract for creation and comparison with a prior request.</summary>
internal sealed record WorkspaceSetupDraft(string WorkspaceName, string CollectionName, string Description, int? ThemeId)
{
    public static WorkspaceSetupDraft FromRequest(SetupWorkspaceRequest request) => new(request.WorkspaceName.Trim(),
        string.IsNullOrWhiteSpace(request.CollectionName) ? Constants.CollectionNames.MyCollection : request.CollectionName.Trim(),
        request.CollectionDescription?.Trim() ?? string.Empty, request.ThemeId);

    public string Fingerprint() => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(this))));
}
