using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services.Support;

public enum SupportCreationStatus { Created, UnknownUser, MissingEmail }
public sealed record SupportCreationResult(SupportCreationStatus Status, SupportRequest? Request = null);

public interface ISupportRequestCreator
{
    Task<SupportCreationResult> CreateAsync(int? userId, CreateSupportRequestDto draft);
}
