using OneBigHead.Server.DTOs;
using OneBigHead.Server.Telemetry;

namespace OneBigHead.Server.Services.Publishing;

[GenerateTracingProxy]
public interface IPublicationService
{
    Task<PublicationResult<PreflightResponse>> PreflightAsync(int workspaceId, PreflightRequest request, CancellationToken cancellationToken = default);
    Task<PublicationResult<ExecuteResponse>> ExecuteAsync(int workspaceId, ExecuteRequest request, CancellationToken cancellationToken = default);
}

public enum PublicationFailure { Invalid, NotFound, Conflict }
public sealed record PublicationError(PublicationFailure Kind, string Message);
public sealed class PublicationResult<T>
{
    private PublicationResult(T? value, PublicationError? error) { Value = value; Error = error; }
    public T? Value { get; }
    public PublicationError? Error { get; }
    public static PublicationResult<T> Success(T value) => new(value, null);
    public static PublicationResult<T> Failure(PublicationError error) => new(default, error);
}
