using OneBigHead.Server.Data;

namespace OneBigHead.Server.Authentication;

public sealed class TokenRevocationService(ITokenRevocationRepository repository, TimeProvider time) : ITokenRevocationService
{
    public Task RevokeAsync(int userId) =>
        repository.UpsertAsync(userId, TokenRevocationTimestamp.From(time.GetUtcNow()));
}
