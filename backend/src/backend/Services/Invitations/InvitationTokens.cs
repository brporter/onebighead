using System.Security.Cryptography;
using System.Text;
using OneBigHead.Server.DTOs;

namespace OneBigHead.Server.Services.Invitations;

internal static class InvitationTokens
{
    public static string Create() => Convert.ToHexString(RandomNumberGenerator.GetBytes(32));

    public static string Hash(string token) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));

    public static string? ReadHash(InvitationAccessRequest request) =>
        request.InvitationId == Guid.Empty || request.Token is null || request.Token.Length != 64 ? null : Hash(request.Token);
}
