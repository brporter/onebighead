using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using OneBigHead.Server.Models;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace OneBigHead.Server.Authentication;

public interface ITokenService
{
    string GenerateAppToken(User user, WorkspaceRole workspaceRole);
    ClaimsPrincipal? ValidateAppToken(string token);
}

public class TokenService : ITokenService
{
    private readonly AuthenticationSettings _settings;
    private readonly SymmetricSecurityKey _signingKey;

    public TokenService(IOptions<AuthenticationSettings> settings)
    {
        _settings = settings.Value;
        _signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_settings.Jwt.SigningKey));
    }

    public string GenerateAppToken(User user, WorkspaceRole workspaceRole)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new(ClaimTypes.Email, user.Email),
            new("workspace_id", user.ActiveWorkspaceId.ToString()),
            new("provider", user.IdentityProvider.ToString()),
            new("workspace_role", workspaceRole.ToString()),
            new(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
        };

        if (user.IsSystemAdministrator)
        {
            claims.Add(new Claim(ClaimTypes.Role, "SystemAdministrator"));
        }

        var credentials = new SigningCredentials(_signingKey, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: _settings.Jwt.Issuer,
            audience: _settings.Jwt.Audience,
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(_settings.Jwt.SlidingExpirationMinutes),
            signingCredentials: credentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public ClaimsPrincipal? ValidateAppToken(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = _signingKey,
            ValidateIssuer = true,
            ValidIssuer = _settings.Jwt.Issuer,
            ValidateAudience = true,
            ValidAudience = _settings.Jwt.Audience,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromMinutes(5)
        };

        try
        {
            var principal = tokenHandler.ValidateToken(token, validationParameters, out _);
            return principal;
        }
        catch
        {
            return null;
        }
    }
}

