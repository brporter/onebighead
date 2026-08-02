using OneBigHead.Server.Authentication;

namespace OneBigHead.Server.Tests.Authentication;

[Trait("Category", "Unit")]
public class AuthErrorMessagesTests
{
    [Fact]
    public void GetMessage_None_ReturnsNull()
    {
        Assert.Null(AuthErrorMessages.GetMessage(AuthErrorType.None));
    }

    [Fact]
    public void GetMessage_SessionRevoked_ReturnsDisplayString()
    {
        var message = AuthErrorMessages.GetMessage(AuthErrorType.SessionRevoked);

        Assert.NotNull(message);
        Assert.Contains("sign in again", message);
    }

    [Fact]
    public void GetMessage_UnknownValue_ReturnsNull()
    {
        Assert.Null(AuthErrorMessages.GetMessage((AuthErrorType)999));
    }
}
