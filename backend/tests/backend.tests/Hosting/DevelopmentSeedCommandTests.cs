#if DEBUG
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using OneBigHead.Server.Services.Seeding;

namespace OneBigHead.Server.Tests.Hosting;

public class DevelopmentSeedCommandTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"startup-seed-{Guid.NewGuid()}");

    public DevelopmentSeedCommandTests() => Directory.CreateDirectory(_root);

    [Fact]
    public void ReadArguments_RemovesOnlyExactSeedFlags_AndPreservesHostConfiguration()
    {
        string[] arguments = ["--seed", "--environment=Development", "--seed", "--Seeding:Path=--seed"];
        var (requested, hostArguments) = DevelopmentSeedCommand.ReadArguments(arguments);
        Assert.True(requested);
        Assert.Equal(["--environment=Development", "--Seeding:Path=--seed"], hostArguments);
        Assert.Equal(4, arguments.Length);
        var ordinary = DevelopmentSeedCommand.ReadArguments(["--environment=Production"]);
        Assert.False(ordinary.Requested);
        Assert.Equal(["--environment=Production"], ordinary.HostArguments);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("relative/seeds")]
    public async Task MissingSeedFiles_ReturnFailureAndLogResolvedPath(string? path)
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?> { ["Seeding:Path"] = path }).Build();
        var environment = Mock.Of<IHostEnvironment>(value => value.ContentRootPath == _root);
        var logger = new Mock<ILogger>();
        var factory = new Mock<ILoggerFactory>();
        factory.Setup(value => value.CreateLogger(It.IsAny<string>())).Returns(logger.Object);
        Assert.Equal(1, await DevelopmentSeedCommand.ExecuteAsync(configuration, environment, factory.Object));
        var resolved = Path.GetFullPath(Path.Combine(_root, path ?? "seeds"));
        logger.Verify(value => value.Log(LogLevel.Error, It.IsAny<EventId>(),
            It.Is<It.IsAnyType>((state, _) => state.ToString()!.Contains(resolved)), null,
            It.IsAny<Func<It.IsAnyType, Exception?, string>>()), Times.Once);
    }

    [Fact]
    public async Task SeedFilesWithoutConnectionString_FailClearlyBeforeConnecting()
    {
        await File.WriteAllTextAsync(Path.Combine(_root, "seed.json"), "{\"tables\":[]}");
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?> { ["Seeding:Path"] = _root }).Build();
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => DevelopmentSeedCommand.ExecuteAsync(
            configuration, Mock.Of<IHostEnvironment>(), NullLoggerFactory.Instance));
        Assert.Equal("ConnectionStrings:DefaultConnection is not configured.", error.Message);
    }

    [Fact]
    public async Task Program_SeedModeReturnsNonzeroWithoutStartingServer_WhenFilesAreMissing()
    {
        var exitCode = await RunProgramAsync(["--seed", "--environment=Testing", $"--contentRoot={_root}"]);
        Assert.Equal(1, exitCode);
    }

    internal static Task<int> RunProgramAsync(string[] args) => Task.Run(() =>
        (int)typeof(Program).Assembly.EntryPoint!.Invoke(null, [args])!);

    public void Dispose() => Directory.Delete(_root, recursive: true);
}
#else
namespace OneBigHead.Server.Tests.Hosting;

public class DevelopmentSeedCommandTests
{
    [Fact]
    public void ReleaseAssembly_DoesNotContainDevelopmentSeedCommand()
        => Assert.Null(typeof(Program).Assembly.GetType("OneBigHead.Server.Services.Seeding.DevelopmentSeedCommand"));
}
#endif
