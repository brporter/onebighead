using OneBigHead.Server.Hosting;
using OneBigHead.Server.Telemetry;
#if DEBUG
using OneBigHead.Server.Services.Seeding;

var (seedRequested, hostArguments) = DevelopmentSeedCommand.ReadArguments(args);
args = hostArguments;
#endif

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddApplicationServices(builder.Configuration, builder.Environment);
builder.AddApplicationTelemetry();

await using var app = builder.Build();
#if DEBUG
if (seedRequested)
    return await DevelopmentSeedCommand.ExecuteAsync(app.Configuration, app.Environment,
        app.Services.GetRequiredService<ILoggerFactory>());
#endif

app.UseApplicationPipeline();
await app.RunAsync();
return 0;

public partial class Program { }
