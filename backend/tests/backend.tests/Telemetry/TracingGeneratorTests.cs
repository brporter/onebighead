using System.Collections.Immutable;
using System.Diagnostics;
using System.Reflection;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.Extensions.DependencyInjection;
using OneBigHead.Generators;
using OneBigHead.Server.Telemetry;

namespace OneBigHead.Server.Tests.Telemetry;

[Trait("Category", "Unit")]
public class TracingGeneratorTests
{
    private static readonly CSharpParseOptions Parse = new(LanguageVersion.Latest);
    private static readonly ImmutableArray<MetadataReference> References = ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!)
        .Split(Path.PathSeparator).Append(typeof(GenerateTracingProxyAttribute).Assembly.Location).Distinct()
        .Select(path => MetadataReference.CreateFromFile(path)).ToImmutableArray<MetadataReference>();

    [Fact]
    public async Task AllReturnShapes_InheritanceAndEscapedIdentifiers_CompileAndPreserveBehavior()
    {
        const string input = """
            using System;
            using System.Collections.Generic;
            using System.Threading.Tasks;
            using OneBigHead.Server.Telemetry;
            namespace GeneratorFixtures;
            public interface IBase { Task<int> Lookup(int itemId); }
            public interface IOther { Task<int> Lookup(int itemId); }
            public interface ILeft : IBase { }
            public interface IRight : IBase { }
            [GenerateTracingProxy]
            public interface IShapes : ILeft, IRight, IOther
            {
                new Task<int> Lookup(int renamedId);
                int Lookup(string itemId);
                void Notify(string message);
                int Read(int number);
                int[] ReadArray();
                IEnumerable<int> ReadMany();
                Task SaveAsync(int itemId);
                Task<object> ReadAsync(Guid key);
                ValueTask SaveValueAsync(int itemId);
                ValueTask<object> ReadValueAsync(Guid key);
                int @event(string @class);
                int DefaultProperty => 7;
            }
            """;
        var (assembly, generated) = Compile(input);
        Assert.Single(generated);
        var contract = assembly.GetType("GeneratorFixtures.IShapes")!;
        var proxy = assembly.GetType(TracingContractHarness.ProxyName(contract))!;
        // The diamond and two identical inherited declarations produce one implementation.
        Assert.Equal(2, proxy.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly).Count(method => method.Name == "Lookup"));
        foreach (var method in TracingContractHarness.Methods(contract))
        foreach (var enabled in new[] { false, true })
        foreach (var fail in new[] { false, true })
            await TracingContractHarness.Verify(contract, method, enabled, fail);
    }

    [Fact]
    public void AttributeDiscovery_HandlesAliasesSuffixesAndPartialInterfaces()
    {
        var (_, generated) = Compile("""
            using Trace = OneBigHead.Server.Telemetry.GenerateTracingProxyAttribute;
            namespace GeneratorFixtures;
            [Trace] public partial interface IAliased { int First(); }
            public partial interface IAliased { int Second(); }
            [OneBigHead.Server.Telemetry.GenerateTracingProxyAttribute]
            public interface ISuffixed { int Third(); }
            [System.Obsolete] public interface IIgnored { int Ignored(); }
            public interface IUndecorated { }
            """);
        Assert.Equal(2, generated.Length);
        Assert.Contains(generated, source => source.HintName.Contains("IAliased", StringComparison.Ordinal));
        Assert.Contains(generated, source => source.SourceText.ToString().Contains("Second()", StringComparison.Ordinal));
        Assert.DoesNotContain(generated, source => source.HintName.Contains("IIgnored", StringComparison.Ordinal));
    }

    [Fact]
    public async Task GlobalNamespaceAndEqualShortNames_DoNotCollide()
    {
        var (assembly, generated) = Compile("""
            using OneBigHead.Server.Telemetry;
            [GenerateTracingProxy] public interface IGlobal { int Read(); }
            namespace First { [GenerateTracingProxy] public interface IShared { int Read(); } }
            namespace Second { [GenerateTracingProxy] public interface IShared { int Read(); } }
            """);
        Assert.Equal(3, generated.Length);
        Assert.Equal(3, generated.Select(source => source.HintName).Distinct().Count());
        foreach (var name in new[] { "IGlobal", "First.IShared", "Second.IShared" })
        {
            var contract = assembly.GetType(name)!;
            await TracingContractHarness.Verify(contract, contract.GetMethod("Read")!, true, false);
        }
    }

    [Fact]
    public void NonInterfaceTargets_DoNotGenerateAProxy()
    {
        var tree = CSharpSyntaxTree.ParseText("""
            [OneBigHead.Server.Telemetry.GenerateTracingProxy]
            public class NotAnInterface { }
            """, Parse);
        var compilation = CSharpCompilation.Create("InvalidTarget", [tree], References, new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        var driver = Driver().RunGenerators(compilation);
        Assert.Empty(driver.GetRunResult().GeneratedTrees);
        Assert.Empty(driver.GetRunResult().Diagnostics);
    }

    [Theory]
    [InlineData("")]
    [InlineData("RegistrationFixture.")]
    public void DependencyInjection_ResolvesOneDecoratorAndOwnsItsImplementation(string prefix)
    {
        var (assembly, _) = Compile("""
            using System;
            using OneBigHead.Server.Telemetry;
            [GenerateTracingProxy] public interface IService { int Read(); }
            public class Service : IService, IDisposable
            {
                public int Disposals { get; private set; }
                public int Read() => 42;
                public void Dispose() => Disposals++;
            }
            namespace RegistrationFixture
            {
                [GenerateTracingProxy] public interface IService { int Read(); }
                public class Service : global::Service, IService { }
            }
            """);
        var contract = assembly.GetType($"{prefix}IService")!;
        var implementation = assembly.GetType($"{prefix}Service")!;
        using var source = new ActivitySource($"Registration.{Guid.NewGuid()}");
        var stopped = new List<Activity>();
        using var listener = TracingContractHarness.Listen(source, true, stopped);
        var services = new ServiceCollection();
        typeof(TracingServiceCollectionExtensions).GetMethod(nameof(TracingServiceCollectionExtensions.AddTracingDecorator))!
            .MakeGenericMethod(contract, implementation).Invoke(null, [services, source]);
        object inner;
        using (var provider = services.BuildServiceProvider())
        {
            inner = provider.GetRequiredService(implementation);
            var proxy = provider.GetRequiredService(contract);
            Assert.Equal(TracingContractHarness.ProxyName(contract), proxy.GetType().FullName);
            Assert.Same(proxy, provider.GetRequiredService(contract));
            Assert.Equal(42, contract.GetMethod("Read")!.Invoke(proxy, null));
            Assert.Equal("IService.Read", Assert.Single(stopped).OperationName);
            Assert.Equal(0, implementation.GetProperty("Disposals")!.GetValue(inner));
        }
        Assert.Equal(1, implementation.GetProperty("Disposals")!.GetValue(inner));
    }

    [Fact]
    public void UnannotatedContract_ResolvesOneSingletonAndDisposesItOnce()
    {
        using var source = new ActivitySource("UnannotatedRegistration");
        var services = new ServiceCollection().AddTracingDecorator<IUnannotated, UnannotatedService>(source);
        UnannotatedService inner;
        using (var provider = services.BuildServiceProvider())
        {
            inner = Assert.IsType<UnannotatedService>(provider.GetRequiredService<IUnannotated>());
            Assert.Same(inner, provider.GetRequiredService<IUnannotated>());
            Assert.Null(provider.GetService<UnannotatedService>());
            Assert.Equal(0, inner.Disposals);
        }
        Assert.Equal(1, inner.Disposals);
    }

    public interface IUnannotated;
    public sealed class UnannotatedService : IUnannotated, IDisposable
    {
        public int Disposals { get; private set; }
        public void Dispose() => Disposals++;
    }

    [Fact]
    public void ScalarTagPolicy_ExcludesPayloadsAndPreservesNamesAndValues()
    {
        var (assembly, _) = Compile("""
            using System;
            using OneBigHead.Server.Telemetry;
            namespace GeneratorFixtures;
            public enum Choice { First, Last }
            [GenerateTracingProxy] public interface ITags
            {
                void Record(bool flag, byte byteValue, sbyte signedByte, char character,
                    short small, ushort unsignedSmall, int WorkspaceID, uint unsigned,
                    long large, ulong unsignedLarge, float fraction, double precision,
                    decimal amount, string text, Choice choice, Guid key,
                    int? optional, object payload, int[] values);
            }
            """);
        using var source = new ActivitySource($"TagPolicy.{Guid.NewGuid()}");
        var stopped = new List<Activity>();
        using var listener = TracingContractHarness.Listen(source, true, stopped);
        var contract = assembly.GetType("GeneratorFixtures.ITags")!;
        var inner = (RecordingService)DispatchProxy.Create(contract, typeof(RecordingService));
        object?[] args = [true, (byte)2, (sbyte)3, 'x', (short)4, (ushort)5, 6, (uint)7,
            8L, 9UL, 1.5f, 2.5d, 3.5m, "text", Enum.ToObject(assembly.GetType("GeneratorFixtures.Choice")!, 1), Guid.NewGuid(), 4, new object(), new[] { 2 }];
        inner.Handle = (_, received) => { Assert.Equal(args, received); return null; };
        var proxy = Activator.CreateInstance(assembly.GetType(TracingContractHarness.ProxyName(contract))!, inner, source)!;
        proxy.GetType().GetMethod("Record")!.Invoke(proxy, args);
        var activity = Assert.Single(stopped);
        var names = new[] { "flag", "byte_value", "signed_byte", "character", "small", "unsigned_small", "workspace_i_d", "unsigned", "large", "unsigned_large", "fraction", "precision", "amount", "text", "choice", "key" };
        for (var index = 0; index < names.Length; index++) Assert.Equal(args[index], activity.GetTagItem(names[index]));
        Assert.Equal(names.Length + 2, activity.TagObjects.Count());
        Assert.Null(activity.GetTagItem("optional"));
        Assert.Null(activity.GetTagItem("payload"));
        Assert.Null(activity.GetTagItem("values"));
    }

    private static GeneratorDriver Driver() => CSharpGeneratorDriver.Create([new TracingProxyGenerator().AsSourceGenerator()], parseOptions: Parse);

    private static (Assembly Assembly, ImmutableArray<GeneratedSourceResult> Generated) Compile(string input)
    {
        var compilation = CSharpCompilation.Create($"TracingFixture_{Guid.NewGuid():N}", [CSharpSyntaxTree.ParseText(input, Parse)], References,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary, nullableContextOptions: NullableContextOptions.Enable));
        var driver = Driver().RunGeneratorsAndUpdateCompilation(compilation, out var output, out var diagnostics);
        Assert.Empty(diagnostics);
        using var stream = new MemoryStream();
        var emit = output.Emit(stream);
        Assert.True(emit.Success, string.Join(Environment.NewLine, emit.Diagnostics));
        return (Assembly.Load(stream.ToArray()), driver.GetRunResult().Results.Single().GeneratedSources);
    }
}
