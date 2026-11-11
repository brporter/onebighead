using System.Text;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Text;

namespace OneBigHead.Generators;

[Generator]
public sealed class TracingProxyGenerator : IIncrementalGenerator
{
    public void Initialize(IncrementalGeneratorInitializationContext context)
    {
        var contracts = context.SyntaxProvider.ForAttributeWithMetadataName(
            "OneBigHead.Server.Telemetry.GenerateTracingProxyAttribute",
            static (node, _) => node is InterfaceDeclarationSyntax,
            static (context, _) => TracingContract.From((INamedTypeSymbol)context.TargetSymbol));

        context.RegisterSourceOutput(contracts, static (output, contract) =>
            output.AddSource($"{contract.FullName}.TracingProxy.g.cs",
                SourceText.From(TracingProxyEmitter.Emit(contract), Encoding.UTF8)));
    }
}
