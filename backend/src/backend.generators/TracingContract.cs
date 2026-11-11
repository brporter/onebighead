using System.Collections.Generic;
using System.Linq;
using Microsoft.CodeAnalysis;

namespace OneBigHead.Generators;

/// <summary>Extracts the method contract independently of generated source formatting.</summary>
internal sealed class TracingContract
{
    public string Name { get; private set; } = "";
    public string Namespace { get; private set; } = "";
    public string FullName { get; private set; } = "";
    public IReadOnlyList<TracingMethod> Methods { get; private set; } = new List<TracingMethod>();

    public static TracingContract From(INamedTypeSymbol symbol) => new()
    {
        Name = symbol.Name,
        Namespace = symbol.ContainingNamespace.IsGlobalNamespace ? "" : symbol.ContainingNamespace.ToDisplayString(),
        FullName = symbol.ToDisplayString(),
        Methods = symbol.GetMembers().Concat(symbol.AllInterfaces.SelectMany(parent => parent.GetMembers()))
            .OfType<IMethodSymbol>().Where(method => method.MethodKind == MethodKind.Ordinary)
            .GroupBy(method => method.Name + "(" + string.Join(",", method.Parameters.Select(p => p.Type.ToDisplayString())) + ")")
            .Select(group => Extract(group.First())).ToList()
    };

    private static TracingMethod Extract(IMethodSymbol method) => new()
    {
        Name = method.Name,
        ReturnType = method.ReturnType.ToDisplayString(),
        ReturnKind = ClassifyReturn(method.ReturnType),
        Parameters = method.Parameters.Select(parameter => new TracingParameter
        {
            Name = parameter.Name, Type = parameter.Type.ToDisplayString(), IsTaggable = IsTaggable(parameter.Type)
        }).ToList()
    };

    private static TracingReturnKind ClassifyReturn(ITypeSymbol type)
    {
        if (type.SpecialType == SpecialType.System_Void) return TracingReturnKind.Void;
        var name = type.ToDisplayString();
        if (name == "System.Threading.Tasks.Task") return TracingReturnKind.Task;
        if (name == "System.Threading.Tasks.ValueTask") return TracingReturnKind.ValueTask;
        if (type is INamedTypeSymbol named && named.IsGenericType)
        {
            var definition = named.OriginalDefinition.ToDisplayString();
            if (definition == "System.Threading.Tasks.Task<TResult>") return TracingReturnKind.TaskOfT;
            if (definition == "System.Threading.Tasks.ValueTask<TResult>") return TracingReturnKind.ValueTaskOfT;
        }
        return TracingReturnKind.Sync;
    }

    private static bool IsTaggable(ITypeSymbol type)
    {
        switch (type.SpecialType)
        {
            case SpecialType.System_Boolean:
            case SpecialType.System_Byte:
            case SpecialType.System_SByte:
            case SpecialType.System_Char:
            case SpecialType.System_Int16:
            case SpecialType.System_UInt16:
            case SpecialType.System_Int32:
            case SpecialType.System_UInt32:
            case SpecialType.System_Int64:
            case SpecialType.System_UInt64:
            case SpecialType.System_Single:
            case SpecialType.System_Double:
            case SpecialType.System_Decimal:
            case SpecialType.System_String:
                return true;
        }
        return type.TypeKind == TypeKind.Enum || type.ToDisplayString() == "System.Guid";
    }
}

internal sealed class TracingMethod
{
    public string Name { get; set; } = "";
    public string ReturnType { get; set; } = "";
    public TracingReturnKind ReturnKind { get; set; }
    public IReadOnlyList<TracingParameter> Parameters { get; set; } = new List<TracingParameter>();
}

internal sealed class TracingParameter
{
    public string Name { get; set; } = "";
    public string Type { get; set; } = "";
    public bool IsTaggable { get; set; }
}

internal enum TracingReturnKind { Void, Task, TaskOfT, ValueTask, ValueTaskOfT, Sync }
