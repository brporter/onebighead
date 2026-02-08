using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Text;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Text;

namespace OneBigHead.Generators;

[Generator]
public class TracingProxyGenerator : IIncrementalGenerator
{
    private const string AttributeName = "GenerateTracingProxy";
    private const string AttributeFullName = "OneBigHead.Server.Telemetry.GenerateTracingProxyAttribute";

    public void Initialize(IncrementalGeneratorInitializationContext context)
    {
        var interfaceDeclarations = context.SyntaxProvider
            .CreateSyntaxProvider(
                predicate: static (node, _) => IsInterfaceWithAttribute(node),
                transform: static (ctx, _) => GetInterfaceInfo(ctx))
            .Where(static info => info is not null)
            .Select(static (info, _) => info!);

        context.RegisterSourceOutput(interfaceDeclarations, static (spc, info) =>
        {
            var source = GenerateProxy(info);
            spc.AddSource($"TracingProxy_{info.InterfaceName}.g.cs", SourceText.From(source, Encoding.UTF8));
        });
    }

    private static bool IsInterfaceWithAttribute(SyntaxNode node)
    {
        return node is InterfaceDeclarationSyntax ids && ids.AttributeLists.Count > 0;
    }

    private static InterfaceInfo? GetInterfaceInfo(GeneratorSyntaxContext context)
    {
        var interfaceSyntax = (InterfaceDeclarationSyntax)context.Node;
        var symbol = context.SemanticModel.GetDeclaredSymbol(interfaceSyntax);
        if (symbol is null) return null;

        var hasAttribute = symbol.GetAttributes().Any(a =>
            a.AttributeClass?.ToDisplayString() == AttributeFullName);

        if (!hasAttribute) return null;

        var methods = new List<MethodInfo>();
        CollectMethods(symbol, methods, context.SemanticModel.Compilation);

        return new InterfaceInfo
        {
            InterfaceName = symbol.Name,
            Namespace = symbol.ContainingNamespace.ToDisplayString(),
            FullName = symbol.ToDisplayString(),
            Methods = methods
        };
    }

    private static void CollectMethods(INamedTypeSymbol interfaceSymbol, List<MethodInfo> methods, Compilation compilation)
    {
        foreach (var member in interfaceSymbol.GetMembers())
        {
            if (member is IMethodSymbol method && method.MethodKind == MethodKind.Ordinary)
            {
                methods.Add(ExtractMethodInfo(method));
            }
        }

        // Include inherited interface methods
        foreach (var baseInterface in interfaceSymbol.AllInterfaces)
        {
            foreach (var member in baseInterface.GetMembers())
            {
                if (member is IMethodSymbol method && method.MethodKind == MethodKind.Ordinary)
                {
                    // Avoid duplicates
                    if (!methods.Any(m => m.Name == method.Name && m.Parameters.Count == method.Parameters.Length))
                    {
                        methods.Add(ExtractMethodInfo(method));
                    }
                }
            }
        }
    }

    private static MethodInfo ExtractMethodInfo(IMethodSymbol method)
    {
        var returnType = method.ReturnType.ToDisplayString();
        var returnKind = ClassifyReturnType(method.ReturnType);

        var parameters = method.Parameters.Select(p => new ParameterInfo
        {
            Name = p.Name,
            Type = p.Type.ToDisplayString(),
            IsTaggable = IsTaggableType(p.Type)
        }).ToList();

        return new MethodInfo
        {
            Name = method.Name,
            ReturnType = returnType,
            ReturnKind = returnKind,
            Parameters = parameters,
            InnerReturnType = GetInnerReturnType(method.ReturnType)
        };
    }

    private static ReturnKind ClassifyReturnType(ITypeSymbol returnType)
    {
        if (returnType.SpecialType == SpecialType.System_Void)
            return ReturnKind.Void;

        var displayString = returnType.ToDisplayString();

        if (displayString == "System.Threading.Tasks.Task" || displayString == "global::System.Threading.Tasks.Task")
            return ReturnKind.Task;

        if (returnType is INamedTypeSymbol named && named.IsGenericType)
        {
            var originalDef = named.OriginalDefinition.ToDisplayString();
            if (originalDef == "System.Threading.Tasks.Task<TResult>")
                return ReturnKind.TaskOfT;
            if (originalDef == "System.Threading.Tasks.ValueTask<TResult>")
                return ReturnKind.ValueTaskOfT;
        }

        if (displayString == "System.Threading.Tasks.ValueTask")
            return ReturnKind.ValueTask;

        return ReturnKind.Sync;
    }

    private static string? GetInnerReturnType(ITypeSymbol returnType)
    {
        if (returnType is INamedTypeSymbol named && named.IsGenericType && named.TypeArguments.Length == 1)
        {
            var originalDef = named.OriginalDefinition.ToDisplayString();
            if (originalDef == "System.Threading.Tasks.Task<TResult>" ||
                originalDef == "System.Threading.Tasks.ValueTask<TResult>")
            {
                return named.TypeArguments[0].ToDisplayString();
            }
        }
        return null;
    }

    private static bool IsTaggableType(ITypeSymbol type)
    {
        // Only tag simple value types: int, long, string, Guid, bool, enum
        switch (type.SpecialType)
        {
            case SpecialType.System_Int32:
            case SpecialType.System_Int64:
            case SpecialType.System_String:
            case SpecialType.System_Boolean:
                return true;
        }

        if (type.TypeKind == TypeKind.Enum)
            return true;

        if (type.ToDisplayString() == "System.Guid")
            return true;

        return false;
    }

    private static string GetTagName(string parameterName)
    {
        return parameterName switch
        {
            "workspaceId" => "obh.workspace_id",
            "collectionId" => "obh.collection_id",
            "categoryId" => "obh.category_id",
            "itemId" => "obh.item_id",
            "templateId" => "obh.template_id",
            "userId" => "obh.user_id",
            "requestId" => "obh.request_id",
            "id" => "obh.entity_id",
            _ => $"obh.{ToSnakeCase(parameterName)}"
        };
    }

    private static string ToSnakeCase(string name)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < name.Length; i++)
        {
            var c = name[i];
            if (char.IsUpper(c) && i > 0)
            {
                sb.Append('_');
            }
            sb.Append(char.ToLowerInvariant(c));
        }
        return sb.ToString();
    }

    private static string GenerateProxy(InterfaceInfo info)
    {
        var sb = new StringBuilder();
        sb.AppendLine("// <auto-generated />");
        sb.AppendLine("#nullable enable");
        sb.AppendLine();
        sb.AppendLine("using System.Diagnostics;");
        sb.AppendLine();
        sb.AppendLine($"namespace {info.Namespace};");
        sb.AppendLine();
        sb.AppendLine($"public class TracingProxy_{info.InterfaceName} : {info.InterfaceName}");
        sb.AppendLine("{");
        sb.AppendLine($"    private readonly {info.InterfaceName} _inner;");
        sb.AppendLine("    private readonly ActivitySource _activitySource;");
        sb.AppendLine();
        sb.AppendLine($"    public TracingProxy_{info.InterfaceName}({info.InterfaceName} inner, ActivitySource activitySource)");
        sb.AppendLine("    {");
        sb.AppendLine("        _inner = inner;");
        sb.AppendLine("        _activitySource = activitySource;");
        sb.AppendLine("    }");

        foreach (var method in info.Methods)
        {
            sb.AppendLine();
            GenerateMethod(sb, info, method);
        }

        sb.AppendLine("}");
        return sb.ToString();
    }

    private static void GenerateMethod(StringBuilder sb, InterfaceInfo info, MethodInfo method)
    {
        var paramList = string.Join(", ", method.Parameters.Select(p => $"{p.Type} {p.Name}"));
        var argList = string.Join(", ", method.Parameters.Select(p => p.Name));
        var activityName = $"{info.InterfaceName}.{method.Name}";

        switch (method.ReturnKind)
        {
            case ReturnKind.TaskOfT:
                sb.AppendLine($"    public async {method.ReturnType} {method.Name}({paramList})");
                sb.AppendLine("    {");
                EmitActivityStart(sb, activityName, info, method);
                sb.AppendLine("        try");
                sb.AppendLine("        {");
                sb.AppendLine($"            var result = await _inner.{method.Name}({argList});");
                sb.AppendLine("            activity?.SetStatus(ActivityStatusCode.Ok);");
                sb.AppendLine("            return result;");
                sb.AppendLine("        }");
                EmitCatch(sb);
                sb.AppendLine("    }");
                break;

            case ReturnKind.Task:
                sb.AppendLine($"    public async {method.ReturnType} {method.Name}({paramList})");
                sb.AppendLine("    {");
                EmitActivityStart(sb, activityName, info, method);
                sb.AppendLine("        try");
                sb.AppendLine("        {");
                sb.AppendLine($"            await _inner.{method.Name}({argList});");
                sb.AppendLine("            activity?.SetStatus(ActivityStatusCode.Ok);");
                sb.AppendLine("        }");
                EmitCatch(sb);
                sb.AppendLine("    }");
                break;

            case ReturnKind.ValueTaskOfT:
                sb.AppendLine($"    public async {method.ReturnType} {method.Name}({paramList})");
                sb.AppendLine("    {");
                EmitActivityStart(sb, activityName, info, method);
                sb.AppendLine("        try");
                sb.AppendLine("        {");
                sb.AppendLine($"            var result = await _inner.{method.Name}({argList});");
                sb.AppendLine("            activity?.SetStatus(ActivityStatusCode.Ok);");
                sb.AppendLine("            return result;");
                sb.AppendLine("        }");
                EmitCatch(sb);
                sb.AppendLine("    }");
                break;

            case ReturnKind.ValueTask:
                sb.AppendLine($"    public async {method.ReturnType} {method.Name}({paramList})");
                sb.AppendLine("    {");
                EmitActivityStart(sb, activityName, info, method);
                sb.AppendLine("        try");
                sb.AppendLine("        {");
                sb.AppendLine($"            await _inner.{method.Name}({argList});");
                sb.AppendLine("            activity?.SetStatus(ActivityStatusCode.Ok);");
                sb.AppendLine("        }");
                EmitCatch(sb);
                sb.AppendLine("    }");
                break;

            case ReturnKind.Void:
                sb.AppendLine($"    public void {method.Name}({paramList})");
                sb.AppendLine("    {");
                EmitActivityStart(sb, activityName, info, method);
                sb.AppendLine("        try");
                sb.AppendLine("        {");
                sb.AppendLine($"            _inner.{method.Name}({argList});");
                sb.AppendLine("            activity?.SetStatus(ActivityStatusCode.Ok);");
                sb.AppendLine("        }");
                EmitCatch(sb);
                sb.AppendLine("    }");
                break;

            case ReturnKind.Sync:
                sb.AppendLine($"    public {method.ReturnType} {method.Name}({paramList})");
                sb.AppendLine("    {");
                EmitActivityStart(sb, activityName, info, method);
                sb.AppendLine("        try");
                sb.AppendLine("        {");
                sb.AppendLine($"            var result = _inner.{method.Name}({argList});");
                sb.AppendLine("            activity?.SetStatus(ActivityStatusCode.Ok);");
                sb.AppendLine("            return result;");
                sb.AppendLine("        }");
                EmitCatch(sb);
                sb.AppendLine("    }");
                break;
        }
    }

    private static void EmitActivityStart(StringBuilder sb, string activityName, InterfaceInfo info, MethodInfo method)
    {
        sb.AppendLine($"        using var activity = _activitySource.StartActivity(\"{activityName}\", ActivityKind.Internal);");
        sb.AppendLine($"        activity?.SetTag(\"code.function\", \"{method.Name}\");");
        sb.AppendLine($"        activity?.SetTag(\"code.namespace\", \"{info.FullName}\");");

        foreach (var param in method.Parameters.Where(p => p.IsTaggable))
        {
            var tagName = GetTagName(param.Name);
            sb.AppendLine($"        activity?.SetTag(\"{tagName}\", {param.Name});");
        }
    }

    private static void EmitCatch(StringBuilder sb)
    {
        sb.AppendLine("        catch (Exception ex)");
        sb.AppendLine("        {");
        sb.AppendLine("            activity?.SetStatus(ActivityStatusCode.Error, ex.Message);");
        sb.AppendLine("            activity?.AddException(ex);");
        sb.AppendLine("            throw;");
        sb.AppendLine("        }");
    }

    private class InterfaceInfo
    {
        public string InterfaceName { get; set; } = "";
        public string Namespace { get; set; } = "";
        public string FullName { get; set; } = "";
        public List<MethodInfo> Methods { get; set; } = new();
    }

    private class MethodInfo
    {
        public string Name { get; set; } = "";
        public string ReturnType { get; set; } = "";
        public ReturnKind ReturnKind { get; set; }
        public string? InnerReturnType { get; set; }
        public List<ParameterInfo> Parameters { get; set; } = new();
    }

    private class ParameterInfo
    {
        public string Name { get; set; } = "";
        public string Type { get; set; } = "";
        public bool IsTaggable { get; set; }
    }

    private enum ReturnKind
    {
        Void,
        Task,
        TaskOfT,
        ValueTask,
        ValueTaskOfT,
        Sync
    }
}
