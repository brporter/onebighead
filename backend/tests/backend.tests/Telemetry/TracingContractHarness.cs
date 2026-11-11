using System.Diagnostics;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.ExceptionServices;
using OneBigHead.Server.Telemetry;

namespace OneBigHead.Server.Tests.Telemetry;

/// <summary>An opaque service double: only forwarding and tracing behavior is under test.</summary>
public class RecordingService : DispatchProxy
{
    public Func<MethodInfo, object?[], object?> Handle { get; set; } = null!;
    protected override object? Invoke(MethodInfo? method, object?[]? arguments) => Handle(method!, arguments!);
}

internal static class TracingContractHarness
{
    public static IEnumerable<MethodInfo> Methods(Type contract) => contract.GetInterfaces().Append(contract)
        .SelectMany(type => type.GetMethods()).Where(method => !method.IsSpecialName)
        .DistinctBy(Signature);

    public static string Signature(MethodInfo method) => method.Name + "(" + string.Join(",", method.GetParameters().Select(p => p.ParameterType.FullName)) + ")";

    public static async Task Verify(Type contract, MethodInfo method, bool enabled, bool fail)
    {
        using var source = new ActivitySource($"TracingContracts.{Guid.NewGuid()}");
        var stopped = new List<Activity>();
        using var listener = Listen(source, enabled, stopped);
        var inner = (RecordingService)DispatchProxy.Create(contract, typeof(RecordingService));
        var parameters = method.GetParameters();
        var arguments = parameters.Select((parameter, index) => Value(parameter.ParameterType, index + 1)).ToArray();
        var resultType = ResultType(method.ReturnType);
        var expected = resultType is null ? null : Value(resultType, 99);
        var failure = new InvalidOperationException("Service failure must survive decoration");
        var calls = 0;
        inner.Handle = (called, received) =>
        {
            calls++;
            Assert.Equal(Signature(method), Signature(called));
            Assert.Equal(arguments, received);
            if (enabled) Assert.Equal(contract.Name + "." + method.Name, Activity.Current!.OperationName);
            if (fail) throw failure;
            return Wrap(method.ReturnType, expected);
        };
        var proxyType = contract.Assembly.GetType(ProxyName(contract), throwOnError: true)!;
        var proxy = Activator.CreateInstance(proxyType, inner, source)!;
        var proxyMethod = proxyType.GetMethod(method.Name, parameters.Select(p => p.ParameterType).ToArray())!;
        if (fail) Assert.Same(failure, await Assert.ThrowsAsync<InvalidOperationException>(() => Invoke(proxyMethod, proxy, arguments)));
        else
        {
            var actual = await Invoke(proxyMethod, proxy, arguments);
            if (resultType?.IsValueType == true) Assert.Equal(expected, actual);
            else Assert.Same(expected, actual);
        }
        Assert.Equal(1, calls);
        if (!enabled) { Assert.Empty(stopped); return; }
        var activity = Assert.Single(stopped);
        Assert.Equal(ActivityKind.Internal, activity.Kind);
        Assert.Equal(method.Name, activity.GetTagItem("code.function"));
        Assert.Equal(contract.FullName, activity.GetTagItem("code.namespace"));
        Assert.Equal(fail ? ActivityStatusCode.Error : ActivityStatusCode.Ok, activity.Status);
        if (fail)
        {
            Assert.Equal(failure.Message, activity.StatusDescription);
            var exception = Assert.Single(activity.Events);
            Assert.Equal("exception", exception.Name);
            Assert.Contains(exception.Tags, tag => tag.Key == "exception.message" && Equals(tag.Value, failure.Message));
        }
        else Assert.Empty(activity.Events);
        var scalarValues = parameters.Select((parameter, index) => (parameter, value: arguments[index]))
            .Where(entry => IsScalar(entry.parameter.ParameterType)).Select(entry => entry.value).ToArray();
        var parameterTags = activity.TagObjects.Where(tag => !tag.Key.StartsWith("code.", StringComparison.Ordinal)).ToArray();
        Assert.Equal(scalarValues.Length, parameterTags.Length);
        Assert.Equal(scalarValues, parameterTags.Select(tag => tag.Value));
    }

    public static ActivityListener Listen(ActivitySource source, bool enabled, List<Activity> stopped)
    {
        var listener = new ActivityListener
        {
            ShouldListenTo = candidate => enabled && ReferenceEquals(candidate, source),
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = stopped.Add
        };
        ActivitySource.AddActivityListener(listener);
        return listener;
    }

    public static string ProxyName(Type contract) => (contract.Namespace is null ? "" : contract.Namespace + ".") + "TracingProxy_" + contract.Name;

    public static async Task<object?> Invoke(MethodInfo method, object instance, object?[] arguments)
    {
        object? result;
        try { result = method.Invoke(instance, arguments); }
        catch (TargetInvocationException exception) { ExceptionDispatchInfo.Capture(exception.InnerException!).Throw(); throw; }
        if (method.ReturnType == typeof(ValueTask)) { await (ValueTask)result!; return null; }
        if (method.ReturnType.IsGenericType && method.ReturnType.GetGenericTypeDefinition() == typeof(ValueTask<>))
            result = method.ReturnType.GetMethod("AsTask")!.Invoke(result, null);
        if (result is Task task)
        {
            await task;
            return ResultType(method.ReturnType) is null ? null : task.GetType().GetProperty("Result")!.GetValue(task);
        }
        return result;
    }

    public static Type? ResultType(Type type) => type == typeof(void) || type == typeof(Task) || type == typeof(ValueTask)
        ? null : type.IsGenericType && (type.GetGenericTypeDefinition() == typeof(Task<>) || type.GetGenericTypeDefinition() == typeof(ValueTask<>))
            ? type.GenericTypeArguments[0] : type;

    public static object? Wrap(Type type, object? value)
    {
        if (type == typeof(Task)) return Task.CompletedTask;
        if (type == typeof(ValueTask)) return ValueTask.CompletedTask;
        if (type.IsGenericType && type.GetGenericTypeDefinition() == typeof(Task<>))
            return typeof(Task).GetMethod(nameof(Task.FromResult))!.MakeGenericMethod(type.GenericTypeArguments).Invoke(null, [value]);
        if (type.IsGenericType && type.GetGenericTypeDefinition() == typeof(ValueTask<>)) return Activator.CreateInstance(type, value);
        return value;
    }

    private static bool IsScalar(Type type) => type.IsPrimitive || type.IsEnum || type == typeof(string) || type == typeof(decimal) || type == typeof(Guid);

    private static object Value(Type type, int seed)
    {
        if (Nullable.GetUnderlyingType(type) is { } underlying) return Value(underlying, seed);
        if (type == typeof(string)) return $"argument-{seed}";
        if (type == typeof(bool)) return true;
        if (type == typeof(char)) return 'x';
        if (type.IsPrimitive || type == typeof(decimal)) return Convert.ChangeType(seed, type);
        if (type == typeof(Guid)) return Guid.NewGuid();
        if (type == typeof(CancellationToken)) return new CancellationToken(canceled: true);
        if (type.IsEnum) return Enum.GetValues(type).GetValue(Enum.GetValues(type).Length - 1)!;
        if (typeof(Stream).IsAssignableFrom(type)) return new MemoryStream([1, 2, 3]);
        if (type.IsArray) return Array.CreateInstance(type.GetElementType()!, 1);
        if (type.IsGenericType && type.GetGenericTypeDefinition().FullName!.StartsWith("System.ValueTuple", StringComparison.Ordinal))
            return Activator.CreateInstance(type, type.GenericTypeArguments.Select(t => Value(t, seed)).ToArray())!;
        if (type.IsInterface)
        {
            var generic = type.GenericTypeArguments;
            if (generic.Length == 1) return Array.CreateInstance(generic[0], 1);
            throw new InvalidOperationException($"Add an explicit opaque sample for {type}");
        }
        // These DTOs/entities are never inspected by the decorator. A unique
        // reference proves pass-through without depending on domain constructors.
        return RuntimeHelpers.GetUninitializedObject(type);
    }
}
