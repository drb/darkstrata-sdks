#if NETSTANDARD2_0
// Polyfill for init-only setters in .NET Standard 2.0
// This enables the use of 'init' accessors which were introduced in C# 9
namespace System.Runtime.CompilerServices
{
    internal static class IsExternalInit { }
}
#endif
