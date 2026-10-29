# LibertyCS

**LibertyCS** is a native .NET client for ER:LC Private Server API v2. Current scope: server queries and sequential commands. Target: .NET 8 or later. Install from NuGet with `dotnet add package LibertyTools.LibertyCS`.

```csharp
using LibertyCS;

using var erlc = new LibertyClient(Environment.GetEnvironmentVariable("ERLC_SERVER_KEY")!);
var server = await erlc.GetPrivateServerApiAsync([ServerOption.Players, ServerOption.Staff]);
Console.WriteLine(server);
```

Run `dotnet build`. API payloads are unvalidated JSON. See the root README for unimplemented parity features.
