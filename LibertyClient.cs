using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using NSec.Cryptography;

namespace LibertyCS;

public enum ServerOption { Players, Staff, JoinLogs, Queue, KillLogs, CommandLogs, ModCalls, EmergencyCalls, Vehicles }

public sealed record WebhookOptions(string? Id = null, string? Url = null, string? IngestUrl = null, string? PollSubscriptionId = null, string? PollToken = null, string? RelayUrl = null, string? PublicKey = null);
public sealed record WebhookVerificationInput(string? Timestamp, string? Signature, byte[] RawBody, string? PublicKey = null);
public sealed record CustomCommandEvent(string Id, string Command, string Argument, IReadOnlyList<string> Args, string UserId, string ServerId, string Username, JsonElement Raw);
public sealed record CommandContext(CustomCommandEvent Event, Func<string, Task<JsonElement>> Reply, Func<string, Task<JsonElement>> Announce);

public sealed class LibertyClient : IDisposable
{
    private readonly HttpClient _http;
    private readonly bool _ownsClient;
    private readonly string _serverKey;
    private readonly string? _globalApiKey;
    private readonly string _baseUrl;
    private readonly int _retries;
    private readonly string _relayUrl;
    private readonly WebhookOptions _webhookOptions;
    public CommandRouter Commands { get; }
    public WebhookClient Webhook { get; }
    public LibertyClient(string serverKey, string? globalApiKey = null, string apiUrl = "https://api.erlc.gg/v2/", int maxRateLimitRetries = 3, HttpClient? httpClient = null, WebhookOptions? webhook = null)
    {
        if (string.IsNullOrWhiteSpace(serverKey)) throw new ArgumentException("serverKey is required", nameof(serverKey));
        if (maxRateLimitRetries < 0) throw new ArgumentOutOfRangeException(nameof(maxRateLimitRetries));
        _serverKey = serverKey; _globalApiKey = globalApiKey; _baseUrl = apiUrl.TrimEnd('/') + "/"; _retries = maxRateLimitRetries;
        _http = httpClient ?? new HttpClient(); _ownsClient = httpClient is null;
        _webhookOptions = webhook ?? new WebhookOptions();
        if ((_webhookOptions.PollSubscriptionId is null) != (_webhookOptions.PollToken is null)) throw new ArgumentException("PollSubscriptionId and PollToken must be configured together", nameof(webhook));
        _relayUrl = (_webhookOptions.RelayUrl ?? _webhookOptions.Url ?? "https://api.libertytools.dev/").TrimEnd('/') + "/";
        if (_webhookOptions.Url is not null && _webhookOptions.PollSubscriptionId is null && string.IsNullOrWhiteSpace(_webhookOptions.Id)) throw new ArgumentException("Webhook Id is required when Webhook Url is configured", nameof(webhook));
        Webhook = new WebhookClient(this, _webhookOptions, _relayUrl);
        Commands = new CommandRouter(Webhook, SendPrivateServerCommandAsync, GetPrivateServerApiAsync);
    }

    public async Task<JsonElement> GetPrivateServerApiAsync(IEnumerable<ServerOption>? fields = null, CancellationToken cancellationToken = default)
    {
        var query = string.Join("&", (fields ?? []).Select(x => Uri.EscapeDataString(x.ToString()) + "=true").Distinct());
        return await SendAsync(HttpMethod.Get, "server" + (query.Length == 0 ? "" : "?" + query), null, cancellationToken);
    }

    public async Task<JsonElement> SendPrivateServerCommandAsync(IEnumerable<string> commands, CancellationToken cancellationToken = default)
    {
        var results = new List<object>(); var failures = new List<object>(); var successes = 0;
        foreach (var raw in commands)
        {
            var command = raw.Trim();
            if (command.Length == 0) { failures.Add(new { command = raw, error = "Command must be a non-empty string" }); continue; }
            var response = await SendAsync(HttpMethod.Post, "server/command", new { command }, cancellationToken);
            results.Add(new { command, response });
            if (response.ValueKind == JsonValueKind.Object && response.TryGetProperty("error", out _)) failures.Add(new { command, response }); else successes++;
        }
        return JsonSerializer.SerializeToElement(new { successes, failures = failures.Count, failureReasons = failures, results });
    }

    internal async Task<JsonElement> SendAsync(HttpMethod method, string path, object? body, CancellationToken cancellationToken, bool relay = false, string? bearer = null)
    {
        for (var attempt = 0; ; attempt++)
        {
            using var request = new HttpRequestMessage(method, relay ? new Uri(new Uri(_relayUrl), path) : new Uri(new Uri(_baseUrl), path));
            if (!relay) {
                request.Headers.TryAddWithoutValidation("server-key", _serverKey);
                if (_globalApiKey is not null) request.Headers.TryAddWithoutValidation("Authorization", _globalApiKey);
            }
            if (bearer is not null) request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", bearer);
            if (body is not null) request.Content = JsonContent.Create(body);
            HttpResponseMessage response;
            try { response = await _http.SendAsync(request, cancellationToken); }
            catch (HttpRequestException ex) { return JsonSerializer.SerializeToElement(new { error = "network-error", message = ex.Message }); }
            using (response)
            {
                var text = await response.Content.ReadAsStringAsync(cancellationToken);
                JsonElement data; try { data = JsonDocument.Parse(text).RootElement.Clone(); } catch { data = JsonSerializer.SerializeToElement<object?>(null); }
                if (response.StatusCode == HttpStatusCode.TooManyRequests && attempt < _retries)
                {
                    var delay = response.Headers.RetryAfter?.Delta ?? TimeSpan.FromSeconds(1);
                    await Task.Delay(delay < TimeSpan.Zero ? TimeSpan.Zero : delay, cancellationToken); continue;
                }
                if (!response.IsSuccessStatusCode) return JsonSerializer.SerializeToElement(new { error = response.StatusCode == HttpStatusCode.TooManyRequests ? "rate-limited" : "api-error", message = $"HTTP {(int)response.StatusCode}", status = (int)response.StatusCode, apiResponse = data });
                return data;
            }
        }
    }

    public void Dispose() { if (_ownsClient) _http.Dispose(); }
}

public sealed class WebhookClient
{
    private readonly LibertyClient _client;
    private readonly WebhookOptions _options;
    private readonly string _relayUrl;
    public const string DefaultPublicKey = "MCowBQYDK2VwAyEAjSICb9pp0kHizGQtdG8ySWsDChfGqi+gyFCttigBNOA=";
    internal WebhookClient(LibertyClient client, WebhookOptions options, string relayUrl) { _client = client; _options = options; _relayUrl = relayUrl; }
    public string? ErlcUrl => _options.IngestUrl ?? (_options.Id is null ? null : new Uri(new Uri((_options.Url ?? _relayUrl).TrimEnd('/') + "/"), $"webhook/{Uri.EscapeDataString(ExtractId(_options.Id))}").ToString());
    public bool Verify(WebhookVerificationInput input)
    {
        try {
            if (!long.TryParse(input.Timestamp, out var stamp) || Math.Abs(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - (stamp > 10_000_000_000 ? stamp : stamp * 1000)) > 300_000) return false;
            var signature = Convert.FromHexString(input.Signature ?? "");
            var prefix = Convert.FromBase64String(input.PublicKey ?? _options.PublicKey ?? DefaultPublicKey);
            var key = new byte[prefix.Length]; Buffer.BlockCopy(prefix, 0, key, 0, prefix.Length);
            var rawKey = key.AsSpan(key.Length - 32).ToArray();
            var publicKey = PublicKey.Import(SignatureAlgorithm.Ed25519, rawKey, KeyBlobFormat.RawPublicKey);
            var timestamp = Encoding.UTF8.GetBytes(input.Timestamp!);
            var data = new byte[timestamp.Length + input.RawBody.Length];
            Buffer.BlockCopy(timestamp, 0, data, 0, timestamp.Length);
            Buffer.BlockCopy(input.RawBody, 0, data, timestamp.Length, input.RawBody.Length);
            return SignatureAlgorithm.Ed25519.Verify(publicKey, data, signature);
        } catch { return false; }
    }
    public async Task<JsonElement> StatusAsync(CancellationToken cancellationToken = default) => await _client.SendAsync(HttpMethod.Get, "health", null, cancellationToken, relay: true);
    public Task<JsonElement> EventsAsync(string? cursor = null, int? limit = null, CancellationToken cancellationToken = default) => ListEventsAsync(cursor, limit, cancellationToken);
    public async Task<JsonElement> ListEventsAsync(string? cursor = null, int? limit = null, CancellationToken cancellationToken = default)
    {
        if (_options.PollSubscriptionId is null && _options.Id is null) return JsonSerializer.SerializeToElement(new { error = "webhook_disabled" });
        if (limit is < 1 or > 100) throw new ArgumentOutOfRangeException(nameof(limit));
        string path;
        if (_options.PollSubscriptionId is { } sub) { path = $"v1/poll/subscriptions/{Uri.EscapeDataString(sub)}/events"; var q = new List<string>(); if (cursor is not null) q.Add("cursor=" + Uri.EscapeDataString(cursor)); if (limit is not null) q.Add("limit=" + limit); if (q.Count > 0) path += "?" + string.Join("&", q); }
        else path = $"webhook/{Uri.EscapeDataString(ExtractId(_options.Id!))}/events";
        return await _client.SendAsync(HttpMethod.Get, path, null, cancellationToken, relay: true, bearer: _options.PollToken);
    }
    public async Task<JsonElement> AcknowledgeAsync(IEnumerable<string> eventIds, CancellationToken cancellationToken = default)
    {
        if (_options.PollSubscriptionId is null || _options.PollToken is null) return JsonSerializer.SerializeToElement(new { error = "webhook_disabled" });
        return await _client.SendAsync(HttpMethod.Post, $"v1/poll/subscriptions/{Uri.EscapeDataString(_options.PollSubscriptionId)}/events/acknowledge", new { eventIds }, cancellationToken, relay: true, bearer: _options.PollToken);
    }
    internal static string ExtractId(string value) { if (Uri.TryCreate(value, UriKind.Absolute, out var url)) value = url.PathAndQuery.Split('?', '#')[0]; var parts = value.Split('?', '#')[0].TrimEnd('/').Split('/', StringSplitOptions.RemoveEmptyEntries); if (parts.Length > 1 && parts[^1].Equals("events", StringComparison.OrdinalIgnoreCase)) return parts[^2]; return parts.LastOrDefault() ?? ""; }
}

public sealed class CommandRouter
{
    private readonly WebhookClient _webhook;
    private readonly Func<IEnumerable<string>, CancellationToken, Task<JsonElement>> _send;
    private readonly Func<IEnumerable<ServerOption>?, CancellationToken, Task<JsonElement>> _server;
    private readonly Dictionary<string, (Func<CommandContext, Task<object?>> Handler, TimeSpan Cooldown)> _handlers = new();
    private readonly Dictionary<string, DateTimeOffset> _cooldowns = new();
    private readonly HashSet<string> _seen = new();
    private CancellationTokenSource? _cts;
    public bool Running => _cts is { IsCancellationRequested: false };
    internal CommandRouter(WebhookClient webhook, Func<IEnumerable<string>, CancellationToken, Task<JsonElement>> send, Func<IEnumerable<ServerOption>?, CancellationToken, Task<JsonElement>> server) { _webhook = webhook; _send = send; _server = server; }
    public CommandRouter Command(string name, Func<CommandContext, Task<object?>> handler, TimeSpan? cooldown = null) { var key = Normalize(name); if (key.Length == 0 || key.Contains(' ')) throw new ArgumentException("Invalid command name"); _handlers[key] = (handler, cooldown ?? TimeSpan.Zero); return this; }
    public bool Remove(string name) => _handlers.Remove(Normalize(name));
    public async Task<JsonElement> HandleAsync(JsonElement input, CancellationToken cancellationToken = default)
    {
        var ev = Parse(input); if (ev is null) return JsonSerializer.SerializeToElement(new { status = "ignored", reason = "unsupported_event" });
        if (!_seen.Add(ev.Id)) return JsonSerializer.SerializeToElement(new { status = "duplicate", eventId = ev.Id, command = ev.Command });
        if (_seen.Count > 1000) _seen.Remove(_seen.First());
        if (!_handlers.TryGetValue(ev.Command, out var registration)) return JsonSerializer.SerializeToElement(new { status = "unhandled", eventId = ev.Id, command = ev.Command });
        var key = ev.Command + ":" + ev.UserId; var now = DateTimeOffset.UtcNow;
        if (_cooldowns.TryGetValue(key, out var until) && until > now) return JsonSerializer.SerializeToElement(new { status = "cooldown", eventId = ev.Id, command = ev.Command, remaining = (until-now).TotalMilliseconds });
        if (registration.Cooldown > TimeSpan.Zero) _cooldowns[key] = now + registration.Cooldown;
        async Task<JsonElement> Reply(string value) { var msg = Sanitize(value); var players = await _server([ServerOption.Players], cancellationToken); if (!players.TryGetProperty("Players", out var arr) || arr.ValueKind != JsonValueKind.Array) return JsonSerializer.SerializeToElement(new { error = "player_not_found" }); foreach (var p in arr.EnumerateArray()) { var combined = p.TryGetProperty("Player", out var cp) ? cp.ToString() : ""; var uid = p.TryGetProperty("Id", out var id) ? id.ToString() : p.TryGetProperty("id", out id) ? id.ToString() : ""; var username = p.TryGetProperty("Username", out var un) ? un.ToString() : combined.Split(':')[0]; if (uid == ev.UserId && username.All(c => char.IsAsciiLetterOrDigit(c) || c == '_')) return await _send([$":pm {username} {msg}"], cancellationToken); } return JsonSerializer.SerializeToElement(new { error = "player_not_found" }); }
        async Task<JsonElement> Announce(string value) => await _send([$":h {Sanitize(value)}"], cancellationToken);
        try { var value = await registration.Handler(new CommandContext(ev, Reply, Announce)); return JsonSerializer.SerializeToElement(new { status = "handled", eventId = ev.Id, command = ev.Command, value }); }
        catch (Exception ex) { _seen.Remove(ev.Id); _cooldowns.Remove(key); return JsonSerializer.SerializeToElement(new { status = "failed", eventId = ev.Id, command = ev.Command, error = ex.Message }); }
    }
    public async Task<JsonElement> HandleWebhookAsync(WebhookVerificationInput input, CancellationToken cancellationToken = default) { if (!_webhook.Verify(input)) return JsonSerializer.SerializeToElement(new { status = "rejected", reason = "invalid_signature" }); try { return await HandleAsync(JsonDocument.Parse(input.RawBody).RootElement, cancellationToken); } catch { return JsonSerializer.SerializeToElement(new { status = "rejected", reason = "invalid_json" }); } }
    public async Task StartAsync(TimeSpan? pollInterval = null, CancellationToken cancellationToken = default) { if (Running) return; _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken); var interval = pollInterval ?? TimeSpan.FromSeconds(2); if (interval < TimeSpan.FromMilliseconds(100)) throw new ArgumentOutOfRangeException(nameof(pollInterval)); _ = PollLoop(interval, _cts.Token); await Task.CompletedTask; }
    public async Task StopAsync() { if (_cts is null) return; await _cts.CancelAsync(); _cts.Dispose(); _cts = null; }
    private async Task PollLoop(TimeSpan interval, CancellationToken token) { string? cursor = null; while (!token.IsCancellationRequested) { try { var page = await _webhook.ListEventsAsync(cursor, cancellationToken: token); if (page.TryGetProperty("events", out var events) && events.ValueKind == JsonValueKind.Array) { var ids = new List<string>(); foreach (var item in events.EnumerateArray()) { var result = await HandleAsync(item, token); if (result.TryGetProperty("status", out var st) && st.ToString() != "failed" && item.TryGetProperty("id", out var id)) ids.Add(id.ToString()); } if (ids.Count > 0) await _webhook.AcknowledgeAsync(ids, token); cursor = page.TryGetProperty("hasMore", out var more) && more.GetBoolean() && page.TryGetProperty("nextCursor", out var next) ? next.ToString() : null; } } catch when (!token.IsCancellationRequested) { } await Task.Delay(interval, token).ContinueWith(_ => { }, TaskScheduler.Default); } }
    private static CustomCommandEvent? Parse(JsonElement input) { try { var data = input.TryGetProperty("data", out var d) && d.ValueKind == JsonValueKind.Object ? d : input; var type = Get(input, "event", "type") ?? Get(data, "event", "type"); if (!string.Equals(type, "CustomCommand", StringComparison.OrdinalIgnoreCase)) return null; var command = Normalize(Get(input, "command") ?? Get(data, "command") ?? ""); if (command.Length == 0) return null; var arg = Get(input, "argument") ?? Get(data, "argument") ?? ""; var user = Get(input, "userId") ?? Get(data, "userId", "userID") ?? ""; var server = Get(input, "serverId", "server") ?? Get(data, "serverId", "server") ?? ""; var id = Get(input, "id", "_id") ?? Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(input.GetRawText()))); return new(id, command, arg, ParseArgs(arg), user, server, Get(input, "username", "playerName") ?? Get(data, "username", "playerName") ?? "", input.Clone()); } catch { return null; } }
    private static string? Get(JsonElement e, params string[] names) { foreach (var n in names) if (e.ValueKind == JsonValueKind.Object && e.TryGetProperty(n, out var p)) return p.ToString(); return null; }
    private static string Normalize(string s) { s = s.Trim(); if (s.StartsWith(';')) s = s[1..]; return s.ToLowerInvariant(); }
    private static List<string> ParseArgs(string s) { var result = new List<string>(); var token = new StringBuilder(); char quote = '\0'; bool escape = false; foreach (var c in s) { if (escape) { token.Append(c); escape = false; } else if (c == '\\') escape = true; else if (quote != '\0') { if (c == quote) quote = '\0'; else token.Append(c); } else if (c is '\'' or '"') quote = c; else if (char.IsWhiteSpace(c)) { if (token.Length > 0) { result.Add(token.ToString()); token.Clear(); } } else token.Append(c); } if (token.Length > 0) result.Add(token.ToString()); return result; }
    private static string Sanitize(string s) { s = string.Join(' ', s.Replace('\r', ' ').Replace('\n', ' ').Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)); if (s.Length is 0 or > 200) throw new ArgumentException("Message must be 1-200 characters"); return s; }
}
