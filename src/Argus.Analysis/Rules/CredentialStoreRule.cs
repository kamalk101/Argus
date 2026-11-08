namespace Argus.Analysis.Rules;

using Argus.Core.Events;
using Argus.Core.Paths;

/// <summary>
/// F-008: a process read a credential store that does not belong to it.
///
/// The stores are recognised by path shape rather than only by the configuration catalog,
/// because the real locations are user-profile paths and replay deliberately drops
/// environment-dependent catalog entries — a rule that could not be replayed could not be
/// tested. The catalog is still consulted first so a user-configured entry can supply the
/// label.
///
/// The owning program is excluded: Chrome reading its own "Login Data" is the browser
/// working, and the same holds for the SSH client reading its own key. What remains is the
/// shape that matters — some other process opening a browser database, a private key or a
/// wallet file, which is the credential-access pattern (T1555) that precedes account theft
/// rather than any normal application behaviour.
/// </summary>
public sealed class CredentialStoreRule : IEventRule
{
    private sealed record Store(
        string[] PathFragments,
        string Label,
        HashSet<string> Owners);

    /// <summary>
    /// Fragments must appear in the canonical path in order. Owners are the executables for
    /// which reading this store is ordinary work.
    /// </summary>
    private static readonly Store[] Stores =
    [
        new(
            [@"\google\chrome\user data\", @"\login data"],
            "Chrome login data",
            new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "chrome.exe" }),
        new(
            [@"\google\chrome\user data\", @"\web data"],
            "Chrome saved form data",
            new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "chrome.exe" }),
        new(
            [@"\microsoft\edge\user data\", @"\login data"],
            "Edge login data",
            new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "msedge.exe" }),
        new(
            [@"\bravesoftware\brave-browser\user data\", @"\login data"],
            "Brave login data",
            new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "brave.exe" }),
        new(
            [@"\opera software\", @"\login data"],
            "Opera login data",
            new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "opera.exe" }),
        new(
            [@"\mozilla\firefox\profiles\", @"\logins.json"],
            "Firefox logins",
            new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "firefox.exe" }),
        new(
            [@"\mozilla\firefox\profiles\", @"\key4.db"],
            "Firefox key database",
            new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "firefox.exe" }),
        new(
            [@"\.ssh\", "id_rsa"],
            "SSH private key",
            new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "ssh.exe", "ssh-agent.exe", "ssh-keygen.exe", "git.exe", "pageant.exe", "putty.exe", "winscp.exe" }),
        new(
            [@"\.ssh\", "id_ed25519"],
            "SSH private key",
            new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "ssh.exe", "ssh-agent.exe", "ssh-keygen.exe", "git.exe", "pageant.exe", "putty.exe", "winscp.exe" }),
        new(
            [@"\.ssh\", "id_ecdsa"],
            "SSH private key",
            new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "ssh.exe", "ssh-agent.exe", "ssh-keygen.exe", "git.exe", "pageant.exe", "putty.exe", "winscp.exe" }),
        new(
            [@"\microsoft\credentials\"],
            "Windows credential files",
            new HashSet<string>(StringComparer.OrdinalIgnoreCase)),
        new(
            [@"\microsoft\protect\"],
            "DPAPI master keys",
            new HashSet<string>(StringComparer.OrdinalIgnoreCase)),
        new(
            [@"\wallet.dat"],
            "Cryptocurrency wallet",
            new HashSet<string>(StringComparer.OrdinalIgnoreCase)),
        new(
            [@"\electrum\wallets\"],
            "Electrum wallet",
            new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "electrum.exe" }),
    ];

    public RuleMetadata Metadata { get; } = new(
        "F-008",
        "Credential store accessed",
        70,
        EvidenceCategory.File,
        ["T1555"],
        "A process opened a credential store that belongs to another program: browser login data, an SSH private key or a wallet file.",
        BaseConfidence: 0.90);

    public IEnumerable<RuleFinding> Evaluate(RuleContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var current = context.Event;
        if (!IsStoreAccess(current) || string.IsNullOrEmpty(current.PathKey))
        {
            yield break;
        }

        var store = Match(current.PathKey);
        if (store is null)
        {
            yield break;
        }

        var image = context.Processes.ImageNameOf(current.Pid) ?? string.Empty;
        if (ProcessNames.IsOneOf(image, store.Owners))
        {
            // The program the store belongs to is doing its job.
            yield break;
        }

        // The catalog can carry a user-specific label for the same location.
        var label = context.Catalog.TryMatch(current.PathKey, out var entry)
            && string.Equals(entry.Group, "credentials", StringComparison.OrdinalIgnoreCase)
            ? entry.Label
            : store.Label;

        var reader = ProcessNames.Display(image);
        if (reader.Length == 0)
        {
            reader = "a process whose image name was not captured";
        }

        var operation = current.Kind == EventKind.FileRead ? "read" : "opened";

        yield return new RuleFinding
        {
            Rule = Metadata,
            Reason = $"{reader} {operation} the {label} store at \"{current.Target}\", which is not its own data. Reading another program's credential store is how saved passwords, private keys and wallets are taken.",
            Counterfactual = $"Would not fire for the owning program ({string.Join(", ", store.Owners.DefaultIfEmpty("none recorded"))}) reading its own store, and does not fire for writes to these paths or for reads outside the recognised store locations.",
            Factors =
            [
                $"store={label}",
                $"reader={ProcessNames.Display(image)}",
                $"operation={operation}",
                $"path={current.PathKey}",
                $"evidence={FileChangeEvidence.Evidence(current)}",
            ],
            TargetPid = current.Pid,
            GroupPid = current.Pid,
            Target = current.Target,
        };
    }

    /// <summary>
    /// Access means the store's content was reachable: a read, or an open of the existing
    /// file. A create with content is a write and belongs to the write rules.
    /// </summary>
    private static bool IsStoreAccess(BehaviorEvent behaviorEvent) =>
        behaviorEvent.Kind switch
        {
            EventKind.FileRead => true,
            EventKind.FileCreate => behaviorEvent.FileEffect == FileEffect.Opened,
            _ => false,
        };

    /// <summary>Recognises a store by path shape; returns null for everything else.</summary>
    internal static StoreLabel? Match(string pathKey)
    {
        var path = PathKey.Canonicalize(pathKey);

        foreach (var store in Stores)
        {
            if (!ContainsInOrder(path, store.PathFragments))
            {
                continue;
            }

            return new StoreLabel(store.Label, store.Owners);
        }

        return null;
    }

    private static bool ContainsInOrder(string path, string[] fragments)
    {
        var index = 0;
        foreach (var fragment in fragments)
        {
            var found = path.IndexOf(fragment, index, StringComparison.OrdinalIgnoreCase);
            if (found < 0)
            {
                return false;
            }

            index = found + fragment.Length;
        }

        return true;
    }

    /// <summary>What a path was recognised as, for tests and reason text.</summary>
    public sealed record StoreLabel(string Label, IReadOnlySet<string> Owners);
}
