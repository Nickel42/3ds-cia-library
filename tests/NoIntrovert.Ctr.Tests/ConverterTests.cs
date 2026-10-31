using NoIntrovert.Ctr.Keys;
using NoIntrovert.Ctr.Operations;
using Xunit;

namespace NoIntrovert.Ctr.Tests;

public class ConverterTests
{
    private static CtrConverter Converter(CtrKeyStore? keys = null) => new(keys ?? Fixtures.Keys());

    private static void AssertMatchesReference(string outputPath, string expectedName, CtrOperationResult result)
    {
        string expected = Fixtures.ExpectedSha256(expectedName);
        Assert.Equal(expected, Fixtures.Sha256OfFile(outputPath));
        Assert.NotNull(result.OutputHashes);
        Assert.Equal(expected, result.OutputHashes!.Sha256);
        var e = Fixtures.Expected(expectedName);
        Assert.Equal(e.GetProperty("crc32").GetString(), result.OutputHashes.Crc32);
        Assert.Equal(e.GetProperty("sha1").GetString(), result.OutputHashes.Sha1);
        Assert.Equal(e.GetProperty("size").GetInt64(), result.OutputHashes.Size);
    }

    [Fact]
    public async Task Decrypt_Cci_MatchesReference()
    {
        using var tmp = new TempDir();
        string output = tmp.File("a.3ds");
        var r = await Converter().DecryptAsync(Fixtures.File("game_a.3ds"), output);
        AssertMatchesReference(output, "game_a.decrypted.3ds", r);
        Assert.Equal(CtrFileType.Cci, r.OutputType);
    }

    [Fact]
    public async Task Decrypt_Cia_MatchesReference()
    {
        using var tmp = new TempDir();
        string output = tmp.File("b.cia");
        var r = await Converter().DecryptAsync(Fixtures.File("game_b.cia"), output);
        AssertMatchesReference(output, "game_b.decrypted.cia", r);
    }

    [Theory]
    [InlineData("system_fixed.cxi", "system_fixed.decrypted.cxi")]
    [InlineData("zero_fixed.cxi", "zero_fixed.decrypted.cxi")]
    public async Task Decrypt_FixedKeyNcch_MatchesReference(string input, string expected)
    {
        using var tmp = new TempDir();
        string output = tmp.File("out.cxi");
        var r = await Converter().DecryptAsync(Fixtures.File(input), output);
        AssertMatchesReference(output, expected, r);
    }

    [Fact]
    public async Task CciToCia_Decrypted_MatchesReference()
    {
        using var tmp = new TempDir();
        string output = tmp.File("a.cia");
        var r = await Converter().ConvertAsync(Fixtures.File("game_a.3ds"), output, CtrOutputFormat.Cia);
        AssertMatchesReference(output, "game_a.cia", r);
    }

    [Fact]
    public async Task CciToCia_KeepEncryption_MatchesReference()
    {
        using var tmp = new TempDir();
        string output = tmp.File("a.cia");
        var r = await Converter().ConvertAsync(Fixtures.File("game_a.3ds"), output, CtrOutputFormat.Cia,
            new CtrConvertOptions { Decrypt = false });
        AssertMatchesReference(output, "game_a.keepenc.cia", r);
    }

    [Fact]
    public async Task CciToCia_WithoutCertificates_WarnsAndMatchesReference()
    {
        using var tmp = new TempDir();
        string output = tmp.File("a.cia");
        var r = await Converter(Fixtures.Keys(certs: false)).ConvertAsync(Fixtures.File("game_a.3ds"), output, CtrOutputFormat.Cia);
        AssertMatchesReference(output, "game_a.nocert.cia", r);
        Assert.Contains(r.Warnings, w => w.Contains("certificate", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task CiaToCci_Decrypted_MatchesReference()
    {
        using var tmp = new TempDir();
        string output = tmp.File("b.3ds");
        var r = await Converter().ConvertAsync(Fixtures.File("game_b.cia"), output, CtrOutputFormat.Cci);
        AssertMatchesReference(output, "game_b.3ds", r);
    }

    [Fact]
    public async Task CiaToCci_KeepEncryption_MatchesReference()
    {
        using var tmp = new TempDir();
        string output = tmp.File("b.3ds");
        var r = await Converter().ConvertAsync(Fixtures.File("game_b.cia"), output, CtrOutputFormat.Cci,
            new CtrConvertOptions { Decrypt = false });
        AssertMatchesReference(output, "game_b.keepenc.3ds", r);
    }

    [Fact]
    public async Task CiaToCci_Untrimmed_MatchesReferenceHash()
    {
        using var tmp = new TempDir();
        string output = tmp.File("b.3ds");
        var r = await Converter().ConvertAsync(Fixtures.File("game_b.cia"), output, CtrOutputFormat.Cci,
            new CtrConvertOptions { Trim = false });
        Assert.Equal(Fixtures.ExpectedSha256("game_b.untrimmed.3ds"), r.OutputHashes!.Sha256);
        Assert.Equal(128L * 1024 * 1024, new FileInfo(output).Length);
    }

    [Fact]
    public async Task UntrimThenTrim_RoundTrips()
    {
        using var tmp = new TempDir();
        var conv = Converter();
        string untrimmed = tmp.File("full.3ds");
        string trimmed = tmp.File("trim.3ds");
        var r1 = await conv.UntrimAsync(Fixtures.File("game_a.3ds"), untrimmed);
        Assert.Equal(Fixtures.ExpectedSha256("game_a.untrimmed.3ds"), r1.OutputHashes!.Sha256);
        await conv.TrimAsync(untrimmed, trimmed);
        Assert.Equal(Fixtures.Sha256OfFile(Fixtures.File("game_a.3ds")), Fixtures.Sha256OfFile(trimmed));
    }

    [Fact]
    public async Task CciToCci_DecryptsAndTrims()
    {
        using var tmp = new TempDir();
        string output = tmp.File("a.3ds");
        var r = await Converter().ConvertAsync(Fixtures.File("game_a.3ds"), output, CtrOutputFormat.Cci);
        AssertMatchesReference(output, "game_a.decrypted.3ds", r);
    }

    [Fact]
    public async Task RoundTrip_CciToCiaToCci_PreservesPartitions()
    {
        using var tmp = new TempDir();
        var conv = Converter();
        string cia = tmp.File("a.cia");
        string cci = tmp.File("a2.3ds");
        await conv.ConvertAsync(Fixtures.File("game_a.3ds"), cia, CtrOutputFormat.Cia);
        await conv.ConvertAsync(cia, cci, CtrOutputFormat.Cci);
        // partitions are identical to a decrypted copy of the original (headers may differ)
        byte[] a = File.ReadAllBytes(Fixtures.File("expected/game_a.decrypted.3ds"));
        byte[] b = File.ReadAllBytes(cci);
        Assert.Equal(a.Length, b.Length);
        Assert.True(a.AsSpan(0x4000).SequenceEqual(b.AsSpan(0x4000)));
    }

    [Fact]
    public async Task MissingKeys_Throw()
    {
        using var tmp = new TempDir();
        var conv = new CtrConverter(new CtrKeyStore());
        await Assert.ThrowsAsync<MissingKeyException>(() => conv.DecryptAsync(Fixtures.File("game_a.3ds"), tmp.File("x.3ds")));
        Assert.False(File.Exists(tmp.File("x.3ds")));
        Assert.Empty(Directory.GetFiles(tmp.Path)); // temp file cleaned up
    }

    [Fact]
    public async Task MissingSeed_ThrowsWithSeedKeyName()
    {
        using var tmp = new TempDir();
        var conv = new CtrConverter(Fixtures.Keys(seeds: false));
        var ex = await Assert.ThrowsAsync<MissingKeyException>(() => conv.DecryptAsync(Fixtures.File("game_b.cia"), tmp.File("x.cia")));
        Assert.StartsWith("seed:", ex.KeyName);
    }

    [Fact]
    public async Task ExistingOutput_IsNotOverwrittenByDefault()
    {
        using var tmp = new TempDir();
        string output = tmp.File("a.3ds");
        File.WriteAllText(output, "keep me");
        await Assert.ThrowsAsync<IOException>(() => Converter().DecryptAsync(Fixtures.File("game_a.3ds"), output));
        Assert.Equal("keep me", File.ReadAllText(output));
    }

    [Fact]
    public async Task Cancellation_LeavesNoOutput()
    {
        using var tmp = new TempDir();
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            Converter().DecryptAsync(Fixtures.File("game_a.3ds"), tmp.File("a.3ds"), ct: cts.Token));
        Assert.Empty(Directory.GetFiles(tmp.Path));
    }

    [Fact]
    public async Task Progress_IsReported()
    {
        using var tmp = new TempDir();
        var seen = new List<NoIntrovert.Core.IO.OperationProgress>();
        var progress = new SyncProgress(p => seen.Add(p));
        await Converter().ConvertAsync(Fixtures.File("game_b.cia"), tmp.File("b.3ds"), CtrOutputFormat.Cci,
            new CtrConvertOptions { Trim = false }, progress);
        Assert.NotEmpty(seen);
        Assert.Equal(1.0, seen[^1].Fraction, 3);
    }

    private sealed class SyncProgress : IProgress<NoIntrovert.Core.IO.OperationProgress>
    {
        private readonly Action<NoIntrovert.Core.IO.OperationProgress> _a;
        public SyncProgress(Action<NoIntrovert.Core.IO.OperationProgress> a) => _a = a;
        public void Report(NoIntrovert.Core.IO.OperationProgress value) => _a(value);
    }
}
