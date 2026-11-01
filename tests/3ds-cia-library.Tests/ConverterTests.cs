using ThreeDsCiaLibrary.Keys;
using ThreeDsCiaLibrary.Operations;
using Xunit;

namespace ThreeDsCiaLibrary.Tests;

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
        var seen = new List<ThreeDsCiaLibrary.IO.OperationProgress>();
        var progress = new SyncProgress(p => seen.Add(p));
        await Converter().ConvertAsync(Fixtures.File("game_b.cia"), tmp.File("b.3ds"), CtrOutputFormat.Cci,
            new CtrConvertOptions { Trim = false }, progress);
        Assert.NotEmpty(seen);
        Assert.Equal(1.0, seen[^1].Fraction, 3);
    }

    [Theory]
    [InlineData("game_b.cia")] // CIA decrypt
    [InlineData("game_a.3ds")] // CCI -> CIA
    public async Task Cia_output_reports_the_hash_pass_and_never_goes_backwards(string input)
    {
        using var tmp = new TempDir();
        var seen = new List<ThreeDsCiaLibrary.IO.OperationProgress>();
        var progress = new SyncProgress(p => seen.Add(p));
        if (input.EndsWith(".cia"))
            await Converter().DecryptAsync(Fixtures.File(input), tmp.File("out.cia"), progress: progress);
        else
            await Converter().ConvertAsync(Fixtures.File(input), tmp.File("out.cia"), CtrOutputFormat.Cia, progress: progress);

        int hashing = seen.FindIndex(p => p.Stage.StartsWith("Hashing"));
        Assert.True(hashing > 0, "no Hashing stage was reported");
        Assert.All(seen.Take(hashing), p => Assert.True(p.Fraction < 1.0, $"reached 100% before hashing ({p.Stage})"));
        for (int i = 1; i < seen.Count; i++)
            Assert.True(seen[i].Fraction >= seen[i - 1].Fraction, $"progress went backwards at '{seen[i].Stage}'");
        Assert.Equal(1.0, seen[^1].Fraction, 3);
    }

    [Fact]
    public async Task Cia_output_without_hashes_has_no_hash_stage_and_still_finishes_at_100()
    {
        using var tmp = new TempDir();
        var seen = new List<ThreeDsCiaLibrary.IO.OperationProgress>();
        var r = await Converter().DecryptAsync(Fixtures.File("game_b.cia"), tmp.File("out.cia"),
            new CtrConvertOptions { ComputeOutputHashes = false }, new SyncProgress(p => seen.Add(p)));
        Assert.Null(r.OutputHashes);
        Assert.DoesNotContain(seen, p => p.Stage.StartsWith("Hashing"));
        Assert.Equal(1.0, seen[^1].Fraction, 3);
    }

    [Theory]
    [InlineData("CTR-P-AJ8E", "USA")]
    [InlineData("CTR-M-AXCE-00", "USA")]   // DLC
    [InlineData("CTR-U-ABEE-00", "USA")]   // update
    [InlineData("KTR-N-UAFE", "USA")]      // New 3DS
    [InlineData("CTR-N-JSNP", "Europe")]
    [InlineData("CTR-P-RCQA", "World")]
    [InlineData("ABCJ", "Japan")]          // bare game code
    [InlineData("GB-P-BL2M", null)]        // homebrew, no region letter
    [InlineData("", null)]
    public void Region_comes_from_the_game_code_even_with_a_suffix(string code, string? expected) =>
        Assert.Equal(expected, CtrFile.RegionFromProductCode(code));

    private sealed class SyncProgress : IProgress<ThreeDsCiaLibrary.IO.OperationProgress>
    {
        private readonly Action<ThreeDsCiaLibrary.IO.OperationProgress> _a;
        public SyncProgress(Action<ThreeDsCiaLibrary.IO.OperationProgress> a) => _a = a;
        public void Report(ThreeDsCiaLibrary.IO.OperationProgress value) => _a(value);
    }
}
