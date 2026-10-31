using NoIntrovert.Core.Hashing;
using NoIntrovert.Ctr.Keys;
using NoIntrovert.Ctr.Ncch;
using NoIntrovert.Ctr.Verification;
using NoIntrovert.Dat;
using Xunit;

namespace NoIntrovert.Ctr.Tests;

public class VerificationTests
{
    private static DatIndex Dats() => DatIndex.FromFiles(new[]
    {
        Fixtures.File("dats/fake_3ds_encrypted.dat"),
        Fixtures.File("dats/fake_3ds_decrypted.dat"),
    });

    [Fact]
    public void Inspect_Cci_ReadsMetadata()
    {
        var info = CtrInspector.Inspect(Fixtures.File("game_a.3ds"), Fixtures.Keys());
        Assert.Equal(CtrFileType.Cci, info.Type);
        Assert.Equal(Fixtures.Fact("game_a_title_id"), info.TitleIdHex);
        Assert.Equal(Fixtures.Fact("game_a_product"), info.ProductCode);
        Assert.Equal("USA", info.Region);
        Assert.Equal(Fixtures.Fact("game_a_title"), info.Titles?.ShortTitle);
        Assert.Equal(Fixtures.Fact("game_a_publisher"), info.Titles?.Publisher);
        Assert.Equal(long.Parse(Fixtures.Fact("game_a_media_size")), info.MediaSize);
        Assert.Equal(long.Parse(Fixtures.Fact("game_a_used_size")), info.UsedSize);
        Assert.True(info.IsTrimmed);
        Assert.True(info.Encrypted);
        Assert.Equal(0x80000UL, info.SaveDataSize);
        Assert.Equal(2, info.Ncchs.Count);
        Assert.All(info.Ncchs, n => Assert.True(n.CanDecrypt));
        Assert.Equal("7.x (0x25)", info.Ncchs[0].Crypto);
    }

    [Fact]
    public void Inspect_WithoutKeys_ReportsMissingKey()
    {
        var info = CtrInspector.Inspect(Fixtures.File("game_a.3ds"));
        Assert.Null(info.Titles);
        Assert.Equal("CTR-P-ATGE", info.ProductCode); // header is plaintext
        Assert.All(info.Ncchs, n => Assert.False(n.CanDecrypt));
        Assert.Equal("slot0x2CKeyX", info.Ncchs[0].MissingKey);
    }

    [Fact]
    public void Inspect_Cia_ReadsMetadata()
    {
        var info = CtrInspector.Inspect(Fixtures.File("game_b.cia"), Fixtures.Keys());
        Assert.Equal(CtrFileType.Cia, info.Type);
        Assert.Equal(Fixtures.Fact("game_b_title_id"), info.TitleIdHex);
        Assert.Equal(Fixtures.Fact("game_b_product"), info.ProductCode);
        Assert.Equal("Japan", info.Region);
        Assert.Equal("Seed Game", info.Titles?.ShortTitle);
        Assert.Contains("seed", info.Ncchs[0].Crypto);
    }

    [Fact]
    public void Inspect_Cia_WithoutKeys_FallsBackToMetaIcon()
    {
        var info = CtrInspector.Inspect(Fixtures.File("game_b.cia"));
        Assert.Equal("Seed Game", info.Titles?.ShortTitle);
    }

    [Fact]
    public async Task Verify_TrimmedEncryptedCci_MatchesUntrimmedDatEntry()
    {
        var v = new CtrVerifier(Fixtures.Keys(), Dats());
        var r = await v.VerifyAsync(Fixtures.File("game_a.3ds"));
        Assert.Equal(CtrVerdict.VerifiedUntrimmed, r.Verdict);
        Assert.Equal("Test Game (USA)", r.Match.Game?.Name);
        Assert.True(r.MatchedUntrimmed);
        Assert.Equal(Fixtures.ExpectedSha256("game_a.untrimmed.3ds"), r.UntrimmedHashes?.Sha256);
        Assert.NotEmpty(r.Checks);
        Assert.All(r.Checks, c => Assert.Equal(CheckStatus.Pass, c.Status));
    }

    [Fact]
    public async Task Verify_DecryptedCci_MatchesClrMameProDat()
    {
        var v = new CtrVerifier(Fixtures.Keys(), Dats());
        var r = await v.VerifyAsync(Fixtures.File("expected/game_a.decrypted.3ds"));
        Assert.Equal(CtrVerdict.VerifiedUntrimmed, r.Verdict);
        Assert.Equal("Test Game (USA)", r.Match.Game?.Name);
        Assert.Contains("Decrypted", r.Match.Game?.Dat?.Name);
    }

    [Fact]
    public async Task Verify_Cia_MatchesBySha1AndPassesTmdChecks()
    {
        var v = new CtrVerifier(Fixtures.Keys(), Dats());
        var r = await v.VerifyAsync(Fixtures.File("game_b.cia"));
        Assert.Equal(CtrVerdict.Verified, r.Verdict);
        Assert.Equal("Seed Game (Japan) (eShop)", r.Match.Game?.Name);
        Assert.Contains(r.Checks, c => c.Name.Contains("TMD SHA-256") && c.Status == CheckStatus.Pass);
        Assert.All(r.Checks, c => Assert.Equal(CheckStatus.Pass, c.Status));
    }

    [Fact]
    public async Task Verify_ConvertedCia_IsIntactButNotInDat()
    {
        var v = new CtrVerifier(Fixtures.Keys(), Dats());
        var r = await v.VerifyAsync(Fixtures.File("expected/game_a.cia"));
        Assert.Equal(CtrVerdict.IntactNotInDat, r.Verdict);
        Assert.Equal(DatMatchKind.Serial, r.Match.Kind);   // still identified by product code
        Assert.Equal("Test Game (USA)", r.Match.Game?.Name);
    }

    [Fact]
    public async Task Verify_CorruptedFile_IsBad()
    {
        using var tmp = new TempDir();
        string bad = tmp.File("bad.3ds");
        byte[] data = File.ReadAllBytes(Fixtures.File("expected/game_a.decrypted.3ds"));
        // flip one bit inside the manual's RomFS superblock (covered by the header hash)
        var info = CtrInspector.Inspect(Fixtures.File("expected/game_a.decrypted.3ds"));
        long p1 = info.Ncchs[1].Offset;
        var hdr = new NcchHeader(data.AsSpan((int)p1, 0x200));
        data[p1 + hdr.RomFs.Offset + 5] ^= 0x01;
        File.WriteAllBytes(bad, data);
        var r = await new CtrVerifier(new CtrKeyStore(), null).VerifyAsync(bad);
        Assert.Equal(CtrVerdict.Bad, r.Verdict);
        Assert.Contains(r.Checks, c => c.Status == CheckStatus.Fail && c.Name.Contains("RomFS"));
    }

    [Fact]
    public async Task Verify_WithoutKeys_SkipsEncryptedChecks()
    {
        var r = await new CtrVerifier(new CtrKeyStore(), null).VerifyAsync(Fixtures.File("game_a.3ds"));
        Assert.Equal(CtrVerdict.Unknown, r.Verdict);
        Assert.All(r.Checks, c => Assert.Equal(CheckStatus.Skipped, c.Status));
    }

    [Fact]
    public async Task Rename_Plan_UsesDatNameOrMetadata()
    {
        using var tmp = new TempDir();
        string a = tmp.File("random name.3ds");
        string c = tmp.File("sys.cxi");
        File.Copy(Fixtures.File("game_a.3ds"), a);
        File.Copy(Fixtures.File("system_fixed.cxi"), c);
        var service = new CtrRenameService(new CtrVerifier(Fixtures.Keys(), Dats()));
        var (_, plan) = await service.PlanAsync(new[] { a, c }, verifyOptions: new CtrVerifyOptions { CheckIntegrity = false });
        var pa = plan.Single(p => p.SourcePath == a);
        Assert.Equal(RenameAction.Rename, pa.Action);
        Assert.Equal("Test Game (USA).3ds", Path.GetFileName(pa.TargetPath));
        var pc = plan.Single(p => p.SourcePath == c);
        Assert.Equal("Test (Spain) [CTR-P-CSYS].cxi", Path.GetFileName(pc.TargetPath));

        var failures = RenamePlanner.Apply(plan);
        Assert.Empty(failures);
        Assert.True(File.Exists(tmp.File("Test Game (USA).3ds")));
    }

    [Fact]
    public void KeyScrambler_MatchesReferenceVector()
    {
        var n = KeyScrambler.Generate(Convert.FromHexString(Fixtures.Fact("scrambler_x")),
            Convert.FromHexString(Fixtures.Fact("scrambler_y")));
        Assert.Equal(Fixtures.Fact("scrambler_normal"), Convert.ToHexString(n).ToLowerInvariant());
    }

    [Fact]
    public void Boot9_UnknownHash_RejectedByDefault()
    {
        var ks = new CtrKeyStore();
        Assert.Throws<CtrFormatException>(() => ks.LoadBoot9(File.ReadAllBytes(Fixtures.File("keys/boot9_fake.bin"))));
    }

    [Fact]
    public void KeyStatus_ReflectsLoadedKeys()
    {
        var s = Fixtures.Keys().GetStatus();
        Assert.True(s.IsRetailReady);
        Assert.Equal(6, s.CommonKeyYCount);
        Assert.Equal(1, s.SeedCount);
        Assert.False(new CtrKeyStore().GetStatus().IsRetailReady);
    }

    [Fact]
    public void Crc32_KnownVector()
    {
        Assert.Equal(0xCBF43926u, Crc32.Compute("123456789"u8));
        Assert.Equal(0u, Crc32.Compute(ReadOnlySpan<byte>.Empty));
    }

    [Fact]
    public void Detect_RecognizesAllFixtureTypes()
    {
        Assert.Equal(CtrFileType.Cci, CtrFile.Detect(Fixtures.File("game_a.3ds")));
        Assert.Equal(CtrFileType.Cia, CtrFile.Detect(Fixtures.File("game_b.cia")));
        Assert.Equal(CtrFileType.Cxi, CtrFile.Detect(Fixtures.File("system_fixed.cxi")));
        Assert.Equal(CtrFileType.Unknown, CtrFile.Detect(Fixtures.File("keys/aes_keys_fake.txt")));
    }
}

public class DatTests
{
    [Fact]
    public void Logiqx_ParsesGamesAndHashes()
    {
        var dat = DatParser.Load(Fixtures.File("dats/fake_3ds_encrypted.dat"));
        Assert.Contains("Encrypted", dat.Name);
        Assert.Equal(3, dat.Games.Count);
        var g = dat.Games[0];
        Assert.Equal("Test Game (USA)", g.Name);
        Assert.Single(g.Roms);
        Assert.Equal("ctr-p-atge", g.Roms[0].Serial!.ToLowerInvariant());
        Assert.Equal(64, g.Roms[0].Sha256!.Length);
        Assert.Equal(g.Roms[0].Crc32, g.Roms[0].Crc32!.ToLowerInvariant());
        Assert.Equal("Unrelated & Other (Europe)", dat.Games[2].Name);
    }

    [Fact]
    public void ClrMamePro_ParsesGamesAndHashes()
    {
        var dat = DatParser.Load(Fixtures.File("dats/fake_3ds_decrypted.dat"));
        Assert.Contains("Decrypted", dat.Name);
        var rom = Assert.Single(Assert.Single(dat.Games).Roms);
        Assert.Equal("Test Game (USA).3ds", rom.Name);
        Assert.Equal(134217728L, rom.Size);
        Assert.Equal(40, rom.Sha1!.Length);
        Assert.Equal(rom.Sha1, rom.Sha1.ToLowerInvariant());
        Assert.Equal("CTR-P-ATGE", rom.Serial);
    }

    [Fact]
    public void Index_LooksUpBySerialAndGameCode()
    {
        var idx = DatIndex.FromFiles(new[] { Fixtures.File("dats/fake_3ds_encrypted.dat") });
        Assert.Equal("Test Game (USA)", idx.LookupSerial("CTR-P-ATGE").Single().Game.Name);
        Assert.Equal("Test Game (USA)", idx.LookupSerial("ATGE").Single().Game.Name);
        Assert.Empty(idx.LookupSerial("CTR-P-NONE"));
    }

    [Fact]
    public void Index_DoesNotTrustCrcWhenStrongHashDisagrees()
    {
        var idx = DatIndex.FromFiles(new[] { Fixtures.File("dats/fake_3ds_encrypted.dat") });
        var e = Fixtures.Expected("game_a.untrimmed.3ds");
        var wrongSha = new FileHashes(e.GetProperty("size").GetInt64(), e.GetProperty("crc32").GetString(), null,
            new string('f', 40), null);
        Assert.Equal(DatMatchKind.None, idx.Lookup(wrongSha).Kind);
    }

    [Theory]
    [InlineData("Zelda: A Link", "Zelda - A Link")]
    [InlineData("What?*", "What")]
    [InlineData("CON", "_CON")]
    [InlineData("  trailing dots...  ", "trailing dots")]
    public void Sanitizer_ProducesSafeNames(string input, string expected) =>
        Assert.Equal(expected, FileNameSanitizer.Sanitize(input));

    [Fact]
    public void Template_DropsEmptyGroups()
    {
        var fields = new Dictionary<string, string?> { ["title"] = "Game", ["region"] = null, ["serial"] = "CTR-P-AAAA" };
        Assert.Equal("Game [CTR-P-AAAA]", FileNameTemplate.Expand("{title} ({region}) [{serial}]", fields));
    }
}
