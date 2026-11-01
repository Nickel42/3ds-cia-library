using System.Buffers.Binary;
using System.Text;
using Lib3dsKit.Cia;
using Lib3dsKit.Keys;
using Lib3dsKit.Operations;
using Xunit;

namespace Lib3dsKit.Tests;

/// <summary>Builds CDN folders from the fixture CIA, the way Nintendo's CDN serves a title.</summary>
internal static class CdnFixture
{
    /// <summary>Structurally valid fake certificates: only the layout and the names are read.</summary>
    public static readonly byte[] Ca = Cert("Root", "CA00000003", 0x00010003);
    public static readonly byte[] Xs = Cert("Root-CA00000003", "XS0000000c", 0x00010004);
    public static readonly byte[] Cp = Cert("Root-CA00000003", "CP0000000b", 0x00010004);

    private static byte[] Cert(string issuer, string name, uint signatureType)
    {
        int sig = signatureType == 0x00010003 ? 4 + 0x200 + 0x3C : 4 + 0x100 + 0x3C;
        var c = new byte[sig + 0x88 + 0x138]; // RSA-2048 public key
        BinaryPrimitives.WriteUInt32BigEndian(c, signatureType);
        Encoding.ASCII.GetBytes(issuer).CopyTo(c, sig);
        BinaryPrimitives.WriteUInt32BigEndian(c.AsSpan(sig + 0x40), 1);
        Encoding.ASCII.GetBytes(name).CopyTo(c, sig + 0x44);
        c.AsSpan(sig + 0x88, 0x100).Fill(0xA5);
        return c;
    }

    /// <summary>
    /// Splits <paramref name="ciaPath"/> into a CDN folder: TMD (+ CP and CA certificates), ticket
    /// (+ XS and CA certificates) and one file per content, still title-key encrypted.
    /// </summary>
    public static CiaFile Split(string ciaPath, string folder, bool nussplNames = false, bool certs = true)
    {
        using var fs = File.OpenRead(ciaPath);
        var cia = CiaFile.Read(fs);
        Directory.CreateDirectory(folder);
        File.WriteAllBytes(Path.Combine(folder, nussplNames ? "title.tmd" : "tmd"), certs ? [.. cia.Tmd.Raw, .. Cp, .. Ca] : cia.Tmd.Raw);
        File.WriteAllBytes(Path.Combine(folder, nussplNames ? "title.tik" : "cetk"), certs ? [.. cia.Ticket.Raw, .. Xs, .. Ca] : cia.Ticket.Raw);
        foreach (var c in cia.Contents)
            File.WriteAllBytes(Path.Combine(folder, c.Chunk.Id.ToString("x8") + (nussplNames ? ".app" : "")), RawContent(fs, c));
        return cia;
    }

    public static byte[] RawContent(Stream cia, CiaContent c)
    {
        var bytes = new byte[(int)c.Chunk.Size];
        cia.Position = c.Offset;
        cia.ReadExactly(bytes);
        return bytes;
    }

    public static (CiaFile Cia, List<byte[]> Contents) ReadCia(string path)
    {
        using var fs = File.OpenRead(path);
        var cia = CiaFile.Read(fs);
        return (cia, cia.Contents.Select(c => RawContent(fs, c)).ToList());
    }
}

public class CdnTests
{
    private static CtrConverter Converter(CtrKeyStore? keys = null) => new(keys ?? Fixtures.Keys());
    private static readonly string Source = Fixtures.File("game_b.cia");

    [Theory]
    [InlineData(false)] // tmd, cetk, 00000000
    [InlineData(true)]  // title.tmd, title.tik, 00000000.app
    public async Task Keeping_encryption_rebuilds_the_ticket_tmd_and_contents_exactly(bool nussplNames)
    {
        using var tmp = new TempDir();
        var original = CdnFixture.Split(Source, tmp.File("cdn"), nussplNames);
        var r = await Converter().ConvertAsync(tmp.File("cdn"), tmp.File("out.cia"), CtrOutputFormat.Cia,
            new CtrConvertOptions { Decrypt = false });

        var (cia, contents) = CdnFixture.ReadCia(r.OutputPath);
        var (_, originalContents) = CdnFixture.ReadCia(Source);
        Assert.Equal([.. CdnFixture.Ca, .. CdnFixture.Xs, .. CdnFixture.Cp], cia.CertificateChain);
        Assert.Equal(original.Ticket.Raw, cia.Ticket.Raw);
        Assert.Equal(original.Tmd.Raw, cia.Tmd.Raw);
        Assert.Empty(cia.Meta);
        Assert.Equal(originalContents, contents);
        Assert.Equal(Fixtures.Sha256OfFile(r.OutputPath), r.OutputHashes!.Sha256);
        Assert.DoesNotContain(r.Warnings, w => w.Contains("not verified"));
    }

    [Fact]
    public async Task Decrypting_a_cdn_folder_gives_the_same_contents_as_decrypting_the_cia()
    {
        using var tmp = new TempDir();
        CdnFixture.Split(Source, tmp.File("cdn"));
        await Converter().DecryptAsync(tmp.File("cdn"), tmp.File("from-cdn.cia"));
        await Converter().DecryptAsync(Source, tmp.File("from-cia.cia"));

        var (fromCdn, cdnContents) = CdnFixture.ReadCia(tmp.File("from-cdn.cia"));
        var (fromCia, ciaContents) = CdnFixture.ReadCia(tmp.File("from-cia.cia"));
        Assert.Equal(fromCia.Tmd.Raw, fromCdn.Tmd.Raw);
        Assert.Equal(fromCia.Ticket.Raw, fromCdn.Ticket.Raw);
        Assert.Equal(ciaContents, cdnContents);
        Assert.All(fromCdn.Tmd.Chunks, c => Assert.False(c.IsEncrypted));
    }

    [Fact]
    public async Task A_damaged_content_fails_verification_and_writes_nothing()
    {
        using var tmp = new TempDir();
        var cia = CdnFixture.Split(Source, tmp.File("cdn"));
        string content = tmp.File(Path.Combine("cdn", cia.Contents[0].Chunk.Id.ToString("x8")));
        var bytes = File.ReadAllBytes(content);
        bytes[^100] ^= 0xFF;
        File.WriteAllBytes(content, bytes);

        var ex = await Assert.ThrowsAsync<CtrFormatException>(() =>
            Converter().ConvertAsync(tmp.File("cdn"), tmp.File("out.cia"), CtrOutputFormat.Cia));
        Assert.Contains("does not match its TMD hash", ex.Message);
        Assert.False(File.Exists(tmp.File("out.cia")));
    }

    [Fact]
    public async Task A_missing_game_content_is_an_error()
    {
        using var tmp = new TempDir();
        var cia = CdnFixture.Split(Source, tmp.File("cdn"));
        File.Delete(tmp.File(Path.Combine("cdn", cia.Contents[^1].Chunk.Id.ToString("x8"))));
        var ex = await Assert.ThrowsAsync<CtrFormatException>(() =>
            Converter().ConvertAsync(tmp.File("cdn"), tmp.File("out.cia"), CtrOutputFormat.Cia));
        Assert.Contains("missing content", ex.Message);
    }

    [Fact]
    public async Task A_truncated_content_is_reported_as_an_incomplete_download()
    {
        using var tmp = new TempDir();
        var cia = CdnFixture.Split(Source, tmp.File("cdn"));
        string content = tmp.File(Path.Combine("cdn", cia.Contents[0].Chunk.Id.ToString("x8")));
        File.WriteAllBytes(content, File.ReadAllBytes(content)[..^16]);
        var ex = await Assert.ThrowsAsync<CtrFormatException>(() =>
            Converter().ConvertAsync(tmp.File("cdn"), tmp.File("out.cia"), CtrOutputFormat.Cia));
        Assert.Contains("incomplete download", ex.Message);
    }

    [Fact]
    public async Task Without_a_ticket_the_error_says_what_is_missing()
    {
        using var tmp = new TempDir();
        CdnFixture.Split(Source, tmp.File("cdn"));
        File.Delete(tmp.File(Path.Combine("cdn", "cetk")));
        var ex = await Assert.ThrowsAsync<CtrFormatException>(() =>
            Converter().ConvertAsync(tmp.File("cdn"), tmp.File("out.cia"), CtrOutputFormat.Cia));
        Assert.Contains("No ticket", ex.Message);
    }

    [Fact]
    public async Task A_ticket_version_mismatch_is_reported_and_can_be_fixed()
    {
        using var tmp = new TempDir();
        var cia = CdnFixture.Split(Source, tmp.File("cdn"));
        string cetk = tmp.File(Path.Combine("cdn", "cetk"));
        var ticket = File.ReadAllBytes(cetk);
        BinaryPrimitives.WriteUInt16BigEndian(ticket.AsSpan(cia.Ticket.BodyOffset + 0xA6), 1);
        File.WriteAllBytes(cetk, ticket);

        var kept = await Converter().ConvertAsync(tmp.File("cdn"), tmp.File("kept.cia"), CtrOutputFormat.Cia,
            new CtrConvertOptions { Decrypt = false });
        Assert.Contains(kept.Warnings, w => w.Contains("does not match the TMD"));
        Assert.Equal(1, CdnFixture.ReadCia(kept.OutputPath).Cia.Ticket.TitleVersion);

        var fixedUp = await Converter().ConvertAsync(tmp.File("cdn"), tmp.File("fixed.cia"), CtrOutputFormat.Cia,
            new CtrConvertOptions { Decrypt = false, MatchTicketVersionToTmd = true });
        var out_ = CdnFixture.ReadCia(fixedUp.OutputPath).Cia;
        Assert.Equal(out_.Tmd.TitleVersion, out_.Ticket.TitleVersion);
        Assert.Contains(fixedUp.Warnings, w => w.Contains($"wrote {out_.Tmd.TitleVersion} into the ticket"));
        Assert.DoesNotContain(fixedUp.Warnings, w => w.Contains("does not match"));
    }

    [Fact]
    public async Task Without_certificates_in_the_download_the_loaded_chain_or_zeros_are_used()
    {
        using var tmp = new TempDir();
        CdnFixture.Split(Source, tmp.File("cdn"), certs: false);

        var withLoaded = await Converter(Fixtures.Keys(certs: true)).ConvertAsync(tmp.File("cdn"), tmp.File("a.cia"), CtrOutputFormat.Cia,
            new CtrConvertOptions { Decrypt = false });
        Assert.Equal(File.ReadAllBytes(Fixtures.File("keys/certs_fake.bin")), CdnFixture.ReadCia(withLoaded.OutputPath).Cia.CertificateChain);

        var withNone = await Converter(Fixtures.Keys(certs: false)).ConvertAsync(tmp.File("cdn"), tmp.File("b.cia"), CtrOutputFormat.Cia,
            new CtrConvertOptions { Decrypt = false });
        Assert.Contains(withNone.Warnings, w => w.Contains("zero-filled"));
        Assert.All(CdnFixture.ReadCia(withNone.OutputPath).Cia.CertificateChain, b => Assert.Equal(0, b));
    }

    [Fact]
    public async Task Progress_covers_verifying_writing_and_hashing_and_never_goes_backwards()
    {
        using var tmp = new TempDir();
        CdnFixture.Split(Source, tmp.File("cdn"));
        var seen = new List<Lib3dsKit.IO.OperationProgress>();
        await Converter().ConvertAsync(tmp.File("cdn"), tmp.File("out.cia"), CtrOutputFormat.Cia,
            progress: new SyncProgress(p => seen.Add(p)));

        Assert.Contains(seen, p => p.Stage.StartsWith("Verifying content"));
        Assert.Contains(seen, p => p.Stage.StartsWith("Decrypting content"));
        Assert.Contains(seen, p => p.Stage.StartsWith("Hashing"));
        for (int i = 1; i < seen.Count; i++)
            Assert.True(seen[i].Fraction >= seen[i - 1].Fraction, $"progress went backwards at '{seen[i].Stage}'");
        Assert.Equal(1.0, seen[^1].Fraction, 3);
    }

    [Fact]
    public async Task A_cdn_folder_cannot_go_straight_to_cci()
    {
        using var tmp = new TempDir();
        CdnFixture.Split(Source, tmp.File("cdn"));
        var ex = await Assert.ThrowsAsync<CtrFormatException>(() =>
            Converter().ConvertAsync(tmp.File("cdn"), tmp.File("out.3ds"), CtrOutputFormat.Cci));
        Assert.Contains("converts to CIA", ex.Message);
    }

    [Fact]
    public async Task Cancelling_leaves_no_output()
    {
        using var tmp = new TempDir();
        CdnFixture.Split(Source, tmp.File("cdn"));
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            Converter().ConvertAsync(tmp.File("cdn"), tmp.File("out.cia"), CtrOutputFormat.Cia, ct: cts.Token));
        Assert.False(File.Exists(tmp.File("out.cia")));
    }

    private sealed class SyncProgress(Action<Lib3dsKit.IO.OperationProgress> a) : IProgress<Lib3dsKit.IO.OperationProgress>
    {
        public void Report(Lib3dsKit.IO.OperationProgress value) => a(value);
    }
}
