using System.Globalization;
using System.Text;
using System.Xml;

namespace NoIntrovert.Dat;

/// <summary>Loads DAT files in Logiqx XML or ClrMamePro text format (auto-detected).</summary>
public static class DatParser
{
    public static DatFile Load(string path)
    {
        using var fs = File.OpenRead(path);
        return Load(fs, path);
    }

    public static DatFile Load(Stream stream, string? sourcePath = null)
    {
        // sniff the first non-whitespace character: '<' means XML
        var buffered = stream.CanSeek ? stream : CopyToMemory(stream);
        long start = buffered.Position;
        int c;
        do { c = buffered.ReadByte(); } while (c is ' ' or '\t' or '\r' or '\n' or 0xEF or 0xBB or 0xBF);
        buffered.Position = start;
        return c == '<' ? ParseLogiqx(buffered, sourcePath) : ParseClrMamePro(buffered, sourcePath);
    }

    private static MemoryStream CopyToMemory(Stream s)
    {
        var ms = new MemoryStream();
        s.CopyTo(ms);
        ms.Position = 0;
        return ms;
    }

    // ------------------------------------------------------------- Logiqx ---

    public static DatFile ParseLogiqx(Stream stream, string? sourcePath = null)
    {
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Ignore,
            XmlResolver = null,
            IgnoreComments = true,
            IgnoreWhitespace = true,
        };
        string name = "", desc = "", version = "";
        var games = new List<DatGame>();
        using var r = XmlReader.Create(stream, settings);
        while (r.Read())
        {
            if (r.NodeType != XmlNodeType.Element) continue;
            switch (r.LocalName)
            {
                case "header":
                    ReadHeader(r.ReadSubtree(), ref name, ref desc, ref version);
                    break;
                case "game":
                case "machine":
                case "software":
                    games.Add(ReadGame(r));
                    break;
            }
        }
        var dat = new DatFile { Name = name, Description = desc, Version = version, SourcePath = sourcePath };
        foreach (var g in games)
        {
            g.Dat = dat;
            dat.Games.Add(g);
        }
        return dat;
    }

    // Note: ReadElementContentAsString() and Skip() already advance the reader, so the
    // child loops below only call Read() for non-element nodes.

    private static void ReadHeader(XmlReader r, ref string name, ref string desc, ref string version)
    {
        using (r)
        {
            r.Read();            // <header>
            if (r.IsEmptyElement) return;
            r.Read();            // first child
            while (!r.EOF && r.Depth > 0)
            {
                if (r.NodeType != XmlNodeType.Element) { r.Read(); continue; }
                switch (r.LocalName)
                {
                    case "name": name = r.ReadElementContentAsString(); break;
                    case "description": desc = r.ReadElementContentAsString(); break;
                    case "version": version = r.ReadElementContentAsString(); break;
                    default: r.Skip(); break;
                }
            }
        }
    }

    private static DatGame ReadGame(XmlReader r)
    {
        string gameName = r.GetAttribute("name") ?? "";
        string? id = r.GetAttribute("id");
        string? serial = r.GetAttribute("serial");
        string description = "";
        var roms = new List<DatRom>();
        if (!r.IsEmptyElement)
        {
            using var sub = r.ReadSubtree();
            sub.Read(); // the game element itself
            sub.Read(); // first child
            while (!sub.EOF && sub.Depth > 0)
            {
                if (sub.NodeType != XmlNodeType.Element) { sub.Read(); continue; }
                switch (sub.LocalName)
                {
                    case "description":
                        description = sub.ReadElementContentAsString();
                        break;
                    case "serial":
                        serial = sub.ReadElementContentAsString();
                        break;
                    case "rom":
                        roms.Add(new DatRom
                        {
                            Name = sub.GetAttribute("name") ?? "",
                            Size = ParseSize(sub.GetAttribute("size")),
                            Crc32 = NormHex(sub.GetAttribute("crc"), 8),
                            Md5 = NormHex(sub.GetAttribute("md5"), 32),
                            Sha1 = NormHex(sub.GetAttribute("sha1"), 40),
                            Sha256 = NormHex(sub.GetAttribute("sha256"), 64),
                            Serial = NullIfEmpty(sub.GetAttribute("serial")),
                            Status = NullIfEmpty(sub.GetAttribute("status")),
                        });
                        sub.Skip();
                        break;
                    default:
                        sub.Skip();
                        break;
                }
            }
        }
        var game = new DatGame { Name = gameName, Description = description, Serial = NullIfEmpty(serial), Id = id };
        foreach (var rom in roms)
        {
            rom.Game = game;
            game.Roms.Add(rom);
        }
        return game;
    }

    // --------------------------------------------------------- ClrMamePro ---

    public static DatFile ParseClrMamePro(Stream stream, string? sourcePath = null)
    {
        string text;
        using (var sr = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, leaveOpen: true))
            text = sr.ReadToEnd();
        var tokens = Tokenize(text);
        int pos = 0;
        string name = "", desc = "", version = "";
        var games = new List<DatGame>();
        while (pos < tokens.Count)
        {
            string key = tokens[pos++].Value;
            if (pos < tokens.Count && tokens[pos].IsOpen)
            {
                var block = ReadBlock(tokens, ref pos);
                switch (key.ToLowerInvariant())
                {
                    case "clrmamepro":
                        name = block.Get("name") ?? "";
                        desc = block.Get("description") ?? "";
                        version = block.Get("version") ?? "";
                        break;
                    case "game":
                    case "machine":
                    case "resource":
                        games.Add(BlockToGame(block));
                        break;
                }
            }
        }
        var dat = new DatFile { Name = name, Description = desc, Version = version, SourcePath = sourcePath };
        foreach (var g in games)
        {
            g.Dat = dat;
            dat.Games.Add(g);
        }
        return dat;
    }

    private static DatGame BlockToGame(Block b)
    {
        var game = new DatGame
        {
            Name = b.Get("name") ?? "",
            Description = b.Get("description") ?? "",
            Serial = NullIfEmpty(b.Get("serial")),
        };
        foreach (var (k, child) in b.Children)
        {
            if (!k.Equals("rom", StringComparison.OrdinalIgnoreCase)) continue;
            var rom = new DatRom
            {
                Name = child.Get("name") ?? "",
                Size = ParseSize(child.Get("size")),
                Crc32 = NormHex(child.Get("crc"), 8),
                Md5 = NormHex(child.Get("md5"), 32),
                Sha1 = NormHex(child.Get("sha1"), 40),
                Sha256 = NormHex(child.Get("sha256"), 64),
                Serial = NullIfEmpty(child.Get("serial")),
                Status = NullIfEmpty(child.Get("flags") ?? child.Get("status")),
            };
            rom.Game = game;
            game.Roms.Add(rom);
        }
        return game;
    }

    private readonly record struct Token(string Value, bool IsOpen, bool IsClose);

    private sealed class Block
    {
        public List<(string Key, string Value)> Values { get; } = new();
        public List<(string Key, Block Child)> Children { get; } = new();

        public string? Get(string key)
        {
            foreach (var (k, v) in Values)
                if (k.Equals(key, StringComparison.OrdinalIgnoreCase)) return v;
            return null;
        }
    }

    private static Block ReadBlock(List<Token> t, ref int pos)
    {
        // t[pos] is '('
        pos++;
        var b = new Block();
        while (pos < t.Count && !t[pos].IsClose)
        {
            string key = t[pos++].Value;
            if (pos >= t.Count) break;
            if (t[pos].IsOpen)
            {
                b.Children.Add((key, ReadBlock(t, ref pos)));
            }
            else if (t[pos].IsClose)
            {
                break;
            }
            else
            {
                b.Values.Add((key, t[pos++].Value));
            }
        }
        pos++; // ')'
        return b;
    }

    private static List<Token> Tokenize(string s)
    {
        var list = new List<Token>();
        int i = 0;
        while (i < s.Length)
        {
            char c = s[i];
            if (char.IsWhiteSpace(c)) { i++; continue; }
            if (c == '(') { list.Add(new Token("(", true, false)); i++; continue; }
            if (c == ')') { list.Add(new Token(")", false, true)); i++; continue; }
            if (c == '"')
            {
                var sb = new StringBuilder();
                i++;
                while (i < s.Length && s[i] != '"')
                {
                    if (s[i] == '\\' && i + 1 < s.Length && s[i + 1] == '"') { sb.Append('"'); i += 2; continue; }
                    sb.Append(s[i++]);
                }
                i++; // closing quote
                list.Add(new Token(sb.ToString(), false, false));
                continue;
            }
            int st = i;
            while (i < s.Length && !char.IsWhiteSpace(s[i]) && s[i] != '(' && s[i] != ')') i++;
            list.Add(new Token(s[st..i], false, false));
        }
        return list;
    }

    // ------------------------------------------------------------ helpers ---

    private static long? ParseSize(string? s)
    {
        if (string.IsNullOrWhiteSpace(s)) return null;
        s = s.Trim();
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase) &&
            long.TryParse(s.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out long hex))
            return hex;
        return long.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out long v) ? v : null;
    }

    internal static string? NormHex(string? s, int expectedLength)
    {
        if (string.IsNullOrWhiteSpace(s)) return null;
        s = s.Trim().ToLowerInvariant();
        if (s.StartsWith("0x")) s = s[2..];
        if (s.Length < expectedLength) s = s.PadLeft(expectedLength, '0');
        foreach (char ch in s)
            if (!Uri.IsHexDigit(ch)) return null;
        return s.Length == expectedLength ? s : null;
    }

    private static string? NullIfEmpty(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();
}
