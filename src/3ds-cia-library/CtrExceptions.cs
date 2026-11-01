namespace ThreeDsCiaLibrary;

/// <summary>The file is not a valid or supported 3DS file.</summary>
public class CtrFormatException : Exception
{
    public CtrFormatException(string message) : base(message) { }
}

/// <summary>A key, seed or certificate needed for the operation was not loaded.</summary>
public class MissingKeyException : Exception
{
    public MissingKeyException(string message, string keyName) : base(message) => KeyName = keyName;

    /// <summary>Identifier of the missing item, e.g. "slot0x25KeyX", "common1", "seed:0004000000123400".</summary>
    public string KeyName { get; }
}
