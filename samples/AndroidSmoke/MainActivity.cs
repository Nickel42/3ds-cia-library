using Android.App;
using Android.OS;
using Android.Widget;
using ThreeDsCiaLibrary;
using ThreeDsCiaLibrary.Keys;

namespace AndroidSmoke;

/// <summary>
/// Calls into the library on Android: key-folder search (with the app's own files folder as the
/// first place to look) and product-code parsing. On a device, put boot9.bin / aes_keys.txt /
/// seeddb.bin in the app's files folder to see "Retail ready: True".
/// </summary>
[Activity(Label = "3DS library smoke test", MainLauncher = true)]
public class MainActivity : Activity
{
    protected override void OnCreate(Bundle? savedInstanceState)
    {
        base.OnCreate(savedInstanceState);
        string filesDir = FilesDir?.AbsolutePath ?? "";
        var keys = KeyLocator.LoadDefault(out var errors, extraDirectories: [filesDir]);
        var status = keys.GetStatus();
        SetContentView(new TextView(this)
        {
            Text = $"Keys folder: {filesDir}\n"
                   + $"Retail ready: {status.IsRetailReady} ({errors.Count} key file problem(s))\n"
                   + $"CTR-M-AXCE-00 region: {CtrFile.RegionFromProductCode("CTR-M-AXCE-00")}\n"
                   + $"Recognised extensions: {string.Join(" ", CtrFile.Extensions)}",
        });
    }
}
