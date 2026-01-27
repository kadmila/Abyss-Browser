
namespace AbyssCLI.AML;

/// <summary>
/// Metadata for AML documents.
/// Initiation setting, security policies, and other metadata 
/// that affects initial parsing and execution of the document.
/// </summary>
public class AmlMetadata
{
    public string title = string.Empty;
    public Vector3 pos = new();
    public Quaternion rot = new();
    public bool is_item = false;
    public string sharer_hash = string.Empty; // only if is_item is true
    public Guid uuid = Guid.Empty; // only if is_item is true
}
