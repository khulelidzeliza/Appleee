namespace ORAA.Models.Apple;

public class AppleAuthRequest
{
    public string Code { get; set; }           // authorization code from frontend
    public string RedirectUri { get; set; }    // must match the one used in frontend
    public string AppleId { get; set; }      // optional, can be null if not provided
}
