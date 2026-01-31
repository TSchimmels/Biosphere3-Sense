using Microsoft.AspNetCore.Mvc;

namespace Biosphere3.Controllers;

[ApiController]
[Route("[controller]")]
public class HelloWorldController : ControllerBase
{
    private static readonly string[] Messages = new[]
    {
        "All 10,000 sensors are humming in harmony — the biosphere is thriving!",
        "Sensor grid nominal. Even the deep-ocean probes are in a good mood today.",
        "Atmospheric array reports: skies clear, data flowing, coffee brewing.",
        "Seismic monitors confirm: the earth moved... but just a tiny bit.",
        "Thermal sensors say it's getting warm in here — or maybe that's the server room.",
        "Bio-luminescence detectors picking up vibes. Good vibes. Literally."
    };

    [HttpGet]
    public IActionResult Get()
    {
        var random = new Random();
        var message = Messages[random.Next(Messages.Length)];

        return Ok(new
        {
            timestamp = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss UTC"),
            message = message,
            system = "Biosphere3 Diagnostic"
        });
    }
}
