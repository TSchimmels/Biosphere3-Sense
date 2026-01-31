using Microsoft.AspNetCore.Mvc;
using Biosphere3.Data;
using Biosphere3.Models;

namespace Biosphere3.Controllers;

[ApiController]
[Route("api/[controller]")]
public class SensorsController : ControllerBase
{
    private readonly DatabaseHelper _db;
    private readonly ILogger<SensorsController> _logger;

    public SensorsController(DatabaseHelper db, ILogger<SensorsController> logger)
    {
        _db = db;
        _logger = logger;
    }

    [HttpGet]
    public async Task<IActionResult> GetAll([FromQuery] bool includeArchived = false)
    {
        var sensors = await _db.GetAllSensorsAsync(includeArchived);
        return Ok(sensors);
    }

    [HttpGet("{id}")]
    public async Task<IActionResult> GetById(int id, [FromQuery] bool includeArchived = false)
    {
        var sensor = await _db.GetSensorByIdAsync(id, includeArchived);
        if (sensor == null) return NotFound();
        return Ok(sensor);
    }

    [HttpPost]
    public async Task<IActionResult> Create([FromBody] Sensor sensor)
    {
        if (string.IsNullOrWhiteSpace(sensor.Name))
            return BadRequest("Sensor name is required.");
        if (string.IsNullOrWhiteSpace(sensor.Location))
            return BadRequest("Sensor location is required.");
        if (string.IsNullOrWhiteSpace(sensor.Type))
            return BadRequest("Sensor type is required.");
        if (string.IsNullOrWhiteSpace(sensor.Unit))
            return BadRequest("Unit is required.");
        if (string.IsNullOrWhiteSpace(sensor.Status))
            return BadRequest("Status is required.");
        if (double.IsNaN(sensor.PosX) || double.IsNaN(sensor.PosY) || double.IsNaN(sensor.PosZ))
            return BadRequest("Position coordinates are required.");

        var created = await _db.CreateSensorAsync(sensor);
        _logger.LogInformation("Sensor created: {SensorId} {Name}", created.Id, created.Name);
        return CreatedAtAction(nameof(GetById), new { id = created.Id }, created);
    }

    [HttpPut("{id}")]
    public async Task<IActionResult> Update(int id, [FromBody] Sensor sensor)
    {
        if (string.IsNullOrWhiteSpace(sensor.Name))
            return BadRequest("Sensor name is required.");
        if (double.IsNaN(sensor.PosX) || double.IsNaN(sensor.PosY) || double.IsNaN(sensor.PosZ))
            return BadRequest("Position coordinates are required.");

        var updated = await _db.UpdateSensorAsync(id, sensor);
        if (!updated) return NotFound();
        _logger.LogInformation("Sensor updated: {SensorId}", id);
        return NoContent();
    }

    [HttpDelete("{id}")]
    public async Task<IActionResult> Delete(int id)
    {
        var deleted = await _db.DeleteSensorAsync(id);
        if (!deleted) return NotFound();
        _logger.LogInformation("Sensor archived: {SensorId}", id);
        return NoContent();
    }

    [HttpPatch("{id}/restore")]
    public async Task<IActionResult> Restore(int id)
    {
        var restored = await _db.RestoreSensorAsync(id);
        if (!restored) return NotFound();
        _logger.LogInformation("Sensor restored: {SensorId}", id);
        return NoContent();
    }

    [HttpPost("import")]
    public async Task<IActionResult> Import([FromBody] List<Sensor> sensors)
    {
        if (sensors == null || sensors.Count == 0)
            return BadRequest("No sensors provided.");

        foreach (var sensor in sensors)
        {
            if (string.IsNullOrWhiteSpace(sensor.Name) ||
                string.IsNullOrWhiteSpace(sensor.Location) ||
                string.IsNullOrWhiteSpace(sensor.Type) ||
                string.IsNullOrWhiteSpace(sensor.Unit) ||
                string.IsNullOrWhiteSpace(sensor.Status))
            {
                return BadRequest("Each sensor must include Name, Location, Type, Unit, and Status.");
            }
            if (double.IsNaN(sensor.PosX) || double.IsNaN(sensor.PosY) || double.IsNaN(sensor.PosZ))
            {
                return BadRequest("Each sensor must include valid PosX, PosY, and PosZ coordinates.");
            }
        }

        var imported = await _db.CreateSensorsAsync(sensors);
        _logger.LogInformation("Sensors imported: {Count}", imported);
        return Ok(new { imported });
    }
}
