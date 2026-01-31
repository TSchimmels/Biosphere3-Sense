using Microsoft.Data.SqlClient;
using Biosphere3.Models;

namespace Biosphere3.Data;

public class DatabaseHelper
{
    private readonly string _connectionString;

    public DatabaseHelper(string connectionString)
    {
        _connectionString = connectionString;
    }

    public async Task InitializeAsync()
    {
        using var conn = new SqlConnection(_connectionString);
        await conn.OpenAsync();

        var createTable = @"
            IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='Sensors' AND xtype='U')
            CREATE TABLE Sensors (
                Id INT IDENTITY(1,1) PRIMARY KEY,
                Name NVARCHAR(100) NOT NULL,
                Location NVARCHAR(200) NOT NULL,
                Type NVARCHAR(50) NOT NULL,
                LastReading FLOAT NOT NULL,
                Unit NVARCHAR(20) NOT NULL,
                Status NVARCHAR(20) NOT NULL,
                LastUpdated DATETIME2 NOT NULL DEFAULT GETUTCDATE(),
                PosX FLOAT NOT NULL DEFAULT 0,
                PosY FLOAT NOT NULL DEFAULT 0,
                PosZ FLOAT NOT NULL DEFAULT 0,
                IsArchived BIT NOT NULL DEFAULT 0,
                ArchivedAt DATETIME2 NULL
            )";

        using var cmd = new SqlCommand(createTable, conn);
        await cmd.ExecuteNonQueryAsync();

        var alterSql = @"
            IF COL_LENGTH('Sensors', 'IsArchived') IS NULL
                ALTER TABLE Sensors ADD IsArchived BIT NOT NULL DEFAULT 0;
            IF COL_LENGTH('Sensors', 'ArchivedAt') IS NULL
                ALTER TABLE Sensors ADD ArchivedAt DATETIME2 NULL;
            IF COL_LENGTH('Sensors', 'PosX') IS NULL
                ALTER TABLE Sensors ADD PosX FLOAT NOT NULL DEFAULT 0;
            IF COL_LENGTH('Sensors', 'PosY') IS NULL
                ALTER TABLE Sensors ADD PosY FLOAT NOT NULL DEFAULT 0;
            IF COL_LENGTH('Sensors', 'PosZ') IS NULL
                ALTER TABLE Sensors ADD PosZ FLOAT NOT NULL DEFAULT 0;";
        using var alterCmd = new SqlCommand(alterSql, conn);
        await alterCmd.ExecuteNonQueryAsync();

        var updatePositionsSql = @"
            UPDATE Sensors
            SET
                PosX = (Id * 3.7) % 50.0,
                PosY = (Id * 5.1) % 20.0,
                PosZ = ((Id * 2.3) % 10.0) - 2.0
            WHERE PosX = 0 AND PosY = 0 AND PosZ = 0;";
        using var updatePositionsCmd = new SqlCommand(updatePositionsSql, conn);
        await updatePositionsCmd.ExecuteNonQueryAsync();

        // Seed sample data if empty
        var countCmd = new SqlCommand("SELECT COUNT(*) FROM Sensors", conn);
        var count = (int)(await countCmd.ExecuteScalarAsync() ?? 0);

        if (count == 0)
        {
            var seedSql = @"
                INSERT INTO Sensors (Name, Location, Type, LastReading, Unit, Status, LastUpdated, PosX, PosY, PosZ) VALUES
                ('ATMO-001', 'Dome A - North Sector', 'Temperature', 22.5, '°C', 'Online', GETUTCDATE(), 12.5, 4.2, 2.1),
                ('ATMO-002', 'Dome A - South Sector', 'Temperature', 23.1, '°C', 'Online', GETUTCDATE(), 14.0, 3.8, 2.0),
                ('HUM-001', 'Dome B - Tropical Zone', 'Humidity', 78.3, '%', 'Online', GETUTCDATE(), 8.4, 6.1, 1.2),
                ('PRES-001', 'Dome C - High Altitude Lab', 'Pressure', 1013.25, 'hPa', 'Online', GETUTCDATE(), 20.0, 9.2, 5.5),
                ('SOIL-001', 'Greenhouse Alpha', 'Soil Moisture', 42.7, '%', 'Warning', GETUTCDATE(), 5.5, 2.4, 0.5),
                ('CO2-001', 'Dome A - Central Hub', 'CO2 Level', 415.2, 'ppm', 'Online', GETUTCDATE(), 10.1, 5.0, 2.8),
                ('LIGHT-001', 'Solar Array East', 'Light Intensity', 850.0, 'lux', 'Online', GETUTCDATE(), 30.2, 1.1, 0.0),
                ('AQUA-001', 'Marine Tank 1', 'Water Temperature', 18.9, '°C', 'Online', GETUTCDATE(), 3.2, 7.4, -1.2),
                ('AQUA-002', 'Marine Tank 1', 'Salinity', 35.0, 'PSU', 'Offline', GETUTCDATE(), 3.0, 7.1, -1.1),
                ('WIND-001', 'External Weather Station', 'Wind Speed', 12.4, 'km/h', 'Online', GETUTCDATE(), 50.0, 12.0, 0.0)";

            using var seedCmd = new SqlCommand(seedSql, conn);
            await seedCmd.ExecuteNonQueryAsync();
        }
    }

    public async Task<List<Sensor>> GetAllSensorsAsync(bool includeArchived = false)
    {
        var sensors = new List<Sensor>();
        using var conn = new SqlConnection(_connectionString);
        await conn.OpenAsync();

        var sql = @"SELECT Id, Name, Location, Type, LastReading, Unit, Status, LastUpdated, IsArchived, ArchivedAt, PosX, PosY, PosZ
                    FROM Sensors
                    WHERE (@IncludeArchived = 1 OR IsArchived = 0)
                    ORDER BY Id";
        using var cmd = new SqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@IncludeArchived", includeArchived ? 1 : 0);
        using var reader = await cmd.ExecuteReaderAsync();

        while (await reader.ReadAsync())
        {
            sensors.Add(new Sensor
            {
                Id = reader.GetInt32(0),
                Name = reader.GetString(1),
                Location = reader.GetString(2),
                Type = reader.GetString(3),
                LastReading = reader.GetDouble(4),
                Unit = reader.GetString(5),
                Status = reader.GetString(6),
                LastUpdated = reader.GetDateTime(7),
                IsArchived = reader.GetBoolean(8),
                ArchivedAt = reader.IsDBNull(9) ? null : reader.GetDateTime(9),
                PosX = reader.GetDouble(10),
                PosY = reader.GetDouble(11),
                PosZ = reader.GetDouble(12)
            });
        }

        return sensors;
    }

    public async Task<Sensor?> GetSensorByIdAsync(int id, bool includeArchived = false)
    {
        using var conn = new SqlConnection(_connectionString);
        await conn.OpenAsync();

        var sql = @"SELECT Id, Name, Location, Type, LastReading, Unit, Status, LastUpdated, IsArchived, ArchivedAt, PosX, PosY, PosZ
                    FROM Sensors
                    WHERE Id = @Id AND (@IncludeArchived = 1 OR IsArchived = 0)";
        using var cmd = new SqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@Id", id);
        cmd.Parameters.AddWithValue("@IncludeArchived", includeArchived ? 1 : 0);
        using var reader = await cmd.ExecuteReaderAsync();

        if (await reader.ReadAsync())
        {
            return new Sensor
            {
                Id = reader.GetInt32(0),
                Name = reader.GetString(1),
                Location = reader.GetString(2),
                Type = reader.GetString(3),
                LastReading = reader.GetDouble(4),
                Unit = reader.GetString(5),
                Status = reader.GetString(6),
                LastUpdated = reader.GetDateTime(7),
                IsArchived = reader.GetBoolean(8),
                ArchivedAt = reader.IsDBNull(9) ? null : reader.GetDateTime(9),
                PosX = reader.GetDouble(10),
                PosY = reader.GetDouble(11),
                PosZ = reader.GetDouble(12)
            };
        }

        return null;
    }

    public async Task<Sensor> CreateSensorAsync(Sensor sensor)
    {
        using var conn = new SqlConnection(_connectionString);
        await conn.OpenAsync();

        var sql = @"INSERT INTO Sensors (Name, Location, Type, LastReading, Unit, Status, LastUpdated, IsArchived, PosX, PosY, PosZ)
                    OUTPUT INSERTED.Id
                    VALUES (@Name, @Location, @Type, @LastReading, @Unit, @Status, GETUTCDATE(), 0, @PosX, @PosY, @PosZ)";

        using var cmd = new SqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@Name", sensor.Name);
        cmd.Parameters.AddWithValue("@Location", sensor.Location);
        cmd.Parameters.AddWithValue("@Type", sensor.Type);
        cmd.Parameters.AddWithValue("@LastReading", sensor.LastReading);
        cmd.Parameters.AddWithValue("@Unit", sensor.Unit);
        cmd.Parameters.AddWithValue("@Status", sensor.Status);
        cmd.Parameters.AddWithValue("@PosX", sensor.PosX);
        cmd.Parameters.AddWithValue("@PosY", sensor.PosY);
        cmd.Parameters.AddWithValue("@PosZ", sensor.PosZ);

        sensor.Id = (int)(await cmd.ExecuteScalarAsync() ?? 0);
        sensor.LastUpdated = DateTime.UtcNow;
        return sensor;
    }

    public async Task<bool> UpdateSensorAsync(int id, Sensor sensor)
    {
        using var conn = new SqlConnection(_connectionString);
        await conn.OpenAsync();

        var sql = @"UPDATE Sensors SET
                    Name = @Name, Location = @Location, Type = @Type,
                    LastReading = @LastReading, Unit = @Unit, Status = @Status,
                    PosX = @PosX, PosY = @PosY, PosZ = @PosZ,
                    LastUpdated = GETUTCDATE()
                    WHERE Id = @Id AND IsArchived = 0";

        using var cmd = new SqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@Id", id);
        cmd.Parameters.AddWithValue("@Name", sensor.Name);
        cmd.Parameters.AddWithValue("@Location", sensor.Location);
        cmd.Parameters.AddWithValue("@Type", sensor.Type);
        cmd.Parameters.AddWithValue("@LastReading", sensor.LastReading);
        cmd.Parameters.AddWithValue("@Unit", sensor.Unit);
        cmd.Parameters.AddWithValue("@Status", sensor.Status);
        cmd.Parameters.AddWithValue("@PosX", sensor.PosX);
        cmd.Parameters.AddWithValue("@PosY", sensor.PosY);
        cmd.Parameters.AddWithValue("@PosZ", sensor.PosZ);

        var rows = await cmd.ExecuteNonQueryAsync();
        return rows > 0;
    }

    public async Task<bool> DeleteSensorAsync(int id)
    {
        using var conn = new SqlConnection(_connectionString);
        await conn.OpenAsync();

        using var cmd = new SqlCommand("UPDATE Sensors SET IsArchived = 1, ArchivedAt = GETUTCDATE() WHERE Id = @Id AND IsArchived = 0", conn);
        cmd.Parameters.AddWithValue("@Id", id);

        var rows = await cmd.ExecuteNonQueryAsync();
        return rows > 0;
    }

    public async Task<bool> RestoreSensorAsync(int id)
    {
        using var conn = new SqlConnection(_connectionString);
        await conn.OpenAsync();

        using var cmd = new SqlCommand("UPDATE Sensors SET IsArchived = 0, ArchivedAt = NULL WHERE Id = @Id", conn);
        cmd.Parameters.AddWithValue("@Id", id);

        var rows = await cmd.ExecuteNonQueryAsync();
        return rows > 0;
    }

    public async Task<int> CreateSensorsAsync(IEnumerable<Sensor> sensors)
    {
        using var conn = new SqlConnection(_connectionString);
        await conn.OpenAsync();
        using var tx = conn.BeginTransaction();
        var inserted = 0;

        try
        {
            foreach (var sensor in sensors)
            {
                var sql = @"INSERT INTO Sensors (Name, Location, Type, LastReading, Unit, Status, LastUpdated, IsArchived, PosX, PosY, PosZ)
                            VALUES (@Name, @Location, @Type, @LastReading, @Unit, @Status, GETUTCDATE(), 0, @PosX, @PosY, @PosZ)";
                using var cmd = new SqlCommand(sql, conn, tx);
                cmd.Parameters.AddWithValue("@Name", sensor.Name);
                cmd.Parameters.AddWithValue("@Location", sensor.Location);
                cmd.Parameters.AddWithValue("@Type", sensor.Type);
                cmd.Parameters.AddWithValue("@LastReading", sensor.LastReading);
                cmd.Parameters.AddWithValue("@Unit", sensor.Unit);
                cmd.Parameters.AddWithValue("@Status", sensor.Status);
                cmd.Parameters.AddWithValue("@PosX", sensor.PosX);
                cmd.Parameters.AddWithValue("@PosY", sensor.PosY);
                cmd.Parameters.AddWithValue("@PosZ", sensor.PosZ);
                inserted += await cmd.ExecuteNonQueryAsync();
            }

            tx.Commit();
            return inserted;
        }
        catch
        {
            tx.Rollback();
            throw;
        }
    }
}
