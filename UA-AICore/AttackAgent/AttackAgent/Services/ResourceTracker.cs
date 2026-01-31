using AttackAgent.Models;
using Serilog;
using System.Collections.Concurrent;

namespace AttackAgent.Services
{
    /// <summary>
    /// Tracks all resources created during testing for comprehensive cleanup
    /// </summary>
    public class ResourceTracker
    {
        private readonly ConcurrentBag<CreatedResource> _createdResources;
        private readonly ILogger _logger;

        public ResourceTracker()
        {
            _createdResources = new ConcurrentBag<CreatedResource>();
            _logger = Log.ForContext<ResourceTracker>();
        }

        /// <summary>
        /// Tracks a created resource
        /// </summary>
        public void TrackResource(CreatedResource resource)
        {
            _createdResources.Add(resource);
            _logger.Debug("Tracked resource: {Type} at {Endpoint} (ID: {Identifier})", 
                resource.ResourceType, resource.Endpoint, resource.Identifier);
        }

        /// <summary>
        /// Tracks an uploaded file
        /// </summary>
        public void TrackUploadedFile(string endpoint, string filename, string? fileId = null, string? deleteEndpoint = null)
        {
            TrackResource(new CreatedResource
            {
                ResourceType = ResourceType.UploadedFile,
                Endpoint = endpoint,
                Identifier = fileId ?? filename,
                DeleteEndpoint = deleteEndpoint,
                Metadata = new Dictionary<string, string> { { "filename", filename } }
            });
        }

        /// <summary>
        /// Tracks a database entry (XSS payload, test data, etc.)
        /// </summary>
        public void TrackDatabaseEntry(string endpoint, string identifier, string? deleteEndpoint = null, Dictionary<string, string>? metadata = null)
        {
            TrackResource(new CreatedResource
            {
                ResourceType = ResourceType.DatabaseEntry,
                Endpoint = endpoint,
                Identifier = identifier,
                DeleteEndpoint = deleteEndpoint,
                Metadata = metadata ?? new Dictionary<string, string>()
            });
        }

        /// <summary>
        /// Tracks a session
        /// </summary>
        public void TrackSession(string endpoint, string sessionId, string? deleteEndpoint = null)
        {
            TrackResource(new CreatedResource
            {
                ResourceType = ResourceType.Session,
                Endpoint = endpoint,
                Identifier = sessionId,
                DeleteEndpoint = deleteEndpoint,
                Metadata = new Dictionary<string, string> { { "sessionId", sessionId } }
            });
        }

        /// <summary>
        /// Tracks a test account
        /// </summary>
        public void TrackTestAccount(string endpoint, string accountId, string? deleteEndpoint = null)
        {
            TrackResource(new CreatedResource
            {
                ResourceType = ResourceType.TestAccount,
                Endpoint = endpoint,
                Identifier = accountId,
                DeleteEndpoint = deleteEndpoint,
                Metadata = new Dictionary<string, string> { { "accountId", accountId } }
            });
        }

        /// <summary>
        /// Gets all tracked resources
        /// </summary>
        public List<CreatedResource> GetAllResources()
        {
            return _createdResources.ToList();
        }

        /// <summary>
        /// Gets resources by type
        /// </summary>
        public List<CreatedResource> GetResourcesByType(ResourceType type)
        {
            return _createdResources.Where(r => r.ResourceType == type).ToList();
        }

        /// <summary>
        /// Gets all uploaded files
        /// </summary>
        public List<CreatedResource> GetUploadedFiles()
        {
            return GetResourcesByType(ResourceType.UploadedFile);
        }

        /// <summary>
        /// Gets all database entries
        /// </summary>
        public List<CreatedResource> GetDatabaseEntries()
        {
            return GetResourcesByType(ResourceType.DatabaseEntry);
        }

        /// <summary>
        /// Gets all sessions
        /// </summary>
        public List<CreatedResource> GetSessions()
        {
            return GetResourcesByType(ResourceType.Session);
        }

        /// <summary>
        /// Gets all test accounts
        /// </summary>
        public List<CreatedResource> GetTestAccounts()
        {
            return GetResourcesByType(ResourceType.TestAccount);
        }

        /// <summary>
        /// Clears all tracked resources (after cleanup)
        /// </summary>
        public void Clear()
        {
            while (!_createdResources.IsEmpty)
            {
                _createdResources.TryTake(out _);
            }
            _logger.Debug("Cleared all tracked resources");
        }

        /// <summary>
        /// Gets count of tracked resources
        /// </summary>
        public int Count => _createdResources.Count;
    }

    /// <summary>
    /// Represents a resource created during testing
    /// </summary>
    public class CreatedResource
    {
        public ResourceType ResourceType { get; set; }
        public string Endpoint { get; set; } = string.Empty;
        public string Identifier { get; set; } = string.Empty; // ID, filename, sessionId, etc.
        public string? DeleteEndpoint { get; set; } // Optional specific delete endpoint
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public Dictionary<string, string> Metadata { get; set; } = new();
    }

    /// <summary>
    /// Types of resources that can be created
    /// </summary>
    public enum ResourceType
    {
        UploadedFile,
        DatabaseEntry,
        Session,
        TestAccount,
        Other
    }
}


















