using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Graph;
using Microsoft.Kiota.Abstractions.Authentication;
using ModelContextProtocol.Server;
using System.ComponentModel;
using System.Security.Authentication;

namespace Den.Dev.LocalMCP.WAM
{
    internal class Program
    {
        static async Task Main(string[] args)
        {
            var builder = Host.CreateApplicationBuilder(args);
            builder.Logging.AddConsole(consoleLogOptions =>
            {
                consoleLogOptions.LogToStandardErrorThreshold = LogLevel.Trace;
            });

            builder.Services
                .AddSingleton(serviceProvider =>
                {
                    var logger = serviceProvider.GetRequiredService<ILogger<AuthenticationService>>();
                    return AuthenticationService.CreateAsync(logger).GetAwaiter().GetResult();
                })
                .AddMcpServer()
                .WithStdioServerTransport()
                .WithToolsFromAssembly();
            await builder.Build().RunAsync();
        }
    }

    [McpServerToolType]
    public static class UserDataTool
    {
        [McpServerTool(Name = "GetUserDetailsFromGraph"), Description("Gets user details from Graph.")]
        public static async Task<string> GetUserDetailsFromGraph(
            IMcpServer thisServer,
            AuthenticationService authService,
            ILoggerFactory loggerFactory,
            CancellationToken cancellationToken)
        {
            var logger = loggerFactory.CreateLogger("UserDataTool");

            try
            {
                var tokenProvider = new TokenProvider(authService);
                var graphClient = new GraphServiceClient(
                            new BaseBearerTokenAuthenticationProvider(tokenProvider));

                var user = await graphClient.Me.GetAsync(cancellationToken: cancellationToken);

                if (user == null)
                {
                    logger.LogWarning("No user data returned from Graph API");
                    return "No user data available";
                }

                logger.LogInformation($"Retrieved user data for: {user.DisplayName}");

                return System.Text.Json.JsonSerializer.Serialize(user);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error retrieving user details from Graph");
                return $"Error: {ex.Message}";
            }
        }
    }

    public class TokenProvider : IAccessTokenProvider
    {
        private readonly AuthenticationService _authService;

        public TokenProvider(AuthenticationService authService)
        {
            _authService = authService ?? throw new ArgumentNullException(nameof(authService));
            AllowedHostsValidator = new AllowedHostsValidator(new[] { "graph.microsoft.com" });
        }

        public async Task<string> GetAuthorizationTokenAsync(Uri uri, Dictionary<string, object> additionalAuthenticationContext = default,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var accessToken = await _authService.AcquireTokenAsync();

                if (string.IsNullOrEmpty(accessToken))
                {
                    throw new AuthenticationException("Failed to acquire access token");
                }

                return accessToken;
            }
            catch (Exception ex)
            {
                throw new AuthenticationException($"Error acquiring access token: {ex.Message}", ex);
            }
        }

        public AllowedHostsValidator AllowedHostsValidator { get; }
    }

}
