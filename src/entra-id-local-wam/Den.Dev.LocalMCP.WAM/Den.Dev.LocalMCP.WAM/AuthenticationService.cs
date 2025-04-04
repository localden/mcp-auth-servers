using Microsoft.Extensions.Logging;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Broker;
using Microsoft.Identity.Client.Extensions.Msal;
using System.Runtime.InteropServices;
using static System.Formats.Asn1.AsnWriter;

namespace Den.Dev.LocalMCP.WAM
{
    public class AuthenticationService
    {
        private readonly IPublicClientApplication _msalClient;
        private static ILogger<AuthenticationService> _logger;
        private const string _clientId = "b4a9dacb-4c8e-45e2-9650-9ebaf98ecc40";
        private static readonly string[] _scopes = ["User.Read"];

        private AuthenticationService(ILogger<AuthenticationService> logger, IPublicClientApplication msalClient)
        {
            _logger = logger;
            _msalClient = msalClient;
        }

        public static async Task<AuthenticationService> CreateAsync(ILogger<AuthenticationService> logger)
        {
            var storageProperties =
                new StorageCreationPropertiesBuilder("authcache.bin", Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Den.Dev.LocalMCP.WAM"))
                .Build();

            logger.LogInformation("Initializing AuthenticationService");

            var msalClient = PublicClientApplicationBuilder
                .Create(_clientId)
                .WithAuthority(AadAuthorityAudience.AzureAdMyOrg)
                .WithTenantId("b811a652-39e6-4a0c-b563-4279a1dd5012")
                .WithParentActivityOrWindow(GetConsoleOrTerminalWindow)
                .WithBroker(new BrokerOptions(BrokerOptions.OperatingSystems.Windows))
                .Build();

            var cacheHelper = await MsalCacheHelper.CreateAsync(storageProperties);
            cacheHelper.RegisterCache(msalClient.UserTokenCache);

            return new AuthenticationService(logger, msalClient);
        }

        public async Task<string> AcquireTokenAsync()
        {
            try
            {
                // Try silent authentication first
                var accounts = await _msalClient.GetAccountsAsync();
                var account = accounts.FirstOrDefault();

                AuthenticationResult? result = null;

                try
                {
                    if (account != null)
                    {
                        result = await _msalClient.AcquireTokenSilent(_scopes, account).ExecuteAsync();
                    }
                    else
                    {
                        result = await _msalClient.AcquireTokenSilent(_scopes, PublicClientApplication.OperatingSystemAccount)
                                            .ExecuteAsync();
                    }
                }
                catch (MsalUiRequiredException ex)
                {
                    result = await _msalClient.AcquireTokenInteractive(_scopes).ExecuteAsync();
                }

                return result.AccessToken;
            }
            catch (Exception ex)
            {
                throw new Exception($"Authentication failed: {ex.Message}", ex);
            }
        }

        enum GetAncestorFlags
        {
            GetParent = 1,
            GetRoot = 2,
            /// <summary>
            /// Retrieves the owned root window by walking the chain of parent and owner windows returned by GetParent.
            /// </summary>
            GetRootOwner = 3
        }

        /// <summary>
        /// Retrieves the handle to the ancestor of the specified window.
        /// </summary>
        /// <param name="hwnd">A handle to the window whose ancestor is to be retrieved.
        /// If this parameter is the desktop window, the function returns NULL. </param>
        /// <param name="flags">The ancestor to be retrieved.</param>
        /// <returns>The return value is the handle to the ancestor window.</returns>
        [DllImport("user32.dll", ExactSpelling = true)]
        private static extern IntPtr GetAncestor(IntPtr hwnd, GetAncestorFlags flags);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetConsoleWindow();

        private static IntPtr GetConsoleOrTerminalWindow()
        {
            _logger.LogInformation("Attempting to get console or terminal window handle");
            
            // Attempt 1: Get console window handle
            IntPtr consoleHandle = GetConsoleWindow();
            _logger.LogInformation($"Console handle: {consoleHandle}");
            
            // If we have a valid console handle, try to get its ancestor
            if (consoleHandle != IntPtr.Zero)
            {
                IntPtr ancestorHandle = GetAncestor(consoleHandle, GetAncestorFlags.GetRootOwner);
                _logger.LogInformation($"Ancestor handle: {ancestorHandle}");
                
                if (ancestorHandle != IntPtr.Zero)
                {
                    return ancestorHandle;
                }
                else
                {
                    _logger.LogWarning("GetAncestor returned zero, falling back to console handle");
                    return consoleHandle; // Return console handle as fallback
                }
            }
            
            // Attempt 2: Try to get parent process window handle
            try
            {
                using var currentProcess = System.Diagnostics.Process.GetCurrentProcess();
                _logger.LogInformation($"Current process ID: {currentProcess.Id}");
                
                // Try to get the current process main window handle first
                if (currentProcess.MainWindowHandle != IntPtr.Zero)
                {
                    _logger.LogInformation($"Using current process main window handle: {currentProcess.MainWindowHandle}");
                    return currentProcess.MainWindowHandle;
                }
                
                // Otherwise, try parent process
                var parentProcessId = GetParentProcessId(currentProcess.Id);
                _logger.LogInformation($"Parent process ID: {parentProcessId}");
                
                if (parentProcessId != 0)
                {
                    try
                    {
                        using var parentProcess = System.Diagnostics.Process.GetProcessById(parentProcessId);
                        var parentHandle = parentProcess.MainWindowHandle;
                        _logger.LogInformation($"Parent process handle: {parentHandle}");
                        
                        if (parentHandle != IntPtr.Zero)
                        {
                            return parentHandle;
                        }
                    }
                    catch (ArgumentException ex)
                    {
                        _logger.LogWarning($"Parent process {parentProcessId} no longer exists: {ex.Message}");
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError($"Error accessing parent process: {ex.Message}");
                    }
                }
                
                // Attempt 3: Find a suitable window from all running processes (last resort)
                _logger.LogInformation("Attempting to find other suitable window handles");
                var processes = System.Diagnostics.Process.GetProcesses();
                foreach (var possibleParent in processes)
                {
                    try
                    {
                        // Look for known terminal or shell processes
                        if ((possibleParent.ProcessName.Contains("cmd") || 
                             possibleParent.ProcessName.Contains("powershell") ||
                             possibleParent.ProcessName.Contains("terminal") ||
                             possibleParent.ProcessName.Contains("explorer")) && 
                            possibleParent.MainWindowHandle != IntPtr.Zero)
                        {
                            _logger.LogInformation($"Found potential parent window in {possibleParent.ProcessName}: {possibleParent.MainWindowHandle}");
                            return possibleParent.MainWindowHandle;
                        }
                    }
                    catch (Exception)
                    {
                        // Skip this process if we can't access it
                        continue;
                    }
                    finally
                    {
                        possibleParent.Dispose();
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to retrieve any window handle: {ex.Message}");
            }
            
            _logger.LogWarning("Returning IntPtr.Zero as window handle - authentication may require additional user interaction");
            return IntPtr.Zero;
        }

        [DllImport("ntdll.dll")]
        private static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, ref PROCESS_BASIC_INFORMATION processInformation, int processInformationLength, out int returnLength);

        private static int GetParentProcessId(int processId)
        {
            var process = System.Diagnostics.Process.GetProcessById(processId);
            var pbi = new PROCESS_BASIC_INFORMATION();
            int returnLength;
            int status = NtQueryInformationProcess(process.Handle, 0, ref pbi, Marshal.SizeOf(pbi), out returnLength);

            if (status != 0)
            {
                throw new InvalidOperationException($"NtQueryInformationProcess failed with status code {status}");
            }

            return pbi.InheritedFromUniqueProcessId.ToInt32();
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebBaseAddress;
            public IntPtr Reserved2_0;
            public IntPtr Reserved2_1;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }
    }
}
