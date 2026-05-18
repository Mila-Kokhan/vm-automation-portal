using System.Diagnostics;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders =
        ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
});

builder.Host.UseWindowsService();
builder.WebHost.UseUrls("http://0.0.0.0:5000");

// =============================
// Configuration
// =============================
builder.Configuration
    .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
    .AddJsonFile($"appsettings.{builder.Environment.EnvironmentName}.json", optional: true, reloadOnChange: true)
    .AddEnvironmentVariables();

// =============================
// Services: Local User Database + Login Auth
// =============================
var authDataDir = @"D:\vmportal\data";
Directory.CreateDirectory(authDataDir);

var authDbPath = Path.Combine(authDataDir, "portal-users.db");

builder.Services.AddDbContext<AppDbContext>(options =>
{
    options.UseSqlite($"Data Source={authDbPath}");
});

builder.Services.AddScoped<PasswordHasher<AppUser>>();

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/login.html";
        options.AccessDeniedPath = "/login.html";
        options.Cookie.Name = "VMPortalAuth";
        options.ExpireTimeSpan = TimeSpan.FromMinutes(15);
        options.SlidingExpiration = true;
    });

builder.Services.AddAuthorization();

// =============================
// Services: Rate Limiting
// =============================
builder.Services.AddRateLimiter(options =>
{
    options.AddPolicy("api", httpContext =>
    {
        var ip = httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";

        return RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: ip,
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 30,
                Window = TimeSpan.FromMinutes(1),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 0
            });
    });
});

var app = builder.Build();

app.UseForwardedHeaders();
app.UseRateLimiter();

var defaultFileOptions = new DefaultFilesOptions();
defaultFileOptions.DefaultFileNames.Clear();
defaultFileOptions.DefaultFileNames.Add("login.html");

app.UseAuthentication();
app.UseAuthorization();

app.Use(async (context, next) =>
{
    var path = context.Request.Path.Value ?? "";

    if (path.Equals("/index.html", StringComparison.OrdinalIgnoreCase) ||
        path.Equals("/", StringComparison.OrdinalIgnoreCase))
    {
        if (context.User.Identity?.IsAuthenticated != true)
        {
            context.Response.Redirect("/login.html");
            return;
        }
    }

    await next();
});

app.UseDefaultFiles(defaultFileOptions);
app.UseStaticFiles();
EnsurePortalDataStores(builder.Configuration);

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    db.Database.EnsureCreated();
}

// =============================
// Middleware: API Key Auth
// =============================
static bool RequireApiKey(HttpRequest req, IConfiguration cfg, out IResult? errorResult)
{
    errorResult = null;

    var ip = req.HttpContext.Connection.RemoteIpAddress;

    if (ip != null)
    {
        if (System.Net.IPAddress.IsLoopback(ip))
            return true;

        // Handles IPv4-mapped IPv6 addresses, e.g. ::ffff:192.168.111.50
        if (ip.IsIPv4MappedToIPv6)
            ip = ip.MapToIPv4();

        var bytes = ip.GetAddressBytes();

        if (bytes.Length == 4)
        {
            // Trust internal lab networks
            if (bytes[0] == 192 && bytes[1] == 168)
            {
                // 192.168.107.x = VM network
                // 192.168.109.x = server/internal network
                // 192.168.110.x = router/Wi-Fi network
                // 192.168.111.x = RADIUS Wi-Fi network
                if (bytes[2] == 107 || bytes[2] == 109 || bytes[2] == 110 || bytes[2] == 111)
                    return true;
            }

            // Optional college/external demo subnet
            if (bytes[0] == 172 && bytes[1] == 16 && bytes[2] == 14)
                return true;
        }
    }

    var apiKey = (req.Headers["X-Api-Key"].FirstOrDefault() ?? "").Trim();
    var expected = (cfg["Portal:ApiKey"] ?? "").Trim();

    if (string.IsNullOrWhiteSpace(expected))
    {
        errorResult = Results.Problem(
            title: "Server configuration error",
            detail: "Missing Portal:ApiKey in appsettings.json",
            statusCode: StatusCodes.Status500InternalServerError
        );
        return false;
    }

    if (string.IsNullOrWhiteSpace(apiKey) || !CryptographicEquals(apiKey, expected))
    {
        errorResult = Results.Unauthorized();
        return false;
    }

    return true;
}

// =============================
// Middleware: Session Login Auth
// =============================
static bool RequireLoggedIn(HttpRequest req, out IResult? errorResult)
{
    errorResult = null;

    if (req.HttpContext.User.Identity?.IsAuthenticated == true)
        return true;

    errorResult = Results.Unauthorized();
    return false;
}

// =============================
// API: Register
// =============================
// =============================
// API: Register
// =============================
app.MapPost("/api/register", async (
    RegisterRequest request,
    AppDbContext db,
    PasswordHasher<AppUser> passwordHasher) =>
{
    var username = SanitizePortalUsername(request.Username);

    if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(request.Password))
    {
        return Results.BadRequest(new { error = "Username and password are required." });
    }

    if (username.Length < 3)
    {
        return Results.BadRequest(new { error = "Username must be at least 3 characters." });
    }

    if (request.Password.Length < 8)
    {
        return Results.BadRequest(new { error = "Password must be at least 8 characters." });
    }

    var usernameExists = await db.Users.AnyAsync(u => u.Username == username);

    if (usernameExists)
    {
        return Results.Conflict(new { error = "Username already exists in portal database." });
    }

    var adResult = await RunPortalAdUserScriptAsync(username, request.Password);

    if (!adResult.Ok)
    {
        var detail = string.IsNullOrWhiteSpace(adResult.Error)
            ? adResult.Output
            : adResult.Error;

        return Results.BadRequest(new
        {
            error = "Failed to create user in Active Directory.",
            detail = detail.Trim()
        });
    }
    var recoveryCode = GenerateRecoveryCode();

    var user = new AppUser
    {
        Username = username,
        Role = "User",
        CreatedAt = DateTime.UtcNow
    };

    user.PasswordHash = passwordHasher.HashPassword(user, request.Password);
    user.RecoveryCodeHash = passwordHasher.HashPassword(user, recoveryCode);

    db.Users.Add(user);
    await db.SaveChangesAsync();

    return Results.Ok(new
    {
        message = "Account created successfully in portal and Active Directory.",
        username = user.Username,
        recoveryCode,
        adOutput = adResult.Output.Trim()
    });
})
.RequireRateLimiting("api");

// =============================
// API: Login
// =============================
app.MapPost("/api/login", async (
    LoginRequest request,
    AppDbContext db,
    PasswordHasher<AppUser> passwordHasher,
    HttpContext context) =>
{
    var username = SanitizePortalUsername(request.Username);

    var user = await db.Users.FirstOrDefaultAsync(u => u.Username == username);

    if (user == null)
    {
        return Results.Unauthorized();
    }

    var passwordResult = passwordHasher.VerifyHashedPassword(
        user,
        user.PasswordHash,
        request.Password
    );

    if (passwordResult == PasswordVerificationResult.Failed)
    {
        return Results.Unauthorized();
    }

    var claims = new List<Claim>
    {
        new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
        new Claim(ClaimTypes.Name, user.Username),
        new Claim(ClaimTypes.Role, user.Role)
    };

    var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
    var principal = new ClaimsPrincipal(identity);

    await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

    return Results.Ok(new
    {
        message = "Logged in successfully.",
        username = user.Username,
        role = user.Role
    });
})
.RequireRateLimiting("api");

// =============================
// API: Reset Password
// =============================
app.MapPost("/api/reset-password", async (
    ResetPasswordRequest request,
    AppDbContext db,
    PasswordHasher<AppUser> passwordHasher) =>
{
    var username = SanitizePortalUsername(request.Username);

    if (string.IsNullOrWhiteSpace(username) ||
        string.IsNullOrWhiteSpace(request.RecoveryCode) ||
        string.IsNullOrWhiteSpace(request.NewPassword))
    {
        return Results.BadRequest(new { error = "Username, recovery code, and new password are required." });
    }

    if (request.NewPassword.Length < 8)
    {
        return Results.BadRequest(new { error = "New password must be at least 8 characters." });
    }

    var user = await db.Users.FirstOrDefaultAsync(u => u.Username == username);

    if (user == null)
    {
        return Results.Unauthorized();
    }

    var recoveryResult = passwordHasher.VerifyHashedPassword(
        user,
        user.RecoveryCodeHash,
        request.RecoveryCode
    );

    if (recoveryResult == PasswordVerificationResult.Failed)
    {
        return Results.Unauthorized();
    }

    user.PasswordHash = passwordHasher.HashPassword(user, request.NewPassword);

    var newRecoveryCode = GenerateRecoveryCode();
    user.RecoveryCodeHash = passwordHasher.HashPassword(user, newRecoveryCode);

    await db.SaveChangesAsync();

    return Results.Ok(new
    {
        message = "Password reset successfully.",
        newRecoveryCode
    });
})
.RequireRateLimiting("api");

// =============================
// API: Logout
// =============================
app.MapPost("/api/logout", async (HttpContext context) =>
{
    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return Results.Ok(new { message = "Logged out." });
})
.RequireRateLimiting("api");

// =============================
// API: Current User
// =============================
app.MapGet("/api/me", (HttpContext context) =>
{
    if (context.User.Identity?.IsAuthenticated != true)
    {
        return Results.Unauthorized();
    }

    return Results.Ok(new
    {
        authenticated = true,
        username = context.User.Identity.Name,
        role = context.User.FindFirstValue(ClaimTypes.Role)
    });
})
.RequireRateLimiting("api");

// =============================
// API: Provision Single VM
// =============================
app.MapPost("/api/provision", async (HttpRequest req, IConfiguration cfg, CancellationToken ct) =>
{
    if (!RequireLoggedIn(req, out var err)) return err!;

    try
    {
        using var doc = await JsonDocument.ParseAsync(req.Body, cancellationToken: ct);
        var root = doc.RootElement;

        var (psExe, scriptPath, workingDir) = LoadProvisioningConfig(cfg, "Provisioning");

        var username = SanitizeUsername(MustString(root, "username", 1, 40));
        var memoryGB = MustInt(root, "memoryGB", 1, 256);
        var dataDiskGB = MustInt(root, "dataDiskGB", 10, 4096);
        var cpuCount = MustInt(root, "cpuCount", 1, 64);

       var portalUser = req.HttpContext.User.Identity?.Name ?? "";

var assignedUser = GetOptionalString(root, "assignedUser", 1, 120);
if (string.IsNullOrWhiteSpace(assignedUser))
    assignedUser = portalUser;

var domain = GetConfiguredDomain(cfg);
var vmNamePrefix = GetConfiguredVmPrefix(cfg);
var vmName = $"{vmNamePrefix}{username}".ToUpperInvariant();

        (memoryGB, dataDiskGB, cpuCount) = EnforceLimits(memoryGB, dataDiskGB, cpuCount);

        var jobId = Guid.NewGuid().ToString("N");

        var existingStore = await LoadVmStoreAsync(cfg, ct);
        var existingVm = existingStore.Vms.FirstOrDefault(x =>
            string.Equals(x.VmName, vmName, StringComparison.OrdinalIgnoreCase));

        if (existingVm != null)
        {
            return Results.BadRequest(new
            {
                ok = false,
                error = $"VM '{vmName}' already exists in inventory"
            });
        }

        var queuedRecord = new ProvisionJobRecord
        {
            JobId = jobId,
            Kind = "single",
            Username = username,
            CreatedByPortalUser = portalUser,
            VmName = vmName,
            AssignedUser = assignedUser,
            Domain = domain,
            MemoryGB = memoryGB,
            CpuCount = cpuCount,
            DataDiskGB = dataDiskGB,
            Prefix = "",
            Count = 1,
            PadWidth = 0,
            Status = "Queued",
            ExitCode = null,
            Output = "",
            Error = "",
            IpAddress = "",
            PublicRdpIp = "",
            ExternalRdpPort = 0,
            RdpAddress = "",
            CreatedUtc = DateTime.UtcNow,
            StartedUtc = null,
            CompletedUtc = null,
            LastUpdatedUtc = DateTime.UtcNow,
            InventoryVmId = ""
        };

        await SaveProvisionJobAsync(cfg, queuedRecord, ct);

        _ = Task.Run(async () =>
        {
            var bgRecord = queuedRecord;

            try
            {
                bgRecord.Status = "Running";
                bgRecord.StartedUtc = DateTime.UtcNow;
                bgRecord.LastUpdatedUtc = DateTime.UtcNow;
                await SaveProvisionJobAsync(cfg, bgRecord, CancellationToken.None);

                var (exitCode, stdout, stderr) = await RunPowerShellAsync(
                    psExe, scriptPath, workingDir,
                    username, memoryGB, dataDiskGB, cpuCount,
                    CancellationToken.None
                );

                var outText = (stdout ?? "").Trim();
                var errText = (stderr ?? "").Trim();

                if (outText.Length > 4000) outText = outText[..4000];
                if (errText.Length > 4000) errText = errText[..4000];

                bgRecord.ExitCode = exitCode;
                bgRecord.Output = outText;
                bgRecord.Error = errText;
                bgRecord.LastUpdatedUtc = DateTime.UtcNow;

                if (exitCode != 0)
                {
                    bgRecord.Status = "Failed";
                    bgRecord.CompletedUtc = DateTime.UtcNow;
                    await SaveProvisionJobAsync(cfg, bgRecord, CancellationToken.None);
                    return;
                }

                var vmSubnetPrefix = GetVmSubnetPrefix(cfg);
                var discoveredIp =
                    await TryGetVmIpv4FromHyperVFiltered(cfg, vmName, vmSubnetPrefix, CancellationToken.None)
                    ?? await GetVmIpv4Async(psExe, vmName, vmSubnetPrefix);

                var vmState = await TryGetVmStateFromHyperV(cfg, vmName, CancellationToken.None);

                var publicRdpIp = GetPublicRdpIp(cfg);

                if (string.IsNullOrWhiteSpace(discoveredIp))
                 throw new InvalidOperationException($"No internal IP was discovered for VM '{vmName}'.");

               var externalPort = BuildExternalRdpPortFromInternalIp(discoveredIp, cfg);

                var record = new VdiVmRecord
                {
                    VmId = Guid.NewGuid().ToString("N"),
                    VmName = vmName,
                    Username = username,
                    CreatedByPortalUser = portalUser,
                    AssignedUser = assignedUser,
                    Domain = domain,
                    IpAddress = discoveredIp ?? "",
                    Status = string.IsNullOrWhiteSpace(vmState) ? "Created" : vmState,
                    CreationDateUtc = DateTime.UtcNow,
                    MemoryGB = memoryGB,
                    CpuCount = cpuCount,
                    DataDiskGB = dataDiskGB,
                    LastKnownPowerState = string.IsNullOrWhiteSpace(vmState) ? "Unknown" : vmState,
                    LastSeenUtc = DateTime.UtcNow,
                    Source = "single",
                    Prefix = "",
                    BatchCount = 1,
                    Notes = $"Created via async /api/provision job {jobId}",
                    PublicRdpIp = publicRdpIp,
                    ExternalRdpPort = externalPort,
                    RdpReady = !string.IsNullOrWhiteSpace(discoveredIp)
                };

await UpsertVmRecordAsync(cfg, record, CancellationToken.None);

// Create Guacamole RDP connection and assign it to the AD user
try
{
    var guacResult = await RunGuacamoleConnectionScriptAsync(
        record.VmName,
        record.IpAddress,
        record.AssignedUser,
        CancellationToken.None
    );

    var guacOut = (guacResult.Output ?? "").Trim();
    var guacErr = (guacResult.Error ?? "").Trim();

    if (guacOut.Length > 1000) guacOut = guacOut[..1000];
    if (guacErr.Length > 1000) guacErr = guacErr[..1000];

    record.Notes = guacResult.ExitCode == 0
        ? $"{record.Notes} | Guacamole assigned to {record.AssignedUser}"
        : $"{record.Notes} | Guacamole assignment failed: {(string.IsNullOrWhiteSpace(guacErr) ? guacOut : guacErr)}";

    await UpsertVmRecordAsync(cfg, record, CancellationToken.None);
}
catch (Exception guacEx)
{
    record.Notes = $"{record.Notes} | Guacamole assignment error: {guacEx.Message}";
    await UpsertVmRecordAsync(cfg, record, CancellationToken.None);
}

                bgRecord.Status = "Completed";                
                bgRecord.CompletedUtc = DateTime.UtcNow;
                bgRecord.LastUpdatedUtc = DateTime.UtcNow;
                bgRecord.IpAddress = record.IpAddress;
                bgRecord.InventoryVmId = record.VmId;
                bgRecord.PublicRdpIp = record.PublicRdpIp;
                bgRecord.ExternalRdpPort = record.ExternalRdpPort;
                bgRecord.RdpAddress = BuildExternalRdpAddress(record.PublicRdpIp, record.ExternalRdpPort);

                await SaveProvisionJobAsync(cfg, bgRecord, CancellationToken.None);
            }
            catch (Exception ex)
            {
                var msg = (ex.ToString() ?? ex.Message ?? "Unknown error").Trim();
                if (msg.Length > 4000) msg = msg[..4000];

                bgRecord.Status = "Failed";
                bgRecord.Error = msg;
                bgRecord.CompletedUtc = DateTime.UtcNow;
                bgRecord.LastUpdatedUtc = DateTime.UtcNow;

                try
                {
                    await SaveProvisionJobAsync(cfg, bgRecord, CancellationToken.None);
                }
                catch
                {
                }
            }
        });

        return Results.Ok(new
        {
            ok = true,
            started = true,
            jobId,
            status = "Queued",
            message = "Provisioning started",
            inventory = new
            {
                vmId = "",
                vmName,
                ipAddress = "",
                assignedUser,
                status = "Queued",
                creationDateUtc = queuedRecord.CreatedUtc,
                memoryGB,
                cpuCount,
                dataDiskGB,
                publicRdpIp = "",
                externalRdpPort = 0,
                rdpAddress = ""
            }
        });
    }
    catch (Exception ex)
    {
        var msg = (ex.ToString() ?? ex.Message ?? "Unknown error").Trim();
        if (msg.Length > 4000) msg = msg[..4000];
        return Results.BadRequest(new { ok = false, error = msg });
    }
})
.RequireRateLimiting("api");

// =============================
// API: Provision Status
// =============================
app.MapGet("/api/provision-status/{jobId}", async (HttpRequest req, IConfiguration cfg, string jobId, CancellationToken ct) =>
{
    if (!RequireLoggedIn(req, out var err)) return err!;

    var portalUser = req.HttpContext.User.Identity?.Name ?? "";

    try
    {
        jobId = SanitizeJobId(jobId);

        var job = await LoadProvisionJobAsync(cfg, jobId, ct);
        if (job == null)
        {
            return Results.NotFound(new
            {
                ok = false,
                error = "Provisioning job not found"
            });
        }

        return Results.Ok(new
        {
            ok = true,
            job = new
            {
                job.JobId,
                job.Kind,
                job.Username,
                job.VmName,
                job.AssignedUser,
                job.Domain,
                job.MemoryGB,
                job.CpuCount,
                job.DataDiskGB,
                job.Prefix,
                job.Count,
                job.PadWidth,
                job.Status,
                job.ExitCode,
                job.Output,
                job.Error,
                job.IpAddress,
                job.PublicRdpIp,
                job.ExternalRdpPort,
                job.RdpAddress,
                job.CreatedUtc,
                job.StartedUtc,
                job.CompletedUtc,
                job.LastUpdatedUtc,
                job.InventoryVmId
            }
        });
    }
    catch (Exception ex)
    {
        var msg = (ex.ToString() ?? ex.Message ?? "Unknown error").Trim();
        if (msg.Length > 4000) msg = msg[..4000];
        return Results.BadRequest(new { ok = false, error = msg });
    }
})
.RequireRateLimiting("api");

// =============================
// API: Latest job by username
// =============================
app.MapGet("/api/provision-status/by-username/{username}", async (HttpRequest req, IConfiguration cfg, string username, CancellationToken ct) =>
{
    if (!RequireLoggedIn(req, out var err)) return err!;

    var portalUser = req.HttpContext.User.Identity?.Name ?? "";

    try
    {
        username = SanitizeUsername(username);

        var jobs = await LoadAllProvisionJobsAsync(cfg, ct);
        var found = jobs
            .Where(x => string.Equals(x.Username, username, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(x => x.CreatedUtc)
            .FirstOrDefault();

        if (found == null)
        {
            return Results.NotFound(new
            {
                ok = false,
                error = "No provisioning job found for that username"
            });
        }

        return Results.Ok(new
        {
            ok = true,
            job = new
            {
                found.JobId,
                found.Kind,
                found.Username,
                found.VmName,
                found.AssignedUser,
                found.Domain,
                found.MemoryGB,
                found.CpuCount,
                found.DataDiskGB,
                found.Prefix,
                found.Count,
                found.PadWidth,
                found.Status,
                found.ExitCode,
                found.Output,
                found.Error,
                found.IpAddress,
                found.PublicRdpIp,
                found.ExternalRdpPort,
                found.RdpAddress,
                found.CreatedUtc,
                found.StartedUtc,
                found.CompletedUtc,
                found.LastUpdatedUtc,
                found.InventoryVmId
            }
        });
    }
    catch (Exception ex)
    {
        var msg = (ex.ToString() ?? ex.Message ?? "Unknown error").Trim();
        if (msg.Length > 4000) msg = msg[..4000];
        return Results.BadRequest(new { ok = false, error = msg });
    }
})
.RequireRateLimiting("api");

// =============================
// API: Batch VMs
// =============================
app.MapPost("/api/provision-batch", async (HttpRequest req, IConfiguration cfg, CancellationToken ct) =>
{
    using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
    cts.CancelAfter(TimeSpan.FromMinutes(30));

    if (!RequireLoggedIn(req, out var err)) return err!;

    var portalUser = req.HttpContext.User.Identity?.Name ?? "";

    try
    {
        using var doc = await JsonDocument.ParseAsync(req.Body, cancellationToken: cts.Token);
        var root = doc.RootElement;

        var (psExeSingle, scriptPathSingle, workingDirSingle) =
            LoadProvisioningConfig(cfg, "Provisioning");

        var (psExeBatch, scriptPathBatch, workingDirBatch) =
            HasSection(cfg, "ProvisioningBatch")
                ? LoadProvisioningConfig(cfg, "ProvisioningBatch")
                : LoadProvisioningConfig(cfg, "Provisioning");

        var domain = GetConfiguredDomain(cfg);
        var vmNamePrefix = GetConfiguredVmPrefix(cfg);
        var publicRdpIp = GetPublicRdpIp(cfg);
        var vmSubnetPrefix = GetVmSubnetPrefix(cfg);

        if (root.TryGetProperty("vms", out var vmsEl) && vmsEl.ValueKind == JsonValueKind.Array)
        {
            var batchList = new List<(string username, int memoryGB, int dataDiskGB, int cpuCount, string assignedUser)>();

            foreach (var vm in vmsEl.EnumerateArray())
            {
                var username = SanitizeUsername(MustString(vm, "username", 1, 40));
                var memoryGB = MustInt(vm, "memoryGB", 1, 256);
                var dataDiskGB = MustInt(vm, "dataDiskGB", 10, 4096);
                var cpuCount = MustInt(vm, "cpuCount", 1, 64);
                var assignedUser = GetOptionalString(vm, "assignedUser", 1, 120);

                if (string.IsNullOrWhiteSpace(assignedUser))
                    assignedUser = username;

                (memoryGB, dataDiskGB, cpuCount) = EnforceLimits(memoryGB, dataDiskGB, cpuCount);
                batchList.Add((username, memoryGB, dataDiskGB, cpuCount, assignedUser));
            }

            if (batchList.Count == 0)
                throw new Exception("Empty 'vms' list.");

            var results = new List<object>();
            var index = 0;

            foreach (var item in batchList)
            {
                index++;

                var (exitCode, stdout, stderr) = await RunPowerShellAsync(
                    psExeSingle, scriptPathSingle, workingDirSingle,
                    item.username, item.memoryGB, item.dataDiskGB, item.cpuCount,
                    cts.Token
                );

                if (exitCode != 0)
                {
                    var errText = string.IsNullOrWhiteSpace(stderr) ? stdout : stderr;
                    errText = (errText ?? "").Trim();
                    if (errText.Length > 4000) errText = errText[..4000];

                    return Results.BadRequest(new
                    {
                        ok = false,
                        mode = "vms[]",
                        index,
                        username = item.username,
                        exitCode,
                        error = errText
                    });
                }

                var vmName = $"{vmNamePrefix}{item.username}".ToUpperInvariant();
                var discoveredIp =
    await TryGetVmIpv4FromHyperVFiltered(cfg, vmName, vmSubnetPrefix, cts.Token)
    ?? await GetVmIpv4Async(psExeSingle, vmName, vmSubnetPrefix, 24, 5);

var vmState = await TryGetVmStateFromHyperV(cfg, vmName, cts.Token);

var externalPort = 0;
if (!string.IsNullOrWhiteSpace(discoveredIp))
{
    externalPort = BuildExternalRdpPortFromInternalIp(discoveredIp, cfg);
}


                var record = new VdiVmRecord
                {
                    VmId = Guid.NewGuid().ToString("N"),
                    VmName = vmName,
                    Username = item.username,
                    CreatedByPortalUser = portalUser,
                    AssignedUser = item.assignedUser,
                    Domain = domain,
                    IpAddress = discoveredIp ?? "",
                    Status = string.IsNullOrWhiteSpace(discoveredIp)
                        ? "Created - IP Pending"
                        : (string.IsNullOrWhiteSpace(vmState) ? "Created" : vmState),
                    CreationDateUtc = DateTime.UtcNow,
                    MemoryGB = item.memoryGB,
                    CpuCount = item.cpuCount,
                    DataDiskGB = item.dataDiskGB,
                    LastKnownPowerState = string.IsNullOrWhiteSpace(vmState) ? "Unknown" : vmState,
                    LastSeenUtc = DateTime.UtcNow,
                    Source = "batch-vms-array",
                    Prefix = "",
                    BatchCount = 1,
                    Notes = "Created via /api/provision-batch using vms[]",
                    PublicRdpIp = publicRdpIp,
                    ExternalRdpPort = externalPort,
                    RdpReady = !string.IsNullOrWhiteSpace(discoveredIp)
                };

                await UpsertVmRecordAsync(cfg, record, cts.Token);

                results.Add(new
                {
                    ok = true,
                    mode = "vms[]",
                    index,
                    username = item.username,
                    exitCode,
                    vmName = record.VmName,
                    ipAddress = record.IpAddress,
                    assignedUser = record.AssignedUser,
                    status = record.Status,
                    publicRdpIp = record.PublicRdpIp,
                    externalRdpPort = record.ExternalRdpPort,
                    rdpAddress = BuildExternalRdpAddress(record.PublicRdpIp, record.ExternalRdpPort)
                });
            }

            return Results.Ok(new { ok = true, mode = "vms[]", results });
        }

        var prefix = MustString(root, "prefix", 1, 20);
        prefix = SanitizePrefix(prefix);

        var count = MustInt(root, "count", 1, 200);

        var padWidth = 2;
        if (root.TryGetProperty("padWidth", out var padEl) && padEl.ValueKind == JsonValueKind.Number)
        {
            padWidth = Math.Clamp(padEl.GetInt32(), 1, 6);
        }

        var memoryGBBatch = MustInt(root, "memoryGB", 1, 256);
        var dataDiskGBBatch = MustInt(root, "dataDiskGB", 10, 4096);
        var cpuCountBatch = MustInt(root, "cpuCount", 1, 64);

        var assignedUserPrefix = GetOptionalString(root, "assignedUserPrefix", 1, 120);

        (memoryGBBatch, dataDiskGBBatch, cpuCountBatch) = EnforceLimits(memoryGBBatch, dataDiskGBBatch, cpuCountBatch);

        var (batchExitCode, batchStdout, batchStderr) = await RunPowerShellCompanyAsync(
            psExeBatch, scriptPathBatch, workingDirBatch,
            prefix, count, padWidth, memoryGBBatch, dataDiskGBBatch, cpuCountBatch,
            cts.Token
        );

        if (batchExitCode != 0)
        {
            var errText = string.IsNullOrWhiteSpace(batchStderr) ? batchStdout : batchStderr;
            errText = (errText ?? "").Trim();
            if (errText.Length > 4000) errText = errText[..4000];

            return Results.BadRequest(new
            {
                ok = false,
                mode = "prefix/count",
                prefix,
                count,
                exitCode = batchExitCode,
                error = errText
            });
        }

        var createdRecords = new List<object>();

        for (var i = 1; i <= count; i++)
        {
            var username = $"{prefix}-{i.ToString().PadLeft(padWidth, '0')}";
            username = SanitizeUsername(username);

            var assignedUser = string.IsNullOrWhiteSpace(assignedUserPrefix)
                ? username
                : $"{assignedUserPrefix}{i.ToString().PadLeft(padWidth, '0')}";

            var vmName = $"{vmNamePrefix}{username}".ToUpperInvariant();
            var vmState = await TryGetVmStateFromHyperV(cfg, vmName, cts.Token);
            var discoveredIp =
               await TryGetVmIpv4FromHyperVFiltered(cfg, vmName, vmSubnetPrefix, cts.Token)
               ?? await GetVmIpv4Async(psExeBatch, vmName, vmSubnetPrefix, 24, 5);

            var externalPort = BuildExternalRdpPortFromInternalIp(discoveredIp, cfg);

            var record = new VdiVmRecord
            {
                VmId = Guid.NewGuid().ToString("N"),
                VmName = vmName,
                Username = username,
                CreatedByPortalUser = portalUser,
                AssignedUser = assignedUser,
                Domain = domain,
                IpAddress = discoveredIp ?? "",
                Status = string.IsNullOrWhiteSpace(discoveredIp)
                    ? "Created - IP Pending"
                    : (string.IsNullOrWhiteSpace(vmState) ? "Created" : vmState),
                CreationDateUtc = DateTime.UtcNow,
                MemoryGB = memoryGBBatch,
                CpuCount = cpuCountBatch,
                DataDiskGB = dataDiskGBBatch,
                LastKnownPowerState = string.IsNullOrWhiteSpace(vmState) ? "Unknown" : vmState,
                LastSeenUtc = DateTime.UtcNow,
                Source = "batch-prefix-count",
                Prefix = prefix,
                BatchCount = count,
                Notes = "Created via /api/provision-batch using prefix/count",
                PublicRdpIp = publicRdpIp,
                ExternalRdpPort = externalPort,
                RdpReady = !string.IsNullOrWhiteSpace(discoveredIp)
            };

            await UpsertVmRecordAsync(cfg, record, cts.Token);

            createdRecords.Add(new
            {
                vmId = record.VmId,
                vmName = record.VmName,
                username = record.Username,
                assignedUser = record.AssignedUser,
                status = record.Status,
                creationDateUtc = record.CreationDateUtc,
                memoryGB = record.MemoryGB,
                cpuCount = record.CpuCount,
                dataDiskGB = record.DataDiskGB,
                ipAddress = record.IpAddress,
                publicRdpIp = record.PublicRdpIp,
                externalRdpPort = record.ExternalRdpPort,
                rdpAddress = BuildExternalRdpAddress(record.PublicRdpIp, record.ExternalRdpPort)
            });
        }

        var outText = (batchStdout ?? "").Trim();
        if (outText.Length > 4000) outText = outText[..4000];

        return Results.Ok(new
        {
            ok = true,
            mode = "prefix/count",
            prefix,
            count,
            exitCode = batchExitCode,
            output = outText,
            results = createdRecords
        });
    }
    catch (OperationCanceledException)
    {
        return Results.StatusCode(StatusCodes.Status504GatewayTimeout);
    }
    catch (Exception ex)
    {
        var msg = (ex.ToString() ?? ex.Message ?? "Unknown error").Trim();
        if (msg.Length > 4000) msg = msg[..4000];
        return Results.BadRequest(new { ok = false, error = msg });
    }
})
.RequireRateLimiting("api");

// =============================
// API: VDI Inventory - List all VMs
// =============================
app.MapGet("/api/vms", async (HttpRequest req, IConfiguration cfg, CancellationToken ct) =>
{
    if (!RequireLoggedIn(req, out var err)) return err!;

    var portalUser = req.HttpContext.User.Identity?.Name ?? "";

    try
    {
        var store = await LoadVmStoreAsync(cfg, ct);

        var ordered = store.Vms
            .OrderByDescending(x => x.CreationDateUtc)
            .ThenBy(x => x.VmName, StringComparer.OrdinalIgnoreCase)
            .ToList();

        return Results.Ok(new
        {
            ok = true,
            count = ordered.Count,
            vms = ordered.Select(vm => new
            {
                vm.VmId,
                vm.VmName,
                vm.Username,
                vm.AssignedUser,
                vm.Domain,
                vm.IpAddress,
                vm.Status,
                vm.CreationDateUtc,
                vm.MemoryGB,
                vm.CpuCount,
                vm.DataDiskGB,
                vm.LastKnownPowerState,
                vm.LastSeenUtc,
                vm.Source,
                vm.Prefix,
                vm.BatchCount,
                vm.Notes,
                vm.PublicRdpIp,
                vm.ExternalRdpPort,
                rdpAddress = BuildExternalRdpAddress(vm.PublicRdpIp, vm.ExternalRdpPort),
                vm.RdpReady
            })
        });
    }
    catch (Exception ex)
    {
        var msg = (ex.ToString() ?? ex.Message ?? "Unknown error").Trim();
        if (msg.Length > 4000) msg = msg[..4000];
        return Results.BadRequest(new { ok = false, error = msg });
    }
})
.RequireRateLimiting("api");


// =============================
// API: My VMs - current logged-in user
// =============================
app.MapGet("/api/my-vms", async (HttpRequest req, IConfiguration cfg, CancellationToken ct) =>
{
    if (!RequireLoggedIn(req, out var err)) return err!;

    try
    {
        var portalUser = req.HttpContext.User.Identity?.Name ?? "";

        var store = await LoadVmStoreAsync(cfg, ct);

        var myVms = store.Vms
            .Where(vm => string.Equals(vm.CreatedByPortalUser, portalUser, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(vm => vm.CreationDateUtc)
            .ThenBy(vm => vm.VmName, StringComparer.OrdinalIgnoreCase)
            .ToList();

        return Results.Ok(new
        {
            ok = true,
            username = portalUser,
            count = myVms.Count,
            vms = myVms.Select(vm => new
            {
                vm.VmId,
                vm.VmName,
                vm.Username,
                vm.CreatedByPortalUser,
                vm.AssignedUser,
                vm.Domain,
                vm.IpAddress,
                vm.Status,
                vm.CreationDateUtc,
                vm.MemoryGB,
                vm.CpuCount,
                vm.DataDiskGB,
                vm.LastKnownPowerState,
                vm.LastSeenUtc,
                vm.PublicRdpIp,
                vm.ExternalRdpPort,
                rdpAddress = BuildExternalRdpAddress(vm.PublicRdpIp, vm.ExternalRdpPort),
                vm.RdpReady
            })
        });
    }
    catch (Exception ex)
    {
        var msg = (ex.ToString() ?? ex.Message ?? "Unknown error").Trim();
        if (msg.Length > 4000) msg = msg[..4000];
        return Results.BadRequest(new { ok = false, error = msg });
    }
})
.RequireRateLimiting("api");

// =============================
// API: VDI Inventory - Get one VM
// =============================
app.MapGet("/api/vms/{vmName}", async (HttpRequest req, IConfiguration cfg, string vmName, CancellationToken ct) =>
{
    if (!RequireLoggedIn(req, out var err)) return err!;

    var portalUser = req.HttpContext.User.Identity?.Name ?? "";

    try
    {
        vmName = SanitizeVmNameForLookup(vmName);

        var store = await LoadVmStoreAsync(cfg, ct);
        var found = store.Vms.FirstOrDefault(x => string.Equals(x.VmName, vmName, StringComparison.OrdinalIgnoreCase));

        if (found == null)
        {
            return Results.NotFound(new
            {
                ok = false,
                error = "VM not found in inventory"
            });
        }

        return Results.Ok(new
        {
            ok = true,
            vm = new
            {
                found.VmId,
                found.VmName,
                found.Username,
                found.AssignedUser,
                found.Domain,
                found.IpAddress,
                found.Status,
                found.CreationDateUtc,
                found.MemoryGB,
                found.CpuCount,
                found.DataDiskGB,
                found.LastKnownPowerState,
                found.LastSeenUtc,
                found.Source,
                found.Prefix,
                found.BatchCount,
                found.Notes,
                found.PublicRdpIp,
                found.ExternalRdpPort,
                rdpAddress = BuildExternalRdpAddress(found.PublicRdpIp, found.ExternalRdpPort),
                found.RdpReady
            }
        });
    }
    catch (Exception ex)
    {
        var msg = (ex.ToString() ?? ex.Message ?? "Unknown error").Trim();
        if (msg.Length > 4000) msg = msg[..4000];
        return Results.BadRequest(new { ok = false, error = msg });
    }
})
.RequireRateLimiting("api");

// =============================
// API: Refresh VM state and IP
// =============================
app.MapPost("/api/vms/{vmName}/refresh", async (HttpRequest req, IConfiguration cfg, string vmName, CancellationToken ct) =>
{
    using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
    cts.CancelAfter(TimeSpan.FromMinutes(5));

    if (!RequireLoggedIn(req, out var err)) return err!;

    var portalUser = req.HttpContext.User.Identity?.Name ?? "";

    try
    {
        vmName = SanitizeVmNameForLookup(vmName);

        var store = await LoadVmStoreAsync(cfg, cts.Token);
        var record = store.Vms.FirstOrDefault(x => string.Equals(x.VmName, vmName, StringComparison.OrdinalIgnoreCase));

        if (record == null)
        {
            return Results.NotFound(new
            {
                ok = false,
                error = "VM not found in inventory"
            });
        }

        var state = await TryGetVmStateFromHyperV(cfg, record.VmName, cts.Token);
        var ip = await TryGetVmIpv4FromHyperVFiltered(cfg, record.VmName, GetVmSubnetPrefix(cfg), cts.Token);

        if (!string.IsNullOrWhiteSpace(state))
        {
            record.Status = state;
            record.LastKnownPowerState = state;
        }

        if (!string.IsNullOrWhiteSpace(ip))
        {
            record.IpAddress = ip;
            record.PublicRdpIp = GetPublicRdpIp(cfg);
            record.ExternalRdpPort = BuildExternalRdpPortFromInternalIp(ip, cfg);
            record.RdpReady = true;
        }

        record.LastSeenUtc = DateTime.UtcNow;

        await SaveVmStoreAsync(cfg, store, cts.Token);

        return Results.Ok(new
        {
            ok = true,
            vm = new
            {
                record.VmId,
                record.VmName,
                record.Username,
                record.AssignedUser,
                record.Domain,
                record.IpAddress,
                record.Status,
                record.CreationDateUtc,
                record.MemoryGB,
                record.CpuCount,
                record.DataDiskGB,
                record.LastKnownPowerState,
                record.LastSeenUtc,
                record.Source,
                record.Prefix,
                record.BatchCount,
                record.Notes,
                record.PublicRdpIp,
                record.ExternalRdpPort,
                rdpAddress = BuildExternalRdpAddress(record.PublicRdpIp, record.ExternalRdpPort),
                record.RdpReady
            }
        });
    }
    catch (OperationCanceledException)
    {
        return Results.StatusCode(StatusCodes.Status504GatewayTimeout);
    }
    catch (Exception ex)
    {
        var msg = (ex.ToString() ?? ex.Message ?? "Unknown error").Trim();
        if (msg.Length > 4000) msg = msg[..4000];
        return Results.BadRequest(new { ok = false, error = msg });
    }
})
.RequireRateLimiting("api");

// =============================
// API: Start VM
// =============================
app.MapPost("/api/vms/{vmName}/start", async (HttpRequest req, IConfiguration cfg, string vmName, CancellationToken ct) =>
{
    using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
    cts.CancelAfter(TimeSpan.FromMinutes(10));

    if (!RequireLoggedIn(req, out var err)) return err!;

    var portalUser = req.HttpContext.User.Identity?.Name ?? "";

    try
    {
        vmName = SanitizeVmNameForLookup(vmName);

        var store = await LoadVmStoreAsync(cfg, cts.Token);
        var record = store.Vms.FirstOrDefault(x => string.Equals(x.VmName, vmName, StringComparison.OrdinalIgnoreCase));

        if (record == null)
        {
            return Results.NotFound(new
            {
                ok = false,
                error = "VM not found in inventory"
            });
        }

        var beforeState = await TryGetVmStateFromHyperV(cfg, record.VmName, cts.Token);

        if (!string.Equals(beforeState, "Running", StringComparison.OrdinalIgnoreCase))
        {
            var startResult = await StartVmHyperVAsync(cfg, record.VmName, cts.Token);
            if (startResult.exitCode != 0)
            {
                var msg = string.IsNullOrWhiteSpace(startResult.stderr)
                    ? startResult.stdout
                    : startResult.stderr;

                msg = (msg ?? "").Trim();
                if (msg.Length > 4000) msg = msg[..4000];

                return Results.BadRequest(new
                {
                    ok = false,
                    error = msg
                });
            }
        }

        var waitSeconds = GetVmStartWaitSeconds(cfg);
        var ip = "";
        var state = "";

        for (var i = 0; i < waitSeconds; i += 5)
        {
            cts.Token.ThrowIfCancellationRequested();

            state = await TryGetVmStateFromHyperV(cfg, record.VmName, cts.Token) ?? "";
            ip = await TryGetVmIpv4FromHyperVFiltered(cfg, record.VmName, GetVmSubnetPrefix(cfg), cts.Token) ?? "";

            if (string.Equals(state, "Running", StringComparison.OrdinalIgnoreCase) &&
                !string.IsNullOrWhiteSpace(ip))
            {
                break;
            }

            await Task.Delay(TimeSpan.FromSeconds(5), cts.Token);
        }

        if (!string.IsNullOrWhiteSpace(state))
        {
            record.Status = state;
            record.LastKnownPowerState = state;
        }

        if (!string.IsNullOrWhiteSpace(ip))
        {
            record.IpAddress = ip;
            record.PublicRdpIp = GetPublicRdpIp(cfg);
            record.ExternalRdpPort = BuildExternalRdpPortFromInternalIp(ip, cfg);
            record.RdpReady = true;
        }

        record.LastSeenUtc = DateTime.UtcNow;

        await SaveVmStoreAsync(cfg, store, cts.Token);

        return Results.Ok(new
        {
            ok = true,
            action = "start",
            vm = new
            {
                record.VmId,
                record.VmName,
                record.Username,
                record.AssignedUser,
                record.Domain,
                record.IpAddress,
                record.Status,
                record.CreationDateUtc,
                record.MemoryGB,
                record.CpuCount,
                record.DataDiskGB,
                record.LastKnownPowerState,
                record.LastSeenUtc,
                record.Source,
                record.Prefix,
                record.BatchCount,
                record.Notes,
                record.PublicRdpIp,
                record.ExternalRdpPort,
                rdpAddress = BuildExternalRdpAddress(record.PublicRdpIp, record.ExternalRdpPort),
                record.RdpReady
            }
        });
    }
    catch (OperationCanceledException)
    {
        return Results.StatusCode(StatusCodes.Status504GatewayTimeout);
    }
    catch (Exception ex)
    {
        var msg = (ex.ToString() ?? ex.Message ?? "Unknown error").Trim();
        if (msg.Length > 4000) msg = msg[..4000];
        return Results.BadRequest(new { ok = false, error = msg });
    }
})
.RequireRateLimiting("api");

// =============================
// API: Stop VM
// =============================
app.MapPost("/api/vms/{vmName}/stop", async (HttpRequest req, IConfiguration cfg, string vmName, CancellationToken ct) =>
{
    using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
    cts.CancelAfter(TimeSpan.FromMinutes(10));

    if (!RequireLoggedIn(req, out var err)) return err!;

    var portalUser = req.HttpContext.User.Identity?.Name ?? "";

    try
    {
        vmName = SanitizeVmNameForLookup(vmName);

        var store = await LoadVmStoreAsync(cfg, cts.Token);
        var record = store.Vms.FirstOrDefault(x => string.Equals(x.VmName, vmName, StringComparison.OrdinalIgnoreCase));

        if (record == null)
        {
            return Results.NotFound(new
            {
                ok = false,
                error = "VM not found in inventory"
            });
        }

        var stopResult = await StopVmHyperVAsync(cfg, record.VmName, cts.Token);
        if (stopResult.exitCode != 0)
        {
            var msg = string.IsNullOrWhiteSpace(stopResult.stderr)
                ? stopResult.stdout
                : stopResult.stderr;

            msg = (msg ?? "").Trim();
            if (msg.Length > 4000) msg = msg[..4000];

            return Results.BadRequest(new
            {
                ok = false,
                error = msg
            });
        }

        var state = await TryGetVmStateFromHyperV(cfg, record.VmName, cts.Token);

        if (!string.IsNullOrWhiteSpace(state))
        {
            record.Status = state;
            record.LastKnownPowerState = state;
        }
        else
        {
            record.Status = "Off";
            record.LastKnownPowerState = "Off";
        }

        record.LastSeenUtc = DateTime.UtcNow;

        await SaveVmStoreAsync(cfg, store, cts.Token);

        return Results.Ok(new
        {
            ok = true,
            action = "stop",
            vm = new
            {
                record.VmId,
                record.VmName,
                record.Username,
                record.AssignedUser,
                record.Domain,
                record.IpAddress,
                record.Status,
                record.CreationDateUtc,
                record.MemoryGB,
                record.CpuCount,
                record.DataDiskGB,
                record.LastKnownPowerState,
                record.LastSeenUtc,
                record.Source,
                record.Prefix,
                record.BatchCount,
                record.Notes,
                record.PublicRdpIp,
                record.ExternalRdpPort,
                rdpAddress = BuildExternalRdpAddress(record.PublicRdpIp, record.ExternalRdpPort),
                record.RdpReady
            }
        });
    }
    catch (OperationCanceledException)
    {
        return Results.StatusCode(StatusCodes.Status504GatewayTimeout);
    }
    catch (Exception ex)
    {
        var msg = (ex.ToString() ?? ex.Message ?? "Unknown error").Trim();
        if (msg.Length > 4000) msg = msg[..4000];
        return Results.BadRequest(new { ok = false, error = msg });
    }
})
.RequireRateLimiting("api");

// =============================
// API: Delete VM
// =============================
app.MapDelete("/api/vms/{vmName}", async (HttpRequest req, IConfiguration cfg, string vmName, CancellationToken ct) =>
{
    using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
    cts.CancelAfter(TimeSpan.FromMinutes(15));

    if (!RequireLoggedIn(req, out var err)) return err!;

    var portalUser = req.HttpContext.User.Identity?.Name ?? "";

    try
    {
        vmName = SanitizeVmNameForLookup(vmName);

        var store = await LoadVmStoreAsync(cfg, cts.Token);
        var record = store.Vms.FirstOrDefault(x => string.Equals(x.VmName, vmName, StringComparison.OrdinalIgnoreCase));

        if (record == null)
        {
            return Results.NotFound(new
            {
                ok = false,
                error = "VM not found in inventory"
            });
        }

        var deleteResult = await RemoveVmHyperVAsync(cfg, record.VmName, cts.Token);
        if (deleteResult.exitCode != 0)
        {
            var msg = string.IsNullOrWhiteSpace(deleteResult.stderr)
                ? deleteResult.stdout
                : deleteResult.stderr;

            msg = (msg ?? "").Trim();
            if (msg.Length > 4000) msg = msg[..4000];

            return Results.BadRequest(new
            {
                ok = false,
                error = msg
            });
        }

        var releasedPort = record.ExternalRdpPort;

        store.Vms.RemoveAll(x => string.Equals(x.VmName, record.VmName, StringComparison.OrdinalIgnoreCase));
        await SaveVmStoreAsync(cfg, store, cts.Token);

        return Results.Ok(new
        {
            ok = true,
            action = "delete",
            vmName = record.VmName,
            releasedPort
        });
    }
    catch (OperationCanceledException)
    {
        return Results.StatusCode(StatusCodes.Status504GatewayTimeout);
    }
    catch (Exception ex)
    {
        var msg = (ex.ToString() ?? ex.Message ?? "Unknown error").Trim();
        if (msg.Length > 4000) msg = msg[..4000];
        return Results.BadRequest(new { ok = false, error = msg });
    }
})
.RequireRateLimiting("api");

// =============================
// API: Generate RDP file
// =============================
app.MapGet("/api/vms/{vmName}/rdp", async (HttpRequest req, IConfiguration cfg, string vmName, CancellationToken ct) =>
{
    using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
    cts.CancelAfter(TimeSpan.FromMinutes(3));

    if (!RequireLoggedIn(req, out var err)) return err!;

    var portalUser = req.HttpContext.User.Identity?.Name ?? "";

    try
    {
        vmName = SanitizeVmNameForLookup(vmName);

        var store = await LoadVmStoreAsync(cfg, cts.Token);
        var record = store.Vms.FirstOrDefault(x => string.Equals(x.VmName, vmName, StringComparison.OrdinalIgnoreCase));

        if (record == null)
        {
            return Results.NotFound(new
            {
                ok = false,
                error = "VM not found in inventory"
            });
        }

        if (string.IsNullOrWhiteSpace(record.IpAddress))
        {
            var refreshedIp = await TryGetVmIpv4FromHyperVFiltered(cfg, record.VmName, GetVmSubnetPrefix(cfg), cts.Token);
            if (!string.IsNullOrWhiteSpace(refreshedIp))
            {
             record.IpAddress = refreshedIp;
             record.PublicRdpIp = GetPublicRdpIp(cfg);
             record.ExternalRdpPort = BuildExternalRdpPortFromInternalIp(refreshedIp, cfg);
             record.RdpReady = true;
             record.LastSeenUtc = DateTime.UtcNow;
             await SaveVmStoreAsync(cfg, store, cts.Token);
            }
            if (!string.IsNullOrWhiteSpace(refreshedIp))
            {
                record.IpAddress = refreshedIp;
                record.RdpReady = true;
                record.LastSeenUtc = DateTime.UtcNow;
                await SaveVmStoreAsync(cfg, store, cts.Token);
            }
        }

        if (string.IsNullOrWhiteSpace(record.IpAddress) && string.IsNullOrWhiteSpace(record.PublicRdpIp))
        {
            return Results.BadRequest(new
            {
                ok = false,
                error = "VM IP address is not known yet"
            });
        }

        var usernameForRdp = BuildRdpUsername(record.Domain, record.AssignedUser);
        var targetAddress = BuildBestRdpTarget(record);
        var rdpText = BuildRdpFile(targetAddress, usernameForRdp, cfg);

        var bytes = Encoding.UTF8.GetBytes(rdpText);
        var fileName = $"{record.VmName}.rdp";

        return Results.File(
            fileContents: bytes,
            contentType: "application/x-rdp",
            fileDownloadName: fileName
        );
    }
    catch (OperationCanceledException)
    {
        return Results.StatusCode(StatusCodes.Status504GatewayTimeout);
    }
    catch (Exception ex)
    {
        var msg = (ex.ToString() ?? ex.Message ?? "Unknown error").Trim();
        if (msg.Length > 4000) msg = msg[..4000];
        return Results.BadRequest(new { ok = false, error = msg });
    }
})
.RequireRateLimiting("api");

// =============================
// API: Connect
// =============================
app.MapPost("/api/vms/{vmName}/connect", async (HttpRequest req, IConfiguration cfg, string vmName, CancellationToken ct) =>
{
    using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
    cts.CancelAfter(TimeSpan.FromMinutes(10));

    if (!RequireLoggedIn(req, out var err)) return err!;

    var portalUser = req.HttpContext.User.Identity?.Name ?? "";

    try
    {
        vmName = SanitizeVmNameForLookup(vmName);

        var store = await LoadVmStoreAsync(cfg, cts.Token);
        var record = store.Vms.FirstOrDefault(x => string.Equals(x.VmName, vmName, StringComparison.OrdinalIgnoreCase));

        if (record == null)
        {
            return Results.NotFound(new
            {
                ok = false,
                error = "VM not found in inventory"
            });
        }

        var state = await TryGetVmStateFromHyperV(cfg, record.VmName, cts.Token);

        if (!string.Equals(state, "Running", StringComparison.OrdinalIgnoreCase))
        {
            var startResult = await StartVmHyperVAsync(cfg, record.VmName, cts.Token);
            if (startResult.exitCode != 0)
            {
                var msg = string.IsNullOrWhiteSpace(startResult.stderr)
                    ? startResult.stdout
                    : startResult.stderr;

                msg = (msg ?? "").Trim();
                if (msg.Length > 4000) msg = msg[..4000];

                return Results.BadRequest(new
                {
                    ok = false,
                    error = msg
                });
            }
        }

        var waitSeconds = GetVmStartWaitSeconds(cfg);
        var ip = "";
        var latestState = "";

        for (var i = 0; i < waitSeconds; i += 5)
        {
            cts.Token.ThrowIfCancellationRequested();

            latestState = await TryGetVmStateFromHyperV(cfg, record.VmName, cts.Token) ?? "";
            ip = await TryGetVmIpv4FromHyperVFiltered(cfg, record.VmName, GetVmSubnetPrefix(cfg), cts.Token) ?? "";

            if (string.Equals(latestState, "Running", StringComparison.OrdinalIgnoreCase) &&
                !string.IsNullOrWhiteSpace(ip))
            {
                break;
            }

            await Task.Delay(TimeSpan.FromSeconds(5), cts.Token);
        }

        if (!string.IsNullOrWhiteSpace(latestState))
        {
            record.Status = latestState;
            record.LastKnownPowerState = latestState;
        }

        if (!string.IsNullOrWhiteSpace(ip))
        {
            record.IpAddress = ip;
            record.PublicRdpIp = GetPublicRdpIp(cfg);
            record.ExternalRdpPort = BuildExternalRdpPortFromInternalIp(ip, cfg);
            record.RdpReady = true;
        }

        record.LastSeenUtc = DateTime.UtcNow;

        await SaveVmStoreAsync(cfg, store, cts.Token);

        if (string.IsNullOrWhiteSpace(record.IpAddress) && string.IsNullOrWhiteSpace(record.PublicRdpIp))
        {
            return Results.BadRequest(new
            {
                ok = false,
                error = "VM started but no usable RDP target could be determined yet"
            });
        }

        var usernameForRdp = BuildRdpUsername(record.Domain, record.AssignedUser);
        var targetAddress = BuildBestRdpTarget(record);
        var rdpText = BuildRdpFile(targetAddress, usernameForRdp, cfg);

        return Results.Ok(new
        {
            ok = true,
            action = "connect",
            vm = new
            {
                record.VmId,
                record.VmName,
                record.Username,
                record.AssignedUser,
                record.Domain,
                record.IpAddress,
                record.Status,
                record.CreationDateUtc,
                record.MemoryGB,
                record.CpuCount,
                record.DataDiskGB,
                record.LastKnownPowerState,
                record.LastSeenUtc,
                record.Source,
                record.Prefix,
                record.BatchCount,
                record.Notes,
                record.PublicRdpIp,
                record.ExternalRdpPort,
                rdpAddress = BuildExternalRdpAddress(record.PublicRdpIp, record.ExternalRdpPort),
                record.RdpReady
            },
            rdp = new
            {
                fullAddress = targetAddress,
                username = usernameForRdp,
                content = rdpText
            }
        });
    }
    catch (OperationCanceledException)
    {
        return Results.StatusCode(StatusCodes.Status504GatewayTimeout);
    }
    catch (Exception ex)
    {
        var msg = (ex.ToString() ?? ex.Message ?? "Unknown error").Trim();
        if (msg.Length > 4000) msg = msg[..4000];
        return Results.BadRequest(new { ok = false, error = msg });
    }
})
.RequireRateLimiting("api");

// =============================
// API: Assign VM to a specific user
// =============================
app.MapPost("/api/vms/{vmName}/assign", async (HttpRequest req, IConfiguration cfg, string vmName, CancellationToken ct) =>
{
    using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
    cts.CancelAfter(TimeSpan.FromMinutes(5));

    if (!RequireLoggedIn(req, out var err)) return err!;

    var portalUser = req.HttpContext.User.Identity?.Name ?? "";

    try
    {
        vmName = SanitizeVmNameForLookup(vmName);

        using var doc = await JsonDocument.ParseAsync(req.Body, cancellationToken: cts.Token);
        var root = doc.RootElement;

        var assignedUser = MustString(root, "assignedUser", 1, 120).Trim();
        var updateLocalRdpGroup = GetOptionalBool(root, "updateLocalRdpGroup") ?? false;

        var store = await LoadVmStoreAsync(cfg, cts.Token);
        var record = store.Vms.FirstOrDefault(x => string.Equals(x.VmName, vmName, StringComparison.OrdinalIgnoreCase));

        if (record == null)
        {
            return Results.NotFound(new
            {
                ok = false,
                error = "VM not found in inventory"
            });
        }

        record.AssignedUser = assignedUser;
        record.LastSeenUtc = DateTime.UtcNow;
        record.Notes = $"Assigned to {assignedUser} on {DateTime.UtcNow:O}";

        await SaveVmStoreAsync(cfg, store, cts.Token);

        if (updateLocalRdpGroup)
        {
            var domain = string.IsNullOrWhiteSpace(record.Domain) ? GetConfiguredDomain(cfg) : record.Domain;
            var fullPrincipal = BuildRdpUsername(domain, assignedUser);

            var addResult = await AddUserToRemoteDesktopUsersAsync(cfg, record.VmName, fullPrincipal, cts.Token);

            if (addResult.exitCode != 0)
            {
                var msg = string.IsNullOrWhiteSpace(addResult.stderr)
                    ? addResult.stdout
                    : addResult.stderr;

                msg = (msg ?? "").Trim();
                if (msg.Length > 4000) msg = msg[..4000];

                return Results.BadRequest(new
                {
                    ok = false,
                    error = msg,
                    vm = record
                });
            }
        }

        return Results.Ok(new
        {
            ok = true,
            action = "assign",
            vm = new
            {
                record.VmId,
                record.VmName,
                record.Username,
                record.AssignedUser,
                record.Domain,
                record.IpAddress,
                record.Status,
                record.CreationDateUtc,
                record.MemoryGB,
                record.CpuCount,
                record.DataDiskGB,
                record.LastKnownPowerState,
                record.LastSeenUtc,
                record.Source,
                record.Prefix,
                record.BatchCount,
                record.Notes,
                record.PublicRdpIp,
                record.ExternalRdpPort,
                rdpAddress = BuildExternalRdpAddress(record.PublicRdpIp, record.ExternalRdpPort),
                record.RdpReady
            }
        });
    }
    catch (OperationCanceledException)
    {
        return Results.StatusCode(StatusCodes.Status504GatewayTimeout);
    }
    catch (Exception ex)
    {
        var msg = (ex.ToString() ?? ex.Message ?? "Unknown error").Trim();
        if (msg.Length > 4000) msg = msg[..4000];
        return Results.BadRequest(new { ok = false, error = msg });
    }
})
.RequireRateLimiting("api");

app.Run();

// =============================
// Helpers
// =============================

static async Task<(int ExitCode, string Output, string Error)> RunGuacamoleConnectionScriptAsync(
    string vmName,
    string vmIp,
    string assignedUser,
    CancellationToken ct)
{
    var scriptPath = @"D:\HyperV\Scripts\New-GuacamoleConnection.ps1";

    var args = new List<string>
    {
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", $"\"{scriptPath}\"",
        "-VmName", $"\"{vmName.Replace("\"", "\\\"")}\"",
        "-VmIp", $"\"{vmIp.Replace("\"", "\\\"")}\"",
        "-AssignedUser", $"\"{assignedUser.Replace("\"", "\\\"")}\""
    };

    var psi = new ProcessStartInfo
    {
        FileName = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        Arguments = string.Join(" ", args),
        UseShellExecute = false,
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        CreateNoWindow = true
    };

    using var p = new Process { StartInfo = psi };

    var stdout = new StringBuilder();
    var stderr = new StringBuilder();

    p.OutputDataReceived += (_, e) => { if (e.Data != null) stdout.AppendLine(e.Data); };
    p.ErrorDataReceived += (_, e) => { if (e.Data != null) stderr.AppendLine(e.Data); };

    p.Start();
    p.BeginOutputReadLine();
    p.BeginErrorReadLine();

    await p.WaitForExitAsync(ct);

    return (p.ExitCode, stdout.ToString(), stderr.ToString());
}

static async Task<(bool Ok, string Output, string Error)> RunPortalAdUserScriptAsync(
    string username,
    string password)
{
    var scriptPath = @"D:\HyperV\Scripts\New-PortalADUser.ps1";

    var args = new List<string>
    {
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", $"\"{scriptPath}\"",
        "-Username", $"\"{username.Replace("\"", "\\\"")}\"",
        "-Password", $"\"{password.Replace("\"", "\\\"")}\""
    };

    var psi = new ProcessStartInfo
    {
        FileName = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        Arguments = string.Join(" ", args),
        UseShellExecute = false,
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        CreateNoWindow = true
    };

    using var p = new Process { StartInfo = psi };

    var stdout = new StringBuilder();
    var stderr = new StringBuilder();

    p.OutputDataReceived += (_, e) => { if (e.Data != null) stdout.AppendLine(e.Data); };
    p.ErrorDataReceived += (_, e) => { if (e.Data != null) stderr.AppendLine(e.Data); };

    p.Start();
    p.BeginOutputReadLine();
    p.BeginErrorReadLine();

    await p.WaitForExitAsync();

    return (p.ExitCode == 0, stdout.ToString(), stderr.ToString());
}

static bool HasSection(IConfiguration cfg, string sectionName)
{
    var sec = cfg.GetSection(sectionName);
    return sec.Exists() && (sec["PowerShellExe"] != null || sec["ScriptPath"] != null || sec["WorkingDir"] != null);
}

static int GetNextFreeRdpPort(VdiVmStore store, int startPort, int endPort)
{
    var usedPorts = store.Vms
        .Where(v => v.ExternalRdpPort > 0)
        .Select(v => v.ExternalRdpPort)
        .ToHashSet();

    for (int port = startPort; port <= endPort; port++)
    {
        if (!usedPorts.Contains(port))
            return port;
    }

    throw new InvalidOperationException("No free external RDP ports available.");
}

static int BuildExternalRdpPortFromInternalIp(string internalIp, IConfiguration cfg)
{
    if (string.IsNullOrWhiteSpace(internalIp))
        throw new InvalidOperationException("Cannot build external RDP port because internal IP is missing.");

    var subnetPrefix = GetVmSubnetPrefix(cfg);

    if (!internalIp.StartsWith(subnetPrefix, StringComparison.OrdinalIgnoreCase))
        throw new InvalidOperationException($"Internal IP '{internalIp}' is outside expected subnet '{subnetPrefix}*'.");

    var parts = internalIp.Split('.', StringSplitOptions.RemoveEmptyEntries);
    if (parts.Length != 4)
        throw new InvalidOperationException($"Invalid IPv4 address '{internalIp}'.");

    if (!int.TryParse(parts[3], out var lastOctet))
        throw new InvalidOperationException($"Invalid IPv4 last octet in '{internalIp}'.");

    if (lastOctet < 1 || lastOctet > 254)
        throw new InvalidOperationException($"Invalid IPv4 last octet '{lastOctet}' in '{internalIp}'.");

    return 5000 + lastOctet;
}

static string BuildExternalRdpAddress(string publicIp, int externalPort)
{
    if (string.IsNullOrWhiteSpace(publicIp) || externalPort <= 0)
        return "";

    return $"{publicIp}:{externalPort}";
}

static string BuildBestRdpTarget(VdiVmRecord record)
{
    if (!string.IsNullOrWhiteSpace(record.PublicRdpIp) && record.ExternalRdpPort > 0)
        return $"{record.PublicRdpIp}:{record.ExternalRdpPort}";

    return record.IpAddress;
}

static async Task<string?> GetVmIpv4Async(
    string powerShellExe,
    string vmName,
    string subnetPrefix,
    int maxAttempts = 18,
    int delaySeconds = 10)
{
    for (int i = 0; i < maxAttempts; i++)
    {
        var ps = @$"
$ip = (Get-VMNetworkAdapter -VMName '{vmName}').IPAddresses |
    Where-Object {{ $_ -match '^\d+\.\d+\.\d+\.\d+$' -and $_ -like '{subnetPrefix}*' }} |
    Select-Object -First 1
if ($ip) {{ Write-Output $ip }}
";

        var psi = new ProcessStartInfo
        {
            FileName = powerShellExe,
            Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"{ps.Replace("\"", "\\\"").Replace("\r", "").Replace("\n", " ")}\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var proc = new Process { StartInfo = psi };
        proc.Start();

        var stdout = await proc.StandardOutput.ReadToEndAsync();
        _ = await proc.StandardError.ReadToEndAsync();
        await proc.WaitForExitAsync();

        var ip = stdout.Trim();
        if (!string.IsNullOrWhiteSpace(ip))
            return ip;

        await Task.Delay(TimeSpan.FromSeconds(delaySeconds));
    }

    return null;
}

static (string psExe, string scriptPath, string workingDir) LoadProvisioningConfig(IConfiguration cfg, string sectionName)
{
    var sec = cfg.GetSection(sectionName);

    var psExe = sec["PowerShellExe"];
    var scriptPath = sec["ScriptPath"];
    var workingDir = sec["WorkingDir"];

    if (string.IsNullOrWhiteSpace(psExe)) throw new Exception($"Missing {sectionName}:PowerShellExe");
    if (string.IsNullOrWhiteSpace(scriptPath)) throw new Exception($"Missing {sectionName}:ScriptPath");
    if (string.IsNullOrWhiteSpace(workingDir)) throw new Exception($"Missing {sectionName}:WorkingDir");

    return (psExe, scriptPath, workingDir);
}

static string GetPortalDataDirectory(IConfiguration cfg)
{
    var configured = (cfg["Portal:DataDirectory"] ?? "").Trim();
    if (!string.IsNullOrWhiteSpace(configured))
        return configured;

    return Path.Combine(AppContext.BaseDirectory, "data");
}

static string GetVmInventoryFilePath(IConfiguration cfg)
{
    var configured = (cfg["Portal:VmInventoryFile"] ?? "").Trim();
    if (!string.IsNullOrWhiteSpace(configured))
        return configured;

    return Path.Combine(GetPortalDataDirectory(cfg), "vms.json");
}

static string GetProvisionJobsDirectory(IConfiguration cfg)
{
    return Path.Combine(GetPortalDataDirectory(cfg), "jobs");
}

static string GetProvisionJobFilePath(IConfiguration cfg, string jobId)
{
    jobId = SanitizeJobId(jobId);
    return Path.Combine(GetProvisionJobsDirectory(cfg), $"{jobId}.json");
}

static string GetConfiguredDomain(IConfiguration cfg)
{
    var domain = (cfg["Portal:Domain"] ?? "").Trim();
    if (string.IsNullOrWhiteSpace(domain))
        domain = Environment.MachineName;

    return domain;
}

static string GetConfiguredVmPrefix(IConfiguration cfg)
{
    var value = (cfg["Portal:VmNamePrefix"] ?? "").Trim();
    if (string.IsNullOrWhiteSpace(value))
        value = "VM-";

    return value;
}

static int GetVmStartWaitSeconds(IConfiguration cfg)
{
    var raw = (cfg["Portal:VmStartWaitSeconds"] ?? "").Trim();
    if (int.TryParse(raw, out var n))
        return Math.Clamp(n, 10, 600);

    return 60;
}

static string GetHyperVManagerHost(IConfiguration cfg)
{
    var value = (cfg["HyperV:Host"] ?? "").Trim();
    if (string.IsNullOrWhiteSpace(value))
        value = Environment.MachineName;

    return value;
}

static string GetPublicRdpIp(IConfiguration cfg)
{
    var value = (cfg["Portal:PublicRdpIp"] ?? "").Trim();

    if (string.IsNullOrWhiteSpace(value))
        throw new InvalidOperationException("Portal:PublicRdpIp is missing in appsettings.json.");

    return value;
}

static int GetRdpPortRangeStart(IConfiguration cfg)
{
    var raw = (cfg["Portal:RdpPortRangeStart"] ?? "").Trim();
    if (int.TryParse(raw, out var n))
        return Math.Clamp(n, 1025, 65535);

    return 5001;
}

static int GetRdpPortRangeEnd(IConfiguration cfg)
{
    var raw = (cfg["Portal:RdpPortRangeEnd"] ?? "").Trim();
    if (int.TryParse(raw, out var n))
        return Math.Clamp(n, 1025, 65535);

    return 5099;
}

static string GetVmSubnetPrefix(IConfiguration cfg)
{
    var value = (cfg["Portal:VmSubnetPrefix"] ?? "").Trim();
    if (string.IsNullOrWhiteSpace(value))
        return "192.168.107.";

    return value;
}

static void EnsurePortalDataStores(IConfiguration cfg)
{
    var dir = GetPortalDataDirectory(cfg);
    Directory.CreateDirectory(dir);

    var inventoryPath = GetVmInventoryFilePath(cfg);
    var inventoryDir = Path.GetDirectoryName(inventoryPath);
    if (!string.IsNullOrWhiteSpace(inventoryDir))
        Directory.CreateDirectory(inventoryDir);

    var jobsDir = GetProvisionJobsDirectory(cfg);
    Directory.CreateDirectory(jobsDir);

    if (!File.Exists(inventoryPath))
    {
        var initial = JsonSerializer.Serialize(new VdiVmStore(), GetJsonOptions());
        File.WriteAllText(inventoryPath, initial, Encoding.UTF8);
    }
}

static JsonSerializerOptions GetJsonOptions()
{
    return new JsonSerializerOptions
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };
}

static Task<VdiVmStore> LoadVmStoreAsync(IConfiguration cfg, CancellationToken ct)
{
    lock (VmInventoryLock)
    {
        var path = GetVmInventoryFilePath(cfg);
        if (!File.Exists(path))
            return Task.FromResult(new VdiVmStore());

        var json = File.ReadAllText(path, Encoding.UTF8);
        if (string.IsNullOrWhiteSpace(json))
            return Task.FromResult(new VdiVmStore());

        var store = JsonSerializer.Deserialize<VdiVmStore>(json, GetJsonOptions());
        return Task.FromResult(store ?? new VdiVmStore());
    }
}

static Task SaveVmStoreAsync(IConfiguration cfg, VdiVmStore store, CancellationToken ct)
{
    lock (VmInventoryLock)
    {
        var path = GetVmInventoryFilePath(cfg);
        var json = JsonSerializer.Serialize(store, GetJsonOptions());
        File.WriteAllText(path, json, Encoding.UTF8);
    }

    return Task.CompletedTask;
}

static async Task UpsertVmRecordAsync(IConfiguration cfg, VdiVmRecord record, CancellationToken ct)
{
    var store = await LoadVmStoreAsync(cfg, ct);

    var existing = store.Vms.FirstOrDefault(x =>
        string.Equals(x.VmName, record.VmName, StringComparison.OrdinalIgnoreCase));

    if (existing == null)
    {
        store.Vms.Add(record);
    }
    else
    {
        existing.Username = record.Username;
        existing.CreatedByPortalUser = record.CreatedByPortalUser;
        existing.AssignedUser = record.AssignedUser;
        existing.Domain = record.Domain;
        existing.IpAddress = record.IpAddress;
        existing.Status = record.Status;
        existing.CreationDateUtc = record.CreationDateUtc;
        existing.MemoryGB = record.MemoryGB;
        existing.CpuCount = record.CpuCount;
        existing.DataDiskGB = record.DataDiskGB;
        existing.LastKnownPowerState = record.LastKnownPowerState;
        existing.LastSeenUtc = record.LastSeenUtc;
        existing.Source = record.Source;
        existing.Prefix = record.Prefix;
        existing.BatchCount = record.BatchCount;
        existing.Notes = record.Notes;
        existing.PublicRdpIp = record.PublicRdpIp;
        existing.ExternalRdpPort = record.ExternalRdpPort;
        existing.RdpReady = record.RdpReady;
    }

    await SaveVmStoreAsync(cfg, store, ct);
}

static Task SaveProvisionJobAsync(IConfiguration cfg, ProvisionJobRecord record, CancellationToken ct)
{
    lock (ProvisionJobsLock)
    {
        record.JobId = SanitizeJobId(record.JobId);
        record.LastUpdatedUtc = DateTime.UtcNow;

        var path = GetProvisionJobFilePath(cfg, record.JobId);
        var dir = Path.GetDirectoryName(path);

        if (!string.IsNullOrWhiteSpace(dir))
            Directory.CreateDirectory(dir);

        var json = JsonSerializer.Serialize(record, GetJsonOptions());

        var tempPath = path + ".tmp";

        File.WriteAllText(tempPath, json, Encoding.UTF8);

        if (File.Exists(path))
        {
            File.Replace(tempPath, path, null);
        }
        else
        {
            File.Move(tempPath, path);
        }
    }

    return Task.CompletedTask;
}

static Task<ProvisionJobRecord?> LoadProvisionJobAsync(IConfiguration cfg, string jobId, CancellationToken ct)
{
    lock (ProvisionJobsLock)
    {
        jobId = SanitizeJobId(jobId);

        var path = GetProvisionJobFilePath(cfg, jobId);
        if (!File.Exists(path))
            return Task.FromResult<ProvisionJobRecord?>(null);

        var json = File.ReadAllText(path, Encoding.UTF8);
        if (string.IsNullOrWhiteSpace(json))
            return Task.FromResult<ProvisionJobRecord?>(null);

        var record = JsonSerializer.Deserialize<ProvisionJobRecord>(json, GetJsonOptions());
        return Task.FromResult(record);
    }
}

static Task<List<ProvisionJobRecord>> LoadAllProvisionJobsAsync(IConfiguration cfg, CancellationToken ct)
{
    lock (ProvisionJobsLock)
    {
        var dir = GetProvisionJobsDirectory(cfg);
        Directory.CreateDirectory(dir);

        var files = Directory.GetFiles(dir, "*.json", SearchOption.TopDirectoryOnly);
        var results = new List<ProvisionJobRecord>();

        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();

            try
            {
                var json = File.ReadAllText(file, Encoding.UTF8);
                if (string.IsNullOrWhiteSpace(json))
                    continue;

                var record = JsonSerializer.Deserialize<ProvisionJobRecord>(json, GetJsonOptions());
                if (record != null)
                    results.Add(record);
            }
            catch
            {
            }
        }

        return Task.FromResult(results);
    }
}

static (int memoryGB, int dataDiskGB, int cpuCount) EnforceLimits(int memoryGB, int dataDiskGB, int cpuCount)
{
    memoryGB = Math.Clamp(memoryGB, 1, 64);
    dataDiskGB = Math.Clamp(dataDiskGB, 10, 2048);
    cpuCount = Math.Clamp(cpuCount, 1, 16);
    return (memoryGB, dataDiskGB, cpuCount);
}

static string MustString(JsonElement root, string name, int minLen, int maxLen)
{
    if (!root.TryGetProperty(name, out var el) || el.ValueKind != JsonValueKind.String)
        throw new Exception($"Missing or invalid '{name}'");

    var s = (el.GetString() ?? "").Trim();
    if (s.Length < minLen || s.Length > maxLen)
        throw new Exception($"'{name}' length must be between {minLen} and {maxLen}");

    return s;
}

static string? GetOptionalString(JsonElement root, string name, int minLen, int maxLen)
{
    if (!root.TryGetProperty(name, out var el))
        return null;

    if (el.ValueKind == JsonValueKind.Null)
        return null;

    if (el.ValueKind != JsonValueKind.String)
        throw new Exception($"Invalid '{name}'");

    var s = (el.GetString() ?? "").Trim();
    if (string.IsNullOrWhiteSpace(s))
        return null;

    if (s.Length < minLen || s.Length > maxLen)
        throw new Exception($"'{name}' length must be between {minLen} and {maxLen}");

    return s;
}

static bool? GetOptionalBool(JsonElement root, string name)
{
    if (!root.TryGetProperty(name, out var el))
        return null;

    if (el.ValueKind == JsonValueKind.True) return true;
    if (el.ValueKind == JsonValueKind.False) return false;
    if (el.ValueKind == JsonValueKind.Null) return null;

    throw new Exception($"Invalid '{name}'");
}

static int MustInt(JsonElement root, string name, int min, int max)
{
    if (!root.TryGetProperty(name, out var el) || el.ValueKind != JsonValueKind.Number)
        throw new Exception($"Missing or invalid '{name}'");

    var v = el.GetInt32();
    if (v < min || v > max)
        throw new Exception($"'{name}' must be between {min} and {max}");

    return v;
}

static string SanitizeUsername(string s)
{
    s = (s ?? "").Trim();

    var sb = new StringBuilder(s.Length);
    foreach (var ch in s)
    {
        if (char.IsLetterOrDigit(ch) || ch == '-' || ch == '_') sb.Append(ch);
    }

    var cleaned = sb.ToString();
    if (string.IsNullOrWhiteSpace(cleaned)) throw new Exception("Invalid username.");
    if (cleaned.Length > 40) cleaned = cleaned[..40];
    return cleaned;
}

static string SanitizePrefix(string s)
{
    s = (s ?? "").Trim();

    var sb = new StringBuilder(s.Length);
    foreach (var ch in s)
    {
        if (char.IsLetterOrDigit(ch) || ch == '-' || ch == '_') sb.Append(ch);
    }

    var cleaned = sb.ToString();
    if (string.IsNullOrWhiteSpace(cleaned)) throw new Exception("Invalid prefix.");
    if (cleaned.Length > 20) cleaned = cleaned[..20];
    return cleaned;
}

static string SanitizeVmNameForLookup(string s)
{
    s = (s ?? "").Trim();

    var sb = new StringBuilder(s.Length);
    foreach (var ch in s)
    {
        if (char.IsLetterOrDigit(ch) || ch == '-' || ch == '_') sb.Append(ch);
    }

    var cleaned = sb.ToString();
    if (string.IsNullOrWhiteSpace(cleaned)) throw new Exception("Invalid VM name.");
    if (cleaned.Length > 120) cleaned = cleaned[..120];
    return cleaned;
}

static string SanitizeJobId(string s)
{
    s = (s ?? "").Trim();

    var sb = new StringBuilder(s.Length);
    foreach (var ch in s)
    {
        if (char.IsLetterOrDigit(ch)) sb.Append(ch);
    }

    var cleaned = sb.ToString();
    if (string.IsNullOrWhiteSpace(cleaned)) throw new Exception("Invalid job id.");
    if (cleaned.Length > 64) cleaned = cleaned[..64];
    return cleaned;
}

static string BuildRdpUsername(string domain, string username)
{
    domain = (domain ?? "").Trim();
    username = (username ?? "").Trim();

    if (string.IsNullOrWhiteSpace(username))
        return "";

    if (username.Contains('\\') || username.Contains('@'))
        return username;

    if (string.IsNullOrWhiteSpace(domain))
        return username;

    if (domain.Contains('.'))
        return $"{username}@{domain}";

    return $"{domain}\\{username}";
}

static string BuildRdpFile(string address, string username, IConfiguration cfg)
{
    var sb = new StringBuilder();
    sb.AppendLine($"full address:s:{address}");
    sb.AppendLine($"username:s:{username}");
    sb.AppendLine("prompt for credentials:i:1");
    sb.AppendLine("administrative session:i:0");
    sb.AppendLine("screen mode id:i:2");
    sb.AppendLine("use multimon:i:0");
    sb.AppendLine("desktopwidth:i:1920");
    sb.AppendLine("desktopheight:i:1080");
    sb.AppendLine("session bpp:i:32");
    sb.AppendLine("compression:i:1");
    sb.AppendLine("keyboardhook:i:2");
    sb.AppendLine("audiocapturemode:i:0");
    sb.AppendLine("videoplaybackmode:i:1");
    sb.AppendLine("connection type:i:7");
    sb.AppendLine("networkautodetect:i:1");
    sb.AppendLine("bandwidthautodetect:i:1");
    sb.AppendLine("displayconnectionbar:i:1");
    sb.AppendLine("enableworkspacereconnect:i:0");
    sb.AppendLine("disable wallpaper:i:0");
    sb.AppendLine("allow font smoothing:i:1");
    sb.AppendLine("allow desktop composition:i:1");
    sb.AppendLine("disable full window drag:i:0");
    sb.AppendLine("disable menu anims:i:0");
    sb.AppendLine("disable themes:i:0");
    sb.AppendLine("disable cursor setting:i:0");
    sb.AppendLine("bitmapcachepersistenable:i:1");

    var gateway = (cfg["Portal:RdpGateway"] ?? "").Trim();
    if (!string.IsNullOrWhiteSpace(gateway))
    {
        sb.AppendLine($"gatewayhostname:s:{gateway}");
        sb.AppendLine("gatewayusagemethod:i:1");
        sb.AppendLine("gatewaycredentialssource:i:0");
        sb.AppendLine("gatewayprofileusagemethod:i:1");
        sb.AppendLine("promptcredentialonce:i:0");
    }

    return sb.ToString();
}

static async Task<(int exitCode, string stdout, string stderr)> RunPowerShellAsync(
    string psExe,
    string scriptPath,
    string workingDir,
    string username,
    int memoryGB,
    int dataDiskGB,
    int cpuCount,
    CancellationToken ct)
{
    var args = new List<string>
    {
        "-ExecutionPolicy", "Bypass",
        "-File", $"\"{scriptPath}\"",
        "-Username", $"\"{username}\"",
        "-MemoryGB", memoryGB.ToString(),
        "-DataDiskGB", dataDiskGB.ToString(),
        "-CpuCount", cpuCount.ToString()
    };

    var psi = new ProcessStartInfo
    {
        FileName = psExe,
        Arguments = string.Join(' ', args),
        WorkingDirectory = workingDir,
        UseShellExecute = false,
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        CreateNoWindow = true
    };

    using var p = new Process { StartInfo = psi };

    var stdout = new StringBuilder();
    var stderr = new StringBuilder();

    p.OutputDataReceived += (_, e) => { if (e.Data != null) stdout.AppendLine(e.Data); };
    p.ErrorDataReceived += (_, e) => { if (e.Data != null) stderr.AppendLine(e.Data); };

    p.Start();
    p.BeginOutputReadLine();
    p.BeginErrorReadLine();

    await p.WaitForExitAsync(ct);

    return (p.ExitCode, stdout.ToString(), stderr.ToString());
}

static async Task<(int exitCode, string stdout, string stderr)> RunPowerShellCompanyAsync(
    string psExe,
    string scriptPath,
    string workingDir,
    string prefix,
    int count,
    int padWidth,
    int memoryGB,
    int dataDiskGB,
    int cpuCount,
    CancellationToken ct)
{
    var args = new List<string>
    {
        "-ExecutionPolicy", "Bypass",
        "-File", $"\"{scriptPath}\"",
        "-Prefix", $"\"{prefix}\"",
        "-Count", count.ToString(),
        "-PadWidth", padWidth.ToString(),
        "-MemoryGB", memoryGB.ToString(),
        "-DataDiskGB", dataDiskGB.ToString(),
        "-CpuCount", cpuCount.ToString()
    };

    var psi = new ProcessStartInfo
    {
        FileName = psExe,
        Arguments = string.Join(' ', args),
        WorkingDirectory = workingDir,
        UseShellExecute = false,
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        CreateNoWindow = true
    };

    using var p = new Process { StartInfo = psi };

    var stdout = new StringBuilder();
    var stderr = new StringBuilder();

    p.OutputDataReceived += (_, e) => { if (e.Data != null) stdout.AppendLine(e.Data); };
    p.ErrorDataReceived += (_, e) => { if (e.Data != null) stderr.AppendLine(e.Data); };

    p.Start();
    p.BeginOutputReadLine();
    p.BeginErrorReadLine();

    await p.WaitForExitAsync(ct);

    return (p.ExitCode, stdout.ToString(), stderr.ToString());
}

static async Task<string?> TryGetVmStateFromHyperV(IConfiguration cfg, string vmName, CancellationToken ct)
{
    var host = GetHyperVManagerHost(cfg);

    var script = $@"
$ErrorActionPreference = 'Stop'
Import-Module Hyper-V
$vm = Get-VM -ComputerName ""{EscapePowerShell(host)}"" -Name ""{EscapePowerShell(vmName)}""
$vm.State.ToString()
";

    var result = await RunInlinePowerShellAsync(script, cfg, ct);
    if (result.exitCode != 0)
        return null;

    var text = (result.stdout ?? "").Trim();
    if (string.IsNullOrWhiteSpace(text))
        return null;

    var line = text
        .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
        .Select(x => x.Trim())
        .LastOrDefault();

    return string.IsNullOrWhiteSpace(line) ? null : line;
}

static async Task<string?> TryGetVmIpv4FromHyperVFiltered(IConfiguration cfg, string vmName, string subnetPrefix, CancellationToken ct)
{
    var host = GetHyperVManagerHost(cfg);

 var script = $@"
$ErrorActionPreference = 'Stop'
Import-Module Hyper-V
$ips = (Get-VMNetworkAdapter -VMName ""{EscapePowerShell(vmName)}"" -ComputerName ""{EscapePowerShell(host)}"").IPAddresses |
    Where-Object {{ $_ -match '^\d{{1,3}}(\.\d{{1,3}}){{3}}$' -and $_ -notlike '169.254.*' -and $_ -like '{EscapePowerShell(subnetPrefix)}*' }} |
    Select-Object -First 1
 if ($ips) {{
    Write-Output $ips
}}
";

    var result = await RunInlinePowerShellAsync(script, cfg, ct);
    if (result.exitCode != 0)
        return null;

    var text = (result.stdout ?? "").Trim();
    if (string.IsNullOrWhiteSpace(text))
        return null;

    var line = text
        .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
        .Select(x => x.Trim())
        .FirstOrDefault(x => System.Net.IPAddress.TryParse(x, out var ip) && ip.GetAddressBytes().Length == 4);

    return string.IsNullOrWhiteSpace(line) ? null : line;
}

static async Task<(int exitCode, string stdout, string stderr)> StartVmHyperVAsync(IConfiguration cfg, string vmName, CancellationToken ct)
{
    var host = GetHyperVManagerHost(cfg);

    var script = $@"
$ErrorActionPreference = 'Stop'
Import-Module Hyper-V
Start-VM -ComputerName ""{EscapePowerShell(host)}"" -Name ""{EscapePowerShell(vmName)}"" | Out-Null
""Started""
";

    return await RunInlinePowerShellAsync(script, cfg, ct);
}

static async Task<(int exitCode, string stdout, string stderr)> StopVmHyperVAsync(IConfiguration cfg, string vmName, CancellationToken ct)
{
    var host = GetHyperVManagerHost(cfg);

    var script = $@"
$ErrorActionPreference = 'Stop'
Import-Module Hyper-V
Stop-VM -ComputerName ""{EscapePowerShell(host)}"" -Name ""{EscapePowerShell(vmName)}"" -Force -TurnOff
""Stopped""
";

    return await RunInlinePowerShellAsync(script, cfg, ct);
}

static async Task<(int exitCode, string stdout, string stderr)> RemoveVmHyperVAsync(IConfiguration cfg, string vmName, CancellationToken ct)
{
    var host = GetHyperVManagerHost(cfg);

    var script = $@"
$ErrorActionPreference = 'Stop'
Import-Module Hyper-V
$vm = Get-VM -ComputerName ""{EscapePowerShell(host)}"" -Name ""{EscapePowerShell(vmName)}""
if ($vm.State -ne 'Off') {{
    Stop-VM -ComputerName ""{EscapePowerShell(host)}"" -Name ""{EscapePowerShell(vmName)}"" -Force -TurnOff
}}
Remove-VM -ComputerName ""{EscapePowerShell(host)}"" -Name ""{EscapePowerShell(vmName)}"" -Force
""Removed""
";

    return await RunInlinePowerShellAsync(script, cfg, ct);
}

static async Task<(int exitCode, string stdout, string stderr)> AddUserToRemoteDesktopUsersAsync(IConfiguration cfg, string vmName, string principal, CancellationToken ct)
{
    var script = $@"
$ErrorActionPreference = 'Stop'
Import-Module Hyper-V

$vmNameValue = ""{EscapePowerShell(vmName)}""
$principalValue = ""{EscapePowerShell(principal)}""

$localUser = (""{EscapePowerShell(cfg["Provisioning:LocalAdminUser"] ?? @".\companyuser")}"")
$localPass = (""{EscapePowerShell(cfg["Provisioning:LocalAdminPassword"] ?? "Password1")}"")
$sec = ConvertTo-SecureString $localPass -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($localUser, $sec)

Invoke-Command -VMName $vmNameValue -Credential $cred -ScriptBlock {{
    param($principalName)

    try {{
        Add-LocalGroupMember -Group ""Remote Desktop Users"" -Member $principalName -ErrorAction Stop
    }}
    catch {{
        & net localgroup ""Remote Desktop Users"" $principalName /add | Out-Null
    }}
}} -ArgumentList $principalValue

""Added""
";

    return await RunInlinePowerShellAsync(script, cfg, ct);
}

static async Task<(int exitCode, string stdout, string stderr)> RunInlinePowerShellAsync(
    string script,
    IConfiguration cfg,
    CancellationToken ct)
{
    var psExe = (cfg["Provisioning:PowerShellExe"] ?? "").Trim();
    if (string.IsNullOrWhiteSpace(psExe))
        psExe = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";

    var workingDir = (cfg["Provisioning:WorkingDir"] ?? "").Trim();
    if (string.IsNullOrWhiteSpace(workingDir))
        workingDir = AppContext.BaseDirectory;

    var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));

    var psi = new ProcessStartInfo
    {
        FileName = psExe,
        Arguments = $"-NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded}",
        WorkingDirectory = workingDir,
        UseShellExecute = false,
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        CreateNoWindow = true
    };

    using var p = new Process { StartInfo = psi };

    var stdout = new StringBuilder();
    var stderr = new StringBuilder();

    p.OutputDataReceived += (_, e) => { if (e.Data != null) stdout.AppendLine(e.Data); };
    p.ErrorDataReceived += (_, e) => { if (e.Data != null) stderr.AppendLine(e.Data); };

    p.Start();
    p.BeginOutputReadLine();
    p.BeginErrorReadLine();

    await p.WaitForExitAsync(ct);

    return (p.ExitCode, stdout.ToString(), stderr.ToString());
}

static string EscapePowerShell(string s)
{
    return (s ?? "").Replace("\"", "`\"");
}

static bool CryptographicEquals(string a, string b)
{
    var ba = Encoding.UTF8.GetBytes(a ?? "");
    var bb = Encoding.UTF8.GetBytes(b ?? "");

    if (ba.Length != bb.Length) return false;

    var diff = 0;
    for (var i = 0; i < ba.Length; i++) diff |= ba[i] ^ bb[i];
    return diff == 0;
}

static string GenerateRecoveryCode()
{
    const string chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

    var bytes = RandomNumberGenerator.GetBytes(12);
    var result = new char[12];

    for (var i = 0; i < result.Length; i++)
    {
        result[i] = chars[bytes[i] % chars.Length];
    }

    return $"{new string(result[0..4])}-{new string(result[4..8])}-{new string(result[8..12])}";
}

static string SanitizePortalUsername(string s)
{
    s = (s ?? "").Trim().ToLowerInvariant();

    var sb = new StringBuilder(s.Length);

    foreach (var ch in s)
    {
        if (char.IsLetterOrDigit(ch) || ch == '-' || ch == '_' || ch == '.')
        {
            sb.Append(ch);
        }
    }

    var cleaned = sb.ToString();

    if (cleaned.Length > 40)
        cleaned = cleaned[..40];

    return cleaned;
}

// =============================
// Models
// =============================
public sealed class VdiVmRecord
{
    public string VmId { get; set; } = "";
    public string VmName { get; set; } = "";
    public string Username { get; set; } = "";
    public string CreatedByPortalUser { get; set; } = "";
    public string AssignedUser { get; set; } = "";
    public string Domain { get; set; } = "";
    public string IpAddress { get; set; } = "";
    public string Status { get; set; } = "";
    public DateTime CreationDateUtc { get; set; }
    public int MemoryGB { get; set; }
    public int CpuCount { get; set; }
    public int DataDiskGB { get; set; }
    public string LastKnownPowerState { get; set; } = "";
    public DateTime LastSeenUtc { get; set; }
    public string Source { get; set; } = "";
    public string Prefix { get; set; } = "";
    public int BatchCount { get; set; }
    public string Notes { get; set; } = "";
    public string PublicRdpIp { get; set; } = "";
    public int ExternalRdpPort { get; set; }
    public bool RdpReady { get; set; }
}

public sealed class VdiVmStore
{
    public List<VdiVmRecord> Vms { get; set; } = new();
}

public partial class Program
{
    private static readonly object VmInventoryLock = new();
    private static readonly object ProvisionJobsLock = new();
}

public sealed class ProvisionJobRecord
{
    public string JobId { get; set; } = "";
    public string Kind { get; set; } = "";
    public string Username { get; set; } = "";
    public string CreatedByPortalUser { get; set; } = "";
    public string VmName { get; set; } = "";
    public string AssignedUser { get; set; } = "";
    public string Domain { get; set; } = "";
    public int MemoryGB { get; set; }
    public int CpuCount { get; set; }
    public int DataDiskGB { get; set; }
    public string Prefix { get; set; } = "";
    public int Count { get; set; }
    public int PadWidth { get; set; }
    public string Status { get; set; } = "";
    public int? ExitCode { get; set; }
    public string Output { get; set; } = "";
    public string Error { get; set; } = "";
    public string IpAddress { get; set; } = "";
    public string PublicRdpIp { get; set; } = "";
    public int ExternalRdpPort { get; set; }
    public string RdpAddress { get; set; } = "";
    public DateTime CreatedUtc { get; set; }
    public DateTime? StartedUtc { get; set; }
    public DateTime? CompletedUtc { get; set; }
    public DateTime LastUpdatedUtc { get; set; }
    public string InventoryVmId { get; set; } = "";
}

public sealed class AppUser
{
    public int Id { get; set; }

    public string Username { get; set; } = "";

    public string PasswordHash { get; set; } = "";

    public string RecoveryCodeHash { get; set; } = "";

    public string Role { get; set; } = "User";

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}

public sealed class AppDbContext : DbContext
{
    public DbSet<AppUser> Users => Set<AppUser>();

    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
    {
    }
}

public sealed record RegisterRequest(string Username, string Password);

public sealed record LoginRequest(string Username, string Password);

public sealed record ResetPasswordRequest(string Username, string RecoveryCode, string NewPassword);