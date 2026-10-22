using System.Data;
using System.Security.Claims;
using System.Security.Cryptography;
using ClosedXML.Excel;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.FileProviders;
using Microsoft.Data.SqlClient;

var builder = WebApplication.CreateBuilder(args);
builder.Services.ConfigureHttpJsonOptions(options => options.SerializerOptions.DictionaryKeyPolicy = System.Text.Json.JsonNamingPolicy.CamelCase);
builder.Services.AddProblemDetails();
builder.Services.AddHealthChecks().AddCheck<SqlServerHealthCheck>("sql-server");
builder.Services.AddSingleton<LegacyDatabase>();
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie(options =>
{
    options.Cookie.Name = "ProyectoTickets.Auth";
    options.Cookie.Path = "/";
    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
    options.Events.OnRedirectToLogin = context => { context.Response.StatusCode = 401; return Task.CompletedTask; };
    options.Events.OnRedirectToAccessDenied = context => { context.Response.StatusCode = 403; return Task.CompletedTask; };
});
builder.Services.AddAuthorization();
builder.Services.AddCors(options => options.AddPolicy("Angular", policy =>
    policy.WithOrigins(builder.Configuration["Frontend:Origin"] ?? "http://localhost:4200")
        .AllowAnyHeader().AllowAnyMethod().AllowCredentials()));

var app = builder.Build();
app.UseExceptionHandler();
app.UseCors("Angular");
app.UseAuthentication();
app.UseAuthorization();
app.UseDefaultFiles();
app.UseStaticFiles();
var evidenceDirectory = Path.Combine(app.Environment.ContentRootPath, "wwwroot", "Evidencias");
Directory.CreateDirectory(evidenceDirectory);
app.UseStaticFiles(new StaticFileOptions { FileProvider = new PhysicalFileProvider(evidenceDirectory), RequestPath = "/Evidencias" });
app.MapGet("/api/health", () => Results.Ok(new { status = "ok", service = "ticket-system-api" }));
app.MapHealthChecks("/api/health/database");

var api = app.MapGroup("/api");
api.MapPost("/auth/login", async (LoginRequest request, LegacyDatabase db, HttpContext http) =>
{
    var rows = await db.QueryAsync("spuUsuarios", new() { ["@opcion"] = 5, ["@Usu_Email"] = request.Email.Trim() });
    if (rows.Count == 0) return Results.Unauthorized();
    Dictionary<string, object?>? user = null;
    foreach (var candidate in rows)
    {
        if (candidate.TryGetValue("Hash", out var hashValue) && hashValue is byte[] hash && candidate.TryGetValue("Salt", out var saltValue) && saltValue is byte[] salt)
        {
            var actual = Rfc2898DeriveBytes.Pbkdf2(request.Password, salt, 100_000, HashAlgorithmName.SHA1, 20);
            if (CryptographicOperations.FixedTimeEquals(hash, actual)) { user = candidate; break; }
        }
    }
    if (user is null || !string.Equals(Value(user, "Status"), "Activo", StringComparison.OrdinalIgnoreCase)) return Results.Unauthorized();

    var claims = new[]
    {
        new Claim(ClaimTypes.NameIdentifier, Value(user, "ID")),
        new Claim(ClaimTypes.Name, $"{Value(user, "Nombre")} {Value(user, "Apellidos")}".Trim()),
        new Claim(ClaimTypes.Email, request.Email.Trim()),
        new Claim(ClaimTypes.Role, Value(user, "Rol")),
        new Claim("departmentId", Value(user, "Área")),
        new Claim("priorityId", Value(user, "Prioridad"))
    };
    await http.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme)));
    return Results.Ok(new { id = Value(user, "ID"), name = $"{Value(user, "Nombre")} {Value(user, "Apellidos")}".Trim(), email = request.Email, roleId = Value(user, "Rol"), departmentId = Value(user, "Área") });
}).AllowAnonymous();
api.MapPost("/auth/logout", async (HttpContext http) => { await http.SignOutAsync(); return Results.NoContent(); }).RequireAuthorization();
api.MapGet("/auth/me", (ClaimsPrincipal user) => Results.Ok(new { id = user.FindFirstValue(ClaimTypes.NameIdentifier), name = user.Identity?.Name, email = user.FindFirstValue(ClaimTypes.Email), roleId = user.FindFirstValue(ClaimTypes.Role), departmentId = user.FindFirstValue("departmentId") })).RequireAuthorization();
api.MapGet("/profile", async (LegacyDatabase db, ClaimsPrincipal user) =>
{
    var rows = await db.QueryTextAsync("SELECT u.IdUsuario AS ID,u.Usu_Nombre AS Nombre,u.Usu_Apellidos AS Apellidos,u.Usu_Email AS Email,u.Usu_Telefono AS Telefono,u.Usu_Status AS Status,u.fk_Departamento AS IdArea,d.Dep_Nombre AS Area FROM dbo.tblUsuario u LEFT JOIN dbo.tblDepartamentos d ON d.Id_Departamento=u.fk_Departamento WHERE u.IdUsuario=@id", new() { ["@id"] = IntClaim(user, ClaimTypes.NameIdentifier) });
    return rows.Count == 0 ? Results.NotFound() : Results.Ok(rows[0]);
}).RequireAuthorization();
api.MapPut("/profile", async (ProfileRequest request, LegacyDatabase db, ClaimsPrincipal user, HttpContext http) =>
{
    var userId = IntClaim(user, ClaimTypes.NameIdentifier);
    if (await EmailInUseAsync(db, request.Email, userId)) return Results.BadRequest(new { message = "Ese correo ya está registrado por otra cuenta." });
    byte[]? hash = null, salt = null;
    if (!string.IsNullOrWhiteSpace(request.NewPassword))
    {
        var credentials = await db.QueryAsync("spuUsuarios", new() { ["@opcion"] = 5, ["@Usu_Email"] = user.FindFirstValue(ClaimTypes.Email) });
        if (credentials.Count == 0 || credentials[0]["Hash"] is not byte[] oldHash || credentials[0]["Salt"] is not byte[] oldSalt) return Results.Unauthorized();
        var oldTest = Rfc2898DeriveBytes.Pbkdf2(request.CurrentPassword ?? "", oldSalt, 100_000, HashAlgorithmName.SHA1, 20);
        if (!CryptographicOperations.FixedTimeEquals(oldHash, oldTest)) return Results.BadRequest(new { message = "La contraseña actual no es correcta." });
        if (request.NewPassword != request.ConfirmPassword || request.NewPassword.Length < 8) return Results.BadRequest(new { message = "Verifica la nueva contraseña y su confirmación." });
        salt = RandomNumberGenerator.GetBytes(16); hash = Rfc2898DeriveBytes.Pbkdf2(request.NewPassword, salt, 100_000, HashAlgorithmName.SHA1, 20);
    }
    if (request.Status is not ("Activo" or "Inactivo")) return Results.BadRequest(new { message = "Selecciona un estado válido." });
    await db.ExecuteAsync("spuUsuarios", new() { ["@opcion"] = 3, ["@Id_Usuario"] = userId, ["@Usu_Nombre"] = request.Name, ["@Usu_Apellidos"] = request.LastName, ["@Usu_Email"] = request.Email, ["@Usu_Telefono"] = request.Phone, ["@fkEmpresa"] = 1, ["@fkRol"] = IntClaim(user, ClaimTypes.Role), ["@Usu_Status"] = request.Status, ["@fkArea"] = request.DepartmentId, ["@Usu_PasswordHash"] = hash, ["@Usu_Salt"] = salt });
    var identity = new ClaimsIdentity(user.Claims, CookieAuthenticationDefaults.AuthenticationScheme);
    identity.RemoveClaim(identity.FindFirst(ClaimTypes.Name)!);
    identity.RemoveClaim(identity.FindFirst(ClaimTypes.Email)!);
    identity.RemoveClaim(identity.FindFirst("departmentId")!);
    identity.AddClaim(new Claim(ClaimTypes.Name, $"{request.Name} {request.LastName}".Trim()));
    identity.AddClaim(new Claim(ClaimTypes.Email, request.Email));
    identity.AddClaim(new Claim("departmentId", request.DepartmentId.ToString()));
    await http.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));
    return Results.NoContent();
}).RequireAuthorization();
api.MapPost("/auth/register", async (RegisterRequest request, LegacyDatabase db, HttpContext http) =>
{
    var name = request.Name?.Trim();
    var lastName = request.LastName?.Trim();
    var email = request.Email?.Trim();
    var phone = request.Phone?.Trim();
    if (string.IsNullOrWhiteSpace(name) || name.Length > 30 || string.IsNullOrWhiteSpace(lastName) || lastName.Length > 70 ||
        string.IsNullOrWhiteSpace(email) || email.Length > 50 || !new System.ComponentModel.DataAnnotations.EmailAddressAttribute().IsValid(email) ||
        string.IsNullOrWhiteSpace(phone) || phone.Length > 15 || request.DepartmentId <= 0)
        return Results.BadRequest(new { message = "Completa los datos correctamente y selecciona un área válida." });
    if (request.Password is null || request.Password.Length < 8 || request.Password != request.ConfirmPassword)
        return Results.BadRequest(new { message = "La contraseña debe tener al menos 8 caracteres y coincidir con su confirmación." });
    var salt = RandomNumberGenerator.GetBytes(16);
    var hash = Rfc2898DeriveBytes.Pbkdf2(request.Password, salt, 100_000, HashAlgorithmName.SHA1, 20);
    // Validate and create with one database round trip; also serialize duplicate-email checks.
    var rows = await db.QueryTextAsync("""
        SET XACT_ABORT ON;
        BEGIN TRANSACTION;
        DECLARE @Result nvarchar(20), @UserId int, @PriorityId int;
        IF NOT EXISTS (SELECT 1 FROM dbo.tblDepartamentos WITH (HOLDLOCK) WHERE Id_Departamento=@fkArea)
            SET @Result=N'area';
        ELSE IF EXISTS (SELECT 1 FROM dbo.tblUsuario WITH (UPDLOCK, HOLDLOCK) WHERE Usu_Email=@Usu_Email)
            SET @Result=N'duplicate';
        ELSE
        BEGIN
            INSERT INTO dbo.tblUsuario (Usu_Nombre, Usu_Apellidos, Usu_Email, Usu_PasswordHash, Usu_Salt, Usu_Telefono, fk_Empresa, fk_Rol, Usu_Status, fk_Departamento)
            VALUES (@Usu_Nombre, @Usu_Apellidos, @Usu_Email, @Usu_PasswordHash, @Usu_Salt, @Usu_Telefono, 1, 1, N'Activo', @fkArea);
            SET @UserId=CONVERT(int, SCOPE_IDENTITY());
            SELECT @PriorityId=fk_Prioridad FROM dbo.tblDepartamentos WHERE Id_Departamento=@fkArea;
            SET @Result=N'created';
        END;
        COMMIT TRANSACTION;
        SELECT @Result AS Result, @UserId AS UserId, @PriorityId AS PriorityId;
        """, new() { ["@Usu_Nombre"] = name, ["@Usu_Apellidos"] = lastName, ["@Usu_Email"] = email, ["@Usu_PasswordHash"] = hash, ["@Usu_Salt"] = salt, ["@Usu_Telefono"] = phone, ["@fkArea"] = request.DepartmentId });
    var result = rows.FirstOrDefault();
    if (result is null || Value(result, "Result") == "area") return Results.BadRequest(new { message = "El área seleccionada ya no está disponible. Actualiza la página e inténtalo de nuevo." });
    if (Value(result, "Result") == "duplicate") return Results.BadRequest(new { message = "Ese correo ya está registrado. Inicia sesión o utiliza otro correo." });

    var fullName = $"{name} {lastName}".Trim();
    var claims = new[]
    {
        new Claim(ClaimTypes.NameIdentifier, Value(result, "UserId")),
        new Claim(ClaimTypes.Name, fullName),
        new Claim(ClaimTypes.Email, email),
        new Claim(ClaimTypes.Role, "1"),
        new Claim("departmentId", request.DepartmentId.ToString()),
        new Claim("priorityId", Value(result, "PriorityId"))
    };
    await http.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme)));
    return Results.Ok(new { message = "Registro completado.", id = Value(result, "UserId"), name = fullName, email, roleId = 1, departmentId = request.DepartmentId });
}).AllowAnonymous();

api.MapGet("/lookups", async (LegacyDatabase db) => Results.Ok(new
{
    areas = await db.QueryAsync("spuDepartamentos", new() { ["@opcion"] = 5 }),
    departments = await db.QueryAsync("spuDepartamentos", new() { ["@opcion"] = 2 }),
    priorities = await db.QueryAsync("spuCombos", new() { ["@opcion"] = 3 }),
    statuses = await db.QueryAsync("spuCombos", new() { ["@opcion"] = 2 }),
    roles = await db.QueryAsync("spuCombos", new() { ["@opcion"] = 1 })
})).AllowAnonymous();

api.MapGet("/tickets", async (LegacyDatabase db, ClaimsPrincipal user) =>
{
    var role = IntClaim(user, ClaimTypes.Role);
    var id = IntClaim(user, ClaimTypes.NameIdentifier);
    var department = IntClaim(user, "departmentId");
    if (role is 1 or 3) return Results.Ok(await db.QueryAsync("spuTickets", new() { ["@opcion"] = 2, ["@Id_Usuario"] = id }));
    if (role == 4) return Results.Ok(await db.QueryAsync("spuTickets", new() { ["@opcion"] = 7, ["@Id_Departamento"] = department }));
    if (role == 2)
    {
        var assigned = await db.QueryAsync("spuTickets", new() { ["@opcion"] = 7, ["@Id_Departamento"] = department });
        return Results.Ok(assigned.Where(ticket => Value(ticket, "AgenteId") == id.ToString()).ToList());
    }
    return Results.Ok(await db.QueryTextAsync("SELECT t.IdTicket AS Id_Ticket,t.Tick_Titulo AS [Título],t.Tick_Descripcion AS [Descripción],e.Est_Descripcion AS Estado,d.Dep_Nombre AS Departamento,p.Pri_Descripcion AS Prioridad,t.Tick_Fecha AS Fecha,u.Usu_Nombre+' '+u.Usu_Apellidos AS Usuario FROM dbo.tblTicket t LEFT JOIN dbo.tbcEstado e ON e.Id_Estado=t.fk_Estado LEFT JOIN dbo.tblDepartamentos d ON d.Id_Departamento=t.fk_Departamento LEFT JOIN dbo.tbcPrioridad p ON p.Id_Prioridad=t.fk_Prioridad LEFT JOIN dbo.tbrUsuTicket ut ON ut.fk_Ticket=t.IdTicket AND ut.fk_Agente IS NULL LEFT JOIN dbo.tblUsuario u ON u.IdUsuario=ut.fk_Usuario ORDER BY t.Tick_Fecha DESC"));
}).RequireAuthorization();
api.MapGet("/tickets/{id:int}", async (int id, LegacyDatabase db, ClaimsPrincipal user) =>
{
    if (!await CanAccessTicketAsync(db, user, id)) return Results.Forbid();
    var rows = await db.QueryTextAsync("""
        SELECT t.IdTicket AS Id_Ticket, t.Tick_Titulo AS [Título], t.Tick_Descripcion AS [Descripción],
               t.Tick_Fecha AS Fecha, t.fk_Estado AS Estado, t.Tick_Calificacion AS Calif,
               t.Tick_EvidenciaRuta AS Ruta, COALESCE(uAg.IdUsuario, 0) AS AgenteId,
               COALESCE(uAg.Usu_Nombre + ' ' + uAg.Usu_Apellidos, N'Sin asignar') AS Agente,
               uRem.Usu_Nombre + ' ' + uRem.Usu_Apellidos AS Solicitante,
               uRem.Usu_Email AS CorreoSolicitante, dOrigen.Dep_Nombre AS AreaOrigenUsuario,
               dDestino.Dep_Nombre AS Departamento
        FROM dbo.tblTicket t
        INNER JOIN dbo.tbrUsuTicket utRem ON utRem.fk_Ticket = t.IdTicket
        INNER JOIN dbo.tblUsuario uRem ON uRem.IdUsuario = utRem.fk_Usuario
        LEFT JOIN dbo.tblDepartamentos dOrigen ON dOrigen.Id_Departamento = uRem.fk_Departamento
        LEFT JOIN dbo.tblDepartamentos dDestino ON dDestino.Id_Departamento = t.fk_Departamento
        LEFT JOIN dbo.tbrUsuTicket utAg ON utAg.fk_Ticket = t.IdTicket AND utAg.fk_Agente IS NOT NULL
        LEFT JOIN dbo.tblUsuario uAg ON uAg.IdUsuario = utAg.fk_Agente
        WHERE t.IdTicket = @ticketId
        """, new() { ["@ticketId"] = id });
    return rows.Count == 0 ? Results.NotFound() : Results.Ok(rows[0]);
}).RequireAuthorization();
api.MapGet("/tickets/{id:int}/followups", async (int id, LegacyDatabase db, ClaimsPrincipal user) =>
{
    var role = IntClaim(user, ClaimTypes.Role);
    if (role is not (2 or 3 or 4) || !await CanAccessTicketAsync(db, user, id)) return Results.Forbid();
    return Results.Ok(await db.QueryTextAsync("""
        SELECT c.Id_Chat AS Id, c.Chat_Mensaje AS Mensaje, c.Chat_fecha AS Fecha,
               u.Usu_Nombre + ' ' + u.Usu_Apellidos AS Agente
        FROM dbo.tblChat c
        INNER JOIN dbo.tbrUsuTicket ut ON ut.Id_UsuTicket = c.fk_UsuTicket
        INNER JOIN dbo.tblUsuario u ON u.IdUsuario = ut.fk_Agente
        WHERE ut.fk_Ticket = @ticketId AND ut.fk_Agente IS NOT NULL
        ORDER BY c.Chat_fecha, c.Id_Chat
        """, new() { ["@ticketId"] = id }));
}).RequireAuthorization();
api.MapPost("/tickets/{id:int}/followups", async (int id, TicketFollowup request, LegacyDatabase db, ClaimsPrincipal user) =>
{
    var agentId = IntClaim(user, ClaimTypes.NameIdentifier);
    if (IntClaim(user, ClaimTypes.Role) != 2 || !await IsAssignedAgentAsync(db, id, agentId)) return Results.Forbid();
    var message = request.Message?.Trim();
    if (string.IsNullOrWhiteSpace(message) || message.Length > 300)
        return Results.BadRequest(new { message = "Escribe un seguimiento de entre 1 y 300 caracteres." });
    var assignment = await db.QueryTextAsync("SELECT Id_UsuTicket AS AssignmentId FROM dbo.tbrUsuTicket WHERE fk_Ticket=@ticketId AND fk_Agente=@agentId", new() { ["@ticketId"] = id, ["@agentId"] = agentId });
    if (assignment.Count == 0) return Results.Forbid();
    if (!int.TryParse(Value(assignment[0], "AssignmentId"), out var assignmentId)) return Results.NotFound();
    await db.ExecuteTextAsync("INSERT INTO dbo.tblChat (Chat_Mensaje, Chat_fecha, fk_UsuTicket) VALUES (@message, GETDATE(), @assignmentId)", new() { ["@message"] = message, ["@assignmentId"] = assignmentId });
    return Results.NoContent();
}).RequireAuthorization(policy => policy.RequireRole("2"));
api.MapPost("/tickets", async (NewTicket request, LegacyDatabase db, ClaimsPrincipal user) =>
{
    var title = request.Title?.Trim();
    var description = request.Description?.Trim();
    if (string.IsNullOrWhiteSpace(title) || title.Length > 70 || string.IsNullOrWhiteSpace(description) || description.Length > 350 || request.DepartmentId <= 0)
        return Results.BadRequest(new { message = "Escribe un título, una descripción y selecciona un área válida para el ticket." });
    await db.ExecuteAsync("spuTickets", new() { ["@opcion"] = 1, ["@UsuarioRemitenteID"] = IntClaim(user, ClaimTypes.NameIdentifier), ["@Tick_Titulo"] = title, ["@Tick_Descripcion"] = description, ["@fkEstado"] = 1, ["@fk_DepDestinatarioID"] = request.DepartmentId, ["@fk_Prioridad"] = IntClaim(user, "priorityId") });
    return Results.Ok(new { message = "Ticket creado." });
}).RequireAuthorization();
api.MapPut("/tickets/{id:int}/status", async (int id, UpdateTicketStatus request, LegacyDatabase db, ClaimsPrincipal user) =>
{
    if (!await CanAccessTicketAsync(db, user, id)) return Results.Forbid();
    var role = IntClaim(user, ClaimTypes.Role);
    // The original user ticket screen only permits cancellation. Use option 6
    // for roles whose ticket workflow is personal; option 4 has role-specific
    // behavior and would clear a role 4 ticket's department on cancellation.
    if (request.StatusId == 4 && role is 1 or 3 or 4)
    {
        var ownTickets = await db.QueryAsync("spuTickets", new() { ["@opcion"] = 2, ["@Id_Usuario"] = IntClaim(user, ClaimTypes.NameIdentifier) });
        if (!ownTickets.Any(ticket => Value(ticket, "Id_Ticket") == id.ToString())) return Results.Forbid();
        await db.ExecuteAsync("spuTickets", new() { ["@opcion"] = 6, ["@Id_Ticket"] = id, ["@fk_Estado"] = 4 });
        return Results.NoContent();
    }
    // spuTickets option 4 supports agents and role 4 only; role 3 has no
    // status-changing workflow in the original application.
    if (role is not (2 or 4)) return Results.Forbid();
    if (role == 2 && !await IsAssignedAgentAsync(db, id, IntClaim(user, ClaimTypes.NameIdentifier))) return Results.Forbid();
    await db.ExecuteAsync("spuTickets", new() { ["@opcion"] = 4, ["@Id_Ticket"] = id, ["@fkEstado"] = request.StatusId, ["@fk_Agente"] = IntClaim(user, ClaimTypes.NameIdentifier), ["@autoselect"] = 0, ["@fk_DepDestinatarioID"] = request.DepartmentId, ["@Rol"] = IntClaim(user, ClaimTypes.Role) });
    return Results.NoContent();
}).RequireAuthorization();
api.MapPost("/tickets/{id:int}/assign", async (int id, AssignTicket request, LegacyDatabase db, ClaimsPrincipal user) =>
{
    if (IntClaim(user, ClaimTypes.Role) != 4) return Results.Forbid();
    if (!await CanAccessTicketAsync(db, user, id)) return Results.Forbid();
    var sameDepartmentAgent = await db.QueryTextAsync("SELECT 1 AS ValidAgent FROM dbo.tblUsuario WHERE IdUsuario=@agentId AND fk_Departamento=@department AND fk_Rol=2 AND Usu_Status=N'Activo'", new() { ["@agentId"] = request.AgentId, ["@department"] = IntClaim(user, "departmentId") });
    if (sameDepartmentAgent.Count == 0) return Results.BadRequest(new { message = "Selecciona un agente activo de tu área." });
    var ticket = (await db.QueryAsync("spuTickets", new() { ["@opcion"] = 7, ["@Id_Departamento"] = IntClaim(user, "departmentId") })).FirstOrDefault(row => Value(row, "Id_Ticket") == id.ToString());
    if (ticket is null) return Results.Forbid();
    if (Value(ticket, "AgenteId") != "0") return Results.Conflict(new { message = "Este ticket ya fue asignado." });
    await db.ExecuteAsync("spuTickets", new() { ["@opcion"] = 8, ["@Id_Ticket"] = id, ["@fk_Agente"] = request.AgentId });
    return Results.NoContent();
}).RequireAuthorization();
api.MapGet("/agents", async (LegacyDatabase db, ClaimsPrincipal user) => Results.Ok(await db.QueryTextAsync("SELECT IdUsuario AS ID,Usu_Nombre AS Nombre,Usu_Apellidos AS Apellidos FROM dbo.tblUsuario WHERE fk_Departamento=@department AND fk_Rol=2 AND Usu_Status=N'Activo' ORDER BY Usu_Nombre", new() { ["@department"] = IntClaim(user, "departmentId") }))).RequireAuthorization(policy => policy.RequireRole("2", "3", "4"));
api.MapPost("/tickets/{id:int}/evidence", async (int id, HttpRequest request, LegacyDatabase db, ClaimsPrincipal user) =>
{
    if (!await CanAccessTicketAsync(db, user, id)) return Results.Forbid();
    if (!await IsAssignedAgentAsync(db, id, IntClaim(user, ClaimTypes.NameIdentifier))) return Results.Forbid();
    var state = await db.QueryTextAsync("SELECT fk_Estado AS EstadoId FROM dbo.tblTicket WHERE IdTicket=@ticketId", new() { ["@ticketId"] = id });
    if (state.Count == 0) return Results.NotFound();
    if (Value(state[0], "EstadoId") != "3") return Results.BadRequest(new { message = "La evidencia PDF solo se puede cargar cuando el ticket está resuelto." });
    if (!request.HasFormContentType) return Results.BadRequest(new { message = "Selecciona un archivo PDF." });
    var file = (await request.ReadFormAsync()).Files.GetFile("file");
    if (file is null || file.Length < 5 || file.Length > 12 * 1024 * 1024 || !Path.GetExtension(file.FileName).Equals(".pdf", StringComparison.OrdinalIgnoreCase)) return Results.BadRequest(new { message = "El archivo debe ser PDF y pesar hasta 12 MB." });
    await using (var input = file.OpenReadStream()) { var signature = new byte[5]; await input.ReadExactlyAsync(signature); if (!signature.SequenceEqual("%PDF-"u8.ToArray())) return Results.BadRequest(new { message = "El archivo seleccionado no tiene formato PDF." }); }
    var fileName = $"ticket_{id}_{Guid.NewGuid():N}.pdf";
    var path = Path.Combine(evidenceDirectory, fileName);
    await using (var stream = File.Create(path)) await file.CopyToAsync(stream);
    await db.ExecuteAsync("spuTickets", new() { ["@opcion"] = 12, ["@Id_Ticket"] = id, ["@Tick_EvidenciaRuta"] = $"/Evidencias/{fileName}" });
    return Results.Ok(new { path = $"/Evidencias/{fileName}" });
}).RequireAuthorization(policy => policy.RequireRole("2"));
api.MapPut("/tickets/{id:int}/rating", async (int id, RateTicket request, LegacyDatabase db, ClaimsPrincipal user) =>
{
    if (IntClaim(user, ClaimTypes.Role) is not (1 or 3 or 4)) return Results.Forbid();
    var ownTickets = await db.QueryAsync("spuTickets", new() { ["@opcion"] = 2, ["@Id_Usuario"] = IntClaim(user, ClaimTypes.NameIdentifier) });
    var ticket = ownTickets.FirstOrDefault(ticket => Value(ticket, "Id_Ticket") == id.ToString());
    if (ticket is null || !Value(ticket, "Estado").Equals("Resuelto", StringComparison.OrdinalIgnoreCase)) return Results.Forbid();
    if (int.TryParse(Value(ticket, "Tick_Calificacion"), out var existingRating) && existingRating > 0)
        return Results.Conflict(new { message = "Este ticket ya tiene una calificación." });
    if (request.Rating is < 1 or > 5) return Results.BadRequest();
    await db.ExecuteAsync("spuTickets", new() { ["@opcion"] = 10, ["@Id_Ticket"] = id, ["@Tick_calificacion"] = request.Rating });
    return Results.NoContent();
}).RequireAuthorization();

api.MapGet("/areas", async (LegacyDatabase db) => Results.Ok(await db.QueryAsync("spuDepartamentos", new() { ["@opcion"] = 5 }))).RequireAuthorization(policy => policy.RequireRole("3"));
api.MapPost("/areas", async (AreaRequest request, LegacyDatabase db) => { await db.ExecuteAsync("spuDepartamentos", new() { ["@opcion"] = 1, ["@Dep_Nombre"] = request.Name, ["@fkPrioridad"] = request.PriorityId }); return Results.NoContent(); }).RequireAuthorization(policy => policy.RequireRole("3"));
api.MapPut("/areas/{id:int}", async (int id, AreaRequest request, LegacyDatabase db) => { await db.ExecuteAsync("spuDepartamentos", new() { ["@opcion"] = 3, ["@Id_Departamento"] = id, ["@Dep_Nombre"] = request.Name, ["@fkPrioridad"] = request.PriorityId, ["@fkId_Empresa"] = 1 }); return Results.NoContent(); }).RequireAuthorization(policy => policy.RequireRole("3"));
api.MapDelete("/areas/{id:int}", async (int id, LegacyDatabase db) => { await db.ExecuteAsync("spuDepartamentos", new() { ["@opcion"] = 4, ["@Id_Departamento"] = id }); return Results.NoContent(); }).RequireAuthorization(policy => policy.RequireRole("3"));

api.MapGet("/users", async (LegacyDatabase db, string? name, string? email, string? status, string? departmentIds, string? roleIds) =>
{
    var rows = await db.QueryAsync("spuUsuarios", new() { ["@opcion"] = 8, ["@Usu_Nombre"] = null, ["@Usu_Email"] = EmptyToNull(email), ["@Usu_Status"] = EmptyToNull(status), ["@lstAreas"] = EmptyToNull(departmentIds), ["@fkRoles"] = EmptyToNull(roleIds) });
    var needle = name?.Trim();
    return Results.Ok(string.IsNullOrEmpty(needle) ? rows : rows.Where(row => ($"{Value(row, "Nombre")} {Value(row, "Apellidos")}").Contains(needle, StringComparison.CurrentCultureIgnoreCase)).ToList());
}).RequireAuthorization(policy => policy.RequireRole("3"));
api.MapPost("/users", async (UserRequest request, LegacyDatabase db) =>
{
    if (await EmailInUseAsync(db, request.Email)) return Results.BadRequest(new { message = "Ese correo ya está registrado por otra cuenta." });
    if (string.IsNullOrWhiteSpace(request.Password) || request.Password.Length < 8) return Results.BadRequest(new { message = "La contraseña debe tener al menos 8 caracteres." });
    var salt = RandomNumberGenerator.GetBytes(16); var hash = Rfc2898DeriveBytes.Pbkdf2(request.Password, salt, 100_000, HashAlgorithmName.SHA1, 20);
    await db.ExecuteAsync("spuUsuarios", new() { ["@opcion"] = 1, ["@Usu_Nombre"] = request.Name, ["@Usu_Apellidos"] = request.LastName, ["@Usu_Email"] = request.Email, ["@Usu_PasswordHash"] = hash, ["@Usu_Salt"] = salt, ["@Usu_Telefono"] = request.Phone, ["@fkEmpresa"] = 1, ["@fkRol"] = request.RoleId, ["@Usu_Status"] = request.Status, ["@fkArea"] = request.DepartmentId });
    return Results.NoContent();
}).RequireAuthorization(policy => policy.RequireRole("3"));
api.MapPut("/users/{id:int}", async (int id, UserRequest request, LegacyDatabase db) =>
{
    if (await EmailInUseAsync(db, request.Email, id)) return Results.BadRequest(new { message = "Ese correo ya está registrado por otra cuenta." });
    byte[]? salt = null, hash = null;
    if (!string.IsNullOrWhiteSpace(request.Password)) { salt = RandomNumberGenerator.GetBytes(16); hash = Rfc2898DeriveBytes.Pbkdf2(request.Password, salt, 100_000, HashAlgorithmName.SHA1, 20); }
    await db.ExecuteAsync("spuUsuarios", new() { ["@opcion"] = 3, ["@Id_Usuario"] = id, ["@Usu_Nombre"] = request.Name, ["@Usu_Apellidos"] = request.LastName, ["@Usu_Email"] = request.Email, ["@Usu_PasswordHash"] = hash, ["@Usu_Salt"] = salt, ["@Usu_Telefono"] = request.Phone, ["@fkEmpresa"] = 1, ["@fkRol"] = request.RoleId, ["@Usu_Status"] = request.Status, ["@fkArea"] = request.DepartmentId });
    return Results.NoContent();
}).RequireAuthorization(policy => policy.RequireRole("3"));
api.MapDelete("/users/{id:int}", async (int id, LegacyDatabase db) => { await db.ExecuteAsync("spuUsuarios", new() { ["@opcion"] = 4, ["@Id_Usuario"] = id }); return Results.NoContent(); }).RequireAuthorization(policy => policy.RequireRole("3"));
api.MapPost("/users/{id:int}/reset-password", async (int id, LegacyDatabase db) =>
{
    var password = Guid.NewGuid().ToString("N")[..8];
    var salt = RandomNumberGenerator.GetBytes(16);
    var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, 100_000, HashAlgorithmName.SHA1, 20);
    await db.ExecuteAsync("spuUsuarios", new() { ["@opcion"] = 9, ["@Id_Usuario"] = id, ["@Usu_PasswordHash"] = hash, ["@Usu_Salt"] = salt });
    return Results.Ok(new { temporaryPassword = password });
}).RequireAuthorization(policy => policy.RequireRole("3"));

api.MapGet("/calendar", async (LegacyDatabase db, ClaimsPrincipal user) =>
{
    if (IntClaim(user, ClaimTypes.Role) == 3) return Results.Ok(await db.QueryAsync("spuCalendario", new() { ["@opcion"] = 4 }));
    var own = await db.QueryAsync("spuCalendario", new() { ["@opcion"] = 5, ["@fk_Usuario"] = IntClaim(user, ClaimTypes.NameIdentifier) });
    var department = await db.QueryAsync("spuCalendario", new() { ["@opcion"] = 6, ["@fk_Departamento"] = IntClaim(user, "departmentId") });
    return Results.Ok(own.Concat(department).GroupBy(item => Value(item, "Id_Evento")).Select(group => group.First()).ToList());
}).RequireAuthorization();
api.MapPost("/calendar", async (CalendarRequest request, LegacyDatabase db, ClaimsPrincipal user) => { if (!ValidEvent(request)) return Results.BadRequest(new { message = "Revisa el título y las fechas del evento." }); await db.ExecuteAsync("spuCalendario", CalendarParameters(request with { DepartmentId = IntClaim(user, "departmentId") }, 1, 0, IntClaim(user, ClaimTypes.NameIdentifier))); return Results.NoContent(); }).RequireAuthorization();
api.MapPut("/calendar/{id:int}", async (int id, CalendarRequest request, LegacyDatabase db, ClaimsPrincipal user) => { if (!await CanEditEventAsync(db, user, id)) return Results.Forbid(); if (!ValidEvent(request)) return Results.BadRequest(new { message = "Revisa el título y las fechas del evento." }); await db.ExecuteAsync("spuCalendario", CalendarParameters(request with { DepartmentId = IntClaim(user, "departmentId") }, 2, id, IntClaim(user, ClaimTypes.NameIdentifier))); return Results.NoContent(); }).RequireAuthorization();
api.MapDelete("/calendar/{id:int}", async (int id, LegacyDatabase db, ClaimsPrincipal user) => { if (!await CanEditEventAsync(db, user, id)) return Results.Forbid(); await db.ExecuteAsync("spuCalendario", new() { ["@opcion"] = 3, ["@Id_Evento"] = id }); return Results.NoContent(); }).RequireAuthorization();

api.MapGet("/dashboard", async (LegacyDatabase db, ClaimsPrincipal user) =>
{
    var cards = await db.QueryAsync("spuHome", new() { ["@opcion"] = 1, ["@idEmpresa"] = 1, ["@idDepartamento"] = IntClaim(user, "departmentId"), ["@idUsuario"] = IntClaim(user, ClaimTypes.NameIdentifier) });
    var role = IntClaim(user, ClaimTypes.Role);
    if (cards.Count > 0)
    {
        var visible = role switch { 1 => new[] { "TicketsTotales" }, 2 => new[] { "TicketsSinAsignar", "TicketsAsignados" }, 3 => new[] { "TicketsTotales", "UsuariosActivos", "DepartamentosActivos" }, 4 => new[] { "TicketsSinDepartamento", "TicketsConDepartamento" }, _ => Array.Empty<string>() };
        foreach (var key in cards[0].Keys.Where(key => !visible.Contains(key, StringComparer.OrdinalIgnoreCase)).ToArray()) cards[0].Remove(key);
    }
    return Results.Ok(new
{
    cards,
    chart = await db.QueryAsync("spuHome", new() { ["@opcion"] = 2, ["@idUsuario"] = IntClaim(user, ClaimTypes.NameIdentifier) }),
    recent = await db.QueryAsync("spuHome", new() { ["@opcion"] = 3, ["@idUsuario"] = IntClaim(user, ClaimTypes.NameIdentifier) })
});
}).RequireAuthorization();
api.MapGet("/statistics", async (LegacyDatabase db, DateTime? from, DateTime? to) =>
{
    if (!ValidDateRange(from, to)) return Results.BadRequest(new { message = "El rango debe ser válido y no exceder 365 días." });
    return Results.Ok(new
{
    general = await db.QueryAsync("spuEstadisticas", DateParameters(1, from, to)),
    byMonth = (await db.QueryAsync("spuEstadisticas", DateParameters(2, from, to))).Select(row => new { agrupador = Value(row, "Agrupador"), cantidad = Value(row, "Cantidad") }),
    byStatus = (await db.QueryAsync("spuEstadisticas", DateParameters(3, from, to))).Select(row => new { estado = Value(row, "Estado"), cantidad = Value(row, "Cantidad"), porcentaje = Value(row, "Porcentaje") }),
    ratings = (await db.QueryAsync("spuEstadisticas", DateParameters(4, from, to))).Select(row => new { departamento = Value(row, "Departamento"), calificacionPromedio = Value(row, "CalificacionPromedio") }),
    byArea = (await db.QueryAsync("spuEstadisticas", DateParameters(5, from, to))).Select(row => new { departamento = Value(row, "Departamento"), cantidadTickets = Value(row, "CantidadTickets") }),
    recent = (await db.QueryAsync("spuEstadisticas", DateParameters(6, from, to))).Select(row => new { id = Value(row, "ID"), asunto = Value(row, "Asunto"), area = Value(row, "Área"), fecha = Value(row, "Fecha"), estado = Value(row, "Estado"), calificacion = Value(row, "Calificacion") }),
    allTickets = await db.QueryAsync("spuEstadisticas", DateParameters(7, from, to))
});
}).RequireAuthorization(policy => policy.RequireRole("3"));

api.MapGet("/statistics/export", async (LegacyDatabase db, DateTime? from, DateTime? to) =>
{
    if (!ValidDateRange(from, to)) return Results.BadRequest(new { message = "El rango debe ser válido y no exceder 365 días." });
    using var workbook = new XLWorkbook();
    var exports = new (string Name, int Option)[] { ("Todos los Tickets", 7), ("Tickets por Área", 5), ("Calificaciones", 4), ("Estados", 3), ("Resumen", 1) };
    foreach (var (name, option) in exports)
    {
        var parameters = DateParameters(option, from, to);
        var rows = option == 7
            ? await db.QueryTextAsync("SELECT t.IdTicket AS ID,t.Tick_Titulo AS Asunto,d.Dep_Nombre AS Area,FORMAT(t.Tick_Fecha,'dd/MM/yyyy') AS Fecha,e.Est_Descripcion AS Estado,ISNULL(CONVERT(varchar(10),t.Tick_Calificacion),'-') AS Calificacion FROM dbo.tblTicket t INNER JOIN dbo.tblDepartamentos d ON d.Id_Departamento=t.fk_Departamento INNER JOIN dbo.tbcEstado e ON e.Id_Estado=t.fk_Estado WHERE (@fechaInicio IS NULL OR t.Tick_Fecha>=@fechaInicio) AND (@fechaFin IS NULL OR t.Tick_Fecha<=@fechaFin) ORDER BY t.Tick_Fecha DESC", new() { ["@fechaInicio"] = from?.Date, ["@fechaFin"] = to?.Date.AddDays(1).AddTicks(-1) })
            : await db.QueryAsync("spuEstadisticas", parameters);
        var sheet = workbook.Worksheets.Add(name);
        var headers = rows.FirstOrDefault()?.Keys.ToArray() ?? [];
        for (var col = 0; col < headers.Length; col++) sheet.Cell(1, col + 1).Value = headers[col];
        for (var row = 0; row < rows.Count; row++)
            for (var col = 0; col < headers.Length; col++) sheet.Cell(row + 2, col + 1).Value = XLCellValue.FromObject(rows[row][headers[col]]);
        sheet.Row(1).Style.Font.Bold = true;
        sheet.Columns().AdjustToContents();
    }
    using var stream = new MemoryStream();
    workbook.SaveAs(stream);
    return Results.File(stream.ToArray(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "tickets.xlsx");
}).RequireAuthorization(policy => policy.RequireRole("3"));

app.MapFallbackToFile("index.html");
app.Run();

static string Value(Dictionary<string, object?> row, string key) => row.TryGetValue(key, out var value) && value is not null ? Convert.ToString(value) ?? "" : "";
static object? EmptyToNull(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;
static int IntClaim(ClaimsPrincipal principal, string type) => int.TryParse(principal.FindFirstValue(type), out var id) ? id : 0;
static async Task<bool> EmailInUseAsync(LegacyDatabase db, string email, int? exceptUserId = null)
{
    var rows = await db.QueryTextAsync("SELECT 1 AS Found FROM dbo.tblUsuario WHERE Usu_Email=@email AND (@exceptUserId IS NULL OR IdUsuario<>@exceptUserId)", new() { ["@email"] = email.Trim(), ["@exceptUserId"] = exceptUserId });
    return rows.Count > 0;
}
static async Task<bool> CanAccessTicketAsync(LegacyDatabase db, ClaimsPrincipal user, int ticketId)
{
    var role = IntClaim(user, ClaimTypes.Role);
    if (role == 3) return true;
    var rows = role == 1
        ? await db.QueryAsync("spuTickets", new() { ["@opcion"] = 2, ["@Id_Usuario"] = IntClaim(user, ClaimTypes.NameIdentifier) })
        : role is 2 or 4
            ? await db.QueryAsync("spuTickets", new() { ["@opcion"] = 7, ["@Id_Departamento"] = IntClaim(user, "departmentId") })
            : [];
    return rows.Any(row => Value(row, "Id_Ticket") == ticketId.ToString() && (role != 2 || Value(row, "AgenteId") == IntClaim(user, ClaimTypes.NameIdentifier).ToString()));
}
static async Task<bool> IsAssignedAgentAsync(LegacyDatabase db, int ticketId, int userId)
{
    var rows = await db.QueryTextAsync("SELECT 1 AS Assigned FROM dbo.tbrUsuTicket WHERE fk_Ticket=@ticketId AND fk_Agente=@userId", new() { ["@ticketId"] = ticketId, ["@userId"] = userId });
    return rows.Count > 0;
}
static async Task<bool> CanEditEventAsync(LegacyDatabase db, ClaimsPrincipal user, int eventId)
{
    if (IntClaim(user, ClaimTypes.Role) == 3) return true;
    var rows = await db.QueryTextAsync("SELECT 1 AS CanEdit FROM dbo.tblCalendario WHERE Id_Evento=@id AND fk_Usuario=@userId", new() { ["@id"] = eventId, ["@userId"] = IntClaim(user, ClaimTypes.NameIdentifier) });
    return rows.Count > 0;
}
static bool ValidEvent(CalendarRequest request) => !string.IsNullOrWhiteSpace(request.Title) && request.Start != default && request.End != default && request.Start <= request.End;
static bool ValidDateRange(DateTime? from, DateTime? to) => !(from.HasValue && to.HasValue && (from.Value.Date > to.Value.Date || (to.Value.Date - from.Value.Date).TotalDays > 365));
static Dictionary<string, object?> DateParameters(int option, DateTime? from, DateTime? to) { var p = new Dictionary<string, object?> { ["@opcion"] = option }; if (from.HasValue) p["@fechaInicio"] = from.Value.Date; if (to.HasValue) p["@fechaFin"] = to.Value.Date.AddDays(1).AddSeconds(-1); return p; }
static Dictionary<string, object?> CalendarParameters(CalendarRequest r, int option, int id, int userId) => new() { ["@opcion"] = option, ["@Id_Evento"] = id, ["@Evento_Titulo"] = r.Title, ["@Evento_Descripcion"] = r.Description, ["@Fecha_Inicio"] = r.Start, ["@Fecha_Fin"] = r.End, ["@Todo_El_Dia"] = r.AllDay, ["@Color"] = r.Color, ["@fk_Usuario"] = userId, ["@fk_Departamento"] = r.DepartmentId };

public sealed record LoginRequest(string Email, string Password);
public sealed record RegisterRequest(string Name, string LastName, string Email, string Phone, int DepartmentId, string Password, string ConfirmPassword);
public sealed record NewTicket(string Title, string Description, int DepartmentId);
public sealed record UpdateTicketStatus(int StatusId, int? DepartmentId);
public sealed record AssignTicket(int AgentId);
public sealed record TicketFollowup(string? Message);
public sealed record RateTicket(int Rating);
public sealed record AreaRequest(string Name, int PriorityId);
public sealed record UserRequest(string Name, string LastName, string Email, string Phone, int DepartmentId, int RoleId, string Status, string? Password);
public sealed record CalendarRequest(string Title, string? Description, DateTime Start, DateTime End, bool AllDay, string Color, int? DepartmentId);
public sealed record ProfileRequest(string Name, string LastName, string Email, string Phone, int DepartmentId, string Status, string? CurrentPassword, string? NewPassword, string? ConfirmPassword);

public sealed class LegacyDatabase(IConfiguration configuration)
{
    private static readonly HashSet<string> AllowedProcedures = new(StringComparer.OrdinalIgnoreCase) { "spuUsuarios", "spuDepartamentos", "spuCombos", "spuTickets", "spuCalendario", "spuHome", "spuEstadisticas" };
    private string ConnectionString => configuration.GetConnectionString("ProyectoTickets") ?? throw new InvalidOperationException("Configure ConnectionStrings__ProyectoTickets.");
    public async Task<List<Dictionary<string, object?>>> QueryAsync(string procedure, Dictionary<string, object?> parameters, CancellationToken cancellationToken = default)
    {
        if (!AllowedProcedures.Contains(procedure)) throw new InvalidOperationException("Stored procedure is not allowed.");
        await using var connection = new SqlConnection(ConnectionString);
        await using var command = new SqlCommand(procedure, connection) { CommandType = CommandType.StoredProcedure };
        AddParameters(command, parameters);
        await connection.OpenAsync(cancellationToken);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var rows = new List<Dictionary<string, object?>>();
        while (await reader.ReadAsync(cancellationToken))
        {
            var row = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
            for (var i = 0; i < reader.FieldCount; i++) row[reader.GetName(i)] = await reader.IsDBNullAsync(i, cancellationToken) ? null : reader.GetValue(i);
            rows.Add(row);
        }
        return rows;
    }
    public async Task<List<Dictionary<string, object?>>> QueryTextAsync(string sql, Dictionary<string, object?>? parameters = null, CancellationToken cancellationToken = default)
    {
        await using var connection = new SqlConnection(ConnectionString);
        await using var command = new SqlCommand(sql, connection);
        if (parameters is not null) AddParameters(command, parameters);
        await connection.OpenAsync(cancellationToken);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var rows = new List<Dictionary<string, object?>>();
        while (await reader.ReadAsync(cancellationToken)) { var row = new Dictionary<string, object?>(); for (var i = 0; i < reader.FieldCount; i++) row[reader.GetName(i)] = reader.IsDBNull(i) ? null : reader.GetValue(i); rows.Add(row); }
        return rows;
    }
    public async Task<int> ExecuteAsync(string procedure, Dictionary<string, object?> parameters, CancellationToken cancellationToken = default)
    {
        if (!AllowedProcedures.Contains(procedure)) throw new InvalidOperationException("Stored procedure is not allowed.");
        await using var connection = new SqlConnection(ConnectionString);
        await using var command = new SqlCommand(procedure, connection) { CommandType = CommandType.StoredProcedure };
        AddParameters(command, parameters);
        await connection.OpenAsync(cancellationToken);
        return await command.ExecuteNonQueryAsync(cancellationToken);
    }
    public async Task<int> ExecuteTextAsync(string sql, Dictionary<string, object?> parameters, CancellationToken cancellationToken = default)
    {
        await using var connection = new SqlConnection(ConnectionString);
        await using var command = new SqlCommand(sql, connection);
        AddParameters(command, parameters);
        await connection.OpenAsync(cancellationToken);
        return await command.ExecuteNonQueryAsync(cancellationToken);
    }
    private static void AddParameters(SqlCommand command, Dictionary<string, object?> parameters)
    {
        foreach (var (name, value) in parameters)
        {
            if (name.Equals("@Usu_PasswordHash", StringComparison.OrdinalIgnoreCase) || name.Equals("@Usu_Salt", StringComparison.OrdinalIgnoreCase))
            {
                command.Parameters.Add(name, SqlDbType.VarBinary, -1).Value = value ?? DBNull.Value;
                continue;
            }
            command.Parameters.AddWithValue(name, value ?? DBNull.Value);
        }
    }
}

public sealed class SqlServerHealthCheck(IConfiguration configuration) : Microsoft.Extensions.Diagnostics.HealthChecks.IHealthCheck
{
    public async Task<Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckResult> CheckHealthAsync(Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        var connectionString = configuration.GetConnectionString("ProyectoTickets");
        if (string.IsNullOrWhiteSpace(connectionString)) return Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckResult.Unhealthy("SQL Server connection is not configured.");
        try { await using var connection = new SqlConnection(connectionString); await connection.OpenAsync(cancellationToken); await using var command = new SqlCommand("SELECT 1", connection); await command.ExecuteScalarAsync(cancellationToken); return Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckResult.Healthy("SQL Server connection succeeded."); }
        catch (Exception exception) { return Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckResult.Unhealthy("SQL Server connection failed.", exception); }
    }
}
