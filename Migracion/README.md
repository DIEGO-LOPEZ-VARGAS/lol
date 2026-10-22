# Proyecto Tickets: migración tecnológica

## Objetivo

La aplicación es una interfaz Angular y una API ASP.NET Core. El sitio publicado es una sola aplicación en IIS: la API sirve los archivos estáticos Angular y atiende las rutas `/api`.

| Parte | Tecnología |
|---|---|
| Frontend | Angular 22 |
| Backend | ASP.NET Core / .NET 10 LTS |
| Servidor | Windows Server + IIS + ASP.NET Core Hosting Bundle |
| Persistencia | SQL Server existente, base `ProyectoTickets` |

## Datos preservados

La migración conserva las tablas, las claves y los procedimientos existentes. La API llama a `spuUsuarios`, `spuDepartamentos`, `spuCombos`, `spuTickets`, `spuCalendario`, `spuHome` y `spuEstadisticas`; para la consulta general de tickets administrativos usa un `SELECT` de lectura sobre esas mismas tablas. No hay scripts de alteración de esquema en esta solución. Los respaldos y datos exportados se conservan fuera del repositorio.

## Módulos incluidos en la migración

- Inicio de sesión y registro, validando el hash PBKDF2 SHA-1 legado con 100,000 iteraciones y conservando sus hashes y sales actuales.
- Panel principal con indicadores, gráfica mensual y tickets recientes.
- Consulta, alta, detalle, cambio de estado, asignación y calificación de tickets.
- Carga y consulta de evidencias PDF; los archivos conservados están en `TicketSystem.Api/wwwroot/Evidencias` y se incluyen en la publicación.
- Gestión de áreas y usuarios con roles, búsqueda y filtros.
- Consulta, alta, edición y eliminación de eventos del calendario.
- Panel de estadísticas con filtros por fecha, estados, áreas, calificaciones y tickets recientes; exportación a Excel e impresión a PDF.
- Menú con visibilidad de opciones según rol y perfil de usuario.

La apariencia conserva los estilos e imágenes usados por las pantallas anteriores. El código fuente original no es requerido para compilar ni publicar esta solución y se conserva fuera del repositorio.

## Ejecutar en desarrollo

Para abrir el sistema completo localmente necesitas tener SQL Server iniciado y la base existente `ProyectoTickets` restaurada. Esta migración no modifica ni crea tablas.

Terminal 1, desde esta carpeta:

```powershell
$env:ConnectionStrings__ProyectoTickets = "Server=localhost;Database=ProyectoTickets;Integrated Security=True;Encrypt=True;TrustServerCertificate=True"
dotnet run --project .\TicketSystem.Api\TicketSystem.Api.csproj
```

Para SQL Server Express, por ejemplo, usa `Server=localhost\SQLEXPRESS` en la cadena. Terminal 2:

```powershell
cd .\TicketSystem.Web
npm install
npm start
```

Angular abrirá normalmente en `http://localhost:4200` y reenviará `/api` a la API local en `http://localhost:5000`. Verifica `/api/health` y `/api/health/database`.

## Publicar en Windows Server / IIS

1. Instala el **ASP.NET Core Hosting Bundle de .NET 10** en Windows Server.
2. Configura la variable de entorno `ConnectionStrings__ProyectoTickets` en el sitio o App Pool. Da a la identidad del App Pool permisos mínimos sobre SQL Server; usa autenticación integrada siempre que sea posible.
3. Ejecuta `Migracion\publicar.ps1` desde PowerShell en un equipo con .NET 10 SDK, Node.js compatible con Angular 22 y acceso al feed de paquetes NuGet/npm.
4. Crea en IIS un sitio para la carpeta `Migracion\publish`, con un App Pool **sin código administrado**, permiso de escritura para la carpeta `Evidencias` y HTTPS habilitado.
5. Abre `/api/health/database` para comprobar conectividad a SQL Server y prueba cada flujo con usuarios de cada rol.

La publicación usa una única dirección para Angular y la API, de modo que las cookies de inicio de sesión funcionen sin configurar CORS entre sitios. Mantén secretos fuera del repositorio y limita la exposición de los mensajes de error en producción.
