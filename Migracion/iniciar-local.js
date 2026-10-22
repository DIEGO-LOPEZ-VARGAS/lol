const { spawn } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const migrationDir = __dirname;
const apiDir = path.join(migrationDir, 'TicketSystem.Api');
const webDir = path.join(migrationDir, 'TicketSystem.Web');
const distDir = path.join(webDir, 'dist', 'ticket-system-web');
const staticDir = path.join(apiDir, 'wwwroot');

const environment = {
  ...process.env,
  ASPNETCORE_ENVIRONMENT: 'Development',
  ASPNETCORE_URLS: 'http://127.0.0.1:5000',
  ConnectionStrings__ProyectoTickets:
    process.env.ConnectionStrings__ProyectoTickets ||
    'Server=localhost;Database=ProyectoTickets;Integrated Security=True;Encrypt=True;TrustServerCertificate=True',
};

const children = new Set();
let stopping = false;

function forward(label, stream, destination) {
  stream.on('data', (chunk) => {
    for (const line of chunk.toString().split(/(?<=\n)/)) {
      if (line) destination.write(`[${label}] ${line}`);
    }
  });
}

function launch(label, command, args, cwd, env = environment) {
  const child = spawn(command, args, {
    cwd,
    env,
    stdio: ['inherit', 'pipe', 'pipe'],
  });
  children.add(child);
  forward(label, child.stdout, process.stdout);
  forward(label, child.stderr, process.stderr);
  child.on('error', (error) => {
    process.stderr.write(`[${label}] No se pudo iniciar: ${error.message}\n`);
    stopChildren(1);
  });
  return child;
}

function stopChildren(exitCode = 0) {
  if (stopping) return;
  stopping = true;
  process.exitCode = exitCode;
  for (const child of children) {
    if (!child.pid || child.exitCode !== null) continue;
    if (process.platform === 'win32') {
      const killer = spawn('taskkill', ['/pid', String(child.pid), '/T', '/F'], { stdio: 'ignore' });
      killer.unref();
    } else {
      child.kill('SIGTERM');
    }
  }
}

function publishAngular() {
  const browserDir = path.join(distDir, 'browser');
  const outputDir = fs.existsSync(path.join(browserDir, 'index.html')) ? browserDir : distDir;
  if (!fs.existsSync(path.join(outputDir, 'index.html'))) {
    throw new Error(`No se encontró Angular compilado en ${outputDir}`);
  }
  fs.mkdirSync(staticDir, { recursive: true });
  fs.cpSync(outputDir, staticDir, { recursive: true, force: true });
}

function startApi() {
  try {
    publishAngular();
  } catch (error) {
    process.stderr.write(`[Angular] ${error.message}\n`);
    stopChildren(1);
    return;
  }

  process.stdout.write('[Angular] Archivos publicados en la API.\n');
  const run = () => {
    if (stopping) return;
    const api = launch('API', 'dotnet', [
      'run',
      '--no-launch-profile',
      '--project',
      path.join(apiDir, 'TicketSystem.Api.csproj'),
    ], apiDir);

    api.on('exit', (code) => {
      if (!stopping) stopChildren(code || 0);
    });
  };

  // A previous F5 run may have left this project's apphost alive after its
  // debugger detached. Stop only that exact executable before dotnet rebuilds it.
  if (process.platform !== 'win32') {
    run();
    return;
  }
  const apiExe = path.join(apiDir, 'bin', 'Debug', 'net10.0', 'TicketSystem.Api.exe');
  const escapedPath = apiExe.replace(/'/g, "''");
  const stopCommand = `$target='${escapedPath}'; $old=Get-Process -Name 'TicketSystem.Api' -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $target }; if ($old) { $old | Stop-Process -Force; Start-Sleep -Milliseconds 500 }; if (Get-Process -Name 'TicketSystem.Api' -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $target }) { exit 2 }`;
  const cleanup = spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', stopCommand], { stdio: 'ignore' });
  cleanup.on('error', (error) => {
    process.stderr.write(`[API] No se pudo cerrar una ejecución anterior: ${error.message}\n`);
    stopChildren(1);
  });
  cleanup.on('exit', (code) => {
    if (code !== 0) {
      process.stderr.write('[API] No se pudo preparar el reinicio de la API.\n');
      stopChildren(code || 1);
      return;
    }
    run();
  });
}

const hasAngularCli = fs.existsSync(path.join(webDir, 'node_modules', '@angular', 'cli', 'bin', 'ng.js'));
const buildCommand = process.platform === 'win32' ? (process.env.ComSpec || 'cmd.exe') : 'npm';
const buildScript = hasAngularCli ? 'npm.cmd run build' : 'npm.cmd install && npm.cmd run build';
const buildArgs = process.platform === 'win32'
  ? ['/d', '/s', '/c', buildScript]
  : hasAngularCli ? ['run', 'build'] : ['install'];

process.stdout.write(hasAngularCli
  ? '[Angular] Compilando la interfaz…\n'
  : '[Angular] Instalando dependencias y compilando la interfaz…\n');
const build = launch('Angular', buildCommand, buildArgs, webDir);
build.on('exit', (code) => {
  children.delete(build);
  if (stopping) return;
  if (code !== 0) {
    process.stderr.write('[Angular] Falló la compilación. Corrige el error mostrado arriba.\n');
    stopChildren(code || 1);
    return;
  }
  if (!hasAngularCli && process.platform !== 'win32') {
    const compile = launch('Angular', 'npm', ['run', 'build'], webDir);
    compile.on('exit', (installCode) => {
      children.delete(compile);
      if (stopping) return;
      if (installCode !== 0) {
        process.stderr.write('[Angular] Falló la compilación. Corrige el error mostrado arriba.\n');
        stopChildren(installCode || 1);
        return;
      }
      startApi();
    });
    return;
  }
  startApi();
});

process.on('SIGINT', () => stopChildren(0));
process.on('SIGTERM', () => stopChildren(0));

process.stdout.write('Al iniciar, abre http://127.0.0.1:5000. Presiona Ctrl+C para detener.\n');
