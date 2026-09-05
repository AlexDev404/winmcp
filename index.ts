import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { createMcpExpressApp } from "@modelcontextprotocol/sdk/server/express.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { execSync, spawn, type ChildProcess } from "child_process";
import { platform } from "os";
import { randomUUID, randomInt, timingSafeEqual } from "crypto";
import { existsSync, readFileSync, statSync } from "fs";
import { resolve, extname } from "path";
import { pathToFileURL } from "url";
import { config as loadDotenv } from "dotenv";
import type { Request, Response, NextFunction } from "express";
import { installOAuthShim } from "./oauth.js";

// Load a .env.local file from the current working directory, if present. dotenv does not
// override variables already set in the process environment.
{
  const envPath = resolve(process.cwd(), ".env.local");
  if (existsSync(envPath)) {
    loadDotenv({ path: envPath });
    console.error(`Loaded environment variables from ${envPath}`);
  }
}

// Detect operating system
const isWindows = platform() === 'win32';

const DANGEROUS_CMD_PATTERNS = [
  'net user', 'net localgroup', 'netsh', 'format', 'rd /s', 'rmdir /s',
  'del /f', 'reg delete', 'shutdown', 'taskkill', 'sc delete', 'bcdedit',
  'cacls', 'icacls', 'takeown', 'diskpart', 'cipher /w', 'schtasks /create',
  'rm -rf', 'sudo', 'chmod', 'chown', 'passwd', 'mkfs', 'dd'
];

const DANGEROUS_PS_PATTERNS = [
  'new-user', 'add-user', 'remove-item -recurse -force', 'format-volume',
  'reset-computer', 'stop-computer', 'restart-computer', 'stop-process -force',
  'remove-item -force', 'set-executionpolicy', 'invoke-webrequest',
  'start-bitstransfer', 'set-location', 'invoke-expression', 'iex', '& {',
  'invoke-command', 'new-psdrive', 'remove-psdrive', 'enable-psremoting',
  'new-service', 'remove-service', 'set-service'
];

// Human-in-the-loop bypass for the dangerous-command blocklist. request_dangerous_override_code
// prints a one-time code to this server's own console (stderr) - never to the MCP response, so
// it can only reach whoever has console/log access to the machine this server runs on. The AI
// must ask that person for the code and pass it to unlock_dangerous_commands before a single
// blocklist-matching command is allowed through.
const UNSAFE_CODE_TTL_MS = 5 * 60 * 1000; // time allowed to enter the code after it's generated
const UNSAFE_UNLOCK_TTL_MS = 2 * 60 * 1000; // time the unlock stays valid if never used

const MAX_UNSAFE_CODE_ATTEMPTS = 5;

interface UnsafeModeState {
  pendingCode: string | null;
  pendingCodeExpiresAt: number | null;
  failedAttempts: number;
  unlockedUntil: number | null;
}
const unsafeMode: UnsafeModeState = { pendingCode: null, pendingCodeExpiresAt: null, failedAttempts: 0, unlockedUntil: null };

function isUnsafeModeUnlocked(): boolean {
  if (!unsafeMode.unlockedUntil) return false;
  if (Date.now() > unsafeMode.unlockedUntil) {
    unsafeMode.unlockedUntil = null;
    return false;
  }
  return true;
}

// Consumes the unlock, so it only ever covers a single dangerous command.
function consumeUnsafeModeUnlock(): void {
  unsafeMode.unlockedUntil = null;
}

// Creates a fresh McpServer instance with all tools registered. Each transport connection
// (the single stdio connection, or each HTTP session) needs its own instance, since a Server
// can only be connected to one transport at a time.
function createServer(): McpServer {
  const server = new McpServer({
    name: "windows-command-line",
    version: "0.3.0",
  });

// Persistent working directory, shared across tool calls on this server process -
// mirrors the "working directory persists between commands" behavior of a shell session.
let currentWorkingDirectory = process.cwd();

const MAX_TIMEOUT_MS = 600000; // 10 minutes, matches typical shell-tool ceilings
const DEFAULT_TIMEOUT_MS = 120000; // 2 minutes
function clampTimeout(timeout: number): number {
  return Math.min(Math.max(timeout, 1), MAX_TIMEOUT_MS);
}

function resolveWorkingDir(workingDir?: string): string {
  if (workingDir) {
    currentWorkingDirectory = workingDir;
  }
  return currentWorkingDirectory;
}

// File download support - reads a file and returns it as an MCP embedded resource, so it can
// be downloaded/saved by the client. Capped in size since the whole file has to fit in the
// tool response (base64-encoded for binaries, ~33% larger than the file itself).
const MAX_DOWNLOAD_BYTES = process.env.MCP_MAX_DOWNLOAD_BYTES
  ? parseInt(process.env.MCP_MAX_DOWNLOAD_BYTES, 10)
  : 10 * 1024 * 1024; // 10 MB

const MIME_TYPES: Record<string, string> = {
  ".txt": "text/plain", ".md": "text/markdown", ".json": "application/json",
  ".xml": "application/xml", ".html": "text/html", ".htm": "text/html",
  ".css": "text/css", ".js": "text/javascript", ".ts": "text/plain",
  ".csv": "text/csv", ".yaml": "text/yaml", ".yml": "text/yaml", ".log": "text/plain",
  ".pdf": "application/pdf", ".zip": "application/zip", ".7z": "application/x-7z-compressed",
  ".rar": "application/vnd.rar", ".gz": "application/gzip",
  ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif",
  ".svg": "image/svg+xml", ".webp": "image/webp", ".bmp": "image/bmp", ".ico": "image/x-icon",
  ".mp3": "audio/mpeg", ".wav": "audio/wav", ".mp4": "video/mp4", ".mov": "video/quicktime",
  ".exe": "application/x-msdownload", ".dll": "application/x-msdownload", ".msi": "application/x-msi",
  ".doc": "application/msword",
  ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  ".xls": "application/vnd.ms-excel",
  ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
};

function guessMimeType(filePath: string): string {
  return MIME_TYPES[extname(filePath).toLowerCase()] ?? "application/octet-stream";
}

function looksLikeText(buffer: Buffer): boolean {
  return !buffer.subarray(0, 8000).includes(0);
}

// Background process tracking, so long-running commands can be started without
// blocking the calling tool call and polled for output afterward.
const MAX_BUFFERED_OUTPUT = 1_000_000; // cap buffered stdout/stderr per stream, in characters

interface BackgroundProcess {
  id: string;
  command: string;
  proc: ChildProcess;
  stdout: string;
  stderr: string;
  status: "running" | "completed" | "failed" | "killed";
  exitCode: number | null;
  startedAt: Date;
  endedAt: Date | null;
}

const backgroundProcesses = new Map<string, BackgroundProcess>();

function appendCapped(existing: string, chunk: string): string {
  const combined = existing + chunk;
  return combined.length > MAX_BUFFERED_OUTPUT
    ? combined.slice(combined.length - MAX_BUFFERED_OUTPUT)
    : combined;
}

// Spawns `file arg0 arg1 ...` detached in the background and tracks it under a new id.
function spawnBackground(file: string, args: string[], cwd: string, displayCommand: string): string {
  const id = randomUUID();
  const proc = spawn(file, args, { cwd, detached: isWindows ? false : true });

  const entry: BackgroundProcess = {
    id,
    command: displayCommand,
    proc,
    stdout: "",
    stderr: "",
    status: "running",
    exitCode: null,
    startedAt: new Date(),
    endedAt: null,
  };
  backgroundProcesses.set(id, entry);

  proc.stdout?.on("data", (chunk) => {
    entry.stdout = appendCapped(entry.stdout, chunk.toString());
  });
  proc.stderr?.on("data", (chunk) => {
    entry.stderr = appendCapped(entry.stderr, chunk.toString());
  });
  proc.on("error", (error) => {
    entry.status = "failed";
    entry.endedAt = new Date();
    entry.stderr = appendCapped(entry.stderr, `\n[process error: ${error.message}]`);
  });
  proc.on("exit", (code) => {
    entry.exitCode = code;
    entry.endedAt = new Date();
    if (entry.status === "running") {
      entry.status = code === 0 ? "completed" : "failed";
    }
  });

  return id;
}

// Helper function to handle command execution based on platform
function executeCommand(command: string, options: any = {}) {
  if (isWindows) {
    return execSync(command, options);
  } else {
    // Log warning for non-Windows environments
    console.error(`Warning: Running in a non-Windows environment (${platform()}). Windows commands may not work.`);
    
    // For testing purposes on non-Windows platforms
    try {
      // For Linux/MacOS, we'll strip cmd.exe and powershell.exe references
      let modifiedCmd = command;
      
      // Replace cmd.exe /c with empty string
      modifiedCmd = modifiedCmd.replace(/cmd\.exe\s+\/c\s+/i, '');
      
      // Replace powershell.exe -Command with empty string or a compatible command
      modifiedCmd = modifiedCmd.replace(/powershell\.exe\s+-Command\s+("|')/i, '');
      
      // Remove trailing quotes if we removed powershell -Command
      if (modifiedCmd !== command) {
        modifiedCmd = modifiedCmd.replace(/("|')$/, '');
      }
      
      console.error(`Attempting to execute modified command: ${modifiedCmd}`);
      return execSync(modifiedCmd, options);
    } catch (error) {
      console.error(`Error executing modified command: ${error}`);
      return Buffer.from(`This tool requires a Windows environment. Current platform: ${platform()}`);
    }
  }
}

// Register the list_running_processes tool
server.tool(
  "list_running_processes",
  "List all running processes on the system. Can be filtered by providing an optional filter string that will match against process names.",
  {
    filter: z.string().optional().describe("Optional filter string to match against process names"),
  },
  async ({ filter }) => {
    try {
      let cmd;
      
      if (isWindows) {
        cmd = "powershell.exe -Command \"Get-Process";
        
        if (filter) {
          // Add filter if provided
          cmd += ` | Where-Object { $_.ProcessName -like '*${filter}*' }`;
        }
        
        cmd += " | Select-Object Id, ProcessName, CPU, WorkingSet, Description | Format-Table -AutoSize | Out-String\"";
      } else {
        // Fallback for Unix systems
        cmd = "ps aux";
        
        if (filter) {
          cmd += ` | grep -i ${filter}`;
        }
      }
      
      const stdout = executeCommand(cmd);
      
      return {
        content: [
          {
            type: "text",
            text: stdout.toString(),
          },
        ],
      };
    } catch (error) {
      return {
        isError: true,
        content: [
          {
            type: "text",
            text: `Error listing processes: ${error}`,
          },
        ],
      };
    }
  }
);

// Register the get_system_info tool
server.tool(
  "get_system_info",
  "Retrieve system information including OS, hardware, and user details. Can provide basic or full details.",
  {
    detail: z.enum(["basic", "full"]).default("basic").describe("Level of detail"),
  },
  async ({ detail }) => {
    try {
      let cmd;
      
      if (isWindows) {
        cmd = "powershell.exe -Command \"";
        
        if (detail === "basic") {
          cmd += "$OS = Get-CimInstance Win32_OperatingSystem; " +
                "$CS = Get-CimInstance Win32_ComputerSystem; " +
                "$Processor = Get-CimInstance Win32_Processor; " +
                "Write-Output 'OS: ' $OS.Caption $OS.Version; " +
                "Write-Output 'Computer: ' $CS.Manufacturer $CS.Model; " +
                "Write-Output 'CPU: ' $Processor.Name; " +
                "Write-Output 'Memory: ' [math]::Round($OS.TotalVisibleMemorySize/1MB, 2) 'GB'";
        } else {
          cmd += "$OS = Get-CimInstance Win32_OperatingSystem; " +
                "$CS = Get-CimInstance Win32_ComputerSystem; " +
                "$Processor = Get-CimInstance Win32_Processor; " +
                "$Disk = Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3'; " +
                "$Network = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object {$_.IPAddress -ne $null}; " +
                "Write-Output '=== OPERATING SYSTEM ==='; " +
                "Write-Output ('OS: ' + $OS.Caption + ' ' + $OS.Version); " +
                "Write-Output ('Architecture: ' + $OS.OSArchitecture); " +
                "Write-Output ('Install Date: ' + $OS.InstallDate); " +
                "Write-Output ('Last Boot: ' + $OS.LastBootUpTime); " +
                "Write-Output (''; '=== HARDWARE ==='); " +
                "Write-Output ('Manufacturer: ' + $CS.Manufacturer); " +
                "Write-Output ('Model: ' + $CS.Model); " +
                "Write-Output ('Serial Number: ' + (Get-CimInstance Win32_BIOS).SerialNumber); " +
                "Write-Output ('Processor: ' + $Processor.Name); " +
                "Write-Output ('Cores: ' + $Processor.NumberOfCores); " +
                "Write-Output ('Logical Processors: ' + $Processor.NumberOfLogicalProcessors); " +
                "Write-Output ('Memory: ' + [math]::Round($OS.TotalVisibleMemorySize/1MB, 2) + ' GB'); " +
                "Write-Output (''; '=== STORAGE ==='); " +
                "foreach($drive in $Disk) { " +
                "Write-Output ('Drive ' + $drive.DeviceID + ' - ' + [math]::Round($drive.Size/1GB, 2) + ' GB (Free: ' + [math]::Round($drive.FreeSpace/1GB, 2) + ' GB)') " +
                "}; " +
                "Write-Output (''; '=== NETWORK ==='); " +
                "foreach($adapter in $Network) { " +
                "Write-Output ('Adapter: ' + $adapter.Description); " +
                "Write-Output ('  IP Address: ' + ($adapter.IPAddress[0])); " +
                "Write-Output ('  MAC Address: ' + $adapter.MACAddress); " +
                "Write-Output ('  Gateway: ' + ($adapter.DefaultIPGateway -join ', ')); " +
                "}";
        }
        
        cmd += "\"";
      } else {
        // Fallback for Unix systems
        if (detail === "basic") {
          cmd = "uname -a && lscpu | grep 'Model name' && free -h | head -n 2";
        } else {
          cmd = "uname -a && lscpu && free -h && df -h && ip addr";
        }
      }
      
      const stdout = executeCommand(cmd);
      
      return {
        content: [
          {
            type: "text",
            text: stdout.toString(),
          },
        ],
      };
    } catch (error) {
      return {
        isError: true,
        content: [
          {
            type: "text",
            text: `Error retrieving system info: ${error}`,
          },
        ],
      };
    }
  }
);

// Register the get_network_info tool
server.tool(
  "get_network_info",
  "Retrieve network configuration information including IP addresses, adapters, and DNS settings. Can be filtered to a specific interface.",
  {
    networkInterface: z.string().optional().describe("Optional interface name to filter results"),
  },
  async ({ networkInterface }) => {
    try {
      let cmd;
      
      if (isWindows) {
        cmd = "powershell.exe -Command \"";
        
        if (networkInterface) {
          cmd += "$adapters = Get-NetAdapter | Where-Object { $_.Name -like '*" + networkInterface + "*' }; ";
        } else {
          cmd += "$adapters = Get-NetAdapter; ";
        }
        
        cmd += "foreach($adapter in $adapters) { " +
              "Write-Output ('======== ' + $adapter.Name + ' (' + $adapter.Status + ') ========'); " +
              "Write-Output ('Interface Description: ' + $adapter.InterfaceDescription); " +
              "Write-Output ('MAC Address: ' + $adapter.MacAddress); " +
              "Write-Output ('Link Speed: ' + $adapter.LinkSpeed); " +
              "$ipconfig = Get-NetIPConfiguration -InterfaceIndex $adapter.ifIndex; " +
              "Write-Output ('IP Address: ' + ($ipconfig.IPv4Address.IPAddress -join ', ')); " +
              "Write-Output ('Subnet: ' + ($ipconfig.IPv4Address.PrefixLength -join ', ')); " +
              "Write-Output ('Gateway: ' + ($ipconfig.IPv4DefaultGateway.NextHop -join ', ')); " +
              "Write-Output ('DNS Servers: ' + ($ipconfig.DNSServer.ServerAddresses -join ', ')); " +
              "Write-Output ''; " +
              "}\"";
      } else {
        // Fallback for Unix systems
        if (networkInterface) {
          cmd = `ip addr show ${networkInterface}`;
        } else {
          cmd = "ip addr";
        }
      }
      
      const stdout = executeCommand(cmd);
      
      return {
        content: [
          {
            type: "text",
            text: stdout.toString(),
          },
        ],
      };
    } catch (error) {
      return {
        isError: true,
        content: [
          {
            type: "text",
            text: `Error retrieving network info: ${error}`,
          },
        ],
      };
    }
  }
);

// Register the get_scheduled_tasks tool
server.tool(
  "get_scheduled_tasks",
  "Retrieve information about scheduled tasks on the system. Can query all tasks or get detailed status of a specific task.",
  {
    action: z.enum(["query", "status"]).default("query").describe("Action to perform"),
    taskName: z.string().optional().describe("Name of the specific task (optional)"),
  },
  async ({ action, taskName }) => {
    if (!isWindows) {
      return {
        content: [
          {
            type: "text",
            text: "The scheduled tasks tool is only available on Windows. Current platform: " + platform(),
          },
        ],
      };
    }
    
    try {
      let cmd = "powershell.exe -Command \"";
      
      if (action === "query") {
        if (taskName) {
          cmd += "Get-ScheduledTask -TaskName '" + taskName + "' | Format-List TaskName, State, Description, Author, LastRunTime, NextRunTime, LastTaskResult";
        } else {
          cmd += "Get-ScheduledTask | Select-Object TaskName, State, Description | Format-Table -AutoSize | Out-String";
        }
      } else if (action === "status" && taskName) {
        cmd += "Get-ScheduledTask -TaskName '" + taskName + "' | Format-List *; " +
              "Get-ScheduledTaskInfo -TaskName '" + taskName + "' | Format-List *";
      } else {
        return {
          isError: true,
          content: [
            {
              type: "text",
              text: "For 'status' action, taskName parameter is required",
            },
          ],
        };
      }
      
      cmd += "\"";
      
      const stdout = executeCommand(cmd);
      
      return {
        content: [
          {
            type: "text",
            text: stdout.toString(),
          },
        ],
      };
    } catch (error) {
      return {
        isError: true,
        content: [
          {
            type: "text",
            text: `Error retrieving scheduled tasks: ${error}`,
          },
        ],
      };
    }
  }
);

// Register the get_service_info tool
server.tool(
  "get_service_info",
  "Retrieve information about Windows services. Can query all services or get detailed status of a specific service.",
  {
    action: z.enum(["query", "status"]).default("query").describe("Action to perform"),
    serviceName: z.string().optional().describe("Service name to get info about (optional)"),
  },
  async ({ action, serviceName }) => {
    if (!isWindows) {
      return {
        content: [
          {
            type: "text",
            text: "The service info tool is only available on Windows. Current platform: " + platform(),
          },
        ],
      };
    }
    
    try {
      let cmd = "powershell.exe -Command \"";
      
      if (action === "query") {
        if (serviceName) {
          cmd += "Get-Service -Name '" + serviceName + "' | Format-List Name, DisplayName, Status, StartType, Description";
        } else {
          cmd += "Get-Service | Select-Object Name, DisplayName, Status, StartType | Format-Table -AutoSize | Out-String";
        }
      } else if (action === "status" && serviceName) {
        cmd += "Get-Service -Name '" + serviceName + "' | Format-List *; " +
              "Get-CimInstance -ClassName Win32_Service -Filter \"Name='" + serviceName + "'\" | Format-List *";
      } else {
        return {
          isError: true,
          content: [
            {
              type: "text",
              text: "For 'status' action, serviceName parameter is required",
            },
          ],
        };
      }
      
      cmd += "\"";
      
      const stdout = executeCommand(cmd);
      
      return {
        content: [
          {
            type: "text",
            text: stdout.toString(),
          },
        ],
      };
    } catch (error) {
      return {
        isError: true,
        content: [
          {
            type: "text",
            text: `Error retrieving service info: ${error}`,
          },
        ],
      };
    }
  }
);

// Register the list_allowed_commands tool
server.tool(
  "list_allowed_commands",
  "List all commands that are allowed to be executed by this server. This helps understand what operations are permitted.",
  {},
  async () => {
    try {
      if (isWindows) {
        return {
          content: [
            {
              type: "text",
              text: "The following commands are allowed to be executed by this server:\n\n" +
                    "- powershell.exe: Used for most system operations\n" +
                    "- cmd.exe: Used for simple command execution\n\n" +
                    "Note: All commands are executed with the same privileges as the user running this server."
            },
          ],
        };
      } else {
        return {
          content: [
            {
              type: "text",
              text: "Running on non-Windows platform: " + platform() + "\n\n" +
                    "Standard Unix/Linux commands are available, but Windows-specific commands like powershell.exe and cmd.exe are not available in this environment.\n\n" +
                    "The following commands should work:\n" +
                    "- ls: List directory contents\n" +
                    "- ps: List processes\n" +
                    "- uname: Print system information\n" +
                    "- ip: Show network information\n\n" +
                    "Note: All commands are executed with the same privileges as the user running this server."
            },
          ],
        };
      }
    } catch (error) {
      return {
        isError: true,
        content: [
          {
            type: "text",
            text: `Error listing allowed commands: ${error}`,
          },
        ],
      };
    }
  }
);

// Register the execute_command tool
server.tool(
  "execute_command",
  "Execute a Windows command and return its output, similar to a shell/bash tool. Only commands not matching the dangerous-pattern blocklist can be executed, " +
  "unless the dangerous-command override is currently unlocked (see request_dangerous_override_code). " +
  "The working directory persists across calls (pass workingDir to change it, like 'cd'). " +
  "For commands that may run longer than the timeout, set runInBackground to true and poll with get_background_output.",
  {
    command: z.string().describe("The command to execute"),
    workingDir: z.string().optional().describe("Working directory for the command. If provided, also becomes the persisted working directory for subsequent calls."),
    timeout: z.number().default(DEFAULT_TIMEOUT_MS).describe(`Timeout in milliseconds (default ${DEFAULT_TIMEOUT_MS}, max ${MAX_TIMEOUT_MS}). Ignored when runInBackground is true.`),
    runInBackground: z.boolean().default(false).describe("If true, start the command detached and return immediately with a process id. Use get_background_output, list_background_processes, and stop_background_process to manage it."),
  },
  async ({ command, workingDir, timeout, runInBackground }) => {
    try {
      // Security check: Ensure only allowed commands are executed
      const commandLower = command.toLowerCase();

      // Block potentially dangerous commands, unless a human has unlocked the override.
      if (DANGEROUS_CMD_PATTERNS.some(pattern => commandLower.includes(pattern.toLowerCase()))) {
        if (!isUnsafeModeUnlocked()) {
          return {
            isError: true,
            content: [
              {
                type: "text",
                text: "Command contains potentially dangerous operations and cannot be executed. " +
                      "Call request_dangerous_override_code and ask the server operator for the code to bypass this for one command.",
              },
            ],
          };
        }
        consumeUnsafeModeUnlock();
        console.error(`[unsafe-mode] Executing dangerous-pattern command via override: ${command}`);
      }

      const cwd = resolveWorkingDir(workingDir);

      if (runInBackground) {
        const id = isWindows
          ? spawnBackground("cmd.exe", ["/c", command], cwd, command)
          : spawnBackground("/bin/sh", ["-c", command], cwd, command);
        return {
          content: [
            {
              type: "text",
              text: `Started in background with id ${id}. Use get_background_output with this id to fetch output.`,
            },
          ],
        };
      }

      const options: any = { timeout: clampTimeout(timeout), cwd };

      let cmdToExecute;
      if (isWindows) {
        cmdToExecute = `cmd.exe /c ${command}`;
      } else {
        // For non-Windows, try to execute the command directly
        cmdToExecute = command;
      }

      const stdout = executeCommand(cmdToExecute, options);
      return {
        content: [
          {
            type: "text",
            text: stdout.toString() || 'Command executed successfully (no output)',
          },
        ],
      };
    } catch (error) {
      return {
        isError: true,
        content: [
          {
            type: "text",
            text: `Error executing command: ${error}`,
          },
        ],
      };
    }
  }
);

// Register the execute_powershell tool
server.tool(
  "execute_powershell",
  "Execute a PowerShell script and return its output. This allows for more complex operations and script execution. Only scripts not matching the " +
  "dangerous-pattern blocklist can be executed, unless the dangerous-command override is currently unlocked (see request_dangerous_override_code). " +
  "The working directory persists across calls (pass workingDir to change it, like 'cd'). " +
  "For scripts that may run longer than the timeout, set runInBackground to true and poll with get_background_output.",
  {
    script: z.string().describe("PowerShell script to execute"),
    workingDir: z.string().optional().describe("Working directory for the script. If provided, also becomes the persisted working directory for subsequent calls."),
    timeout: z.number().default(DEFAULT_TIMEOUT_MS).describe(`Timeout in milliseconds (default ${DEFAULT_TIMEOUT_MS}, max ${MAX_TIMEOUT_MS}). Ignored when runInBackground is true.`),
    runInBackground: z.boolean().default(false).describe("If true, start the script detached and return immediately with a process id. Use get_background_output, list_background_processes, and stop_background_process to manage it."),
  },
  async ({ script, workingDir, timeout, runInBackground }) => {
    if (!isWindows) {
      return {
        content: [
          {
            type: "text",
            text: "The PowerShell execution tool is only available on Windows. Current platform: " + platform(),
          },
        ],
      };
    }

    try {
      // Security check: Ensure no dangerous operations
      const scriptLower = script.toLowerCase();

      // Block potentially dangerous commands, unless a human has unlocked the override.
      if (DANGEROUS_PS_PATTERNS.some(pattern => scriptLower.includes(pattern.toLowerCase()))) {
        if (!isUnsafeModeUnlocked()) {
          return {
            isError: true,
            content: [
              {
                type: "text",
                text: "Script contains potentially dangerous operations and cannot be executed. " +
                      "Call request_dangerous_override_code and ask the server operator for the code to bypass this for one command.",
              },
            ],
          };
        }
        consumeUnsafeModeUnlock();
        console.error(`[unsafe-mode] Executing dangerous-pattern PowerShell script via override: ${script}`);
      }

      const cwd = resolveWorkingDir(workingDir);

      if (runInBackground) {
        const id = spawnBackground("powershell.exe", ["-Command", script], cwd, script);
        return {
          content: [
            {
              type: "text",
              text: `Started in background with id ${id}. Use get_background_output with this id to fetch output.`,
            },
          ],
        };
      }

      const options: any = { timeout: clampTimeout(timeout), cwd };

      const stdout = executeCommand(`powershell.exe -Command "${script}"`, options);
      return {
        content: [
          {
            type: "text",
            text: stdout.toString() || 'PowerShell script executed successfully (no output)',
          },
        ],
      };
    } catch (error) {
      return {
        isError: true,
        content: [
          {
            type: "text",
            text: `Error executing PowerShell script: ${error}`,
          },
        ],
      };
    }
  }
);

// Register the dangerous-command override tools. These exist to let a human who has console/log
// access to this machine deliberately authorize one otherwise-blocked command, without ever
// putting the unlock code in front of the AI/MCP client itself.
server.tool(
  "request_dangerous_override_code",
  "Request a one-time code to bypass the dangerous-command blocklist for a single execute_command or execute_powershell call. " +
  "The code is printed to this server's own console/log output, NOT returned here - you must ask the person operating this " +
  "server for it, then call unlock_dangerous_commands with the code they give you.",
  {},
  async () => {
    const code = String(randomInt(100000, 1000000));
    unsafeMode.pendingCode = code;
    unsafeMode.pendingCodeExpiresAt = Date.now() + UNSAFE_CODE_TTL_MS;
    unsafeMode.failedAttempts = 0;

    console.error(
      "\n" +
      "================================================================\n" +
      " DANGEROUS COMMAND OVERRIDE REQUESTED\n" +
      ` Confirmation code: ${code}\n` +
      ` Expires in ${Math.round(UNSAFE_CODE_TTL_MS / 60000)} minute(s).\n` +
      " Only share this code if you intend to let the AI run ONE command\n" +
      " that this server would otherwise block as dangerous.\n" +
      "================================================================\n"
    );

    return {
      content: [
        {
          type: "text",
          text: "A confirmation code was generated and printed to this server's console/log output. " +
                "Ask the person operating this server to read it to you, then call unlock_dangerous_commands with that code. " +
                `It expires in ${Math.round(UNSAFE_CODE_TTL_MS / 60000)} minute(s).`,
        },
      ],
    };
  }
);

server.tool(
  "unlock_dangerous_commands",
  "Redeem the code from request_dangerous_override_code to bypass the dangerous-command blocklist for the next single " +
  "execute_command or execute_powershell call that would otherwise be blocked.",
  {
    code: z.string().describe("The confirmation code shown on the server's console by request_dangerous_override_code"),
  },
  async ({ code }) => {
    if (!unsafeMode.pendingCode || !unsafeMode.pendingCodeExpiresAt || Date.now() > unsafeMode.pendingCodeExpiresAt) {
      unsafeMode.pendingCode = null;
      unsafeMode.pendingCodeExpiresAt = null;
      return {
        isError: true,
        content: [{ type: "text", text: "No pending code (or it expired). Call request_dangerous_override_code to get a new one." }],
      };
    }

    if (code.trim() !== unsafeMode.pendingCode) {
      unsafeMode.failedAttempts += 1;
      if (unsafeMode.failedAttempts >= MAX_UNSAFE_CODE_ATTEMPTS) {
        unsafeMode.pendingCode = null;
        unsafeMode.pendingCodeExpiresAt = null;
        unsafeMode.failedAttempts = 0;
        return {
          isError: true,
          content: [{ type: "text", text: "Incorrect code, too many attempts. Call request_dangerous_override_code to get a new one." }],
        };
      }
      return {
        isError: true,
        content: [{ type: "text", text: `Incorrect code (${MAX_UNSAFE_CODE_ATTEMPTS - unsafeMode.failedAttempts} attempt(s) remaining before it is invalidated).` }],
      };
    }

    unsafeMode.pendingCode = null;
    unsafeMode.pendingCodeExpiresAt = null;
    unsafeMode.failedAttempts = 0;
    unsafeMode.unlockedUntil = Date.now() + UNSAFE_UNLOCK_TTL_MS;
    console.error("[unsafe-mode] Dangerous-command override unlocked for the next matching command.");

    return {
      content: [
        {
          type: "text",
          text: "Unlocked. The next execute_command or execute_powershell call that matches the dangerous-pattern blocklist will be allowed " +
                `through (expires in ${Math.round(UNSAFE_UNLOCK_TTL_MS / 60000)} minute(s) if unused).`,
        },
      ],
    };
  }
);

// Register the download_file tool
server.tool(
  "download_file",
  "Read a file from this computer and return its contents so it can be downloaded/saved by the MCP client. " +
  `Text files are returned as plain text by default; binary files are base64-encoded. Files larger than ${MAX_DOWNLOAD_BYTES} bytes are rejected (set MCP_MAX_DOWNLOAD_BYTES to change this).`,
  {
    path: z.string().describe("Path to the file to download. Relative paths are resolved against the current persisted working directory (see execute_command's workingDir)."),
    encoding: z.enum(["auto", "text", "base64"]).default("auto").describe("'auto' picks text for text-like files and base64 for everything else; 'text' forces UTF-8 text; 'base64' forces base64 encoding."),
  },
  async ({ path: filePath, encoding }) => {
    try {
      const resolvedPath = resolve(currentWorkingDirectory, filePath);
      if (!existsSync(resolvedPath)) {
        return { isError: true, content: [{ type: "text", text: `File not found: ${resolvedPath}` }] };
      }
      const stats = statSync(resolvedPath);
      if (!stats.isFile()) {
        return { isError: true, content: [{ type: "text", text: `Not a regular file: ${resolvedPath}` }] };
      }
      if (stats.size > MAX_DOWNLOAD_BYTES) {
        return {
          isError: true,
          content: [
            {
              type: "text",
              text: `File is too large to download (${stats.size} bytes, limit is ${MAX_DOWNLOAD_BYTES} bytes). ` +
                    `Set MCP_MAX_DOWNLOAD_BYTES to raise the limit.`,
            },
          ],
        };
      }

      const buffer = readFileSync(resolvedPath);
      const mimeType = guessMimeType(resolvedPath);
      const asText =
        encoding === "text" ||
        (encoding === "auto" &&
          (mimeType.startsWith("text/") || mimeType === "application/json" || mimeType === "application/xml" || looksLikeText(buffer)));
      const uri = pathToFileURL(resolvedPath).href;

      return {
        content: [
          {
            type: "text",
            text: `Downloaded ${resolvedPath} (${stats.size} bytes, ${mimeType}, ${asText ? "text" : "base64"}).`,
          },
          {
            type: "resource",
            resource: asText
              ? { uri, mimeType, text: buffer.toString("utf-8") }
              : { uri, mimeType, blob: buffer.toString("base64") },
          },
        ],
      };
    } catch (error) {
      return { isError: true, content: [{ type: "text", text: `Error downloading file: ${error}` }] };
    }
  }
);

// Register background-process management tools (mirrors run_in_background + monitor/stop tooling
// found in interactive shell tools).
server.tool(
  "get_background_output",
  "Fetch the buffered stdout/stderr and status of a command started with runInBackground. Output accumulates until the process exits.",
  {
    id: z.string().describe("The background process id returned when it was started"),
  },
  async ({ id }) => {
    const entry = backgroundProcesses.get(id);
    if (!entry) {
      return {
        isError: true,
        content: [{ type: "text", text: `No background process found with id ${id}` }],
      };
    }
    const summary =
      `id: ${entry.id}\n` +
      `command: ${entry.command}\n` +
      `status: ${entry.status}\n` +
      `exitCode: ${entry.exitCode ?? "(still running)"}\n` +
      `startedAt: ${entry.startedAt.toISOString()}\n` +
      `endedAt: ${entry.endedAt ? entry.endedAt.toISOString() : "(still running)"}\n\n` +
      `--- stdout ---\n${entry.stdout || "(empty)"}\n\n` +
      `--- stderr ---\n${entry.stderr || "(empty)"}`;
    return { content: [{ type: "text", text: summary }] };
  }
);

server.tool(
  "list_background_processes",
  "List all background processes started via runInBackground, with their status.",
  {},
  async () => {
    if (backgroundProcesses.size === 0) {
      return { content: [{ type: "text", text: "No background processes." }] };
    }
    const lines = Array.from(backgroundProcesses.values()).map(
      (entry) =>
        `${entry.id}  [${entry.status}]  started ${entry.startedAt.toISOString()}  ${entry.command}`
    );
    return { content: [{ type: "text", text: lines.join("\n") }] };
  }
);

server.tool(
  "stop_background_process",
  "Terminate a running background process started via runInBackground.",
  {
    id: z.string().describe("The background process id to terminate"),
  },
  async ({ id }) => {
    const entry = backgroundProcesses.get(id);
    if (!entry) {
      return {
        isError: true,
        content: [{ type: "text", text: `No background process found with id ${id}` }],
      };
    }
    if (entry.status !== "running") {
      return {
        content: [{ type: "text", text: `Process ${id} is already ${entry.status}.` }],
      };
    }
    try {
      if (isWindows && entry.proc.pid) {
        execSync(`taskkill /PID ${entry.proc.pid} /T /F`);
      } else {
        entry.proc.kill("SIGTERM");
      }
      entry.status = "killed";
      entry.endedAt = new Date();
      return { content: [{ type: "text", text: `Process ${id} terminated.` }] };
    } catch (error) {
      return {
        isError: true,
        content: [{ type: "text", text: `Error terminating process ${id}: ${error}` }],
      };
    }
  }
);

  return server;
}

// Constant-time comparison of a bearer token against the configured secret.
function isValidToken(provided: string, expected: string): boolean {
  const providedBuf = Buffer.from(provided);
  const expectedBuf = Buffer.from(expected);
  if (providedBuf.length !== expectedBuf.length) {
    // Still run a comparison so response time doesn't leak length info.
    timingSafeEqual(expectedBuf, expectedBuf);
    return false;
  }
  return timingSafeEqual(providedBuf, expectedBuf);
}

// Start the server over stdio (default; used by MCP clients that spawn this as a local subprocess).
async function startStdio() {
  const server = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Windows Command Line MCP Server running on stdio");
}

// Start the server as a standalone HTTP service using the MCP Streamable HTTP transport,
// so it can be reached the same way as any other remote MCP server (POST/GET/DELETE /mcp).
async function startHttp() {
  const host = process.env.MCP_HOST || "127.0.0.1";
  const port = process.env.MCP_PORT ? parseInt(process.env.MCP_PORT, 10) : 3000;
  const authToken = process.env.MCP_AUTH_TOKEN;

  if (host !== "127.0.0.1" && host !== "localhost" && host !== "::1" && !authToken) {
    console.error(
      `Warning: Binding to ${host} without MCP_AUTH_TOKEN set. This server can execute arbitrary ` +
      `commands - anyone who can reach this address and port will be able to run commands on this machine. ` +
      `Set MCP_AUTH_TOKEN or bind to localhost only.`
    );
  }

  const publicUrl = process.env.MCP_PUBLIC_URL || `http://${host === "0.0.0.0" ? "localhost" : host}:${port}`;
  const resourceServerUrl = new URL("/mcp", publicUrl);

  // Allow the loopback aliases plus whatever hostname MCP_PUBLIC_URL points at, so a reverse
  // proxy or tunnel (which sends its own Host header, not "localhost") isn't rejected by the
  // DNS-rebinding-protection middleware below.
  const allowedHosts = Array.from(new Set(["127.0.0.1", "localhost", "[::1]", host, resourceServerUrl.hostname]));
  const app = createMcpExpressApp({ host, allowedHosts });

  // When MCP_PUBLIC_URL points somewhere other than this process's own bind address, we're
  // behind a reverse proxy or tunnel. Tell Express to trust its X-Forwarded-* headers (one hop)
  // so req.ip/req.protocol are correct and express-rate-limit doesn't reject them.
  if (resourceServerUrl.hostname !== host) {
    const trustProxyHops = process.env.MCP_TRUST_PROXY ? parseInt(process.env.MCP_TRUST_PROXY, 10) : 1;
    app.set("trust proxy", trustProxyHops);
  }

  let oauthBearer: ((req: Request, res: Response, next: NextFunction) => void) | undefined;
  try {
    oauthBearer = installOAuthShim({
      app,
      issuerUrl: new URL(publicUrl),
      resourceServerUrl,
      authToken,
    });
    console.error(`OAuth endpoints available under ${publicUrl} (discovery, /register, /authorize, /token).`);
  } catch (error) {
    console.error(
      `OAuth support disabled: ${error}. Set MCP_PUBLIC_URL to an https:// URL (or a localhost URL) to enable it. ` +
      `Falling back to plain bearer-token auth only.`
    );
  }
  if (!process.env.MCP_PUBLIC_URL && host !== "127.0.0.1" && host !== "localhost" && host !== "::1") {
    console.error(
      "Warning: MCP_PUBLIC_URL is not set. OAuth issuer/resource URLs default to this server's bind address, " +
      "which is wrong if it's reached through a reverse proxy or tunnel - set MCP_PUBLIC_URL to the externally visible https:// URL."
    );
  }

  // Accepts either the raw MCP_AUTH_TOKEN as a static bearer token, or a token issued by the
  // OAuth shim's /token endpoint after a client completed the /authorize login form.
  const requireAuth = (req: Request, res: Response, next: NextFunction) => {
    if (!authToken) return next();
    const header = req.headers.authorization;
    const provided = header?.startsWith("Bearer ") ? header.slice(7) : undefined;
    if (provided && isValidToken(provided, authToken)) {
      next();
      return;
    }
    if (oauthBearer) {
      oauthBearer(req, res, next);
      return;
    }
    res.status(401).json({
      jsonrpc: "2.0",
      error: { code: -32001, message: "Unauthorized" },
      id: null,
    });
  };

  // Map of active sessions, keyed by MCP session ID.
  const transports: Record<string, StreamableHTTPServerTransport> = {};

  app.post("/mcp", requireAuth, async (req: Request, res: Response) => {
    const sessionId = req.headers["mcp-session-id"] as string | undefined;
    try {
      let transport: StreamableHTTPServerTransport;
      if (sessionId && transports[sessionId]) {
        transport = transports[sessionId];
      } else if (!sessionId && isInitializeRequest(req.body)) {
        transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          onsessioninitialized: (sid) => {
            transports[sid] = transport;
          },
        });
        transport.onclose = () => {
          const sid = transport.sessionId;
          if (sid && transports[sid]) {
            delete transports[sid];
          }
        };
        await createServer().connect(transport);
        await transport.handleRequest(req, res, req.body);
        return;
      } else {
        res.status(400).json({
          jsonrpc: "2.0",
          error: { code: -32000, message: "Bad Request: No valid session ID provided" },
          id: null,
        });
        return;
      }
      await transport.handleRequest(req, res, req.body);
    } catch (error) {
      console.error("Error handling MCP request:", error);
      if (!res.headersSent) {
        res.status(500).json({
          jsonrpc: "2.0",
          error: { code: -32603, message: "Internal server error" },
          id: null,
        });
      }
    }
  });

  const handleSessionRequest = async (req: Request, res: Response) => {
    const sessionId = req.headers["mcp-session-id"] as string | undefined;
    if (!sessionId || !transports[sessionId]) {
      res.status(400).send("Invalid or missing session ID");
      return;
    }
    await transports[sessionId].handleRequest(req, res);
  };

  app.get("/mcp", requireAuth, handleSessionRequest);
  app.delete("/mcp", requireAuth, handleSessionRequest);

  app.listen(port, host, () => {
    console.error(`Windows Command Line MCP Server listening on http://${host}:${port}/mcp`);
    if (!authToken) {
      console.error("Warning: MCP_AUTH_TOKEN is not set - the /mcp endpoint has no authentication.");
    }
  });

  process.on("SIGINT", async () => {
    for (const sessionId of Object.keys(transports)) {
      await transports[sessionId].close().catch(() => {});
      delete transports[sessionId];
    }
    process.exit(0);
  });
}

// Start the server
async function main() {
  // Log platform information on startup
  console.error(`Starting Windows Command Line MCP Server on platform: ${platform()}`);

  if (!isWindows) {
    console.error("Warning: This server is designed for Windows environments. Some features may not work on " + platform());
  }

  const transportMode = (process.env.MCP_TRANSPORT || "stdio").toLowerCase();
  if (transportMode === "http") {
    await startHttp();
  } else {
    await startStdio();
  }
}

main().catch((error) => {
  console.error("Fatal error in main():", error);
  process.exit(1);
});
