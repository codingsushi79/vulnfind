// vulnfind for VS Code: runs the vulnfind CLI and shows findings as diagnostics.
// No build step and no dependencies - plain CommonJS against the VS Code API.
const vscode = require('vscode');
const { execFile } = require('child_process');
const path = require('path');

const SEVERITY = {
  CRITICAL: vscode.DiagnosticSeverity.Error,
  HIGH: vscode.DiagnosticSeverity.Error,
  MEDIUM: vscode.DiagnosticSeverity.Warning,
  LOW: vscode.DiagnosticSeverity.Information,
  INFO: vscode.DiagnosticSeverity.Hint,
};
const HASH_COMMENT = new Set(['python', 'ruby', 'shellscript', 'yaml', 'dockerfile', 'terraform', 'perl', 'r', 'toml', 'properties', 'makefile']);

let diagnostics, status, timer, running = false, pending = null;

function config() {
  return vscode.workspace.getConfiguration('vulnfind');
}

function scan(folder, full) {
  if (running) { pending = { folder, full }; return; }
  running = true;
  status.text = '$(sync~spin) vulnfind';
  const cfg = config();
  const args = [folder.uri.fsPath, '-f', 'json', '--no-progress', '--fail-on', 'none', '--no-record',
    '--min-severity', cfg.get('minSeverity')];
  if (!full) args.push('--scanners', cfg.get('scanners'));
  execFile(cfg.get('executable'), args, { maxBuffer: 64 * 1024 * 1024, cwd: folder.uri.fsPath }, (err, stdout, stderr) => {
    running = false;
    if (err && !stdout) {
      status.text = '$(warning) vulnfind';
      status.tooltip = (err.code === 'ENOENT')
        ? 'vulnfind not found - install it (uv tool install git+https://github.com/codingsushi79/vulnfind) or set vulnfind.executable'
        : String(stderr || err.message).slice(0, 500);
      return next();
    }
    try {
      publish(folder, JSON.parse(stdout));
    } catch (e) {
      status.text = '$(warning) vulnfind';
      status.tooltip = 'could not parse vulnfind output: ' + e.message;
    }
    next();
  });
}

function next() {
  if (pending) { const p = pending; pending = null; scan(p.folder, p.full); }
}

function publish(folder, report) {
  const byFile = new Map();
  for (const f of report.findings || []) {
    if (!f.file || /^(image:|dns:|https?:)/.test(f.file)) continue;
    const uri = vscode.Uri.file(path.join(folder.uri.fsPath, f.file));
    const line = Math.max(0, (f.line || 1) - 1);
    const col = Math.max(0, (f.column || 1) - 1);
    const range = new vscode.Range(line, col, line, Number.MAX_SAFE_INTEGER);
    const d = new vscode.Diagnostic(range, `${f.title}${f.fix ? '\nFix: ' + f.fix : ''}`, SEVERITY[f.severity] ?? vscode.DiagnosticSeverity.Warning);
    d.source = 'vulnfind';
    d.code = f.references && f.references[0] ? { value: f.rule_id, target: vscode.Uri.parse(f.references[0]) } : f.rule_id;
    const flow = (f.extra && f.extra.flow) || [];
    d.relatedInformation = flow.map(step => {
      const m = /^(?:(.+?):)?(?:line )?(\d+): (.*)$/.exec(step);
      if (!m) return null;
      const target = m[1] && !m[1].startsWith('line') ? vscode.Uri.file(path.join(folder.uri.fsPath, m[1])) : uri;
      const ln = Math.max(0, parseInt(m[2], 10) - 1);
      return new vscode.DiagnosticRelatedInformation(new vscode.Location(target, new vscode.Position(ln, 0)), m[3]);
    }).filter(Boolean);
    if (!byFile.has(uri.toString())) byFile.set(uri.toString(), { uri, list: [] });
    byFile.get(uri.toString()).list.push(d);
  }
  for (const [key] of diagnostics) if (key.fsPath && key.fsPath.startsWith(folder.uri.fsPath)) diagnostics.delete(key);
  for (const { uri, list } of byFile.values()) diagnostics.set(uri, list);
  const c = (report.summary && report.summary.counts) || {};
  const serious = (c.CRITICAL || 0) + (c.HIGH || 0);
  status.text = serious ? `$(shield) vulnfind: ${serious} critical/high` : `$(shield) vulnfind ${report.summary ? report.summary.grade : ''}`;
  status.tooltip = `${report.summary ? report.summary.total : 0} findings - click for a full scan incl. dependency CVEs`;
}

class SuppressAction {
  provideCodeActions(document, range, context) {
    return context.diagnostics.filter(d => d.source === 'vulnfind').map(d => {
      const rule = typeof d.code === 'object' ? d.code.value : d.code;
      const line = document.lineAt(d.range.start.line);
      const indent = line.text.slice(0, line.firstNonWhitespaceCharacterIndex);
      const prefix = HASH_COMMENT.has(document.languageId) ? '#' : '//';
      const action = new vscode.CodeAction(`Suppress ${rule} here (vulnfind:ignore)`, vscode.CodeActionKind.QuickFix);
      action.edit = new vscode.WorkspaceEdit();
      action.edit.insert(document.uri, new vscode.Position(d.range.start.line, 0), `${indent}${prefix} vulnfind:ignore ${rule} - reason: \n`);
      action.diagnostics = [d];
      return action;
    });
  }
}

function activate(context) {
  diagnostics = vscode.languages.createDiagnosticCollection('vulnfind');
  status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
  status.command = 'vulnfind.scanFull';
  status.text = '$(shield) vulnfind';
  status.show();
  const folders = () => vscode.workspace.workspaceFolders || [];
  context.subscriptions.push(
    diagnostics, status,
    vscode.commands.registerCommand('vulnfind.scan', () => folders().forEach(f => scan(f, false))),
    vscode.commands.registerCommand('vulnfind.scanFull', () => folders().forEach(f => scan(f, true))),
    vscode.commands.registerCommand('vulnfind.clear', () => diagnostics.clear()),
    vscode.languages.registerCodeActionsProvider({ scheme: 'file' }, new SuppressAction(), { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }),
    vscode.workspace.onDidSaveTextDocument(doc => {
      if (!config().get('scanOnSave')) return;
      const folder = vscode.workspace.getWorkspaceFolder(doc.uri);
      if (!folder) return;
      clearTimeout(timer);
      timer = setTimeout(() => scan(folder, false), 1200);
    }),
  );
  folders().forEach(f => scan(f, false));
}

function deactivate() {}

module.exports = { activate, deactivate };
