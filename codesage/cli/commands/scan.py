import click
import os
import sys
from pathlib import Path
from typing import Optional, List, Dict

from codesage.semantic_digest.python_snapshot_builder import PythonSemanticSnapshotBuilder, SnapshotConfig
from codesage.semantic_digest.go_snapshot_builder import GoSemanticSnapshotBuilder
from codesage.semantic_digest.shell_snapshot_builder import ShellSemanticSnapshotBuilder
from codesage.semantic_digest.java_snapshot_builder import JavaSemanticSnapshotBuilder
from codesage.snapshot.models import ProjectSnapshot, Issue, IssueLocation, FileSnapshot, ProjectRiskSummary, ProjectIssuesSummary, SnapshotMetadata, DependencyGraph
from collections import namedtuple
from codesage.reporters import ConsoleReporter, JsonReporter, GitHubPRReporter
from codesage.cli.plugin_loader import PluginManager
from codesage.history.store import StorageEngine
from codesage.core.interfaces import CodeIssue
from codesage.risk.risk_scorer import RiskScorer
from codesage.config.risk_baseline import RiskBaselineConfig
from codesage.rules.jules_specific_rules import JULES_RULESET
from codesage.rules.base import RuleContext
from datetime import datetime, timezone

# Create a simple wrapper class for Dict-based snapshots
class DictSnapshot:
    """Wrapper for Dict-based snapshots to make them compatible with ProjectSnapshot."""
    def __init__(self, data: dict):
        self.data = data
    
    @property
    def files(self):
        # Extract files from dict structure
        return self.data.get("files", [])
    
    @property
    def languages(self):
        # Extract languages from dict (with backward compatibility)
        return self.data.get("languages") or ["python"]
    
    @property
    def metadata(self):
        # Return a simple metadata object
        class SimpleMetadata:
            def __init__(self, data):
                self.file_count = len(data.get("files", []))
                self.total_size = 0  # Not available in dict
                self.version = "v1.0"
                self.timestamp = datetime.now(timezone.utc)
                self.project_name = "unknown"
                self.tool_version = "0.2.0"
                self.config_hash = "unknown"
                self.git_commit = None
        
        return SimpleMetadata(self.data)
    
    @property
    def dependencies(self):
        # Extract dependencies from dict
        class SimpleDeps:
            def __init__(self, data):
                self.internal = []
                self.external = data.get("deps", {}).get("imports", []) if isinstance(data.get("deps"), dict) else []
                self.edges = []
        
        return SimpleDeps(self.data)
    
    @property
    def risk_summary(self):
        return None
    
    @property
    def issues_summary(self):
        return None
    
    @property
    def llm_stats(self):
        return None
    
    @property
    def language_stats(self):
        return {}

def get_builder(language: str, path: Path):
    config = SnapshotConfig()
    if language == 'python':
        return PythonSemanticSnapshotBuilder(path, config)
    elif language == 'go':
        return GoSemanticSnapshotBuilder(path, config)
    elif language == 'shell':
        return ShellSemanticSnapshotBuilder(path, config)
    elif language == 'java':
        return JavaSemanticSnapshotBuilder(path, config)
    else:
        return None

def detect_languages(path: Path) -> List[str]:
    languages = set()
    for root, _, files in os.walk(path):
        for file in files:
            if file.endswith(".py"):
                languages.add("python")
            elif file.endswith(".go"):
                languages.add("go")
            elif file.endswith(".java"):
                languages.add("java")
            elif file.endswith(".sh"):
                languages.add("shell")
    return list(languages)

def merge_snapshots(snapshots: List, project_name: str) -> ProjectSnapshot:
    if not snapshots:
        raise ValueError("No snapshots to merge")
    
    # Handle single DictSnapshot case - return the first ProjectSnapshot or create a minimal one
    if len(snapshots) == 1 and isinstance(snapshots[0], DictSnapshot):
        # For DictSnapshot, we need to create a minimal ProjectSnapshot
        dict_snap = snapshots[0].data
        from codesage.snapshot.yaml_generator import YAMLGenerator
        generator = YAMLGenerator()
        
        # Convert dict-based snapshot to ProjectSnapshot structure
        # This is a minimal conversion for compatibility
        files_list = []
        for file_path in dict_snap.get("files", []):
            files_list.append(FileSnapshot(
                path=file_path,
                language="python",
                size=None,
                content=None,
                metrics=None,
                symbols={},
                risk=None,
                issues=[]
            ))
        
        return ProjectSnapshot(
            metadata=SnapshotMetadata(
                version="v1.0",
                timestamp=datetime.now(timezone.utc),
                project_name=project_name,
                file_count=len(files_list),
                total_size=0,
                tool_version="0.2.0",
                config_hash="dict-snapshot",
                git_commit=None
            ),
            files=files_list,
            dependencies=DependencyGraph(
                internal=[],
                external=[],
                edges=[]
            ),
            languages=["python"],
            risk_summary=None,
            issues_summary=None,
            llm_stats=None,
            language_stats={}
        )

    if len(snapshots) == 1:
        return snapshots[0]

    files: List[FileSnapshot] = []
    languages: List[str] = []
    file_count = 0
    total_size = 0

    # Collect files and calculate basic metadata
    for s in snapshots:
        files.extend(s.files)
        languages.extend(s.languages if s.languages else [])
        file_count += s.metadata.file_count
        total_size += s.metadata.total_size

    # Deduplicate languages
    languages = list(set(languages))

    # Merge Risk Summary
    # This is a simplified merge. Ideally, we should recalculate.
    # But summarize_project_risk takes file_risks map. We can do that.
    # Re-import summarize logic if needed, or just aggregate counts.
    high_risk = sum(s.risk_summary.high_risk_files for s in snapshots if s.risk_summary)
    medium_risk = sum(s.risk_summary.medium_risk_files for s in snapshots if s.risk_summary)
    low_risk = sum(s.risk_summary.low_risk_files for s in snapshots if s.risk_summary)

    # Average risk is weighted by file count
    total_risk_score = sum(s.risk_summary.avg_risk * s.metadata.file_count for s in snapshots if s.risk_summary)
    avg_risk = total_risk_score / file_count if file_count > 0 else 0.0

    risk_summary = ProjectRiskSummary(
        avg_risk=avg_risk,
        high_risk_files=high_risk,
        medium_risk_files=medium_risk,
        low_risk_files=low_risk
    )

    # Merge Issues Summary
    total_issues = 0
    by_severity = {}
    by_rule = {}

    for s in snapshots:
        if s.issues_summary:
            total_issues += s.issues_summary.total_issues
            for sev, count in s.issues_summary.by_severity.items():
                by_severity[sev] = by_severity.get(sev, 0) + count
            for rule, count in s.issues_summary.by_rule.items():
                by_rule[rule] = by_rule.get(rule, 0) + count

    issues_summary = ProjectIssuesSummary(
        total_issues=total_issues,
        by_severity=by_severity,
        by_rule=by_rule
    )

    # Merge Dependencies (Simple concatenation)
    internal_deps = []
    external_deps = []
    for s in snapshots:
        if s.dependencies:
            internal_deps.extend(s.dependencies.internal)
            external_deps.extend(s.dependencies.external)

    dependency_graph = DependencyGraph(
        internal=internal_deps,
        external=list(set(external_deps)),
        edges=[]
    )

    metadata = SnapshotMetadata(
        version=snapshots[0].metadata.version,
        timestamp=datetime.now(timezone.utc),
        project_name=project_name,
        file_count=file_count,
        total_size=total_size,
        tool_version=snapshots[0].metadata.tool_version,
        config_hash=snapshots[0].metadata.config_hash # Assuming same config for all
    )

    return ProjectSnapshot(
        metadata=metadata,
        files=files,
        dependencies=dependency_graph,
        risk_summary=risk_summary,
        issues_summary=issues_summary,
        languages=languages
    )

@click.command('scan')
@click.argument('path', type=click.Path(exists=True, dir_okay=True))
@click.option('--language', '-l', type=click.Choice(['python', 'go', 'shell', 'java', 'auto']), default='auto', help='Language to analyze.')
@click.option('--reporter', '-r', type=click.Choice(['console', 'json', 'github']), default='console', help='Reporter to use.')
@click.option('--output', '-o', help='Output path for JSON reporter.')
@click.option('--fail-on-high', is_flag=True, help='Exit with non-zero code if high severity issues are found.')
@click.option('--ci-mode', is_flag=True, help='Enable CI mode (auto-detect GitHub environment).')
@click.option('--plugins-dir', default='.codesage/plugins', help='Directory containing plugins.')
@click.option('--db-url', default='sqlite:///codesage.db', help='Database URL for storage.')
@click.option('--git-repo', type=click.Path(), help='Git 仓库路径（用于变更历史分析）')
@click.option('--coverage-report', type=click.Path(), help='覆盖率报告路径（Cobertura/JaCoCo XML）')
@click.pass_context
def scan(ctx, path, language, reporter, output, fail_on_high, ci_mode, plugins_dir, db_url, git_repo, coverage_report):
    """
    Scan the codebase and report issues.
    """
    # 1. Initialize Database
    try:
        storage = StorageEngine(db_url)
        click.echo(f"Connected to storage: {db_url}")
    except Exception as e:
        click.echo(f"Warning: Could not connect to storage: {e}", err=True)
        storage = None

    # 2. Load Plugins
    plugin_manager = PluginManager(plugins_dir)
    plugin_manager.load_plugins()

    root_path = Path(path)
    target_languages = []

    if language == 'auto':
        click.echo(f"Auto-detecting languages in {path}...")
        target_languages = detect_languages(root_path)
        if not target_languages:
            click.echo("No supported languages found.", err=True)
            ctx.exit(1)
        click.echo(f"Detected languages: {', '.join(target_languages)}")
    else:
        target_languages = [language]

    snapshots = []

    for lang in target_languages:
        click.echo(f"Scanning {path} for {lang}...")
        builder = get_builder(lang, root_path)

        if not builder:
            click.echo(f"Unsupported language: {lang}", err=True)
            continue

        try:
            s = builder.build()
            # Handle both Dict and ProjectSnapshot return types
            # Some builders (e.g., PythonSemanticSnapshotBuilder) return Dict instead of ProjectSnapshot
            if isinstance(s, dict):
                # Wrap Dict in DictSnapshot for compatibility
                if "languages" not in s:
                    s["languages"] = [lang]
                s = DictSnapshot(s)
            else:
                # For ProjectSnapshot, ensure language list is populated
                if not s.languages:
                    s.languages = [lang]
            snapshots.append(s)
        except Exception as e:
            click.echo(f"Scan failed for {lang}: {e}", err=True)
            # We continue to try other languages

    if not snapshots:
        click.echo("No snapshots generated.", err=True)
        ctx.exit(1)

    # Merge snapshots
    try:
        snapshot = merge_snapshots(snapshots, root_path.name)
    except Exception as e:
        click.echo(f"Failed to merge snapshots: {e}", err=True)
        ctx.exit(1)

    # Populate file contents if missing (needed for rules)
    click.echo("Populating file contents...")
    for file_snapshot in snapshot.files:
        if not file_snapshot.content:
            try:
                full_path = root_path / file_snapshot.path
                if full_path.exists():
                    file_snapshot.content = full_path.read_text(errors='ignore')
                    # Update size if missing
                    if file_snapshot.size is None:
                        file_snapshot.size = len(file_snapshot.content)
            except Exception as e:
                # logger.warning(f"Failed to read file {file_snapshot.path}: {e}")
                pass

    # 3. Apply Risk Scoring (Enhanced in Phase 1)
    try:
        risk_config = RiskBaselineConfig() # Load default config
        scorer = RiskScorer(
            config=risk_config,
            repo_path=git_repo or path, # Default to scanned path if not specified
            coverage_report=coverage_report
        )
        snapshot = scorer.score_project(snapshot)
    except Exception as e:
        click.echo(f"Warning: Risk scoring failed: {e}", err=True)

    # 4. Apply Custom Rules (Plugins & Jules Rules)

    # Create RuleContext
    # We need a dummy config for now as RuleContext expects one, but JulesRules might not use it.
    # However, PythonRulesetBaselineConfig is expected by RuleContext definition in base.py.
    # We need to import it or mock it.
    from codesage.config.rules_python_baseline import RulesPythonBaselineConfig
    rule_config = RulesPythonBaselineConfig() # Default config

    # Apply Jules Specific Rules
    click.echo("Applying Jules-specific rules...")
    for rule in JULES_RULESET:
        for file_snapshot in snapshot.files:
             try:
                # Create context for this file
                rule_ctx = RuleContext(
                    project=snapshot,
                    file=file_snapshot,
                    config=rule_config
                )

                # Call rule.check(ctx)
                # Ensure rule supports check(ctx)
                issues = rule.check(rule_ctx)

                if issues:
                    if file_snapshot.issues is None:
                        file_snapshot.issues = []
                    file_snapshot.issues.extend(issues)
             except Exception as e:
                 click.echo(f"Error applying rule {rule.rule_id} to {file_snapshot.path}: {e}", err=True)

    # Apply Plugin Rules
    for rule in plugin_manager.rules:
        # Ensure we iterate over the list of files
        for file_snapshot in snapshot.files:
            file_path = Path(file_snapshot.path)
            try:
                # Content is already populated now
                content = file_snapshot.content or ""

                issues = rule.check(str(file_path), content, {})
                if issues:
                    for i in issues:
                        # Convert plugin CodeIssue to standard Issue model

                        # Map severity to Issue severity Literal
                        severity = "warning"
                        if i.severity.lower() in ["info", "warning", "error"]:
                            severity = i.severity.lower()
                        elif i.severity.lower() == "high":
                            severity = "error"
                        elif i.severity.lower() == "low":
                            severity = "info"

                        new_issue = Issue(
                            rule_id=rule.id,
                            severity=severity,
                            message=i.description,
                            location=IssueLocation(
                                file_path=str(file_path),
                                line=i.line_number
                            ),
                            symbol=None,
                            tags=["custom-rule"]
                        )

                        if file_snapshot.issues is None:
                            file_snapshot.issues = []
                        file_snapshot.issues.append(new_issue)

            except Exception as e:
                 click.echo(f"Error running rule {rule.id} on {file_path}: {e}", err=True)

    # Recalculate Issues Summary after Plugins & Jules Rules
    total_issues = 0
    by_severity = {}
    by_rule = {}

    for f in snapshot.files:
        if f.issues:
            total_issues += len(f.issues)
            for issue in f.issues:
                by_severity[issue.severity] = by_severity.get(issue.severity, 0) + 1
                if issue.rule_id:
                    by_rule[issue.rule_id] = by_rule.get(issue.rule_id, 0) + 1

    # Update snapshot summary if issues changed
    if snapshot.issues_summary:
         snapshot.issues_summary.total_issues = total_issues
         snapshot.issues_summary.by_severity = by_severity
         snapshot.issues_summary.by_rule = by_rule
    else:
         snapshot.issues_summary = ProjectIssuesSummary(
             total_issues=total_issues,
             by_severity=by_severity,
             by_rule=by_rule
         )


    # 5. Save to Storage
    if storage:
        try:
            storage.save_snapshot(snapshot.metadata.project_name, snapshot)
            click.echo("Snapshot saved to database.")
        except Exception as e:
             click.echo(f"Failed to save snapshot: {e}", err=True)

    # Select Reporter
    reporters = []

    # Always add console reporter unless we are in json mode only?
    # Usually CI logs want console output too.
    if reporter == 'console':
        reporters.append(ConsoleReporter())
    elif reporter == 'json':
        # Ensure absolute path if output is specified, to avoid CWD issues in tests or complex environments
        out_path = output or "codesage_report.json"
        if not os.path.isabs(out_path) and output:
            # If user provided relative path, it's relative to CWD.
            # JsonReporter handles path, but let's be explicit if needed.
            pass
        reporters.append(JsonReporter(output_path=out_path))
    elif reporter == 'github':
        reporters.append(ConsoleReporter()) # Still print to console

        # Check environment
        token = os.environ.get("GITHUB_TOKEN")
        repo = os.environ.get("GITHUB_REPOSITORY")

        # Try to get PR number
        pr_number = None
        ref = os.environ.get("GITHUB_REF") # refs/pull/123/merge
        if ref and "pull" in ref:
            try:
                pr_number = int(ref.split("/")[2])
            except (IndexError, ValueError):
                pass

        # Or from event.json
        event_path = os.environ.get("GITHUB_EVENT_PATH")
        if not pr_number and event_path and os.path.exists(event_path):
            import json
            try:
                with open(event_path) as f:
                    event = json.load(f)
                    pr_number = event.get("pull_request", {}).get("number")
            except Exception:
                pass

        if token and repo and pr_number:
            reporters.append(GitHubPRReporter(token=token, repo=repo, pr_number=pr_number))
        else:
            click.echo("GitHub reporter selected but missing environment variables (GITHUB_TOKEN, GITHUB_REPOSITORY) or not in a PR context.", err=True)

    # CI Mode overrides
    if ci_mode and os.environ.get("GITHUB_ACTIONS") == "true":
         # In CI mode, we might force certain reporters or behavior
         pass

    # Execute Reporters
    for r in reporters:
        r.report(snapshot)

    # Check Fail Condition
    if fail_on_high:
        has_high_risk = False
        if snapshot.issues_summary:
            if snapshot.issues_summary.by_severity.get('high', 0) > 0 or \
               snapshot.issues_summary.by_severity.get('error', 0) > 0:
                has_high_risk = True

        # Also check risk summary if issues are not populated but risk is
        if snapshot.risk_summary and snapshot.risk_summary.high_risk_files > 0:
             has_high_risk = True

        if has_high_risk:
            click.echo("Failure: High risk issues detected.", err=True)
            ctx.exit(1)

    click.echo("Scan finished successfully.")
