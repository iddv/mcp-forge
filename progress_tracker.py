#!/usr/bin/env python
"""
Progress Tracker for MCP-Forge Project

This script manages the project plan and updates the progress in the markdown file.
It provides functionality to:
- Update task status
- Generate progress statistics
- Create reports
"""

import os
import re
import json
import subprocess
from datetime import datetime

class ProgressTracker:
    """Tracks progress of the MCP-Forge implementation project."""
    
    STATUS_OPTIONS = ["Not Started", "In Progress", "Completed", "Blocked"]
    PLAN_FILE = os.path.join(os.path.dirname(__file__), "forge_mcp_server_plan.md")
    PROGRESS_DATA_FILE = os.path.join(os.path.dirname(__file__), "progress_data.json")
    
    def __init__(self):
        """Initialize the progress tracker."""
        self.tasks = []
        self.load_tasks_from_plan()
        self.load_progress_data()
        
    def load_tasks_from_plan(self):
        """Load tasks from the plan markdown file."""
        if not os.path.exists(self.PLAN_FILE):
            print(f"Plan file not found: {self.PLAN_FILE}")
            return
            
        with open(self.PLAN_FILE, 'r') as f:
            content = f.read()
            
        # Extract tasks table
        table_pattern = r'\|\s*Phase\s*\|\s*Task\s*\|\s*Status\s*\|\s*Notes\s*\|(.*?)(?=\n\n|\Z)'
        table_match = re.search(table_pattern, content, re.DOTALL)
        
        if not table_match:
            print("Could not find tasks table in plan file")
            return
            
        table_content = table_match.group(1)
        
        # Parse table rows
        row_pattern = r'\|\s*(\d+)\s*\|\s*(.*?)\s*\|\s*(.*?)\s*\|\s*(.*?)\s*\|'
        rows = re.findall(row_pattern, table_content)
        
        self.tasks = []
        for phase, task, status, notes in rows:
            self.tasks.append({
                'phase': int(phase),
                'task': task.strip(),
                'status': status.strip() or "Not Started",
                'notes': notes.strip(),
                'last_updated': None
            })
    
    def load_progress_data(self):
        """Load additional progress data from JSON file if it exists."""
        if os.path.exists(self.PROGRESS_DATA_FILE):
            try:
                with open(self.PROGRESS_DATA_FILE, 'r') as f:
                    progress_data = json.load(f)
                    
                # Merge additional data with tasks
                task_dict = {f"{t['phase']}:{t['task']}": t for t in self.tasks}
                
                for task_key, data in progress_data.items():
                    if task_key in task_dict:
                        task_dict[task_key].update(data)
                        
                # Recreate tasks list
                self.tasks = list(task_dict.values())
            except Exception as e:
                print(f"Error loading progress data: {e}")
    
    def save_progress_data(self):
        """Save additional progress data to JSON file."""
        # Create a dictionary of tasks with additional data
        progress_data = {}
        for task in self.tasks:
            task_key = f"{task['phase']}:{task['task']}"
            progress_data[task_key] = {
                'status': task['status'],
                'notes': task['notes'],
                'last_updated': task['last_updated'],
                'commit_sha': task.get('commit_sha')
            }
            
        with open(self.PROGRESS_DATA_FILE, 'w') as f:
            json.dump(progress_data, f, indent=2)
    
    def update_plan_file(self):
        """Update the markdown plan file with current task statuses."""
        if not os.path.exists(self.PLAN_FILE):
            print(f"Plan file not found: {self.PLAN_FILE}")
            return
            
        with open(self.PLAN_FILE, 'r') as f:
            content = f.read()
            
        # Update tasks in phases section
        for phase in range(1, 9):  # We have 8 phases
            phase_pattern = rf'### Phase {phase}:(.*?)(?=###|\Z)'
            phase_match = re.search(phase_pattern, content, re.DOTALL)
            
            if not phase_match:
                continue
                
            phase_content = phase_match.group(1)
            updated_phase_content = phase_content
            
            for task in self.tasks:
                if task['phase'] == phase:
                    task_pattern = rf'- \[([ x])\] {re.escape(task["task"])}'
                    checkbox = 'x' if task['status'] == 'Completed' else ' '
                    updated_task = f'- [{checkbox}] {task["task"]}'
                    
                    # Try to update the existing task
                    if re.search(task_pattern, updated_phase_content):
                        updated_phase_content = re.sub(task_pattern, updated_task, updated_phase_content)
            
            # Replace phase content
            content = content.replace(phase_match.group(0), f'### Phase {phase}:{updated_phase_content}')
        
        # Update task table
        table_pattern = r'(\| Phase \| Task \| Status \| Notes \|\n\|[-\s]*\|[-\s]*\|[-\s]*\|[-\s]*\|)(.*?)(?=\n\n|\Z)'
        table_match = re.search(table_pattern, content, re.DOTALL)
        
        if table_match:
            table_header = table_match.group(1)
            table_rows = ""
            
            for task in sorted(self.tasks, key=lambda x: (x['phase'], x['task'])):
                table_rows += f"| {task['phase']} | {task['task']} | {task['status']} | {task['notes']} |\n"
                
            updated_table = f"{table_header}\n{table_rows}"
            content = content.replace(table_match.group(0), updated_table)
        
        # Update summary statistics
        stats = self.get_statistics()
        stats_pattern = r'## Summary Statistics\n(.*?)(?=\n\n|\n##|\Z)'
        stats_text = f"## Summary Statistics\n- Total Tasks: {stats['total']}\n- Completed: {stats['completed']} ({stats['percent_completed']}%)\n- In Progress: {stats['in_progress']} ({stats['percent_in_progress']}%)\n- Not Started: {stats['not_started']} ({stats['percent_not_started']}%)\n- Blocked: {stats['blocked']} ({stats['percent_blocked']}%)"
        
        if re.search(stats_pattern, content, re.DOTALL):
            content = re.sub(stats_pattern, stats_text, content, flags=re.DOTALL)
        
        # Write updated content
        with open(self.PLAN_FILE, 'w') as f:
            f.write(content)
    
    def update_task_status(self, phase, task_name, new_status, notes=None, commit_sha=None):
        """
        Update the status of a specific task.
        
        Args:
            phase: Phase number
            task_name: Task name
            new_status: New status
            notes: Optional notes
            commit_sha: Optional commit SHA to associate with this update
        """
        if new_status not in self.STATUS_OPTIONS:
            print(f"Invalid status. Choose from: {', '.join(self.STATUS_OPTIONS)}")
            return False
            
        for task in self.tasks:
            if task['phase'] == phase and task['task'] == task_name:
                task['status'] = new_status
                task['last_updated'] = datetime.now().isoformat()
                if notes:
                    task['notes'] = notes
                if commit_sha:
                    task['commit_sha'] = commit_sha
                    
                self.save_progress_data()
                self.update_plan_file()
                return True
                
        print(f"Task not found: Phase {phase}, Task: {task_name}")
        return False
    
    def get_statistics(self):
        """Calculate statistics about task progress."""
        total = len(self.tasks)
        completed = sum(1 for t in self.tasks if t['status'] == 'Completed')
        in_progress = sum(1 for t in self.tasks if t['status'] == 'In Progress')
        not_started = sum(1 for t in self.tasks if t['status'] == 'Not Started')
        blocked = sum(1 for t in self.tasks if t['status'] == 'Blocked')
        
        return {
            'total': total,
            'completed': completed,
            'in_progress': in_progress,
            'not_started': not_started,
            'blocked': blocked,
            'percent_completed': round(completed / total * 100, 1) if total else 0,
            'percent_in_progress': round(in_progress / total * 100, 1) if total else 0,
            'percent_not_started': round(not_started / total * 100, 1) if total else 0,
            'percent_blocked': round(blocked / total * 100, 1) if total else 0
        }
    
    def get_current_commit(self):
        """
        Get the current commit SHA.
        
        Returns:
            Current commit SHA or None if not in a git repository
        """
        try:
            result = subprocess.run(
                ['git', 'rev-parse', 'HEAD'],
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout.strip()
        except (subprocess.CalledProcessError, FileNotFoundError):
            return None
    
    def generate_report(self):
        """Generate a detailed progress report."""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report = [f"# MCP-Forge Progress Report", f"Generated: {now}", ""]
        
        # Overall progress
        stats = self.get_statistics()
        report.append("## Overall Progress")
        report.append(f"- Completed: {stats['completed']}/{stats['total']} tasks ({stats['percent_completed']}%)")
        report.append(f"- In Progress: {stats['in_progress']}/{stats['total']} tasks ({stats['percent_in_progress']}%)")
        report.append("")
        
        # Visual progress bar
        progress_bar_length = 50
        completed_chars = int(progress_bar_length * stats['completed'] / stats['total'])
        in_progress_chars = int(progress_bar_length * stats['in_progress'] / stats['total'])
        remaining_chars = progress_bar_length - completed_chars - in_progress_chars
        
        progress_bar = "["
        progress_bar += "=" * completed_chars
        progress_bar += ">" * in_progress_chars
        progress_bar += " " * remaining_chars
        progress_bar += "]"
        
        report.append(f"Overall Progress: {progress_bar} {stats['percent_completed']}%")
        report.append("")
        
        # Phase-wise progress
        report.append("## Phase Status")
        
        for phase in range(1, 9):  # We have 8 phases
            phase_tasks = [t for t in self.tasks if t['phase'] == phase]
            if not phase_tasks:
                continue
                
            completed_tasks = [t for t in phase_tasks if t['status'] == 'Completed']
            in_progress_tasks = [t for t in phase_tasks if t['status'] == 'In Progress']
            
            total_phase_tasks = len(phase_tasks)
            completed_phase_tasks = len(completed_tasks)
            
            percent_complete = round(completed_phase_tasks / total_phase_tasks * 100, 1) if total_phase_tasks > 0 else 0
            
            # Generate phase progress bar
            phase_bar_length = 20
            phase_completed_chars = int(phase_bar_length * completed_phase_tasks / total_phase_tasks) if total_phase_tasks > 0 else 0
            phase_in_progress_chars = int(phase_bar_length * len(in_progress_tasks) / total_phase_tasks) if total_phase_tasks > 0 else 0
            phase_remaining_chars = phase_bar_length - phase_completed_chars - phase_in_progress_chars
            
            phase_bar = "["
            phase_bar += "=" * phase_completed_chars
            phase_bar += ">" * phase_in_progress_chars
            phase_bar += " " * phase_remaining_chars
            phase_bar += "]"
            
            report.append(f"### Phase {phase}")
            report.append(f"- Progress: {completed_phase_tasks}/{total_phase_tasks} tasks ({percent_complete}%)")
            report.append(f"- {phase_bar} {percent_complete}%")
            
            for task in sorted(phase_tasks, key=lambda x: (0 if x['status'] == 'Completed' else 1, x['task'])):
                task_status_icon = "✓" if task['status'] == 'Completed' else "→" if task['status'] == 'In Progress' else "•"
                task_commit = f" [commit:{task.get('commit_sha', '')[:7]}]" if task.get('commit_sha') else ""
                report.append(f"- {task_status_icon} {task['task']}: {task['status']}{task_commit}")
            
            report.append("")
        
        # Recent updates
        recent_tasks = sorted(
            [t for t in self.tasks if t.get('last_updated')],
            key=lambda x: x.get('last_updated', ''),
            reverse=True
        )[:5]
        
        if recent_tasks:
            report.append("## Recent Updates")
            for task in recent_tasks:
                task_date = datetime.fromisoformat(task['last_updated']).strftime("%Y-%m-%d")
                task_commit = f" [commit:{task.get('commit_sha', '')[:7]}]" if task.get('commit_sha') else ""
                report.append(f"- {task_date}: Phase {task['phase']} - {task['task']} → {task['status']}{task_commit}")
        
        return "\n".join(report)

def main():
    """Command-line interface for the progress tracker."""
    import argparse
    
    parser = argparse.ArgumentParser(description="MCP-Forge Progress Tracker")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Update command
    update_parser = subparsers.add_parser("update", help="Update task status")
    update_parser.add_argument("phase", type=int, help="Phase number")
    update_parser.add_argument("task", type=str, help="Task name")
    update_parser.add_argument("status", choices=ProgressTracker.STATUS_OPTIONS, help="New status")
    update_parser.add_argument("--notes", type=str, help="Optional notes")
    update_parser.add_argument("--commit", type=str, help="Commit SHA to associate with this update")
    
    # Stats command
    subparsers.add_parser("stats", help="Show progress statistics")
    
    # Report command
    report_parser = subparsers.add_parser("report", help="Generate progress report")
    report_parser.add_argument("--output", type=str, help="Output file (default: print to console)")
    
    # Refresh command
    subparsers.add_parser("refresh", help="Refresh plan file with current progress")
    
    args = parser.parse_args()
    
    tracker = ProgressTracker()
    
    if args.command == "update":
        # If commit not provided, try to get current commit
        commit_sha = args.commit
        if not commit_sha:
            commit_sha = tracker.get_current_commit()
            
        tracker.update_task_status(args.phase, args.task, args.status, args.notes, commit_sha)
        
        commit_info = f" [commit:{commit_sha[:7]}]" if commit_sha else ""
        print(f"Updated task: Phase {args.phase} - {args.task} → {args.status}{commit_info}")
        
    elif args.command == "stats":
        stats = tracker.get_statistics()
        print(f"Total Tasks: {stats['total']}")
        print(f"Completed: {stats['completed']} ({stats['percent_completed']}%)")
        print(f"In Progress: {stats['in_progress']} ({stats['percent_in_progress']}%)")
        print(f"Not Started: {stats['not_started']} ({stats['percent_not_started']}%)")
        print(f"Blocked: {stats['blocked']} ({stats['percent_blocked']}%)")
        
    elif args.command == "report":
        report = tracker.generate_report()
        if args.output:
            with open(args.output, 'w') as f:
                f.write(report)
            print(f"Report written to {args.output}")
        else:
            print(report)
            
    elif args.command == "refresh":
        tracker.update_plan_file()
        print("Plan file refreshed with current progress")
        
    else:
        parser.print_help()

if __name__ == "__main__":
    main() 