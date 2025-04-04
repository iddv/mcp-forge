#!/bin/bash
# progress.sh - MCP-Forge Project Progress Viewer
# Displays progress information from progress_data.json in a nicely formatted view

echo "Generating MCP-Forge Progress Report..."

# Get the current commit SHA
CURRENT_COMMIT=$(git rev-parse HEAD)
SHORT_COMMIT=$(git rev-parse --short HEAD)
echo "Current repository commit: ${SHORT_COMMIT} (${CURRENT_COMMIT})"

cat progress_data.json | jq -r --arg current_commit "$CURRENT_COMMIT" 'to_entries | sort_by(.key | split(":") | .[0] | tonumber) | group_by(.key | split(":") | .[0]) | map({"phase": (.[0].key | split(":") | .[0]), "tasks": map({"name": (.key | split(":") | .[1]), "status": .value.status, "updated": (.value.last_updated // "Unknown date"), "completed": (.value.status == "Completed"), "commit": (.value.commit_sha // "unknown")}), "completed_count": map(select(.value.status == "Completed")) | length, "total_count": length}) | "MCP-FORGE PROJECT SUMMARY\n=====================\nTotal tasks: \(map(.total_count) | add)\nCompleted: \(map(.completed_count) | add)\nProgress: \((map(.completed_count) | add) * 100 / (map(.total_count) | add) | floor)%\n\n" + (map("Phase \(.phase) (\(.completed_count)/\(.total_count) complete):\n\(.tasks | sort_by(.completed | not) | map("  \(if .completed then "✅" else "⬜️" end) \(.name): \(.status) (\(.updated | sub("T.*"; ""))) [commit: \(if .commit != "unknown" then .commit[0:7] else "unknown" end)]") | join("\n"))\n") | join(""))'

echo -e "\nProgress report complete. To update progress AND track commit, use:"
echo "python3 progress_tracker.py update <phase> \"<task>\" \"<status>\" --notes \"<notes>\" --commit \$(git rev-parse HEAD)" 