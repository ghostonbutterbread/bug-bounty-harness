#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="${HOME}/projects/bug_bounty_harness"
SOURCE_DIR="${REPO_DIR}/skills"
DEST_DIR="${HOME}/.openclaw/workspace/skills"

echo "[sync] repo: ${REPO_DIR}"
cd "${REPO_DIR}"

echo "[sync] pulling latest from origin/master"
git pull --ff-only origin master

echo "[sync] syncing skills from ${SOURCE_DIR} to ${DEST_DIR}"

for skill_dir in "${SOURCE_DIR}"/*; do
  [ -d "${skill_dir}" ] || continue

  skill_name="$(basename "${skill_dir}")"
  dest_skill_dir="${DEST_DIR}/${skill_name}"

  mkdir -p "${dest_skill_dir}"
  cp "${skill_dir}/SKILL.md" "${dest_skill_dir}/SKILL.md"
  [ -f "${skill_dir}/_meta.json" ] && cp "${skill_dir}/_meta.json" "${dest_skill_dir}/_meta.json" || true

  echo "[sync] ${skill_name}"
done

echo "[sync] complete"
