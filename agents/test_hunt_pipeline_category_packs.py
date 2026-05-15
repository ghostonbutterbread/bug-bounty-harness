from __future__ import annotations

from agents.hunt_pipeline.category_pack_planner import plan_category_packs
from agents.hunt_pipeline.models import HypothesisAgentPacket


def _packet(
    hypothesis_id: str,
    *,
    surface_family: str,
    title: str,
    role: str = "entry",
    priority: str = "high",
    file_path: str = "src/app.ts",
    evidence_id: str | None = None,
    tags: tuple[str, ...] = (),
    reasons: tuple[str, ...] = (),
    evidence_kind: str = "rendering",
    description: str = "",
    scheduler_metadata: dict[str, object] | None = None,
) -> HypothesisAgentPacket:
    return HypothesisAgentPacket(
        id=hypothesis_id,
        key=f"{surface_family}-{hypothesis_id.lower()}",
        title=title,
        role=role,
        surface_family=surface_family,
        priority=priority,
        target_kind="electron",
        ruleset_id="electron-overlay",
        source_evidence=(
            {
                "id": evidence_id or hypothesis_id.replace("HP", "S"),
                "kind": evidence_kind,
                "file": file_path,
                "description": description,
            },
        ),
        evidence_requirements=("trace attacker control",),
        chain_requirements=(),
        focus_files=(file_path,),
        tags=tags,
        reasons=reasons,
        scheduler_metadata=scheduler_metadata or {},
    )


def test_xss_methodology_subclasses_split_into_distinct_packs() -> None:
    packets = [
        _packet(
            "HP-REFLECTED",
            surface_family="rendering-content-parser",
            title="Reflected renderer query sink",
            tags=("reflected", "query"),
            description="URL query parameter reaches HTML render sink",
            scheduler_metadata={"route": "/preview", "entry_path": "query-string"},
        ),
        _packet(
            "HP-STORED",
            surface_family="rendering-content-parser",
            title="Stored comment renderer sink",
            tags=("stored", "comment"),
            description="Saved comment body is later rendered in the workspace",
            scheduler_metadata={"route": "/comments"},
        ),
        _packet(
            "HP-DOM",
            surface_family="rendering-content-parser",
            title="DOM runtime sink from location.hash",
            tags=("dom-xss", "hash"),
            description="location.hash reaches innerHTML in client-side bootstrap",
            scheduler_metadata={"route": "/offline"},
        ),
        _packet(
            "HP-RICH",
            surface_family="rendering-content-parser",
            title="Rich text renderer import sink",
            tags=("rich-text", "markdown"),
            description="Imported markdown reaches the ProseMirror rich-text renderer",
            scheduler_metadata={"route": "/editor/import"},
        ),
    ]

    plan = plan_category_packs(packets)

    subclasses = {pack.subclass for pack in plan.packs}

    assert subclasses == {
        "reflected-xss",
        "stored-xss",
        "dom-xss",
        "rich-text-renderer-xss",
    }
    assert len(plan.packs) == 4


def test_same_file_file_import_hypotheses_pack_together() -> None:
    packets = [
        _packet(
            "HP-IMPORT-1",
            surface_family="file-ingestion-import",
            title="Project import parser handoff",
            file_path="src/import/project.ts",
            evidence_kind="file-import",
            tags=("project", "config"),
            description="Imported project config reaches project loader",
        ),
        _packet(
            "HP-IMPORT-2",
            surface_family="file-ingestion-import",
            title="Project import trust boundary",
            file_path="src/import/project.ts",
            evidence_kind="file-import",
            tags=("project", "manifest"),
            description="Same project config file crosses trust boundary into loader",
        ),
    ]

    plan = plan_category_packs(packets)

    assert len(plan.packs) == 1
    assert plan.packs[0].vuln_class == "file-import"
    assert plan.packs[0].hypothesis_ids == ("HP-IMPORT-1", "HP-IMPORT-2")
    assert plan.hypothesis_to_pack_id["HP-IMPORT-1"] == plan.packs[0].pack_id
    assert plan.packs[0].context_cluster_id == "src/import/project.ts"


def test_same_file_xss_different_route_splits() -> None:
    packets = [
        _packet(
            "HP-XSS-PREVIEW",
            surface_family="rendering-content-parser",
            title="Preview query renderer sink",
            file_path="src/render/preview.ts",
            tags=("reflected", "query"),
            description="Preview route query parameter reaches HTML render sink",
            scheduler_metadata={"route": "/preview", "entry_path": "query-string"},
        ),
        _packet(
            "HP-XSS-SHARE",
            surface_family="rendering-content-parser",
            title="Share preview query renderer sink",
            file_path="src/render/preview.ts",
            tags=("reflected", "query"),
            description="Share preview route query parameter reaches the same HTML render sink",
            scheduler_metadata={"route": "/share/preview", "entry_path": "query-string"},
        ),
    ]

    plan = plan_category_packs(packets)

    assert len(plan.packs) == 2
    assert {pack.route_or_endpoint_keys for pack in plan.packs} == {("/preview",), ("/share/preview",)}


def test_missing_route_pack_id_stays_stable_when_concrete_route_siblings_change() -> None:
    missing_route = _packet(
        "HP-XSS-MISSING-ROUTE",
        surface_family="rendering-content-parser",
        title="Renderer sink without route metadata",
        file_path="src/render/preview.ts",
        tags=("reflected", "query"),
        description="Query-derived renderer sink was identified without resolved route metadata",
        scheduler_metadata={"entry_path": "query-string"},
    )
    preview_sibling = _packet(
        "HP-XSS-PREVIEW",
        surface_family="rendering-content-parser",
        title="Preview query renderer sink",
        file_path="src/render/preview.ts",
        tags=("reflected", "query"),
        description="Preview route query parameter reaches HTML render sink",
        scheduler_metadata={"route": "/preview", "entry_path": "query-string"},
    )
    share_sibling = _packet(
        "HP-XSS-SHARE",
        surface_family="rendering-content-parser",
        title="Share query renderer sink",
        file_path="src/render/preview.ts",
        tags=("reflected", "query"),
        description="Share route query parameter reaches HTML render sink",
        scheduler_metadata={"route": "/share", "entry_path": "query-string"},
    )

    solo_plan = plan_category_packs([missing_route])
    preview_plan = plan_category_packs([missing_route, preview_sibling])
    share_plan = plan_category_packs([missing_route, share_sibling])

    solo_pack_id = solo_plan.hypothesis_to_pack_id["HP-XSS-MISSING-ROUTE"]
    preview_pack_id = preview_plan.hypothesis_to_pack_id["HP-XSS-MISSING-ROUTE"]
    share_pack_id = share_plan.hypothesis_to_pack_id["HP-XSS-MISSING-ROUTE"]

    assert solo_pack_id == preview_pack_id == share_pack_id
    assert ".route-" not in solo_pack_id
    assert len(preview_plan.packs) == 2
    assert len(share_plan.packs) == 2


def test_same_file_ipc_different_entry_path_splits() -> None:
    packets = [
        _packet(
            "HP-IPC-RENDERER",
            surface_family="ipc-bridge",
            title="Renderer-originated open project IPC",
            file_path="src/main/ipc.ts",
            evidence_kind="ipc",
            tags=("filesystem", "openfile"),
            description="Renderer-controlled openProject bridge reads arbitrary project paths",
            role="amplifier",
            scheduler_metadata={
                "policy_id": "electron-application-first-loose",
                "route": "dialog:openProject",
                "entry_path": "renderer-dom-xss",
            },
        ),
        _packet(
            "HP-IPC-IMPORT",
            surface_family="ipc-bridge",
            title="Import-originated open project IPC",
            file_path="src/main/ipc.ts",
            evidence_kind="ipc",
            tags=("filesystem", "openfile"),
            description="Imported project config reaches the same openProject bridge",
            role="entry",
            scheduler_metadata={
                "policy_id": "electron-application-first-loose",
                "route": "dialog:openProject",
                "entry_path": "imported-project-file",
            },
        ),
    ]

    plan = plan_category_packs(packets)

    assert len(plan.packs) == 2
    assert {pack.entry_paths for pack in plan.packs} == {
        ("renderer-dom-xss", "renderer-ipc"),
        ("imported-project-file", "renderer-ipc"),
    }


def test_same_file_ipc_and_hostrpc_same_subclass_get_distinct_pack_ids() -> None:
    packets = [
        _packet(
            "HP-IPC-FS",
            surface_family="ipc-bridge",
            title="Renderer file open IPC",
            file_path="src/main/ipc.ts",
            evidence_kind="ipc",
            tags=("filesystem", "openfile"),
            description="Renderer-controlled openFile bridge reads arbitrary project paths",
            role="amplifier",
            scheduler_metadata={
                "policy_id": "electron-application-first-loose",
                "route": "dialog:openProject",
                "entry_path": "renderer-dom-xss",
            },
        ),
        _packet(
            "HP-HOSTRPC-FS",
            surface_family="hostrpc",
            title="Renderer file open HostRpc",
            file_path="src/main/ipc.ts",
            evidence_kind="ipc",
            tags=("filesystem", "openfile"),
            description="Renderer-controlled host RPC bridge reads arbitrary project paths",
            role="amplifier",
            scheduler_metadata={
                "policy_id": "electron-application-first-loose",
                "route": "dialog:openProject",
                "entry_path": "renderer-dom-xss",
            },
        ),
    ]

    plan = plan_category_packs(packets)

    assert len(plan.packs) == 2
    assert len(plan.pack_to_hypothesis_ids) == 2
    assert plan.hypothesis_to_pack_id["HP-IPC-FS"] != plan.hypothesis_to_pack_id["HP-HOSTRPC-FS"]
    assert "family-ipc-bridge" in plan.hypothesis_to_pack_id["HP-IPC-FS"]
    assert "family-hostrpc" in plan.hypothesis_to_pack_id["HP-HOSTRPC-FS"]
    assert plan.pack_to_hypothesis_ids[plan.hypothesis_to_pack_id["HP-IPC-FS"]] == ("HP-IPC-FS",)
    assert plan.pack_to_hypothesis_ids[plan.hypothesis_to_pack_id["HP-HOSTRPC-FS"]] == ("HP-HOSTRPC-FS",)


def test_ipc_filesystem_and_navigation_split_under_electron_policy() -> None:
    packets = [
        _packet(
            "HP-IPC-FS",
            surface_family="ipc-bridge",
            title="Renderer file open IPC",
            file_path="src/main/ipc.ts",
            evidence_kind="ipc",
            tags=("filesystem", "openfile"),
            description="Renderer-controlled openFile bridge reads arbitrary project paths",
            role="amplifier",
            scheduler_metadata={"policy_id": "electron-application-first-loose"},
        ),
        _packet(
            "HP-IPC-NAV",
            surface_family="ipc-bridge",
            title="Renderer window navigation IPC",
            file_path="src/main/ipc.ts",
            evidence_kind="ipc",
            tags=("window", "loadurl"),
            description="Renderer-controlled loadURL bridge opens attacker supplied destinations",
            role="amplifier",
            scheduler_metadata={"policy_id": "electron-application-first-loose"},
        ),
    ]

    plan = plan_category_packs(packets)
    by_subclass = {pack.subclass: pack for pack in plan.packs}

    assert set(by_subclass) == {"ipc-filesystem", "ipc-window-navigation"}
    assert by_subclass["ipc-filesystem"].policy_id == "electron-application-first-loose"
    assert by_subclass["ipc-window-navigation"].policy_id == "electron-application-first-loose"
    assert by_subclass["ipc-filesystem"].context_cluster_id == "src/main/ipc.ts"


def test_pack_id_for_policy_group_is_stable_when_sibling_exists() -> None:
    policy_b_packet = _packet(
        "HP-POLICY-B",
        surface_family="file-ingestion-import",
        title="Project import parser handoff policy B",
        file_path="src/import/project.ts",
        evidence_kind="file-import",
        tags=("project", "config"),
        description="Imported project config reaches the project loader",
        scheduler_metadata={"policy_id": "policy-b"},
    )
    policy_a_packet = _packet(
        "HP-POLICY-A",
        surface_family="file-ingestion-import",
        title="Project import parser handoff policy A",
        file_path="src/import/project.ts",
        evidence_kind="file-import",
        tags=("project", "config"),
        description="Imported project config reaches the project loader",
        scheduler_metadata={"policy_id": "policy-a"},
    )

    solo_plan = plan_category_packs([policy_b_packet])
    sibling_plan = plan_category_packs([policy_a_packet, policy_b_packet])

    solo_pack_id = solo_plan.hypothesis_to_pack_id["HP-POLICY-B"]
    sibling_pack_id = sibling_plan.hypothesis_to_pack_id["HP-POLICY-B"]

    assert solo_pack_id == sibling_pack_id
    assert ".policy-policy-b." in solo_pack_id


def test_max_pack_size_splits_deterministically() -> None:
    packets = [
        _packet(
            f"HP-{index}",
            surface_family="file-ingestion-import",
            title=f"Import hypothesis {index}",
            file_path="src/import/project.ts",
            evidence_kind="file-import",
            tags=("project",),
            description="Imported project config reaches loader",
        )
        for index in range(1, 6)
    ]

    plan = plan_category_packs(packets, max_pack_size=2)

    assert [pack.hypothesis_ids for pack in plan.packs] == [
        ("HP-1", "HP-2"),
        ("HP-3", "HP-4"),
        ("HP-5",),
    ]
    assert [pack.pack_id for pack in plan.packs] == [
        "file-import.family-file-ingestion-import.file-import-project-config.src-import-project-ts.policy-electron-policy.sink-file-import.entry-imported-file.chunk001",
        "file-import.family-file-ingestion-import.file-import-project-config.src-import-project-ts.policy-electron-policy.sink-file-import.entry-imported-file.chunk002",
        "file-import.family-file-ingestion-import.file-import-project-config.src-import-project-ts.policy-electron-policy.sink-file-import.entry-imported-file.chunk003",
    ]
