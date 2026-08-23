from __future__ import annotations

import hashlib
import inspect
import json
import os
import shutil
import socket
import sqlite3
import stat
import subprocess
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

class _FakeFastMCP:
    def __init__(self, *args, **kwargs):
        pass
    def tool(self, *args, **kwargs):
        return lambda function: function

class _FakeToolAnnotations:
    def __init__(self, **kwargs):
        self.values = kwargs

if "mcp" not in sys.modules:
    fake_mcp = types.ModuleType("mcp")
    fake_server = types.ModuleType("mcp.server")
    fake_fastmcp = types.ModuleType("mcp.server.fastmcp")
    fake_types = types.ModuleType("mcp.types")
    fake_fastmcp.FastMCP = _FakeFastMCP
    fake_types.ToolAnnotations = _FakeToolAnnotations
    sys.modules["mcp"] = fake_mcp
    sys.modules["mcp.server"] = fake_server
    sys.modules["mcp.server.fastmcp"] = fake_fastmcp
    sys.modules["mcp.types"] = fake_types

import grabowski_workers as workers


def result(returncode: int = 0, stdout: str = "") -> dict[str, object]:
    return {
        "returncode": returncode,
        "stdout": stdout,
        "stderr": "",
        "timed_out": False,
        "stdout_truncated": False,
        "stderr_truncated": False,
    }

class WorkerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.state = self.root / "workers"
        self.db = self.state / "workers.sqlite3"
        self.resource_db = self.root / "resources.sqlite3"
        self.patches = [
            patch.object(workers, "WORKER_STATE", self.state),
            patch.object(workers, "WORKER_DB", self.db),
            patch.object(workers.resources, "RESOURCE_DB", self.resource_db),
        ]
        for item in self.patches:
            item.start()
        self.binary = self.root / "google-chrome"
        self.binary.write_text("#!/bin/sh\nexit 0\n")
        self.binary.chmod(0o755)

    def tearDown(self) -> None:
        for item in reversed(self.patches):
            item.stop()
        self.temporary.cleanup()

    def _run_browser_form_node(
        self,
        scenario: str,
        *,
        cleanup_only: bool = True,
        action_mode: str = "readiness",
        allowed_addresses: list[str] | None = None,
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
        node = shutil.which("node")
        if node is None:
            self.skipTest("Node.js is required for the browser helper runtime test")
        helper_path = self.root / "stored-form-helper.mjs"
        preload_path = self.root / "fake-cdp.mjs"
        request_path = self.root / "request.json"
        helper_path.write_text(workers.BROWSER_FORM_NODE_SOURCE, encoding="utf-8")
        preload_path.write_text(
            r"""
const scenario = process.env.GRABOWSKI_TEST_SCENARIO;
const expectedOrigin = 'http://device.home.arpa';
const allowedAddress = '192.168.1.10';
const initialLoader = 'loader-before-reload';
const reloadLoader = 'loader-after-reload';
let frameTreeCalls = 0;
let formContractCalls = 0;
let clearFieldsCalls = 0;

function message(target, payload) {
  if (target.onmessage) target.onmessage({data: JSON.stringify(payload)});
}

class FakeWebSocket {
  static OPEN = 1;

  constructor() {
    this.readyState = 0;
    queueMicrotask(() => {
      this.readyState = FakeWebSocket.OPEN;
      if (this.onopen) this.onopen();
    });
  }

  send(raw) {
    const request = JSON.parse(raw);
    const reply = (result = {}) => {
      message(this, {id: request.id, result});
    };
    const fail = () => {
      message(this, {id: request.id, error: {message: 'protocol'}});
    };
    const emit = (method, params = {}) => {
      message(this, {method, params});
    };
    switch (request.method) {
      case 'Runtime.enable':
      case 'Page.enable':
      case 'Page.setLifecycleEventsEnabled':
      case 'Network.enable':
      case 'Network.setCacheDisabled':
      case 'Input.dispatchMouseEvent':
      case 'Input.dispatchKeyEvent':
        reply();
        return;
      case 'Page.getFrameTree': {
        frameTreeCalls += 1;
        const finalOrigin = scenario === 'wrong-final-origin'
          ? 'http://other.home.arpa' : expectedOrigin;
        reply({
          frameTree: {
            frame: {
              id: 'main',
              loaderId: frameTreeCalls === 1 ? initialLoader : reloadLoader,
              url: (frameTreeCalls === 1 ? expectedOrigin : finalOrigin) + '/',
            },
          },
        });
        if (frameTreeCalls === 1 && scenario === 'stale-events') {
          emit('Network.responseReceived', {
            requestId: 'stale-document',
            loaderId: initialLoader,
            type: 'Document',
            frameId: 'main',
            response: {
              url: expectedOrigin + '/',
              remoteIPAddress: allowedAddress,
            },
          });
          emit('Page.lifecycleEvent', {
            name: 'load', frameId: 'main', loaderId: initialLoader,
          });
        }
        return;
      }
      case 'Page.reload': {
        if (request.params.loaderId !== initialLoader) {
          fail();
          return;
        }
        if (scenario === 'old-loader-events-during-reload') {
          emit('Network.responseReceived', {
            requestId: 'old-loader-document',
            loaderId: initialLoader,
            type: 'Document',
            frameId: 'main',
            response: {url: expectedOrigin + '/', remoteIPAddress: allowedAddress},
          });
          emit('Page.lifecycleEvent', {
            name: 'load', frameId: 'main', loaderId: initialLoader,
          });
        }
        const remoteIPAddress = scenario === 'disallowed-address'
          ? '203.0.113.7'
          : (scenario === 'invalid-address'
            ? 'not-an-ip'
            : (scenario === 'ipv6-zone-address' ? '[fd00:0:0::1%eth0]' : allowedAddress));
        const responseLoader = scenario === 'loader-mismatch'
          ? 'different-loader' : reloadLoader;
        emit('Network.responseReceived', {
          requestId: 'reload-document',
          loaderId: responseLoader,
          type: 'Document',
          frameId: 'main',
          response: {url: expectedOrigin + '/', remoteIPAddress},
        });
        if (scenario === 'response-then-close') {
          setInterval(() => {}, 1000);
          this.readyState = 3;
          if (this.onclose) this.onclose();
          return;
        }
        emit('Page.lifecycleEvent', {
          name: 'load', frameId: 'main', loaderId: reloadLoader,
        });
        reply();
        return;
      }
      case 'Runtime.evaluate': {
        const expression = String(request.params.expression || '');
        if (expression.includes('identity_type: identityType')) {
          formContractCalls += 1;
          if (scenario === 'verified-then-element-failure') {
            reply({result: {value: {
              valid: false, origin: expectedOrigin, selector_error: true,
            }}});
          } else if (scenario === 'delayed-form-hydration' && formContractCalls < 3) {
            reply({result: {value: {
              valid: false, origin: expectedOrigin, selector_error: false,
            }}});
          } else {
            reply({result: {value: {
              valid: true,
              origin: expectedOrigin,
              selector_error: false,
              identity_type: 'text',
              protected_type: 'password',
              submit_type: 'submit',
              identity_visible: true,
              protected_visible: true,
              submit_visible: true,
              identity_disabled: false,
              protected_disabled: false,
              submit_disabled: false,
            }}});
          }
          return;
        }
        if (expression.includes('for (const selector of [s.identity, s.protected])')) {
          clearFieldsCalls += 1;
          const changed = scenario !== 'delayed-cleanup-hydration' || clearFieldsCalls >= 3;
          reply({result: {value: changed}});
          return;
        }
        if (expression.includes('document.elementFromPoint')) {
          reply({result: {value: {x: 10, y: 10}}});
          return;
        }
        if (expression.includes('identity_filled')) {
          reply({result: {value: {identity_filled: true, protected_filled: true}}});
          return;
        }
        reply({result: {value: true}});
        return;
      }
      default:
        reply();
    }
  }

  close() {
    if (this.readyState === 3) return;
    this.readyState = 3;
    queueMicrotask(() => {
      if (this.onclose) this.onclose();
    });
  }
}

globalThis.WebSocket = FakeWebSocket;
globalThis.fetch = async () => ({
  ok: true,
  json: async () => [{
    type: 'page',
    url: expectedOrigin + '/',
    webSocketDebuggerUrl: 'ws://127.0.0.1:9222/devtools/page/1',
  }],
});
""",
            encoding="utf-8",
        )
        request_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "port": 9222,
                    "expected_origin": "http://device.home.arpa",
                    "allowed_addresses": allowed_addresses or ["192.168.1.10"],
                    "cleanup_only": cleanup_only,
                    "action_mode": action_mode,
                    "selectors": {
                        "identity": "#identity",
                        "protected": "#protected",
                        "submit": "button",
                    },
                    "identity_choice": None,
                    "timeout_ms": 250,
                }
            ),
            encoding="utf-8",
        )
        execution = subprocess.run(
            [node, "--import", str(preload_path), str(helper_path), str(request_path)],
            cwd=self.root,
            env={**os.environ, "GRABOWSKI_TEST_SCENARIO": scenario},
            text=True,
            capture_output=True,
            timeout=5,
            check=False,
        )
        lines = [line for line in execution.stdout.splitlines() if line.strip()]
        self.assertTrue(lines, execution.stderr)
        return execution, json.loads(lines[-1])

    def _run_browser_semantic_node(
        self, scenario: str
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
        node = shutil.which("node")
        if node is None:
            self.skipTest("Node.js is required for the browser helper runtime test")
        fixture_root = Path(
            tempfile.mkdtemp(prefix=".browser-semantic-test-", dir=ROOT)
        )
        self.addCleanup(shutil.rmtree, fixture_root, True)
        helper_path = fixture_root / "browser-semantic-helper.mjs"
        preload_path = fixture_root / "fake-semantic-cdp.mjs"
        request_path = fixture_root / "semantic-request.json"
        helper_path.write_text(workers.BROWSER_SEMANTIC_NODE_SOURCE, encoding="utf-8")
        preload_path.write_text(
            r"""
const scenario = process.env.GRABOWSKI_TEST_SCENARIO;
let frameTreeCalls = 0;
let historyCalls = 0;
let describeCalls = 0;
const activateScenario = scenario.startsWith('activate-');
const readNameFallbackScenario = scenario === 'read-name-fallback';
const readSensitiveDescendantFallbackScenario = scenario === 'read-sensitive-descendant-fallback';
const readSensitiveRootFallbackScenario = scenario === 'read-sensitive-root-fallback';
const readRoleTokenDescendantFallbackScenario = scenario === 'read-role-token-descendant-fallback';
const readLongRoleTokenFallbackScenario = scenario === 'read-long-role-token-fallback';
const readMeterRoleFallbackScenario = scenario === 'read-meter-role-fallback';
const readHiddenDescendantFallbackScenario = scenario === 'read-hidden-descendant-fallback';
const readCssHiddenFallbackScenario = scenario === 'read-css-hidden-fallback';
const readInheritedContentEditableFallbackScenario = scenario === 'read-inherited-contenteditable-fallback';
const readContentEditableFalseBoundaryScenario = scenario === 'read-contenteditable-false-boundary-fallback';
const readInheritedValueRoleFallbackScenario = scenario === 'read-inherited-value-role-fallback';
const readInheritedValueTagFallbackScenario = scenario === 'read-inherited-value-tag-fallback';
const readAncestorOpacityFallbackScenario = scenario === 'read-ancestor-opacity-fallback';
const readAncestorFilterOpacityFallbackScenario = scenario === 'read-ancestor-filter-opacity-fallback';
const readUrlFilterFallbackScenario = scenario === 'read-url-filter-fallback';
const readAncestorAriaHiddenFallbackScenario = scenario === 'read-ancestor-aria-hidden-fallback';
const readAncestorInertFallbackScenario = scenario === 'read-ancestor-inert-fallback';
const readTextHeavyPageFallbackScenario = scenario === 'read-text-heavy-page-fallback';
const readLongUnrelatedTextFallbackScenario = scenario === 'read-long-unrelated-text-fallback';
const readDesignModeFallbackScenario = scenario === 'read-design-mode-fallback';
const readChildDesignModeFallbackScenario = scenario === 'read-child-design-mode-fallback';
const readTransformZeroFallbackScenario = scenario === 'read-transform-zero-fallback';
const readTransformZeroDescendantFallbackScenario = scenario === 'read-transform-zero-descendant-fallback';
const readClipPathFallbackScenario = scenario === 'read-clip-path-fallback';
const readMaskImageFallbackScenario = scenario === 'read-mask-image-fallback';
const readEmbeddingOpacityFallbackScenario = scenario === 'read-embedding-opacity-fallback';
const readOverflowClippedFallbackScenario = scenario === 'read-overflow-clipped-fallback';
const readOverflowContainedFallbackScenario = scenario === 'read-overflow-contained-fallback';
const readTransparentColorFallbackScenario = scenario === 'read-transparent-color-fallback';
const readTransparentFillFallbackScenario = scenario === 'read-transparent-fill-fallback';
const readSvgTextFallbackScenario = scenario === 'read-svg-text-fallback';
const readVisibilityOverrideFallbackScenario = scenario === 'read-visibility-override-fallback';
const readValueRoleFallbackScenario = scenario === 'read-value-role-fallback';
const scrollFallbackRevalidationFailureScenario = scenario === 'scroll-fallback-revalidation-failure';
const activateTarget = 'https://private.invalid/issues';

function message(target, payload) {
  if (target.onmessage) target.onmessage({data: JSON.stringify(payload)});
}

function makeSemanticSnapshot(spec, child = null) {
  const strings = [];
  const stringIndex = (value) => {
    const text = String(value);
    let index = strings.indexOf(text);
    if (index < 0) { index = strings.length; strings.push(text); }
    return index;
  };
  const makeDocument = (documentSpec) => {
    const nodes = {
      parentIndex: [], nodeType: [], nodeName: [], backendNodeId: [], attributes: [],
      contentDocumentIndex: {index: [], value: []},
    };
    const layout = {nodeIndex: [], styles: [], bounds: [], text: []};
    documentSpec.forEach((node, nodeIndex) => {
      nodes.parentIndex.push(node.parent);
      nodes.nodeType.push(node.nodeType || (node.nodeName === '#text' ? 3 : 1));
      nodes.nodeName.push(stringIndex(node.nodeName));
      nodes.backendNodeId.push(node.backendNodeId);
      nodes.attributes.push((node.attributes || []).map(stringIndex));
      if (node.layout === false) return;
      layout.nodeIndex.push(nodeIndex);
      layout.styles.push([
        stringIndex(node.visibility || 'visible'),
        stringIndex(node.opacity === undefined ? '1' : node.opacity),
        stringIndex(node.contentVisibility || 'visible'),
        stringIndex(node.filter || 'none'),
        stringIndex(node.clipPath || 'none'),
        stringIndex(node.clip || 'auto'),
        stringIndex(node.overflowX || 'visible'),
        stringIndex(node.overflowY || 'visible'),
        stringIndex(node.color === undefined ? 'rgb(0, 0, 0)' : node.color),
        stringIndex(node.textFillColor === undefined
          ? (node.color === undefined ? 'rgb(0, 0, 0)' : node.color)
          : node.textFillColor),
        stringIndex(node.maskImage || 'none'),
      ]);
      layout.bounds.push(node.bounds || [10 + nodeIndex, 10 + nodeIndex, 100, 20]);
      layout.text.push(stringIndex(node.layoutText || ''));
    });
    return {nodes, layout};
  };
  const documents = [makeDocument(spec)];
  if (child) {
    if (!Number.isInteger(child.ownerNodeIndex) || child.ownerNodeIndex < 0 ||
        child.ownerNodeIndex >= spec.length || !Array.isArray(child.spec)) {
      throw new Error('invalid child semantic snapshot fixture');
    }
    documents[0].nodes.contentDocumentIndex.index.push(child.ownerNodeIndex);
    documents[0].nodes.contentDocumentIndex.value.push(1);
    documents.push(makeDocument(child.spec));
  }
  return {strings, documents};
}

function fallbackSnapshot() {
  const marker = 'se' + 'cret';
  if (readNameFallbackScenario) return makeSemanticSnapshot([
    {parent: -1, backendNodeId: 101, nodeName: 'BUTTON', attributes: ['aria-label', '   ', 'title', '\\t']},
    {parent: 0, backendNodeId: 102, nodeName: 'SPAN'},
    {parent: 1, backendNodeId: 103, nodeName: '#text', layoutText: '  Dismiss   onboarding  ' + 'x'.repeat(200)},
  ]);
  if (readSensitiveDescendantFallbackScenario) return makeSemanticSnapshot([
    {parent: -1, backendNodeId: 101, nodeName: 'DIV', attributes: ['role', 'button']},
    {parent: 0, backendNodeId: 102, nodeName: 'TEXTAREA', attributes: ['aria-hidden', 'true']},
    {parent: 1, backendNodeId: 103, nodeName: '#text', layoutText: 'textarea-' + marker},
    {parent: 0, backendNodeId: 104, nodeName: 'DIV', attributes: ['role', 'textbox']},
    {parent: 3, backendNodeId: 105, nodeName: '#text', layoutText: 'aria-' + marker},
    {parent: 0, backendNodeId: 106, nodeName: 'DIV', attributes: ['contenteditable', 'plaintext-only']},
    {parent: 5, backendNodeId: 107, nodeName: '#text', layoutText: 'editable-' + marker},
    {parent: 0, backendNodeId: 108, nodeName: 'SPAN'},
    {parent: 7, backendNodeId: 109, nodeName: '#text', layoutText: 'Continue'},
  ]);
  if (readSensitiveRootFallbackScenario) return makeSemanticSnapshot([
    {parent: -1, backendNodeId: 101, nodeName: 'DIV', attributes: ['role', 'button', 'contenteditable', 'plaintext-only']},
    {parent: 0, backendNodeId: 102, nodeName: '#text', layoutText: 'root-' + marker},
  ]);
  if (readRoleTokenDescendantFallbackScenario) return makeSemanticSnapshot([
    {parent: -1, backendNodeId: 101, nodeName: 'DIV', attributes: ['role', 'button']},
    {parent: 0, backendNodeId: 102, nodeName: 'DIV', attributes: ['role', 'future-widget textbox']},
    {parent: 1, backendNodeId: 103, nodeName: '#text', layoutText: 'token-' + marker},
    {parent: 0, backendNodeId: 104, nodeName: 'SPAN'},
    {parent: 3, backendNodeId: 105, nodeName: '#text', layoutText: 'Proceed'},
  ]);
  if (readLongRoleTokenFallbackScenario) {
    const longRole = Array.from({length: 45}, (_, index) => 'future' + index).join(' ') + ' textbox';
    return makeSemanticSnapshot([
      {parent: -1, backendNodeId: 101, nodeName: 'DIV', attributes: ['role', 'button']},
      {parent: 0, backendNodeId: 102, nodeName: 'DIV', attributes: ['role', longRole]},
      {parent: 1, backendNodeId: 103, nodeName: '#text', layoutText: 'long-role-' + marker},
      {parent: 0, backendNodeId: 104, nodeName: 'SPAN'},
      {parent: 3, backendNodeId: 105, nodeName: '#text', layoutText: 'Proceed'},
    ]);
  }
  if (readMeterRoleFallbackScenario) return makeSemanticSnapshot([
    {parent: -1, backendNodeId: 101, nodeName: 'DIV', attributes: ['role', 'button']},
    {parent: 0, backendNodeId: 102, nodeName: 'DIV', attributes: ['role', 'meter']},
    {parent: 1, backendNodeId: 103, nodeName: '#text', layoutText: '73 percent'},
    {parent: 0, backendNodeId: 104, nodeName: 'SPAN'},
    {parent: 3, backendNodeId: 105, nodeName: '#text', layoutText: 'Continue'},
  ]);
  if (readHiddenDescendantFallbackScenario) return makeSemanticSnapshot([
    {parent: -1, backendNodeId: 101, nodeName: 'BUTTON'},
    {parent: 0, backendNodeId: 102, nodeName: 'SPAN', attributes: ['hidden', '']},
    {parent: 1, backendNodeId: 103, nodeName: '#text', layoutText: 'hidden-' + marker},
    {parent: 0, backendNodeId: 104, nodeName: 'SPAN', attributes: ['aria-hidden', 'true']},
    {parent: 3, backendNodeId: 105, nodeName: '#text', layoutText: 'aria-hidden-' + marker},
    {parent: 0, backendNodeId: 106, nodeName: 'SPAN', attributes: ['inert', '']},
    {parent: 5, backendNodeId: 107, nodeName: '#text', layoutText: 'inert-' + marker},
    {parent: 0, backendNodeId: 108, nodeName: 'SPAN'},
    {parent: 7, backendNodeId: 109, nodeName: '#text', layoutText: 'Continue'},
  ]);
  if (readCssHiddenFallbackScenario) return makeSemanticSnapshot([
    {parent: -1, backendNodeId: 101, nodeName: 'BUTTON'},
    {parent: 0, backendNodeId: 102, nodeName: 'SPAN', attributes: ['class', 'collapsed-by-sheet'], layout: false},
    {parent: 1, backendNodeId: 103, nodeName: '#text', layoutText: 'display-' + marker, layout: false},
    {parent: 0, backendNodeId: 104, nodeName: 'SPAN', visibility: 'hidden'},
    {parent: 3, backendNodeId: 105, nodeName: '#text', layoutText: 'visibility-' + marker, visibility: 'hidden'},
    {parent: 0, backendNodeId: 106, nodeName: 'SPAN', opacity: '0'},
    {parent: 5, backendNodeId: 107, nodeName: '#text', layoutText: 'opacity-' + marker},
    {parent: 0, backendNodeId: 108, nodeName: 'SPAN', contentVisibility: 'hidden'},
    {parent: 7, backendNodeId: 109, nodeName: '#text', layoutText: 'content-' + marker},
    {parent: 0, backendNodeId: 110, nodeName: 'SPAN'},
    {parent: 9, backendNodeId: 111, nodeName: '#text', layoutText: 'Continue'},
  ]);
  if (readInheritedContentEditableFallbackScenario) return makeSemanticSnapshot([
    {parent: -1, backendNodeId: 100, nodeName: 'DIV', attributes: ['contenteditable', '']},
    {parent: 0, backendNodeId: 101, nodeName: 'DIV', attributes: ['role', 'button', 'aria-label', ' ']},
    {parent: 1, backendNodeId: 102, nodeName: '#text', layoutText: 'inherited-' + marker},
  ]);
  if (readContentEditableFalseBoundaryScenario) return makeSemanticSnapshot([
    {parent: -1, backendNodeId: 100, nodeName: 'DIV', attributes: ['contenteditable', '']},
    {parent: 0, backendNodeId: 101, nodeName: 'DIV', attributes: ['role', 'button', 'contenteditable', 'false']},
    {parent: 1, backendNodeId: 102, nodeName: '#text', layoutText: 'Continue'},
  ]);
  if (readInheritedValueRoleFallbackScenario) return makeSemanticSnapshot([
    {parent: -1, backendNodeId: 100, nodeName: 'DIV', attributes: ['role', 'textbox']},
    {parent: 0, backendNodeId: 101, nodeName: 'DIV', attributes: ['role', 'button', 'aria-label', ' ']},
    {parent: 1, backendNodeId: 102, nodeName: '#text', layoutText: 'role-' + marker},
  ]);
  if (readInheritedValueTagFallbackScenario) return makeSemanticSnapshot([
    {parent: -1, backendNodeId: 100, nodeName: 'TEXTAREA'},
    {parent: 0, backendNodeId: 101, nodeName: 'DIV', attributes: ['role', 'button', 'aria-label', ' ']},
    {parent: 1, backendNodeId: 102, nodeName: '#text', layoutText: 'tag-' + marker},
  ]);
  if (readAncestorOpacityFallbackScenario) return makeSemanticSnapshot([
    {parent: -1, backendNodeId: 100, nodeName: 'DIV', opacity: '0'},
    {parent: 0, backendNodeId: 101, nodeName: 'BUTTON', attributes: ['aria-label', ' ']},
    {parent: 1, backendNodeId: 102, nodeName: '#text', layoutText: 'ancestor-opacity-' + marker},
  ]);
  if (readAncestorFilterOpacityFallbackScenario) return makeSemanticSnapshot([
    {parent: -1, backendNodeId: 100, nodeName: 'DIV', filter: 'blur(1px) opacity(0%)'},
    {parent: 0, backendNodeId: 101, nodeName: 'BUTTON', attributes: ['aria-label', ' ']},
    {parent: 1, backendNodeId: 102, nodeName: '#text', layoutText: 'ancestor-filter-' + marker},
  ]);
  if (readUrlFilterFallbackScenario) return makeSemanticSnapshot([
    {parent: -1, backendNodeId: 100, nodeName: 'DIV', filter: 'url("#hide-text")'},
    {parent: 0, backendNodeId: 101, nodeName: 'BUTTON', attributes: ['aria-label', ' ']},
    {parent: 1, backendNodeId: 102, nodeName: '#text', layoutText: 'url-filter-' + marker},
  ]);
  if (readAncestorAriaHiddenFallbackScenario) return makeSemanticSnapshot([
    {parent: -1, backendNodeId: 100, nodeName: 'DIV', attributes: ['aria-hidden', 'true']},
    {parent: 0, backendNodeId: 101, nodeName: 'BUTTON', attributes: ['aria-label', ' ']},
    {parent: 1, backendNodeId: 102, nodeName: '#text', layoutText: 'ancestor-aria-' + marker},
  ]);
  if (readAncestorInertFallbackScenario) return makeSemanticSnapshot([
    {parent: -1, backendNodeId: 100, nodeName: 'DIV', attributes: ['inert', '']},
    {parent: 0, backendNodeId: 101, nodeName: 'BUTTON', attributes: ['aria-label', ' ']},
    {parent: 1, backendNodeId: 102, nodeName: '#text', layoutText: 'ancestor-inert-' + marker},
  ]);
  if (readTextHeavyPageFallbackScenario) {
    const spec = [{parent: -1, backendNodeId: 100, nodeName: 'DIV'}];
    for (let index = 0; index < 520; index += 1) {
      const spanIndex = spec.length;
      spec.push({parent: 0, backendNodeId: 1000 + (index * 2), nodeName: 'SPAN'});
      spec.push({
        parent: spanIndex,
        backendNodeId: 1001 + (index * 2),
        nodeName: '#text',
        layoutText: 'outside-' + index,
      });
    }
    const targetIndex = spec.length;
    spec.push({parent: 0, backendNodeId: 101, nodeName: 'BUTTON', attributes: ['aria-label', ' ']});
    spec.push({parent: targetIndex, backendNodeId: 102, nodeName: '#text', layoutText: 'Continue'});
    return makeSemanticSnapshot(spec);
  }
  if (readLongUnrelatedTextFallbackScenario) return makeSemanticSnapshot([
    {parent: -1, backendNodeId: 100, nodeName: 'DIV'},
    {parent: 0, backendNodeId: 200, nodeName: 'SPAN'},
    {parent: 1, backendNodeId: 201, nodeName: '#text', layoutText: 'x'.repeat(5000)},
    {parent: 0, backendNodeId: 101, nodeName: 'BUTTON', attributes: ['aria-label', ' ']},
    {parent: 3, backendNodeId: 102, nodeName: '#text', layoutText: 'Continue'},
  ]);
  if (readTransformZeroFallbackScenario) return makeSemanticSnapshot([
    {parent: -1, backendNodeId: 101, nodeName: 'BUTTON', attributes: ['aria-label', ' ']},
    {parent: 0, backendNodeId: 102, nodeName: '#text', layoutText: 'collapsed-' + marker, bounds: [49.328125, 18.5, 0.015625, 0]},
  ]);
  if (readTransformZeroDescendantFallbackScenario) return makeSemanticSnapshot([
    {parent: -1, backendNodeId: 101, nodeName: 'BUTTON', attributes: ['aria-label', ' ']},
    {parent: 0, backendNodeId: 102, nodeName: 'SPAN'},
    {parent: 1, backendNodeId: 103, nodeName: '#text', layoutText: 'collapsed-' + marker, bounds: [49.328125, 18.5, 0.015625, 0]},
    {parent: 0, backendNodeId: 104, nodeName: 'SPAN'},
    {parent: 3, backendNodeId: 105, nodeName: '#text', layoutText: 'Continue', bounds: [60, 18, 55, 15]},
  ]);
  if (readClipPathFallbackScenario) return makeSemanticSnapshot([
    {parent: -1, backendNodeId: 101, nodeName: 'BUTTON', attributes: ['aria-label', ' '], clipPath: 'inset(100%)'},
    {parent: 0, backendNodeId: 102, nodeName: '#text', layoutText: 'clipped-' + marker, clipPath: 'inset(100%)'},
  ]);
  if (readMaskImageFallbackScenario) return makeSemanticSnapshot([
    {parent: -1, backendNodeId: 101, nodeName: 'BUTTON', attributes: ['aria-label', ' '], maskImage: 'linear-gradient(transparent, transparent)'},
    {parent: 0, backendNodeId: 102, nodeName: '#text', layoutText: 'masked-' + marker},
  ]);
  if (readEmbeddingOpacityFallbackScenario) return makeSemanticSnapshot([
    {parent: -1, backendNodeId: 200, nodeName: 'DIV', opacity: '0'},
    {parent: 0, backendNodeId: 201, nodeName: 'IFRAME'},
  ], {ownerNodeIndex: 1, spec: [
    {parent: -1, backendNodeId: 300, nodeName: 'HTML'},
    {parent: 0, backendNodeId: 101, nodeName: 'BUTTON', attributes: ['aria-label', ' ']},
    {parent: 1, backendNodeId: 102, nodeName: '#text', layoutText: 'embedded-' + marker},
  ]});
  if (readOverflowClippedFallbackScenario) return makeSemanticSnapshot([
    {parent: -1, backendNodeId: 100, nodeName: 'DIV', overflowX: 'hidden', overflowY: 'hidden', bounds: [10, 10, 0, 0]},
    {parent: 0, backendNodeId: 101, nodeName: 'BUTTON', attributes: ['aria-label', ' '], bounds: [10, 10, 80, 30]},
    {parent: 1, backendNodeId: 102, nodeName: '#text', layoutText: 'overflow-' + marker, bounds: [18, 13, 60, 20]},
  ]);
  if (readOverflowContainedFallbackScenario) return makeSemanticSnapshot([
    {parent: -1, backendNodeId: 100, nodeName: 'DIV', overflowX: 'hidden', overflowY: 'hidden', bounds: [10, 10, 120, 50]},
    {parent: 0, backendNodeId: 101, nodeName: 'BUTTON', attributes: ['aria-label', ' '], bounds: [20, 15, 80, 30]},
    {parent: 1, backendNodeId: 102, nodeName: '#text', layoutText: 'Continue', bounds: [28, 18, 55, 20]},
  ]);
  if (readTransparentColorFallbackScenario) return makeSemanticSnapshot([
    {parent: -1, backendNodeId: 101, nodeName: 'BUTTON', attributes: ['aria-label', ' '], color: 'rgba(0, 0, 0, 0)'},
    {parent: 0, backendNodeId: 102, nodeName: '#text', layoutText: 'color-' + marker, color: 'rgba(0, 0, 0, 0)'},
  ]);
  if (readTransparentFillFallbackScenario) return makeSemanticSnapshot([
    {parent: -1, backendNodeId: 101, nodeName: 'BUTTON', attributes: ['aria-label', ' '], textFillColor: 'rgba(0, 0, 0, 0)'},
    {parent: 0, backendNodeId: 102, nodeName: '#text', layoutText: 'fill-' + marker, textFillColor: 'rgba(0, 0, 0, 0)'},
  ]);
  if (readSvgTextFallbackScenario) return makeSemanticSnapshot([
    {parent: -1, backendNodeId: 101, nodeName: 'BUTTON', attributes: ['aria-label', ' ']},
    {parent: 0, backendNodeId: 102, nodeName: 'svg'},
    {parent: 1, backendNodeId: 103, nodeName: 'text'},
    {parent: 2, backendNodeId: 104, nodeName: '#text', layoutText: 'svg-' + marker},
    {parent: 0, backendNodeId: 105, nodeName: 'SPAN'},
    {parent: 4, backendNodeId: 106, nodeName: '#text', layoutText: 'Continue'},
  ]);
  if (readVisibilityOverrideFallbackScenario) return makeSemanticSnapshot([
    {parent: -1, backendNodeId: 100, nodeName: 'DIV', visibility: 'hidden'},
    {parent: 0, backendNodeId: 101, nodeName: 'BUTTON', attributes: ['aria-label', ' '], visibility: 'visible'},
    {parent: 1, backendNodeId: 102, nodeName: '#text', layoutText: 'Continue', visibility: 'visible'},
  ]);
  if (readDesignModeFallbackScenario) return makeSemanticSnapshot([
    {parent: -1, backendNodeId: 100, nodeName: 'HTML'},
    {parent: 0, backendNodeId: 101, nodeName: 'BUTTON', attributes: ['aria-label', ' ']},
    {parent: 1, backendNodeId: 102, nodeName: '#text', layoutText: 'design-mode-' + marker},
  ]);
  if (readChildDesignModeFallbackScenario) return makeSemanticSnapshot([
    {parent: -1, backendNodeId: 100, nodeName: 'HTML'},
    {parent: 0, backendNodeId: 101, nodeName: 'BUTTON', attributes: ['aria-label', ' ']},
    {parent: 1, backendNodeId: 102, nodeName: '#text', layoutText: 'child-design-mode-' + marker},
  ]);
  if (scrollFallbackRevalidationFailureScenario) return makeSemanticSnapshot([
    {parent: -1, backendNodeId: 101, nodeName: 'BUTTON'},
  ]);
  return null;
}

class FakeWebSocket {
  static OPEN = 1;

  constructor() {
    this.readyState = 0;
    queueMicrotask(() => {
      this.readyState = FakeWebSocket.OPEN;
      if (this.onopen) this.onopen();
    });
  }

  send(raw) {
    const request = JSON.parse(raw);
    const reply = (result = {}) => message(this, {id: request.id, result});
    const fail = () => message(this, {id: request.id, error: {message: 'protocol'}});
    const emit = (method, params = {}) => message(this, {method, params});
    switch (request.method) {
      case 'Runtime.enable':
      case 'Page.enable':
      case 'DOM.enable':
      case 'Accessibility.enable':
        reply();
        return;
      case 'Page.getFrameTree': {
        frameTreeCalls += 1;
        if (scenario === 'readback-failure' && frameTreeCalls > 1) {
          fail();
          return;
        }
        const after = frameTreeCalls > 1;
        const loaderId = ['correlated-new-document', 'activate-correlated-new-document'].includes(scenario) && after
          ? 'loader-after' : 'loader-before';
        const frameTree = {frame: {id: 'main-frame', loaderId}};
        if (readChildDesignModeFallbackScenario || readEmbeddingOpacityFallbackScenario) {
          frameTree.childFrames = [{frame: {id: 'child-frame', loaderId: 'child-loader'}}];
        }
        reply({frameTree});
        return;
      }
      case 'Page.createIsolatedWorld': {
        const params = request.params || {};
        const validFrame = params.frameId === 'main-frame' ||
          ((readChildDesignModeFallbackScenario || readEmbeddingOpacityFallbackScenario) && params.frameId === 'child-frame');
        if (!validFrame || params.worldName !== 'grabowski-semantic-design-mode-v1' ||
            params.grantUniveralAccess !== false) {
          fail();
          return;
        }
        reply({executionContextId: params.frameId === 'child-frame' ? 902 : 901});
        return;
      }
      case 'Page.getNavigationHistory': {
        historyCalls += 1;
        const after = historyCalls > 1;
        const entryId = scenario === 'correlated-same-document' && after ? 8 : 7;
        reply({currentIndex: 0, entries: [{id: entryId, url: 'about:blank'}]});
        return;
      }
      case 'Runtime.evaluate': {
        if (request.params && request.params.expression === 'document.designMode') {
          const contextId = request.params.contextId;
          if (contextId !== 901 && contextId !== 902) {
            fail();
            return;
          }
          const enabled = readDesignModeFallbackScenario ||
            (readChildDesignModeFallbackScenario && contextId === 902);
          reply({result: {value: enabled ? 'on' : 'off'}});
          return;
        }
        const title = scenario === 'stale-before-navigate' ? 'Drifted' : 'Before';
        reply({result: {value: {
          origin: 'https://before.invalid', ready_state: 'complete', title,
        }}});
        return;
      }
      case 'Accessibility.getFullAXTree':
        reply({nodes: [{
          backendDOMNodeId: 101,
          ignored: false,
          role: {value: readValueRoleFallbackScenario ? 'textbox' : (activateScenario ? 'link' : 'button')},
          name: {value: (readNameFallbackScenario || readSensitiveDescendantFallbackScenario || readSensitiveRootFallbackScenario || readRoleTokenDescendantFallbackScenario || readLongRoleTokenFallbackScenario || readMeterRoleFallbackScenario || readHiddenDescendantFallbackScenario || readCssHiddenFallbackScenario || readInheritedContentEditableFallbackScenario || readContentEditableFalseBoundaryScenario || readInheritedValueRoleFallbackScenario || readInheritedValueTagFallbackScenario || readAncestorOpacityFallbackScenario || readAncestorFilterOpacityFallbackScenario || readUrlFilterFallbackScenario || readAncestorAriaHiddenFallbackScenario || readAncestorInertFallbackScenario || readTextHeavyPageFallbackScenario || readLongUnrelatedTextFallbackScenario || readTransformZeroFallbackScenario || readTransformZeroDescendantFallbackScenario || readClipPathFallbackScenario || readMaskImageFallbackScenario || readEmbeddingOpacityFallbackScenario || readOverflowClippedFallbackScenario || readOverflowContainedFallbackScenario || readTransparentColorFallbackScenario || readTransparentFillFallbackScenario || readSvgTextFallbackScenario || readVisibilityOverrideFallbackScenario || readDesignModeFallbackScenario || readChildDesignModeFallbackScenario || readValueRoleFallbackScenario || scrollFallbackRevalidationFailureScenario) ? '' : (activateScenario ? 'Issues' : 'Target')},
        }]});
        return;
      case 'Accessibility.getPartialAXTree':
        reply({nodes: [{
          backendDOMNodeId: 101,
          ignored: false,
          role: {value: scrollFallbackRevalidationFailureScenario ? 'button' : 'link'},
          name: {value: scrollFallbackRevalidationFailureScenario ? '' : 'Issues'},
        }]});
        return;
      case 'DOM.resolveNode':
        reply({object: {objectId: 'link-object'}});
        return;
      case 'Runtime.callFunctionOn':
        if (readNameFallbackScenario || readSensitiveDescendantFallbackScenario || readSensitiveRootFallbackScenario || readRoleTokenDescendantFallbackScenario || readLongRoleTokenFallbackScenario || readMeterRoleFallbackScenario || readHiddenDescendantFallbackScenario || readCssHiddenFallbackScenario || readInheritedContentEditableFallbackScenario || readContentEditableFalseBoundaryScenario || readInheritedValueRoleFallbackScenario || readInheritedValueTagFallbackScenario || readAncestorOpacityFallbackScenario || readAncestorFilterOpacityFallbackScenario || readUrlFilterFallbackScenario || readAncestorAriaHiddenFallbackScenario || readAncestorInertFallbackScenario || readTextHeavyPageFallbackScenario || readLongUnrelatedTextFallbackScenario || readTransformZeroFallbackScenario || readTransformZeroDescendantFallbackScenario || readClipPathFallbackScenario || readMaskImageFallbackScenario || readEmbeddingOpacityFallbackScenario || readOverflowClippedFallbackScenario || readOverflowContainedFallbackScenario || readTransparentColorFallbackScenario || readTransparentFillFallbackScenario || readSvgTextFallbackScenario || readVisibilityOverrideFallbackScenario || readDesignModeFallbackScenario || readChildDesignModeFallbackScenario || readValueRoleFallbackScenario || scrollFallbackRevalidationFailureScenario) {
          fail();
          return;
        }
        reply({result: {value: null}});
        return;
      case 'Runtime.releaseObject':
        reply();
        return;
      case 'DOM.getDocument':
        reply({root: {
          baseURL: 'https://before.invalid/repository/',
          documentURL: 'https://before.invalid/repository/',
        }});
        return;
      case 'DOMSnapshot.captureSnapshot': {
        const expectedStyles = ['visibility', 'opacity', 'content-visibility', 'filter', 'clip-path', 'clip', 'overflow-x', 'overflow-y', 'color', '-webkit-text-fill-color', 'mask-image'];
        if (JSON.stringify(request.params && request.params.computedStyles) !== JSON.stringify(expectedStyles) ||
            request.params.includePaintOrder !== false || request.params.includeDOMRects !== false) {
          fail();
          return;
        }
        const snapshot = fallbackSnapshot();
        if (!snapshot) {
          fail();
          return;
        }
        reply(snapshot);
        return;
      }
      case 'DOM.describeNode': {
        if (!request.params || request.params.depth !== 0 || request.params.pierce !== false) {
          fail();
          return;
        }
        describeCalls += 1;
        if (readNameFallbackScenario) {
          reply({node: {
            backendNodeId: 101,
            nodeType: 1,
            localName: 'button',
            nodeName: 'BUTTON',
            attributes: ['aria-label', '   ', 'title', '\t'],
            children: [{
              backendNodeId: 102,
              nodeType: 1,
              localName: 'span',
              nodeName: 'SPAN',
              attributes: [],
              children: [{
                backendNodeId: 103,
                nodeType: 3,
                localName: '',
                nodeName: '#text',
                nodeValue: '  Dismiss   onboarding  ' + 'x'.repeat(200),
              }],
            }],
          }});
          return;
        }
        if (readSensitiveDescendantFallbackScenario) {
          reply({node: {
            backendNodeId: 101,
            nodeType: 1,
            localName: 'div',
            nodeName: 'DIV',
            attributes: ['role', 'button'],
            children: [
              {
                backendNodeId: 102,
                nodeType: 1,
                localName: 'textarea',
                nodeName: 'TEXTAREA',
                attributes: ['aria-hidden', 'true'],
                children: [{backendNodeId: 103, nodeType: 3, nodeName: '#text', nodeValue: 'textarea-secret'}],
              },
              {
                backendNodeId: 104,
                nodeType: 1,
                localName: 'div',
                nodeName: 'DIV',
                attributes: ['role', 'textbox'],
                children: [{backendNodeId: 105, nodeType: 3, nodeName: '#text', nodeValue: 'aria-secret'}],
              },
              {
                backendNodeId: 106,
                nodeType: 1,
                localName: 'div',
                nodeName: 'DIV',
                attributes: ['contenteditable', 'plaintext-only'],
                children: [{backendNodeId: 107, nodeType: 3, nodeName: '#text', nodeValue: 'editable-secret'}],
              },
              {
                backendNodeId: 108,
                nodeType: 1,
                localName: 'span',
                nodeName: 'SPAN',
                attributes: [],
                children: [{backendNodeId: 109, nodeType: 3, nodeName: '#text', nodeValue: 'Continue'}],
              },
            ],
          }});
          return;
        }
        if (readSensitiveRootFallbackScenario) {
          reply({node: {
            backendNodeId: 101,
            nodeType: 1,
            localName: 'div',
            nodeName: 'DIV',
            attributes: ['role', 'button', 'contenteditable', 'plaintext-only'],
            children: [{
              backendNodeId: 102,
              nodeType: 3,
              localName: '',
              nodeName: '#text',
              nodeValue: 'root-secret',
            }],
          }});
          return;
        }
        if (readRoleTokenDescendantFallbackScenario) {
          reply({node: {
            backendNodeId: 101,
            nodeType: 1,
            localName: 'div',
            nodeName: 'DIV',
            attributes: ['role', 'button'],
            children: [
              {
                backendNodeId: 102,
                nodeType: 1,
                localName: 'div',
                nodeName: 'DIV',
                attributes: ['role', 'future-widget textbox'],
                children: [{backendNodeId: 103, nodeType: 3, nodeName: '#text', nodeValue: 'token-secret'}],
              },
              {
                backendNodeId: 104,
                nodeType: 1,
                localName: 'span',
                nodeName: 'SPAN',
                attributes: [],
                children: [{backendNodeId: 105, nodeType: 3, nodeName: '#text', nodeValue: 'Proceed'}],
              },
            ],
          }});
          return;
        }
        if (readLongRoleTokenFallbackScenario) {
          const longRole = Array.from({length: 45}, (_, index) => 'future' + index).join(' ') + ' textbox';
          reply({node: {
            backendNodeId: 101,
            nodeType: 1,
            localName: 'div',
            nodeName: 'DIV',
            attributes: ['role', 'button'],
            children: [
              {
                backendNodeId: 102,
                nodeType: 1,
                localName: 'div',
                nodeName: 'DIV',
                attributes: ['role', longRole],
                children: [{backendNodeId: 103, nodeType: 3, nodeName: '#text', nodeValue: 'long-role-secret'}],
              },
              {
                backendNodeId: 104,
                nodeType: 1,
                localName: 'span',
                nodeName: 'SPAN',
                attributes: [],
                children: [{backendNodeId: 105, nodeType: 3, nodeName: '#text', nodeValue: 'Proceed'}],
              },
            ],
          }});
          return;
        }
        if (readInheritedContentEditableFallbackScenario) {
          reply({node: {
            backendNodeId: 101,
            nodeType: 1,
            localName: 'div',
            nodeName: 'DIV',
            attributes: ['role', 'button', 'aria-label', ' '],
            children: [{backendNodeId: 102, nodeType: 3, nodeName: '#text', nodeValue: 'inherited-secret'}],
          }});
          return;
        }
        if (readContentEditableFalseBoundaryScenario) {
          reply({node: {
            backendNodeId: 101,
            nodeType: 1,
            localName: 'div',
            nodeName: 'DIV',
            attributes: ['role', 'button', 'contenteditable', 'false'],
            children: [{backendNodeId: 102, nodeType: 3, nodeName: '#text', nodeValue: 'Continue'}],
          }});
          return;
        }
        if (readInheritedValueRoleFallbackScenario || readInheritedValueTagFallbackScenario) {
          reply({node: {
            backendNodeId: 101,
            nodeType: 1,
            localName: 'div',
            nodeName: 'DIV',
            attributes: ['role', 'button', 'aria-label', ' '],
            children: [{backendNodeId: 102, nodeType: 3, nodeName: '#text', nodeValue: 'ancestor-secret'}],
          }});
          return;
        }
        if (readAncestorOpacityFallbackScenario || readAncestorFilterOpacityFallbackScenario || readUrlFilterFallbackScenario || readAncestorAriaHiddenFallbackScenario || readAncestorInertFallbackScenario || readTextHeavyPageFallbackScenario || readLongUnrelatedTextFallbackScenario || readMeterRoleFallbackScenario || readTransformZeroFallbackScenario || readTransformZeroDescendantFallbackScenario || readClipPathFallbackScenario || readMaskImageFallbackScenario || readEmbeddingOpacityFallbackScenario || readOverflowClippedFallbackScenario || readOverflowContainedFallbackScenario || readTransparentColorFallbackScenario || readTransparentFillFallbackScenario || readSvgTextFallbackScenario || readVisibilityOverrideFallbackScenario || readDesignModeFallbackScenario || readChildDesignModeFallbackScenario) {
          reply({node: {
            backendNodeId: 101,
            nodeType: 1,
            localName: 'button',
            nodeName: 'BUTTON',
            attributes: ['aria-label', ' '],
            children: [{backendNodeId: 102, nodeType: 3, nodeName: '#text', nodeValue: 'Continue'}],
          }});
          return;
        }
        if (readHiddenDescendantFallbackScenario || readCssHiddenFallbackScenario) {
          reply({node: {
            backendNodeId: 101,
            nodeType: 1,
            localName: 'button',
            nodeName: 'BUTTON',
            attributes: [],
            children: [
              {
                backendNodeId: 102,
                nodeType: 1,
                localName: 'span',
                nodeName: 'SPAN',
                attributes: ['hidden', ''],
                children: [{backendNodeId: 103, nodeType: 3, nodeName: '#text', nodeValue: 'hidden-secret'}],
              },
              {
                backendNodeId: 104,
                nodeType: 1,
                localName: 'span',
                nodeName: 'SPAN',
                attributes: ['aria-hidden', 'true'],
                children: [{backendNodeId: 105, nodeType: 3, nodeName: '#text', nodeValue: 'aria-hidden-secret'}],
              },
              {
                backendNodeId: 106,
                nodeType: 1,
                localName: 'span',
                nodeName: 'SPAN',
                attributes: ['inert', ''],
                children: [{backendNodeId: 107, nodeType: 3, nodeName: '#text', nodeValue: 'inert-secret'}],
              },
              {
                backendNodeId: 108,
                nodeType: 1,
                localName: 'span',
                nodeName: 'SPAN',
                attributes: [],
                children: [{backendNodeId: 109, nodeType: 3, nodeName: '#text', nodeValue: 'Continue'}],
              },
            ],
          }});
          return;
        }
        if (readValueRoleFallbackScenario) {
          reply({node: {
            backendNodeId: 101,
            nodeType: 1,
            localName: 'div',
            nodeName: 'DIV',
            attributes: [],
            children: [{
              backendNodeId: 102,
              nodeType: 3,
              localName: '',
              nodeName: '#text',
              nodeValue: 'secret-value',
            }],
          }});
          return;
        }
        if (scrollFallbackRevalidationFailureScenario) {
          if (describeCalls > 1) {
            message(this, {id: request.id, error: {message: 'simulated describe failure'}});
            return;
          }
          reply({node: {
            backendNodeId: 101,
            nodeType: 1,
            localName: 'button',
            nodeName: 'BUTTON',
            attributes: [],
            children: [],
          }});
          return;
        }
        let href = scenario === 'activate-target-drift' && describeCalls > 1
          ? 'https://private.invalid/pulls' : activateTarget;
        if (scenario === 'activate-backslash-target') {
          href = activateTarget + String.fromCharCode(92);
        }
        reply({node: {
          backendNodeId: 101,
          localName: 'a',
          nodeName: 'A',
          attributes: ['href', href],
        }});
        return;
      }
      case 'Page.navigate': {
        if (['stale-before-navigate', 'activate-target-drift', 'activate-backslash-target'].includes(scenario)) {
          throw new Error('Page.navigate must not run after stale revalidation');
        }
        if (scenario === 'transport-loss') {
          this.readyState = 3;
          if (this.onclose) this.onclose();
          return;
        }
        if (scenario === 'navigation-error') {
          reply({frameId: 'main-frame', errorText: 'ERR_FAILED private-target'});
          return;
        }
        if (['correlated-new-document', 'activate-correlated-new-document'].includes(scenario)) {
          reply({frameId: 'main-frame', loaderId: 'loader-after'});
          return;
        }
        if (scenario === 'correlated-same-document') {
          emit('Page.navigatedWithinDocument', {
            frameId: 'main-frame', url: 'https://private.invalid/#changed',
            navigationType: 'fragment',
          });
          reply({frameId: 'main-frame'});
          return;
        }
        reply({frameId: 'main-frame', loaderId: 'loader-before'});
        return;
      }
      default:
        reply();
    }
  }

  close() {
    if (this.readyState === 3) return;
    this.readyState = 3;
    queueMicrotask(() => {
      if (this.onclose) this.onclose();
    });
  }
}

globalThis.WebSocket = FakeWebSocket;
globalThis.fetch = async () => ({
  ok: true,
  json: async () => [{
    type: 'page',
    webSocketDebuggerUrl: 'ws://127.0.0.1:9222/devtools/page/1',
  }],
});
""",
            encoding="utf-8",
        )
        read_only = scenario.startswith("read-")
        activate = scenario.startswith("activate-")
        scroll = scenario.startswith("scroll-")
        expected_element = (
            self._semantic_link(
                name="Issues", target="https://private.invalid/issues"
            )
            if activate
            else {
                "backend_node_id": "101",
                "role": "button",
                "name": "" if scroll else "Target",
                "navigation_target_sha256": None,
            }
        )
        request = {
            "schema_version": 1,
            "port": 9222,
            "timeout_ms": 250,
            "op": "read_state" if read_only else ("activate" if activate else ("scroll_into_view" if scroll else "navigate")),
            "expected_state": {
                "origin": "https://before.invalid",
                "ready_state": "complete",
                "title": "Before",
                "main_frame_id": "main-frame",
                "loader_id": "loader-before",
                "navigation_entry_id": "7",
                "elements": [expected_element],
            },
        }
        if activate or scroll:
            request["expected_element"] = expected_element
        elif not read_only:
            request["navigation_target"] = (
                "https://private.invalid/path?secret=value"
            )
        request_path.write_text(
            json.dumps(request),
            encoding="utf-8",
        )
        execution = subprocess.run(
            [node, "--import", str(preload_path), str(helper_path), str(request_path)],
            cwd=fixture_root,
            env={**os.environ, "GRABOWSKI_TEST_SCENARIO": scenario},
            text=True,
            capture_output=True,
            timeout=5,
            check=False,
        )
        lines = [line for line in execution.stdout.splitlines() if line.strip()]
        self.assertTrue(lines, execution.stderr)
        return execution, json.loads(lines[-1])

    def test_browser_launch_is_loopback_only_and_leased(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ) as run:
            started = workers.browser_start(
                str(self.binary), port=9222, args=["--headless=new"], runtime_seconds=60
            )
        worker = started["worker"]
        self.assertEqual(worker["kind"], "browser")
        self.assertEqual(worker["state"], "running")
        self.assertIn("--remote-debugging-address=127.0.0.1", worker["argv"])
        self.assertIn("--remote-debugging-port=9222", worker["argv"])
        launch = run.call_args.args[0]
        descriptions = [item for item in launch if item.startswith("--description=")]
        self.assertEqual(1, len(descriptions))
        self.assertIn("Grabowski browser-worker grabowski-browser-worker-", descriptions[0])
        self.assertIn(" argv=", descriptions[0])
        self.assertNotIn("\n", descriptions[0])
        self.assertIn("--slice=grabowski-workers.slice", launch)
        self.assertEqual(launch.count("--property=LimitCORE=0"), 1)
        self.assertIn("--property=NoNewPrivileges=yes", launch)
        self.assertEqual(
            workers.resources.inspect_resource("port:9222")["owner_id"],
            f"worker:{worker['worker_id']}",
        )

    def test_browser_control_plane_projects_canonical_chrome_without_new_state(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            started = workers.browser_start(
                str(self.binary), port=9224, args=["--headless=new"], runtime_seconds=60
            )
        worker = started["worker"]
        control = worker["control_plane"]
        self.assertEqual(control["schema_version"], 1)
        self.assertEqual(control["authority"]["control_plane"], "grabowski")
        self.assertEqual(control["intent"]["effect_class"], "managed-runtime-process")
        self.assertEqual(control["adapter"]["id"], "chrome-cdp")
        self.assertEqual(control["adapter"]["protocol"], "cdp")
        self.assertTrue(control["adapter"]["implemented"])
        self.assertEqual(control["browser"]["family"], "chrome-stable")
        self.assertEqual(control["browser"]["selection_role"], "canonical-operator")
        self.assertEqual(control["endpoint"]["address"], "127.0.0.1")
        self.assertTrue(control["endpoint"]["loopback_only"])
        self.assertEqual(control["profile"]["mode"], "ephemeral")
        self.assertEqual(control["profile"]["scope_kind"], "worker-ephemeral")
        self.assertEqual(
            control["profile"]["identity_sha256"],
            workers._browser_profile_identity(worker["profile_path"]),
        )
        future = control["adapter"]["future_adapters"]
        self.assertEqual(future[0]["id"], "webdriver-bidi")
        self.assertFalse(future[0]["implemented"])

    def test_distinct_ephemeral_profiles_can_run_concurrently(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            first = workers.browser_start(
                str(self.binary), port=9240, runtime_seconds=60
            )["worker"]
            second = workers.browser_start(
                str(self.binary), port=9241, runtime_seconds=60
            )["worker"]
        self.assertNotEqual(first["worker_id"], second["worker_id"])
        self.assertNotEqual(first["profile_path"], second["profile_path"])
        self.assertEqual(first["control_plane"]["profile"]["mode"], "ephemeral")
        self.assertEqual(second["control_plane"]["profile"]["mode"], "ephemeral")
        self.assertEqual(
            workers.resources.inspect_resource(f"browser-profile:{first['profile_path']}")["owner_id"],
            f"worker:{first['worker_id']}",
        )
        self.assertEqual(
            workers.resources.inspect_resource(f"browser-profile:{second['profile_path']}")["owner_id"],
            f"worker:{second['worker_id']}",
        )

    def test_browser_start_routes_launch_through_adapter_contract(self) -> None:
        with patch.object(
            workers,
            "_browser_adapter_launch_argv",
            wraps=workers._browser_adapter_launch_argv,
        ) as launch_adapter, patch.object(
            workers, "_executable", return_value=self.binary.resolve()
        ), patch.object(workers.operator, "_run", return_value=result()):
            started = workers.browser_start(
                str(self.binary), port=9242, args=["--headless=new"], runtime_seconds=60
            )
        launch_adapter.assert_called_once()
        call = launch_adapter.call_args
        self.assertEqual(call.args[0]["adapter_id"], "chrome-cdp")
        self.assertEqual(call.kwargs["port"], 9242)
        self.assertEqual(
            started["worker"]["control_plane"]["endpoint"],
            {"address": "127.0.0.1", "port": 9242, "loopback_only": True},
        )
        self.assertIn(
            "loopback-debugging",
            started["worker"]["control_plane"]["adapter"]["capabilities"],
        )

    def test_brave_uses_chromium_cdp_fallback_policy(self) -> None:
        brave = self.root / "brave-browser"
        brave.write_text("#!/bin/sh\nexit 0\n")
        brave.chmod(0o755)
        with patch.object(workers, "_executable", return_value=brave.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            started = workers.browser_start(str(brave), port=9227, runtime_seconds=60)
        control = started["worker"]["control_plane"]
        self.assertEqual(control["adapter"]["id"], "chromium-cdp")
        self.assertEqual(control["adapter"]["protocol"], "cdp")
        self.assertEqual(control["browser"]["family"], "brave")
        self.assertEqual(control["browser"]["selection_role"], "fallback-test")

    def test_chrome_for_testing_is_reproducible_test_only(self) -> None:
        policy = workers._browser_adapter_policy(
            "/opt/chrome-for-testing/chrome-linux64/chrome"
        )
        self.assertEqual(policy["family"], "chrome-for-testing")
        self.assertEqual(policy["adapter_id"], "chrome-cdp")
        self.assertEqual(policy["selection_role"], "reproducible-test")

    def test_non_chromium_browser_fails_closed_before_profile_creation(self) -> None:
        firefox = self.root / "firefox"
        firefox.write_text("#!/bin/sh\nexit 0\n")
        firefox.chmod(0o755)
        with patch.object(workers, "_executable", return_value=firefox.resolve()):
            with self.assertRaisesRegex(ValueError, "WebDriver BiDi is not implemented"):
                workers.browser_start(str(firefox), port=9228, runtime_seconds=60)
        self.assertFalse(workers.WORKER_STATE.exists())
        projected = workers._browser_adapter_policy(firefox, require_supported=False)
        self.assertFalse(projected["implemented"])
        self.assertEqual(projected["selection_role"], "unsupported")

    def test_same_persistent_profile_is_exclusive(self) -> None:
        profile_root = self.root / "browser-profiles"
        profile_root.mkdir()
        profile = profile_root / "github-auth"
        configured_roots = [str(profile_root)]
        with patch.object(workers.base, "_load_policy", return_value={}), patch.object(
            workers.base, "_profile_values", return_value=configured_roots
        ), patch.object(
            workers, "_executable", return_value=self.binary.resolve()
        ), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            first = workers.browser_start(
                str(self.binary),
                port=9230,
                persistent_profile=str(profile),
                runtime_seconds=60,
            )["worker"]
            with self.assertRaises(workers.resources.ResourceConflict):
                workers.browser_start(
                    str(self.binary),
                    port=9231,
                    persistent_profile=str(profile),
                    runtime_seconds=60,
                )
        profile_key = f"browser-profile:{profile}"
        self.assertEqual(
            workers.resources.inspect_resource(profile_key)["owner_id"],
            f"worker:{first['worker_id']}",
        )
        self.assertIsNone(workers.resources.inspect_resource("port:9231"))
        self.assertEqual(first["control_plane"]["profile"]["mode"], "persistent")
        self.assertEqual(
            first["control_plane"]["profile"]["scope_kind"],
            "explicit-auth-trust-scope",
        )

    def test_distinct_persistent_profiles_can_run_concurrently(self) -> None:
        profile_root = self.root / "browser-profiles"
        profile_root.mkdir()
        first_profile = profile_root / "github-auth"
        second_profile = profile_root / "n8n-auth"
        configured_roots = [str(profile_root)]
        with patch.object(workers.base, "_load_policy", return_value={}), patch.object(
            workers.base, "_profile_values", return_value=configured_roots
        ), patch.object(
            workers, "_executable", return_value=self.binary.resolve()
        ), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            first = workers.browser_start(
                str(self.binary),
                port=9232,
                persistent_profile=str(first_profile),
                runtime_seconds=60,
            )["worker"]
            second = workers.browser_start(
                str(self.binary),
                port=9233,
                persistent_profile=str(second_profile),
                runtime_seconds=60,
            )["worker"]
        self.assertNotEqual(first["worker_id"], second["worker_id"])
        self.assertNotEqual(
            first["control_plane"]["profile"]["identity_sha256"],
            second["control_plane"]["profile"]["identity_sha256"],
        )
        self.assertEqual(
            workers.resources.inspect_resource(f"browser-profile:{first_profile}")["owner_id"],
            f"worker:{first['worker_id']}",
        )
        self.assertEqual(
            workers.resources.inspect_resource(f"browser-profile:{second_profile}")["owner_id"],
            f"worker:{second['worker_id']}",
        )

    def test_browser_audit_uses_hashed_profile_identity_only(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            started = workers.browser_start(str(self.binary), port=9234, runtime_seconds=60)
        worker = started["worker"]
        with patch.object(workers.base, "_append_audit") as append:
            workers._audit("browser-worker-start", started)
        audit = append.call_args.args[0]
        serialized = json.dumps(audit, sort_keys=True)
        self.assertNotIn(worker["profile_path"], serialized)
        control = audit["browser_control_plane"]
        self.assertEqual(control["adapter_id"], "chrome-cdp")
        self.assertEqual(control["protocol"], "cdp")
        self.assertEqual(control["profile_mode"], "ephemeral")
        self.assertEqual(
            control["profile_identity_sha256"],
            worker["control_plane"]["profile"]["identity_sha256"],
        )
        self.assertTrue(control["loopback_only"])

    def test_persistent_profile_ignores_missing_alternative_roots(self) -> None:
        existing_root = self.root / "brave"
        existing_root.mkdir()
        missing_root = self.root / "chromium"
        profile = existing_root / "schauwerk"
        configured_roots = [str(existing_root), str(missing_root)]

        with patch.object(
            workers.base, "_load_policy", return_value={}
        ), patch.object(
            workers.base, "_profile_values", return_value=configured_roots
        ):
            resolved, ephemeral = workers._browser_profile("0" * 20, str(profile))

        self.assertEqual(resolved, profile)
        self.assertTrue(resolved.is_dir())
        self.assertFalse(ephemeral)

    def test_browser_args_cannot_override_binding_or_profile(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()):
            for argument in (
                "--remote-debugging-address=0.0.0.0",
                "--remote-debugging-port=9999",
                "--user-data-dir=/tmp/x",
            ):
                with self.assertRaises(ValueError):
                    workers.browser_start(str(self.binary), port=9222, args=[argument])

    def test_terminal_status_releases_leases_and_ephemeral_profile(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            started = workers.browser_start(str(self.binary), port=9223, runtime_seconds=60)
        worker = started["worker"]
        profile = Path(worker["profile_path"])
        self.assertTrue(profile.exists())
        probe = result(
            stdout=(
                "LoadState=loaded\nActiveState=inactive\nSubState=dead\n"
                "Result=success\nExecMainStatus=0\n"
            )
        )
        with patch.object(workers.operator, "_run", return_value=probe):
            status = workers.worker_status(worker["worker_id"], expected_kind="browser")
        self.assertEqual(status["state"], "completed")
        self.assertIsNone(workers.resources.inspect_resource("port:9223"))
        self.assertFalse(profile.exists())

    def test_failed_terminalization_resets_exact_unit_after_cleanup(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            started = workers.browser_start(
                str(self.binary), port=9234, runtime_seconds=60
            )
        worker = started["worker"]
        failed_probe = result(
            stdout=(
                "LoadState=loaded\nActiveState=failed\nSubState=failed\n"
                "Result=exit-code\nExecMainCode=1\nExecMainStatus=1\n"
            )
        )
        with patch.object(
            workers.operator, "_run", side_effect=[failed_probe, result()]
        ) as run:
            status = workers.worker_status(
                worker["worker_id"], expected_kind="browser"
            )

        self.assertEqual(status["state"], "failed")
        terminalization = status["last_observation"]["terminalization"]
        self.assertEqual(terminalization["release"]["status"], "released")
        self.assertEqual(terminalization["cleanup"]["status"], "completed")
        self.assertEqual(terminalization["unit_reset"]["status"], "reset")
        self.assertEqual(
            run.call_args_list[1].args[0],
            ["systemctl", "--user", "reset-failed", worker["unit"]],
        )
        self.assertEqual(workers.worker_list("browser", limit=10)["count"], 0)

        with patch.object(
            workers,
            "_observe",
            side_effect=AssertionError("settled worker must not re-probe"),
        ), patch.object(
            workers.operator,
            "_run",
            side_effect=AssertionError("settled worker must not re-run systemd"),
        ):
            repeated = workers.worker_status(
                worker["worker_id"], expected_kind="browser"
            )
        self.assertEqual(repeated["state"], "failed")
        self.assertEqual(
            repeated["last_observation"]["terminalization"]["unit_reset"]["status"],
            "reset",
        )

    def test_failed_unit_reset_failure_stays_attention_and_retries_without_reprobe(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            started = workers.browser_start(
                str(self.binary), port=9235, runtime_seconds=60
            )
        worker = started["worker"]
        failed_probe = result(
            stdout=(
                "LoadState=loaded\nActiveState=failed\nSubState=failed\n"
                "Result=exit-code\nExecMainCode=1\nExecMainStatus=1\n"
            )
        )
        with patch.object(
            workers.operator,
            "_run",
            side_effect=[failed_probe, result(returncode=1), failed_probe],
        ) as run:
            status = workers.worker_status(
                worker["worker_id"], expected_kind="browser"
            )
        unit_reset = status["last_observation"]["terminalization"]["unit_reset"]
        self.assertEqual(unit_reset["status"], "incomplete")
        self.assertEqual(unit_reset["readback"]["status"], "failed")
        self.assertEqual(run.call_count, 3)
        self.assertEqual(
            run.call_args_list[2].args[0],
            [
                "systemctl",
                "--user",
                "show",
                worker["unit"],
                "--no-pager",
                "--property=LoadState",
                "--property=ActiveState",
                "--property=SubState",
            ],
        )
        current = workers.worker_list("browser", limit=10)
        self.assertEqual(current["count"], 1)
        self.assertEqual(
            current["workers"][0]["projection"]["reason"],
            "terminalization-incomplete",
        )

        with patch.object(
            workers,
            "_observe",
            side_effect=AssertionError("reset retry must not re-probe"),
        ), patch.object(workers.operator, "_run", return_value=result()) as run:
            retried = workers.worker_status(
                worker["worker_id"], expected_kind="browser"
            )
        self.assertEqual(run.call_count, 1)
        self.assertEqual(
            run.call_args.args[0],
            ["systemctl", "--user", "reset-failed", worker["unit"]],
        )
        self.assertEqual(
            retried["last_observation"]["terminalization"]["unit_reset"]["status"],
            "reset",
        )
        self.assertEqual(workers.worker_list("browser", limit=10)["count"], 0)

    def test_failed_unit_reset_retry_settles_when_unit_is_no_longer_loaded(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            started = workers.browser_start(
                str(self.binary), port=9355, runtime_seconds=60
            )
        worker = started["worker"]
        failed_probe = result(
            stdout="LoadState=loaded\nActiveState=failed\nSubState=failed\n"
        )
        with patch.object(
            workers.operator,
            "_run",
            side_effect=[failed_probe, result(returncode=1), failed_probe],
        ):
            first = workers.worker_status(
                worker["worker_id"], expected_kind="browser"
            )
        self.assertEqual(
            first["last_observation"]["terminalization"]["unit_reset"]["status"],
            "incomplete",
        )
        not_loaded_probe = result(
            stdout="LoadState=not-found\nActiveState=inactive\nSubState=dead\n"
        )
        with patch.object(
            workers,
            "_observe",
            side_effect=AssertionError("reset retry must not use full worker observation"),
        ), patch.object(
            workers.operator,
            "_run",
            side_effect=[result(returncode=1), not_loaded_probe],
        ) as run:
            settled = workers.worker_status(
                worker["worker_id"], expected_kind="browser"
            )
        unit_reset = settled["last_observation"]["terminalization"]["unit_reset"]
        self.assertEqual(unit_reset["status"], "not-required")
        self.assertEqual(unit_reset["readback"]["status"], "not-failed")
        self.assertEqual(run.call_count, 2)
        self.assertEqual(
            run.call_args_list[0].args[0],
            ["systemctl", "--user", "reset-failed", worker["unit"]],
        )
        self.assertEqual(
            run.call_args_list[1].args[0],
            [
                "systemctl",
                "--user",
                "show",
                worker["unit"],
                "--no-pager",
                "--property=LoadState",
                "--property=ActiveState",
                "--property=SubState",
            ],
        )
        self.assertEqual(workers.worker_list("browser", limit=10)["count"], 0)

    def test_planned_runtime_completion_resets_failed_systemd_unit(self) -> None:
        with patch.object(workers, "_now", return_value=1000), patch.object(
            workers, "_executable", return_value=self.binary.resolve()
        ), patch.object(workers.operator, "_run", return_value=result()):
            started = workers.browser_start(
                str(self.binary), port=9236, runtime_seconds=60
            )
        worker = started["worker"]
        timeout_probe = result(
            stdout=(
                "LoadState=loaded\nActiveState=failed\nSubState=failed\n"
                "Result=timeout\nExecMainCode=1\nExecMainStatus=0\n"
                "RuntimeMaxUSec=1min\n"
                "ActiveEnterTimestampMonotonic=1000000\n"
                "ActiveExitTimestampMonotonic=61000000\n"
            )
        )
        with patch.object(workers, "_now", return_value=1060), patch.object(
            workers.operator, "_run", side_effect=[timeout_probe, result()]
        ) as run:
            status = workers.worker_status(
                worker["worker_id"], expected_kind="browser"
            )
        self.assertEqual(status["state"], "completed")
        self.assertEqual(
            status["last_observation"]["terminalization"]["unit_reset"]["status"],
            "reset",
        )
        self.assertEqual(
            run.call_args_list[1].args[0],
            ["systemctl", "--user", "reset-failed", worker["unit"]],
        )

    def test_legacy_failed_terminalization_is_migrated_without_reprobe(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            started = workers.browser_start(
                str(self.binary), port=9237, runtime_seconds=60
            )
        worker = started["worker"]
        record = workers._row(worker["worker_id"])
        terminalization = {
            "release": workers._release(record),
            "cleanup": workers._cleanup(record),
        }
        legacy_observation = {
            "state": "failed",
            "properties": {
                "LoadState": "loaded",
                "ActiveState": "failed",
                "SubState": "failed",
                "Result": "timeout",
            },
            "observed_at_unix": 123456,
            "terminalization": terminalization,
        }
        workers._update(
            worker["worker_id"], "failed", observation=legacy_observation
        )

        current = workers.worker_list("browser", limit=10)
        self.assertEqual(current["count"], 1)
        self.assertEqual(
            current["workers"][0]["projection"]["reason"],
            "terminalization-incomplete",
        )
        with patch.object(
            workers,
            "_observe",
            side_effect=AssertionError("legacy migration must not re-probe"),
        ), patch.object(workers.operator, "_run", return_value=result()) as run:
            migrated = workers.worker_status(
                worker["worker_id"], expected_kind="browser"
            )
        self.assertEqual(run.call_count, 1)
        self.assertEqual(
            run.call_args.args[0],
            ["systemctl", "--user", "reset-failed", worker["unit"]],
        )
        self.assertEqual(
            migrated["last_observation"]["terminalization"]["unit_reset"]["status"],
            "reset",
        )
        self.assertEqual(workers.worker_list("browser", limit=10)["count"], 0)

    def test_planned_runtime_limit_is_completed_and_releases_ephemeral_profile(self) -> None:
        with patch.object(workers, "_now", return_value=1000), patch.object(
            workers, "_executable", return_value=self.binary.resolve()
        ), patch.object(workers.operator, "_run", return_value=result()):
            started = workers.browser_start(str(self.binary), port=9224, runtime_seconds=60)
        worker = started["worker"]
        profile = Path(worker["profile_path"])
        timeout_probe = result(
            stdout=(
                "LoadState=loaded\nActiveState=failed\nSubState=failed\n"
                "Result=timeout\nExecMainCode=1\nExecMainStatus=0\n"
                "RuntimeMaxUSec=1min\n"
                "ActiveEnterTimestampMonotonic=1000000\n"
                "ActiveExitTimestampMonotonic=61000000\n"
            )
        )
        with patch.object(workers, "_now", return_value=1060), patch.object(
            workers.operator, "_run", return_value=timeout_probe
        ):
            status = workers.worker_status(worker["worker_id"], expected_kind="browser")
        self.assertEqual(status["state"], "completed")
        self.assertEqual(status["last_observation"]["properties"]["Result"], "timeout")
        self.assertIsNone(workers.resources.inspect_resource("port:9224"))
        self.assertFalse(profile.exists())

    def test_planned_runtime_sigterm_is_completed(self) -> None:
        with patch.object(workers, "_now", return_value=1000), patch.object(
            workers, "_executable", return_value=self.binary.resolve()
        ), patch.object(workers.operator, "_run", return_value=result()):
            started = workers.browser_start(str(self.binary), port=9390, runtime_seconds=300)
        timeout_probe = result(
            stdout=(
                "RuntimeMaxUSec=5min\n"
                "Result=timeout\nExecMainCode=2\nExecMainStatus=15\n"
                "LoadState=loaded\nActiveState=failed\nSubState=failed\n"
                "ActiveEnterTimestampMonotonic=423983505569\n"
                "ActiveExitTimestampMonotonic=424283631535\n"
            )
        )
        with patch.object(workers, "_now", return_value=1300), patch.object(
            workers.operator, "_run", return_value=timeout_probe
        ):
            status = workers.worker_status(
                started["worker"]["worker_id"], expected_kind="browser"
            )
        self.assertEqual(status["state"], "completed")
        self.assertEqual(status["last_observation"]["properties"]["ExecMainStatus"], "15")
        self.assertIsNone(workers.resources.inspect_resource("port:9390"))

    def test_planned_runtime_sigterm_with_mismatched_runtime_limit_is_failed(self) -> None:
        with patch.object(workers, "_now", return_value=1000), patch.object(
            workers, "_executable", return_value=self.binary.resolve()
        ), patch.object(workers.operator, "_run", return_value=result()):
            started = workers.browser_start(str(self.binary), port=9391, runtime_seconds=300)
        timeout_probe = result(
            stdout=(
                "RuntimeMaxUSec=4min\n"
                "Result=timeout\nExecMainCode=2\nExecMainStatus=15\n"
                "LoadState=loaded\nActiveState=failed\nSubState=failed\n"
                "ActiveEnterTimestampMonotonic=423983505569\n"
                "ActiveExitTimestampMonotonic=424283631535\n"
            )
        )
        with patch.object(workers, "_now", return_value=1300), patch.object(
            workers.operator, "_run", return_value=timeout_probe
        ):
            status = workers.worker_status(
                started["worker"]["worker_id"], expected_kind="browser"
            )
        self.assertEqual(status["state"], "failed")

    def test_planned_runtime_sigterm_without_runtime_limit_evidence_is_failed(self) -> None:
        with patch.object(workers, "_now", return_value=1000), patch.object(
            workers, "_executable", return_value=self.binary.resolve()
        ), patch.object(workers.operator, "_run", return_value=result()):
            started = workers.browser_start(str(self.binary), port=9392, runtime_seconds=300)
        timeout_probe = result(
            stdout=(
                "Result=timeout\nExecMainCode=2\nExecMainStatus=15\n"
                "LoadState=loaded\nActiveState=failed\nSubState=failed\n"
                "ActiveEnterTimestampMonotonic=423983505569\n"
                "ActiveExitTimestampMonotonic=424283631535\n"
            )
        )
        with patch.object(workers, "_now", return_value=1300), patch.object(
            workers.operator, "_run", return_value=timeout_probe
        ):
            status = workers.worker_status(
                started["worker"]["worker_id"], expected_kind="browser"
            )
        self.assertEqual(status["state"], "failed")

    def test_timeout_before_planned_runtime_limit_is_failed(self) -> None:
        with patch.object(workers, "_now", return_value=1000), patch.object(
            workers, "_executable", return_value=self.binary.resolve()
        ), patch.object(workers.operator, "_run", return_value=result()):
            started = workers.browser_start(str(self.binary), port=9228, runtime_seconds=60)
        timeout_probe = result(
            stdout=(
                "LoadState=loaded\nActiveState=failed\nSubState=failed\n"
                "Result=timeout\nExecMainCode=1\nExecMainStatus=0\n"
                "RuntimeMaxUSec=1min\n"
                "ActiveEnterTimestampMonotonic=1000000\n"
                "ActiveExitTimestampMonotonic=60000000\n"
            )
        )
        with patch.object(workers, "_now", return_value=1100), patch.object(
            workers.operator, "_run", return_value=timeout_probe
        ):
            status = workers.worker_status(
                started["worker"]["worker_id"], expected_kind="browser"
            )
        self.assertEqual(status["state"], "failed")

    def test_timeout_with_nonzero_exit_is_failed_after_runtime_limit(self) -> None:
        with patch.object(workers, "_now", return_value=1000), patch.object(
            workers, "_executable", return_value=self.binary.resolve()
        ), patch.object(workers.operator, "_run", return_value=result()):
            started = workers.browser_start(str(self.binary), port=9229, runtime_seconds=60)
        timeout_probe = result(
            stdout=(
                "LoadState=loaded\nActiveState=failed\nSubState=failed\n"
                "Result=timeout\nExecMainCode=1\nExecMainStatus=1\n"
                "RuntimeMaxUSec=1min\n"
                "ActiveEnterTimestampMonotonic=1000000\n"
                "ActiveExitTimestampMonotonic=61000000\n"
            )
        )
        with patch.object(workers, "_now", return_value=1060), patch.object(
            workers.operator, "_run", return_value=timeout_probe
        ):
            status = workers.worker_status(
                started["worker"]["worker_id"], expected_kind="browser"
            )
        self.assertEqual(status["state"], "failed")

    def test_collected_successful_unit_is_completed(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            started = workers.browser_start(str(self.binary), port=9225, runtime_seconds=60)
        probe = result(
            stdout=(
                "LoadState=not-found\nActiveState=inactive\nSubState=dead\n"
                "Result=success\nExecMainStatus=0\n"
            )
        )
        with patch.object(workers.operator, "_run", return_value=probe):
            status = workers.worker_status(
                started["worker"]["worker_id"], expected_kind="browser"
            )
        self.assertEqual(status["state"], "completed")
        self.assertIsNone(workers.resources.inspect_resource("port:9225"))

    def test_collected_failed_unit_is_failed(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            started = workers.browser_start(str(self.binary), port=9226, runtime_seconds=60)
        probe = result(
            stdout=(
                "LoadState=not-found\nActiveState=inactive\nSubState=dead\n"
                "Result=exit-code\nExecMainStatus=1\n"
            )
        )
        with patch.object(workers.operator, "_run", return_value=probe):
            status = workers.worker_status(
                started["worker"]["worker_id"], expected_kind="browser"
            )
        self.assertEqual(status["state"], "failed")
        self.assertIsNone(workers.resources.inspect_resource("port:9226"))

    def test_collected_unit_without_result_is_interrupted(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            started = workers.browser_start(str(self.binary), port=9227, runtime_seconds=60)
        probe = result(
            stdout=(
                "LoadState=not-found\nActiveState=inactive\nSubState=dead\n"
                "Result=\nExecMainStatus=\n"
            )
        )
        with patch.object(workers.operator, "_run", return_value=probe):
            status = workers.worker_status(
                started["worker"]["worker_id"], expected_kind="browser"
            )
        self.assertEqual(status["state"], "interrupted")
        self.assertIsNone(workers.resources.inspect_resource("port:9227"))

    def _running_browser(self, port: int = 9333) -> dict[str, object]:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            return workers.browser_start(str(self.binary), port=port, runtime_seconds=60)["worker"]

    def _confirmation(
        self,
        worker_id: str,
        *,
        origin: str = "http://device.home.arpa",
        identity: str = "#identity",
        protected: str = "#protected",
        submit: str = "button",
        choice: str | None = None,
        action_mode: str = "submit",
    ) -> str:
        scope, _, _ = workers._browser_form_action_scope(
            worker_id,
            origin,
            {"identity": identity, "protected": protected, "submit": submit},
            choice,
            action_mode,
        )
        return workers._browser_form_confirmation(worker_id, origin, scope)

    def test_stored_form_action_is_target_bound_and_redacted(self) -> None:
        worker = self._running_browser()
        payload = {
            "schema_version": 1,
            "ok": True,
            "result_code": "ok",
            "fill_confirmed": True,
            "submitted": True,
            "action_effect_observed": True,
            "navigation_observed": False,
            "form_disappeared": True,
            "post_origin": "http://device.home.arpa",
            "post_path_sha256": "a" * 64,
            "remote_address_sha256": "d" * 64,
            "cleaned": False,
        }
        audit_path = self.root / "audit.jsonl"
        with patch.object(workers, "_canonical_local_origin", return_value=("http://device.home.arpa", "b" * 64, ["192.168.1.1"])), patch.object(
            workers, "_run_node_form_action", return_value=payload
        ) as action, patch.object(workers.base, "_append_audit") as append, patch.object(
            workers.base, "_verify_audit_log", return_value={"last_record_sha256": "c" * 64}
        ), patch.object(workers.base, "AUDIT_LOG", audit_path), patch.object(
            workers, "_observe", return_value={"state": "running", "properties": {}, "probe": result(), "observed_at_unix": 1}
        ):
            response = workers.browser_stored_form_action(
                worker["worker_id"],
                expected_origin="http://device.home.arpa",
                identity_selector="#identity",
                protected_selector="#protected",
                submit_selector="button[type=submit]",
                identity_choice="operator",
                confirmation=self._confirmation(
                    worker["worker_id"],
                    submit="button[type=submit]",
                    choice="operator",
                ),
            )
        self.assertTrue(response["ok"])
        self.assertTrue(response["submitted"])
        self.assertNotIn("#identity", json.dumps(response))
        self.assertNotIn("#protected", json.dumps(response))
        request = action.call_args.args[1]
        self.assertEqual(request["expected_origin"], "http://device.home.arpa")
        record = append.call_args.args[0]
        self.assertNotIn("identity_selector", record)
        self.assertNotIn("protected_selector", record)
        self.assertEqual(record["selector_sha256"]["identity"], workers._sha256_text("#identity"))
        self.assertIsNone(workers.resources.inspect_resource(f"component:browser-action:{worker['worker_id']}"))

    def test_stored_form_readiness_is_fill_only_and_cleans_fields(self) -> None:
        worker = self._running_browser(port=9342)
        payload = {
            "schema_version": 1,
            "ok": True,
            "result_code": "ready",
            "fill_confirmed": True,
            "submitted": False,
            "action_effect_observed": False,
            "navigation_observed": False,
            "form_disappeared": False,
            "post_origin": "http://device.home.arpa",
            "post_path_sha256": None,
            "remote_address_sha256": "d" * 64,
            "cleaned": True,
        }
        with patch.object(
            workers,
            "_canonical_local_origin",
            return_value=("http://device.home.arpa", "b" * 64, ["192.168.1.1"]),
        ), patch.object(workers, "_run_node_form_action", return_value=payload) as action, patch.object(
            workers.base, "_append_audit"
        ) as append, patch.object(
            workers.base, "_verify_audit_log", return_value={"last_record_sha256": "c" * 64}
        ), patch.object(
            workers,
            "_observe",
            return_value={"state": "running", "properties": {}, "probe": result(), "observed_at_unix": 1},
        ):
            response = workers.browser_stored_form_action(
                worker["worker_id"],
                expected_origin="http://device.home.arpa",
                identity_selector="#identity",
                protected_selector="#protected",
                submit_selector="button",
                action_mode="readiness",
                confirmation=self._confirmation(worker["worker_id"], action_mode="readiness"),
            )
        self.assertTrue(response["ok"])
        self.assertEqual(response["result_code"], "ready")
        self.assertIs(response["submitted"], False)
        self.assertIs(response["cleaned"], True)
        self.assertEqual(response["action_mode"], "readiness")
        self.assertEqual(action.call_args.args[1]["action_mode"], "readiness")
        self.assertEqual(append.call_args.args[0]["action_mode"], "readiness")
        self.assertEqual(
            response["does_not_establish"],
            [
                "authentication_success",
                "future_submit_success",
                "browser_profile_contains_a_reusable_stored_entry",
            ],
        )

    def test_stored_form_action_rejects_invalid_mode_before_transport(self) -> None:
        worker = self._running_browser(port=9344)
        with patch.object(workers, "_canonical_local_origin") as origin, patch.object(
            workers, "_run_node_form_action"
        ) as action:
            with self.assertRaisesRegex(ValueError, "action_mode"):
                workers.browser_stored_form_action(
                    worker["worker_id"],
                    expected_origin="http://device.home.arpa",
                    identity_selector="#identity",
                    protected_selector="#protected",
                    submit_selector="button",
                    action_mode="inspect",
                    confirmation="unused",
                )
        origin.assert_not_called()
        action.assert_not_called()

    def test_stored_form_readiness_rejects_drifted_success_receipts(self) -> None:
        worker = self._running_browser(port=9345)
        base_payload = {
            "schema_version": 1,
            "ok": True,
            "result_code": "ready",
            "fill_confirmed": True,
            "submitted": False,
            "action_effect_observed": False,
            "navigation_observed": False,
            "form_disappeared": False,
            "post_origin": "http://device.home.arpa",
            "post_path_sha256": None,
            "remote_address_sha256": "d" * 64,
            "cleaned": True,
        }
        record = workers._row(worker["worker_id"])
        request = {
            "schema_version": 1,
            "port": 9345,
            "expected_origin": "http://device.home.arpa",
            "allowed_addresses": ["192.168.1.1"],
            "cleanup_only": False,
            "action_mode": "readiness",
            "selectors": {"identity": "#i", "protected": "#p", "submit": "button"},
            "identity_choice": None,
            "timeout_ms": 5000,
        }
        for key, value in (
            ("form_disappeared", True),
            ("post_origin", "http://other.home.arpa"),
            ("post_path_sha256", "a" * 64),
        ):
            with self.subTest(key=key):
                payload = {**base_payload, key: value}
                execution = result(stdout=json.dumps(payload) + "\n")
                node = self.root / f"node-{key}"
                node.write_text("#!/bin/sh\nexit 0\n")
                node.chmod(0o755)
                with patch.object(workers.shutil, "which", return_value=str(node)), patch.object(
                    workers.operator, "_run", return_value=execution
                ):
                    with self.assertRaisesRegex(RuntimeError, "readiness receipt"):
                        workers._run_node_form_action(
                            record,
                            request,
                            timeout_seconds=5,
                        )

    def test_stored_form_readiness_confirmation_cannot_authorize_submit(self) -> None:
        worker = self._running_browser(port=9343)
        readiness_confirmation = self._confirmation(
            worker["worker_id"], action_mode="readiness"
        )
        with patch.object(
            workers,
            "_canonical_local_origin",
            return_value=("http://device.home.arpa", "b" * 64, ["192.168.1.1"]),
        ), patch.object(workers, "_run_node_form_action") as action:
            with self.assertRaisesRegex(PermissionError, "confirmation mismatch"):
                workers.browser_stored_form_action(
                    worker["worker_id"],
                    expected_origin="http://device.home.arpa",
                    identity_selector="#identity",
                    protected_selector="#protected",
                    submit_selector="button",
                    action_mode="submit",
                    confirmation=readiness_confirmation,
                )
        action.assert_not_called()

    def test_stored_form_readiness_helper_clears_before_submit_branch(self) -> None:
        source = workers.BROWSER_FORM_NODE_SOURCE
        readiness = source.index("if (request.action_mode === 'readiness')")
        clear = source.index("cleaned = await clearFields();", readiness)
        ready_receipt = source.index("result_code: 'ready'", readiness)
        submit = source.index("stage = 'submit-target';", readiness)
        self.assertLess(readiness, clear)
        self.assertLess(clear, ready_receipt)
        self.assertLess(ready_receipt, submit)

    def test_stored_form_action_requires_exact_confirmation(self) -> None:
        worker = self._running_browser(port=9334)
        with patch.object(workers, "_canonical_local_origin", return_value=("http://device.home.arpa", "b" * 64, ["192.168.1.1"])), patch.object(
            workers, "_run_node_form_action"
        ) as action:
            with self.assertRaisesRegex(PermissionError, "confirmation mismatch"):
                workers.browser_stored_form_action(
                    worker["worker_id"],
                    expected_origin="http://device.home.arpa",
                    identity_selector="#identity",
                    protected_selector="#protected",
                    submit_selector="button",
                    confirmation="wrong",
                )
        action.assert_not_called()

    def test_stored_form_action_rejects_public_resolution(self) -> None:
        public_answer = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 80))]
        with patch.object(workers.socket, "getaddrinfo", return_value=public_answer):
            with self.assertRaisesRegex(PermissionError, "outside local"):
                workers._canonical_local_origin("http://example.invalid")

    def test_stored_form_action_canonicalizes_resolved_ipv6_addresses(self) -> None:
        local_answers = [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("fd00:0:0:0:0:0:0:1", 80, 0, 3)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("fd00::1", 80, 0, 0)),
        ]
        with patch.object(workers.socket, "getaddrinfo", return_value=local_answers):
            origin, address_sha256, addresses = workers._canonical_local_origin(
                "http://device.invalid"
            )
        self.assertEqual(origin, "http://device.invalid")
        self.assertEqual(addresses, ["fd00::1"])
        self.assertEqual(address_sha256, hashlib.sha256(b"fd00::1").hexdigest())

    def test_stored_form_action_rejects_invalid_resolver_address(self) -> None:
        invalid_answers = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("not-an-ip", 80))
        ]
        with patch.object(workers.socket, "getaddrinfo", return_value=invalid_answers):
            with self.assertRaisesRegex(RuntimeError, "invalid address"):
                workers._canonical_local_origin("http://device.invalid")

    def test_stored_form_action_rejects_multiline_selector(self) -> None:
        with self.assertRaisesRegex(ValueError, "bounded single-line"):
            workers._validate_form_selector("#field\nscript", "identity_selector")

    def test_stored_form_action_fails_closed_when_browser_fill_is_absent(self) -> None:
        worker = self._running_browser(port=9335)
        payload = {
            "schema_version": 1,
            "ok": False,
            "result_code": "browser-fill",
            "fill_confirmed": False,
            "submitted": False,
            "action_effect_observed": False,
            "navigation_observed": False,
            "form_disappeared": False,
            "post_origin": None,
            "post_path_sha256": None,
            "remote_address_sha256": "d" * 64,
            "cleaned": True,
        }
        with patch.object(workers, "_canonical_local_origin", return_value=("http://device.home.arpa", "b" * 64, ["192.168.1.1"])), patch.object(
            workers, "_run_node_form_action", return_value=payload
        ), patch.object(workers.base, "_append_audit") as append, patch.object(
            workers.base, "_verify_audit_log", return_value={"last_record_sha256": "c" * 64}
        ), patch.object(workers, "_observe", return_value={"state": "running", "properties": {}, "probe": result(), "observed_at_unix": 1}):
            response = workers.browser_stored_form_action(
                worker["worker_id"],
                expected_origin="http://device.home.arpa",
                identity_selector="#identity",
                protected_selector="#protected",
                submit_selector="button",
                confirmation=self._confirmation(worker["worker_id"]),
            )
        self.assertFalse(response["ok"])
        self.assertEqual(response["result_code"], "browser-fill")
        self.assertTrue(response["cleaned"])
        self.assertTrue(append.call_args.args[0]["cleaned"])

    def test_node_action_removes_private_request_files(self) -> None:
        worker = self._running_browser(port=9336)
        record = workers._row(worker["worker_id"])
        output = json.dumps({
            "schema_version": 1,
            "ok": False,
            "result_code": "transport",
            "fill_confirmed": False,
            "submitted": False,
            "action_effect_observed": False,
            "navigation_observed": False,
            "form_disappeared": False,
            "post_origin": None,
            "post_path_sha256": None,
            "remote_address_sha256": None,
            "cleaned": False,
        }) + "\n"
        node_target = self.root / "heim-node-tool"
        node_target.write_text("#!/bin/sh\nexit 0\n")
        node_target.chmod(0o755)
        node = self.root / "node"
        node.symlink_to(node_target)
        with patch.object(workers.shutil, "which", return_value=str(node)), patch.object(
            workers.operator, "_run", return_value=result(returncode=2, stdout=output)
        ) as run:
            parsed = workers._run_node_form_action(
                record,
                {
                    "schema_version": 1,
                    "port": 9336,
                    "expected_origin": "http://device.home.arpa",
                    "allowed_addresses": ["192.168.1.1"],
                    "cleanup_only": False,
                    "selectors": {"identity": "#i", "protected": "#p", "submit": "button"},
                    "identity_choice": None,
                    "timeout_ms": 5000,
                },
                timeout_seconds=5,
            )
        self.assertEqual(parsed["result_code"], "transport")
        self.assertEqual(run.call_args.args[0][0], str(node))
        self.assertNotEqual(run.call_args.args[0][0], str(node_target))
        instance = Path(record["config_path"]).parent
        self.assertEqual(list(instance.glob(".stored-form-*")), [])

    def test_stored_form_action_rejects_origin_path_query_and_fragment(self) -> None:
        local_answer = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.1", 80))]
        with patch.object(workers.socket, "getaddrinfo", return_value=local_answer):
            for value in (
                "http://device.home.arpa/login",
                "http://device.home.arpa?next=login",
                "http://device.home.arpa/#login",
            ):
                with self.subTest(value=value), self.assertRaisesRegex(ValueError, "canonical"):
                    workers._canonical_local_origin(value)

    def test_stored_form_action_rejects_terminal_worker_before_transport(self) -> None:
        worker = self._running_browser(port=9337)
        completed = {
            "state": "completed",
            "properties": {},
            "probe": result(),
            "observed_at_unix": 1,
        }
        with patch.object(
            workers,
            "_canonical_local_origin",
            return_value=("http://device.home.arpa", "b" * 64, ["192.168.1.1"]),
        ), patch.object(workers, "_observe", return_value=completed), patch.object(
            workers, "_run_node_form_action"
        ) as action:
            with self.assertRaisesRegex(RuntimeError, "not running"):
                workers.browser_stored_form_action(
                    worker["worker_id"],
                    expected_origin="http://device.home.arpa",
                    identity_selector="#identity",
                    protected_selector="#protected",
                    submit_selector="button",
                    confirmation=self._confirmation(worker["worker_id"]),
                )
        action.assert_not_called()

    def test_stored_form_action_audits_protocol_failure_after_cleanup_retry(self) -> None:
        worker = self._running_browser(port=9338)
        cleanup = {
            "schema_version": 1,
            "ok": True,
            "result_code": "cleanup",
            "fill_confirmed": False,
            "submitted": False,
            "action_effect_observed": False,
            "navigation_observed": False,
            "form_disappeared": False,
            "post_origin": "http://device.home.arpa",
            "post_path_sha256": None,
            "remote_address_sha256": "d" * 64,
            "cleaned": True,
        }
        audit_path = self.root / "audit.jsonl"
        with patch.object(
            workers,
            "_canonical_local_origin",
            return_value=("http://device.home.arpa", "b" * 64, ["192.168.1.1"]),
        ), patch.object(
            workers,
            "_run_node_form_action",
            side_effect=[RuntimeError("untrusted internal detail"), cleanup],
        ) as action, patch.object(workers.base, "_append_audit") as append, patch.object(
            workers.base, "_verify_audit_log", return_value={"last_record_sha256": "c" * 64}
        ), patch.object(workers.base, "AUDIT_LOG", audit_path), patch.object(
            workers,
            "_observe",
            return_value={"state": "running", "properties": {}, "probe": result(), "observed_at_unix": 1},
        ):
            response = workers.browser_stored_form_action(
                worker["worker_id"],
                expected_origin="http://device.home.arpa",
                identity_selector="#identity",
                protected_selector="#protected",
                submit_selector="button",
                confirmation=self._confirmation(worker["worker_id"]),
            )
        self.assertFalse(response["ok"])
        self.assertEqual(response["result_code"], "protocol")
        self.assertNotIn("untrusted internal detail", json.dumps(response))
        self.assertEqual(action.call_count, 2)
        self.assertEqual(append.call_count, 2)
        self.assertIs(action.call_args_list[1].args[1]["cleanup_only"], True)
        record = append.call_args.args[0]
        self.assertEqual(record["result_code"], "protocol")
        self.assertIs(record["outcome_known"], False)
        self.assertIsNone(record["ok"])
        self.assertIsNone(record["submitted"])
        self.assertTrue(record["cleaned"])
        self.assertNotIn("untrusted internal detail", json.dumps(record))
        self.assertIsNone(
            workers.resources.inspect_resource(
                f"component:browser-action:{worker['worker_id']}"
            )
        )

    def test_stored_form_action_preserves_fixed_element_contract_failure(self) -> None:
        worker = self._running_browser(port=9339)
        payload = {
            "schema_version": 1,
            "ok": False,
            "result_code": "element-contract",
            "fill_confirmed": False,
            "submitted": False,
            "action_effect_observed": False,
            "navigation_observed": False,
            "form_disappeared": False,
            "post_origin": None,
            "post_path_sha256": None,
            "remote_address_sha256": "d" * 64,
            "cleaned": True,
        }
        with patch.object(
            workers,
            "_canonical_local_origin",
            return_value=("http://device.home.arpa", "b" * 64, ["192.168.1.1"]),
        ), patch.object(workers, "_run_node_form_action", return_value=payload), patch.object(
            workers.base, "_append_audit"
        ), patch.object(
            workers.base, "_verify_audit_log", return_value={"last_record_sha256": "c" * 64}
        ), patch.object(
            workers,
            "_observe",
            return_value={"state": "running", "properties": {}, "probe": result(), "observed_at_unix": 1},
        ):
            response = workers.browser_stored_form_action(
                worker["worker_id"],
                expected_origin="http://device.home.arpa",
                identity_selector="#identity",
                protected_selector="#protected",
                submit_selector="button",
                confirmation=self._confirmation(worker["worker_id"]),
            )
        self.assertFalse(response["ok"])
        self.assertEqual(response["result_code"], "element-contract")
        self.assertTrue(response["cleaned"])

    def test_stored_form_confirmation_changes_with_every_selector(self) -> None:
        worker = self._running_browser(port=9340)
        original = self._confirmation(worker["worker_id"])
        for key, kwargs in (
            ("identity", {"identity": "#other-identity"}),
            ("protected", {"protected": "#other-protected"}),
            ("submit", {"submit": "button.primary"}),
            ("choice", {"choice": "other-user"}),
            ("action_mode", {"action_mode": "readiness"}),
        ):
            with self.subTest(key=key):
                self.assertNotEqual(original, self._confirmation(worker["worker_id"], **kwargs))

    def test_stored_form_action_requires_worker_owned_port_lease(self) -> None:
        worker = self._running_browser(port=9341)
        workers.resources.release_resources(
            f"worker:{worker['worker_id']}",
            ["port:9341"],
        )
        with patch.object(
            workers,
            "_canonical_local_origin",
            return_value=("http://device.home.arpa", "b" * 64, ["192.168.1.1"]),
        ), patch.object(workers, "_observe", return_value={
            "state": "running",
            "properties": {},
            "probe": result(),
            "observed_at_unix": 1,
        }), patch.object(workers, "_run_node_form_action") as action:
            with self.assertRaisesRegex(RuntimeError, "no longer owns"):
                workers.browser_stored_form_action(
                    worker["worker_id"],
                    expected_origin="http://device.home.arpa",
                    identity_selector="#identity",
                    protected_selector="#protected",
                    submit_selector="button",
                    confirmation=self._confirmation(worker["worker_id"]),
                )
        action.assert_not_called()

    def test_stored_form_helper_handles_prearmed_reload_events_at_runtime(self) -> None:
        execution, receipt = self._run_browser_form_node("reload-events-before-reply")
        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertIs(receipt["ok"], True)
        self.assertEqual(receipt["result_code"], "cleanup")
        self.assertEqual(
            receipt["remote_address_sha256"],
            hashlib.sha256(b"192.168.1.10").hexdigest(),
        )

    def test_stored_form_helper_ignores_stale_pre_reload_events(self) -> None:
        execution, receipt = self._run_browser_form_node("stale-events")
        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertIs(receipt["ok"], True)
        self.assertEqual(
            receipt["remote_address_sha256"],
            hashlib.sha256(b"192.168.1.10").hexdigest(),
        )

    def test_stored_form_helper_ignores_old_loader_events_during_reload(self) -> None:
        execution, receipt = self._run_browser_form_node(
            "old-loader-events-during-reload"
        )
        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertIs(receipt["ok"], True)
        self.assertEqual(
            receipt["remote_address_sha256"],
            hashlib.sha256(b"192.168.1.10").hexdigest(),
        )

    def test_stored_form_helper_rejects_loader_mismatch(self) -> None:
        execution, receipt = self._run_browser_form_node("loader-mismatch")
        self.assertEqual(execution.returncode, 2, execution.stderr)
        self.assertEqual(receipt["result_code"], "target-origin")
        self.assertIsNone(receipt["remote_address_sha256"])

    def test_stored_form_helper_rejects_final_frame_origin_drift(self) -> None:
        execution, receipt = self._run_browser_form_node("wrong-final-origin")
        self.assertEqual(execution.returncode, 2, execution.stderr)
        self.assertEqual(receipt["result_code"], "target-origin")
        self.assertIsNone(receipt["remote_address_sha256"])

    def test_stored_form_helper_does_not_claim_incomplete_transport_evidence(self) -> None:
        execution, receipt = self._run_browser_form_node("response-then-close")
        self.assertEqual(execution.returncode, 2, execution.stderr)
        self.assertIs(receipt["ok"], False)
        self.assertEqual(receipt["result_code"], "transport")
        self.assertIsNone(receipt["remote_address_sha256"])

    def test_stored_form_helper_flushes_receipt_before_bounded_exit(self) -> None:
        source = workers.BROWSER_FORM_NODE_SOURCE
        self.assertIn("const EXIT_FLUSH_TIMEOUT_MS = 1000;", source)
        self.assertIn("process.stdout.write(line, () => {", source)
        self.assertIn("const forcedExit = setTimeout(finish, EXIT_FLUSH_TIMEOUT_MS);", source)
        self.assertIn("process.exit(status);", source)

    def test_stored_form_helper_preserves_digest_after_verified_later_failure(self) -> None:
        execution, receipt = self._run_browser_form_node(
            "verified-then-element-failure", cleanup_only=False
        )
        self.assertEqual(execution.returncode, 2, execution.stderr)
        self.assertEqual(receipt["result_code"], "element-contract")
        self.assertEqual(
            receipt["remote_address_sha256"],
            hashlib.sha256(b"192.168.1.10").hexdigest(),
        )

    def test_stored_form_helper_does_not_disclose_rejected_remote_address(self) -> None:
        execution, receipt = self._run_browser_form_node("disallowed-address")
        self.assertEqual(execution.returncode, 2, execution.stderr)
        self.assertIs(receipt["ok"], False)
        self.assertEqual(receipt["result_code"], "target-origin")
        self.assertIsNone(receipt["remote_address_sha256"])

    def test_stored_form_helper_rejects_invalid_remote_address(self) -> None:
        execution, receipt = self._run_browser_form_node("invalid-address")
        self.assertEqual(execution.returncode, 2, execution.stderr)
        self.assertEqual(receipt["result_code"], "target-origin")
        self.assertIsNone(receipt["remote_address_sha256"])

    def test_stored_form_helper_normalizes_ipv6_zone_address(self) -> None:
        execution, receipt = self._run_browser_form_node(
            "ipv6-zone-address", allowed_addresses=["fd00::1"]
        )
        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertEqual(
            receipt["remote_address_sha256"],
            hashlib.sha256(b"fd00::1").hexdigest(),
        )

    def test_stored_form_helper_executes_non_cleanup_readiness_path(self) -> None:
        execution, receipt = self._run_browser_form_node(
            "readiness-success", cleanup_only=False, action_mode="readiness"
        )
        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertIs(receipt["ok"], True)
        self.assertEqual(receipt["result_code"], "ready")
        self.assertIs(receipt["fill_confirmed"], True)
        self.assertIs(receipt["cleaned"], True)

    def test_stored_form_helper_polls_until_form_contract_is_hydrated(self) -> None:
        execution, receipt = self._run_browser_form_node(
            "delayed-form-hydration", cleanup_only=False, action_mode="readiness"
        )
        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertEqual(receipt["result_code"], "ready")
        self.assertIs(receipt["fill_confirmed"], True)
        self.assertIs(receipt["cleaned"], True)

    def test_stored_form_helper_polls_cleanup_until_fields_are_hydrated(self) -> None:
        execution, receipt = self._run_browser_form_node("delayed-cleanup-hydration")
        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertEqual(receipt["result_code"], "cleanup")
        self.assertIs(receipt["cleaned"], True)

    def test_stored_form_helper_uses_topmost_pointer_and_guarded_enter(self) -> None:
        source = workers.BROWSER_FORM_NODE_SOURCE
        self.assertIn("document.elementFromPoint", source)
        self.assertIn("Input.dispatchMouseEvent", source)
        self.assertIn("guardedEnter", source)
        browser_fill = source.split("stage = 'browser-fill';", 1)[1].split(
            "stage = 'submit-target';", 1
        )[0]
        self.assertNotIn(".focus()", browser_fill)
        self.assertIn("await key('Tab', 'Tab', 9)", browser_fill)
        self.assertIn("await guardedEnter()", browser_fill)

    def test_gui_fails_clearly_without_xvfb(self) -> None:
        with patch.object(workers.shutil, "which", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "Xvfb is not installed"):
                workers.gui_start(str(self.binary), display_number=20)

    def test_gui_config_has_no_tcp_listener(self) -> None:
        xvfb = self.root / "Xvfb"
        xvfb.write_text("#!/bin/sh\nexit 0\n")
        xvfb.chmod(0o755)
        with patch.object(workers.shutil, "which", return_value=str(xvfb)), patch.object(
            workers, "_executable", return_value=self.binary.resolve()
        ), patch.object(workers.operator, "_run", return_value=result()):
            started = workers.gui_start(
                str(self.binary), display_number=21, args=["--example"], runtime_seconds=60
            )
        worker = started["worker"]
        record = workers._row(worker["worker_id"])
        config = json.loads(Path(record["config_path"]).read_text())
        self.assertEqual(config["environment"]["DISPLAY"], ":21")
        self.assertIn("-nolisten", config["xvfb_argv"])
        self.assertIn("tcp", config["xvfb_argv"])
        self.assertNotIn("vnc", " ".join(config["xvfb_argv"]).lower())
        self.assertEqual(
            workers.resources.inspect_resource("display:21")["owner_id"],
            f"worker:{worker['worker_id']}",
        )

    def test_launch_failure_releases_worker_leases_and_clears_missing_unit(self) -> None:
        missing_probe = result(
            stdout=(
                "LoadState=not-found\nActiveState=inactive\nSubState=dead\n"
            )
        )
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator,
            "_run",
            side_effect=[result(returncode=1), missing_probe],
        ) as run:
            started = workers.browser_start(str(self.binary), port=9224, runtime_seconds=60)
        self.assertEqual(started["worker"]["state"], "failed")
        terminalization = started["worker"]["last_observation"]["terminalization"]
        self.assertEqual(terminalization["release"]["status"], "released")
        self.assertEqual(terminalization["cleanup"]["status"], "completed")
        self.assertEqual(terminalization["unit_reset"]["status"], "not-required")
        self.assertEqual(run.call_count, 2)
        self.assertEqual(run.call_args_list[1].args[0][0:4], [
            "systemctl", "--user", "show", started["worker"]["unit"]
        ])
        self.assertIsNone(workers.resources.inspect_resource("port:9224"))

    def test_launch_failure_resets_exact_failed_unit_after_cleanup(self) -> None:
        failed_probe = result(
            stdout=(
                "LoadState=loaded\nActiveState=failed\nSubState=failed\n"
            )
        )
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator,
            "_run",
            side_effect=[result(returncode=1), failed_probe, result()],
        ) as run:
            started = workers.browser_start(str(self.binary), port=9224, runtime_seconds=60)
        worker = started["worker"]
        self.assertEqual(worker["state"], "failed")
        terminalization = worker["last_observation"]["terminalization"]
        self.assertEqual(terminalization["release"]["status"], "released")
        self.assertEqual(terminalization["cleanup"]["status"], "completed")
        self.assertEqual(terminalization["unit_reset"]["status"], "reset")
        self.assertEqual(terminalization["unit_reset"]["probe"]["status"], "failed")
        self.assertEqual(
            run.call_args_list[2].args[0],
            ["systemctl", "--user", "reset-failed", worker["unit"]],
        )
        self.assertIsNone(workers.resources.inspect_resource("port:9224"))


    def test_browser_prelaunch_failure_cleans_private_key_and_ephemeral_state(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers, "_write_config", side_effect=OSError("simulated config write failure")
        ):
            with self.assertRaisesRegex(OSError, "simulated config write failure"):
                workers.browser_start(str(self.binary), port=9225, runtime_seconds=60)
        self.assertIsNone(workers.resources.inspect_resource("port:9225"))
        instances = workers.WORKER_STATE / "instances"
        profiles = workers.WORKER_STATE / "profiles"
        self.assertEqual(list(instances.iterdir()) if instances.exists() else [], [])
        self.assertEqual(list(profiles.iterdir()) if profiles.exists() else [], [])


    def test_current_list_observes_stale_running_without_mutation(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            started = workers.browser_start(str(self.binary), port=9320, runtime_seconds=60)
        worker = started["worker"]
        record = workers._row(worker["worker_id"])
        config_path = Path(record["config_path"])
        probe = result(
            stdout=(
                "LoadState=loaded\nActiveState=inactive\nSubState=dead\n"
                "Result=success\nExecMainStatus=0\n"
            )
        )
        with patch.object(workers.operator, "_run", return_value=probe), patch.object(
            workers, "_update", side_effect=AssertionError("list must not persist")
        ), patch.object(
            workers, "_release", side_effect=AssertionError("list must not release")
        ), patch.object(
            workers, "_cleanup", side_effect=AssertionError("list must not cleanup")
        ):
            current = workers.worker_list("browser", limit=10)
        self.assertEqual(current["view"], "current")
        self.assertEqual(current["count"], 0)
        self.assertEqual(current["observed_count"], 1)
        self.assertEqual(
            workers.resources.inspect_resource("port:9320")["owner_id"],
            f"worker:{worker['worker_id']}",
        )
        self.assertEqual(workers._row(worker["worker_id"])["state"], "running")
        self.assertTrue(config_path.exists())

        with patch.object(workers.operator, "_run", return_value=probe):
            reconciled = workers.worker_status(worker["worker_id"], expected_kind="browser")
        self.assertEqual(reconciled["state"], "completed")
        self.assertIsNone(workers.resources.inspect_resource("port:9320"))
        observation = reconciled["last_observation"]
        self.assertEqual(observation["terminalization"]["release"]["status"], "released")
        self.assertIn(
            str(config_path.parent),
            observation["terminalization"]["cleanup"]["preserved_evidence"],
        )
        with patch.object(workers, "_observe", side_effect=AssertionError("history must not probe")):
            history = workers.worker_list("browser", limit=10, view="history")
        self.assertEqual(history["count"], 1)
        self.assertEqual(history["workers"][0]["state"], "completed")
        self.assertFalse(history["workers"][0]["projection"]["fresh"])

    def test_list_missing_registry_does_not_create_state(self) -> None:
        self.assertFalse(workers.WORKER_STATE.exists())
        current = workers.worker_list("browser", limit=10)
        history = workers.worker_list("gui", limit=10, view="history")
        self.assertEqual(current["count"], 0)
        self.assertEqual(history["count"], 0)
        self.assertFalse(workers.WORKER_STATE.exists())
        self.assertFalse(workers.WORKER_DB.exists())

    def test_current_list_does_not_migrate_worker_database(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            workers.browser_start(str(self.binary), port=9323, runtime_seconds=60)
        with sqlite3.connect(workers.WORKER_DB) as connection:
            before = connection.execute(
                "SELECT type, name, sql FROM sqlite_master ORDER BY type, name"
            ).fetchall()
        before_bytes = workers.WORKER_DB.read_bytes()
        before_stat = workers.WORKER_DB.stat()
        before_entries = sorted(path.name for path in workers.WORKER_STATE.iterdir())
        observation = {
            "state": "running",
            "properties": {"LoadState": "loaded", "ActiveState": "active"},
            "probe": result(),
            "observed_at_unix": 223344,
        }
        with patch.object(workers, "_observe", return_value=observation):
            current = workers.worker_list("browser", limit=10)
        self.assertEqual(current["count"], 1)
        with sqlite3.connect(workers.WORKER_DB) as connection:
            after = connection.execute(
                "SELECT type, name, sql FROM sqlite_master ORDER BY type, name"
            ).fetchall()
        after_stat = workers.WORKER_DB.stat()
        self.assertEqual(after, before)
        self.assertEqual(workers.WORKER_DB.read_bytes(), before_bytes)
        self.assertEqual(after_stat.st_mode, before_stat.st_mode)
        self.assertEqual(after_stat.st_size, before_stat.st_size)
        self.assertEqual(after_stat.st_mtime_ns, before_stat.st_mtime_ns)
        self.assertEqual(
            sorted(path.name for path in workers.WORKER_STATE.iterdir()),
            before_entries,
        )

    def test_current_list_surfaces_ambiguous_missing_unit_without_persisting(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            started = workers.browser_start(str(self.binary), port=9321, runtime_seconds=60)
        worker_id = started["worker"]["worker_id"]
        probe = result(
            stdout=(
                "LoadState=not-found\nActiveState=inactive\nSubState=dead\n"
                "Result=\nExecMainStatus=\n"
            )
        )
        with patch.object(workers.operator, "_run", return_value=probe):
            current = workers.worker_list("browser", limit=10)
        self.assertEqual(current["count"], 1)
        item = current["workers"][0]
        self.assertEqual(item["state"], "interrupted")
        self.assertEqual(item["projection"]["stored_state"], "running")
        self.assertFalse(item["projection"]["persisted_by_list"])
        self.assertEqual(item["projection"]["bucket"], "attention")
        self.assertEqual(item["projection"]["reason"], "systemd-observation-ambiguous")
        self.assertEqual(workers._row(worker_id)["state"], "running")
        self.assertIsNotNone(workers.resources.inspect_resource("port:9321"))
        with patch.object(workers.operator, "_run", return_value=probe):
            reconciled = workers.worker_status(worker_id, expected_kind="browser")
        self.assertEqual(reconciled["state"], "interrupted")
        self.assertIsNone(workers.resources.inspect_resource("port:9321"))

    def test_status_releases_only_exact_worker_owned_leases(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            started = workers.browser_start(str(self.binary), port=9322, runtime_seconds=60)
        worker = started["worker"]
        owner = f"worker:{worker['worker_id']}"
        profile_key = f"browser-profile:{worker['profile_path']}"
        workers.resources.release_resources(owner, ["port:9322"])
        workers.resources.acquire_resources(
            "foreign-owner",
            ["port:9322"],
            purpose="foreign replacement",
            ttl_seconds=60,
        )
        probe = result(
            stdout=(
                "LoadState=loaded\nActiveState=inactive\nSubState=dead\n"
                "Result=success\nExecMainStatus=0\n"
            )
        )
        with patch.object(workers.operator, "_run", return_value=probe):
            reconciled = workers.worker_status(worker["worker_id"], expected_kind="browser")
        release = reconciled["last_observation"]["terminalization"]["release"]
        self.assertEqual(release["status"], "partial")
        self.assertEqual(release["blocked"][0]["resource_key"], "port:9322")
        self.assertEqual(
            workers.resources.inspect_resource("port:9322")["owner_id"],
            "foreign-owner",
        )
        self.assertIsNone(workers.resources.inspect_resource(profile_key))

        current = workers.worker_list("browser", limit=10)
        self.assertEqual(current["count"], 1)
        self.assertEqual(current["observed_count"], 0)
        self.assertEqual(
            current["workers"][0]["projection"]["reason"],
            "terminalization-incomplete",
        )
        self.assertFalse(current["workers"][0]["projection"]["fresh"])
        workers.resources.release_resources("foreign-owner", ["port:9322"])
        still_attention = workers.worker_list("browser", limit=10)
        self.assertEqual(still_attention["count"], 1)
        with patch.object(workers.operator, "_run", return_value=probe):
            workers.worker_status(worker["worker_id"], expected_kind="browser")
        final = workers.worker_list("browser", limit=10)
        self.assertEqual(final["count"], 0)
        self.assertIsNone(workers.resources.inspect_resource("port:9322"))

    def test_history_cursor_is_stable_for_same_second_records(self) -> None:
        created: list[str] = []
        with patch.object(workers, "_now", return_value=123456), patch.object(
            workers, "_executable", return_value=self.binary.resolve()
        ), patch.object(workers.operator, "_run", return_value=result()):
            for port in (9330, 9331, 9332):
                worker = workers.browser_start(
                    str(self.binary), port=port, runtime_seconds=60
                )["worker"]
                created.append(worker["worker_id"])
                workers._update(worker["worker_id"], "completed")
        with patch.object(workers, "_observe", side_effect=AssertionError("history must not probe")):
            first = workers.worker_list("browser", limit=2, view="history")
            second = workers.worker_list(
                "browser", limit=2, view="history", cursor=first["next_cursor"]
            )
        first_ids = [item["worker_id"] for item in first["workers"]]
        second_ids = [item["worker_id"] for item in second["workers"]]
        self.assertEqual(first["count"], 2)
        self.assertTrue(first["has_more"])
        self.assertEqual(second["count"], 1)
        self.assertFalse(second["has_more"])
        self.assertEqual(set(first_ids + second_ids), set(created))
        self.assertEqual(len(first_ids + second_ids), len(set(first_ids + second_ids)))

    def test_current_cursor_is_stable_and_reconciles_each_page(self) -> None:
        created: list[str] = []
        with patch.object(workers, "_now", return_value=222222), patch.object(
            workers, "_executable", return_value=self.binary.resolve()
        ), patch.object(workers.operator, "_run", return_value=result()):
            for port in (9340, 9341, 9342):
                worker = workers.browser_start(
                    str(self.binary), port=port, runtime_seconds=60
                )["worker"]
                created.append(worker["worker_id"])
        observation = {
            "state": "running",
            "properties": {"LoadState": "loaded", "ActiveState": "active"},
            "probe": result(),
            "observed_at_unix": 222223,
        }
        with patch.object(workers, "_observe", return_value=observation) as observe, patch.object(
            workers, "_update", side_effect=AssertionError("list must not persist")
        ), patch.object(
            workers, "_release", side_effect=AssertionError("list must not release")
        ), patch.object(
            workers, "_cleanup", side_effect=AssertionError("list must not cleanup")
        ):
            first = workers.worker_list("browser", limit=2)
            second = workers.worker_list(
                "browser", limit=2, cursor=first["next_cursor"]
            )
        ids = [item["worker_id"] for item in first["workers"] + second["workers"]]
        self.assertEqual(set(ids), set(created))
        self.assertEqual(first["observed_count"], 2)
        self.assertEqual(second["observed_count"], 1)
        self.assertEqual(observe.call_count, 3)
        self.assertTrue(all(item["projection"]["bucket"] == "active" for item in first["workers"] + second["workers"]))

    def test_gui_list_uses_shared_terminal_reconciliation(self) -> None:
        xvfb = self.root / "Xvfb-list"
        xvfb.write_text("#!/bin/sh\nexit 0\n")
        xvfb.chmod(0o755)
        with patch.object(workers.shutil, "which", return_value=str(xvfb)), patch.object(
            workers, "_executable", return_value=self.binary.resolve()
        ), patch.object(workers.operator, "_run", return_value=result()):
            started = workers.gui_start(
                str(self.binary), display_number=31, runtime_seconds=60
            )
        config_path = Path(workers._row(started["worker"]["worker_id"])["config_path"])
        probe = result(
            stdout=(
                "LoadState=not-found\nActiveState=inactive\nSubState=dead\n"
                "Result=success\nExecMainStatus=0\n"
            )
        )
        worker_id = started["worker"]["worker_id"]
        with patch.object(workers.operator, "_run", return_value=probe):
            current = workers.worker_list("gui", limit=10)
        self.assertEqual(current["count"], 0)
        self.assertIsNotNone(workers.resources.inspect_resource("display:31"))
        self.assertEqual(workers._row(worker_id)["state"], "running")
        with patch.object(workers.operator, "_run", return_value=probe):
            reconciled = workers.worker_status(worker_id, expected_kind="gui")
        self.assertEqual(reconciled["state"], "completed")
        self.assertIsNone(workers.resources.inspect_resource("display:31"))
        self.assertTrue(config_path.exists())

    def test_stop_records_terminalization_and_preserves_manifest(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            started = workers.browser_start(str(self.binary), port=9350, runtime_seconds=60)
        worker = started["worker"]
        config_path = Path(workers._row(worker["worker_id"])["config_path"])
        handle_key = config_path.parent / ".semantic-handle-key"
        self.assertTrue(handle_key.is_file())
        with patch.object(workers.operator, "_run", return_value=result()):
            stopped = workers.worker_stop(worker["worker_id"], expected_kind="browser")
        self.assertEqual(stopped["worker"]["state"], "stopped")
        self.assertTrue(config_path.exists())
        self.assertFalse(handle_key.exists())
        self.assertIsNone(workers.resources.inspect_resource("port:9350"))
        terminalization = stopped["worker"]["last_observation"]["terminalization"]
        self.assertEqual(terminalization["release"]["status"], "released")
        self.assertEqual(terminalization["cleanup"]["status"], "completed")
        self.assertIn(str(handle_key), terminalization["cleanup"]["removed"])

    def test_stop_unlinks_semantic_handle_key_symlink_without_following_target(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            started = workers.browser_start(str(self.binary), port=9380, runtime_seconds=60)
        worker = started["worker"]
        config_path = Path(workers._row(worker["worker_id"])["config_path"])
        handle_key = config_path.parent / ".semantic-handle-key"
        target = self.root / "semantic-key-cleanup-target"
        target.write_text("preserve-me")
        handle_key.unlink()
        handle_key.symlink_to(target)

        with patch.object(workers.operator, "_run", return_value=result()):
            stopped = workers.worker_stop(worker["worker_id"], expected_kind="browser")

        self.assertFalse(handle_key.exists())
        self.assertEqual(target.read_text(), "preserve-me")
        terminalization = stopped["worker"]["last_observation"]["terminalization"]
        self.assertEqual(terminalization["cleanup"]["status"], "completed")
        self.assertIn(str(handle_key), terminalization["cleanup"]["removed"])

    def test_stop_removes_private_bidi_session_file(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            started = workers.browser_start(str(self.binary), port=9381, runtime_seconds=60)
        worker = started["worker"]
        config_path = Path(workers._row(worker["worker_id"])["config_path"])
        session_path = workers._write_private_worker_json(
            config_path.parent,
            workers.BROWSER_BIDI_SESSION_NAME,
            {"schema_version": 1, "session_id": "dead-session"},
        )
        self.assertTrue(session_path.is_file())

        with patch.object(workers.operator, "_run", return_value=result()):
            stopped = workers.worker_stop(worker["worker_id"], expected_kind="browser")

        self.assertFalse(session_path.exists())
        terminalization = stopped["worker"]["last_observation"]["terminalization"]
        self.assertEqual(terminalization["cleanup"]["status"], "completed")
        self.assertIn(str(session_path), terminalization["cleanup"]["removed"])

    def test_stopped_status_reconciles_legacy_bidi_session_file(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            started = workers.browser_start(str(self.binary), port=9384, runtime_seconds=60)
        worker = started["worker"]
        with patch.object(workers.operator, "_run", return_value=result()):
            stopped = workers.worker_stop(worker["worker_id"], expected_kind="browser")
        self.assertEqual(stopped["worker"]["state"], "stopped")
        record = workers._row(worker["worker_id"])
        session_path = workers._write_private_worker_json(
            Path(record["config_path"]).parent,
            workers.BROWSER_BIDI_SESSION_NAME,
            {"schema_version": 1, "session_id": "legacy-dead-session"},
        )
        self.assertTrue(session_path.is_file())

        reconciled = workers.worker_status(worker["worker_id"], expected_kind="browser")

        self.assertEqual(reconciled["state"], "stopped")
        self.assertFalse(session_path.exists())
        terminalization = reconciled["last_observation"]["terminalization"]
        self.assertEqual(terminalization["cleanup"]["status"], "completed")
        private_cleanup = terminalization["private_session_cleanup"]
        self.assertEqual(private_cleanup["status"], "completed")
        self.assertIn(str(session_path), private_cleanup["removed"])

    def test_completed_status_reconciles_legacy_bidi_session_file(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            started = workers.browser_start(str(self.binary), port=9385, runtime_seconds=60)
        worker = started["worker"]
        with patch.object(workers.operator, "_run", return_value=result()):
            stopped = workers.worker_stop(worker["worker_id"], expected_kind="browser")
        record = workers._row(worker["worker_id"])
        terminal_observation = json.loads(record["last_observation_json"])
        workers._update(worker["worker_id"], "completed", observation=terminal_observation)
        record = workers._row(worker["worker_id"])
        session_path = workers._write_private_worker_json(
            Path(record["config_path"]).parent,
            workers.BROWSER_BIDI_SESSION_NAME,
            {"schema_version": 1, "session_id": "legacy-completed-session"},
        )
        self.assertTrue(session_path.is_file())

        reconciled = workers.worker_status(worker["worker_id"], expected_kind="browser")

        self.assertEqual(reconciled["state"], "completed")
        self.assertFalse(session_path.exists())
        terminalization = reconciled["last_observation"]["terminalization"]
        self.assertEqual(terminalization["cleanup"]["status"], "completed")
        private_cleanup = terminalization["private_session_cleanup"]
        self.assertEqual(private_cleanup["status"], "completed")
        self.assertIn(str(session_path), private_cleanup["removed"])

    def test_failed_status_private_cleanup_retry_preserves_terminal_state(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            started = workers.browser_start(str(self.binary), port=9387, runtime_seconds=60)
        worker = started["worker"]
        with patch.object(workers.operator, "_run", return_value=result()):
            workers.worker_stop(worker["worker_id"], expected_kind="browser")
        record = workers._row(worker["worker_id"])
        terminal_observation = json.loads(record["last_observation_json"])
        workers._update(worker["worker_id"], "failed", observation=terminal_observation)
        record = workers._row(worker["worker_id"])
        session_path = Path(record["config_path"]).parent / workers.BROWSER_BIDI_SESSION_NAME
        session_path.mkdir()

        with patch.object(
            workers.operator,
            "_run",
            side_effect=AssertionError("settled cleanup retry must not reprobe systemd"),
        ):
            first = workers.worker_status(worker["worker_id"], expected_kind="browser")
            second = workers.worker_status(worker["worker_id"], expected_kind="browser")

        self.assertEqual(first["state"], "failed")
        self.assertEqual(second["state"], "failed")
        self.assertTrue(session_path.is_dir())
        for current in (first, second):
            terminalization = current["last_observation"]["terminalization"]
            self.assertEqual(terminalization["cleanup"]["status"], "completed")
            self.assertEqual(
                terminalization["private_session_cleanup"]["status"], "partial"
            )

    def test_stop_unlinks_bidi_session_symlink_without_following_target(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            started = workers.browser_start(str(self.binary), port=9382, runtime_seconds=60)
        worker = started["worker"]
        config_path = Path(workers._row(worker["worker_id"])["config_path"])
        session_path = config_path.parent / workers.BROWSER_BIDI_SESSION_NAME
        target = self.root / "bidi-session-cleanup-target"
        target.write_text("preserve-me", encoding="utf-8")
        session_path.symlink_to(target)

        with patch.object(workers.operator, "_run", return_value=result()):
            stopped = workers.worker_stop(worker["worker_id"], expected_kind="browser")

        self.assertFalse(session_path.exists())
        self.assertEqual(target.read_text(encoding="utf-8"), "preserve-me")
        terminalization = stopped["worker"]["last_observation"]["terminalization"]
        self.assertEqual(terminalization["cleanup"]["status"], "completed")
        self.assertIn(str(session_path), terminalization["cleanup"]["removed"])

    def test_stop_removes_semantic_temp_files_but_preserves_symlinks(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            started = workers.browser_start(
                str(self.binary), port=9383, runtime_seconds=60
            )
        worker = started["worker"]
        config_path = Path(workers._row(worker["worker_id"])["config_path"])
        directory = config_path.parent
        request_temp = directory / (".browser-semantic-" + "a" * 32 + ".json")
        script_temp = directory / (".browser-semantic-" + "b" * 32 + ".mjs")
        symlink_target = self.root / "semantic-temp-cleanup-target"
        symlink_temp = directory / (".browser-semantic-" + "c" * 32 + ".json")
        unrelated = directory / ".browser-semantic-not-a-token.json"
        group_readable = directory / (".browser-semantic-" + "d" * 32 + ".json")
        # The adapter creates these through _write_private_action_file at 0o600;
        # cleanup only removes files that still carry exactly that private mode.
        workers._write_private_action_file(request_temp, "private-request")
        workers._write_private_action_file(script_temp, "private-script")
        symlink_target.write_text("preserve-me", encoding="utf-8")
        symlink_temp.symlink_to(symlink_target)
        unrelated.write_text("preserve-unrelated", encoding="utf-8")
        workers._write_private_action_file(group_readable, "not-ours")
        group_readable.chmod(0o644)

        with patch.object(workers.operator, "_run", return_value=result()):
            stopped = workers.worker_stop(
                worker["worker_id"], expected_kind="browser"
            )

        self.assertFalse(request_temp.exists())
        self.assertFalse(script_temp.exists())
        self.assertTrue(symlink_temp.is_symlink())
        self.assertEqual(symlink_target.read_text(encoding="utf-8"), "preserve-me")
        self.assertEqual(unrelated.read_text(encoding="utf-8"), "preserve-unrelated")
        self.assertEqual(group_readable.read_text(encoding="utf-8"), "not-ours")
        cleanup = stopped["worker"]["last_observation"]["terminalization"]["cleanup"]
        self.assertIn(str(request_temp), cleanup["removed"])
        self.assertIn(str(script_temp), cleanup["removed"])
        self.assertIn(str(symlink_temp), cleanup["preserved_evidence"])
        self.assertIn(str(group_readable), cleanup["preserved_evidence"])

    def test_semantic_temp_cleanup_treats_missing_instance_directory_as_clean(self) -> None:
        missing = self.root / "missing-worker-instance"
        removed, preserved, errors = workers._cleanup_browser_semantic_temps(missing)
        self.assertEqual(removed, [])
        self.assertEqual(preserved, [])
        self.assertEqual(errors, [])

    def test_stop_converges_when_browser_instance_directory_is_already_absent(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            started = workers.browser_start(
                str(self.binary), port=9386, runtime_seconds=60
            )
        worker = started["worker"]
        record = workers._row(worker["worker_id"])
        instance_directory = Path(record["config_path"]).parent
        shutil.rmtree(instance_directory)

        with patch.object(workers.operator, "_run", return_value=result()):
            stopped = workers.worker_stop(
                worker["worker_id"], expected_kind="browser"
            )

        terminalization = stopped["worker"]["last_observation"]["terminalization"]
        self.assertEqual(terminalization["cleanup"]["status"], "completed")
        self.assertIn(
            str(instance_directory / ".semantic-handle-key"),
            terminalization["cleanup"]["already_absent"],
        )
        self.assertEqual(terminalization["unit_reset"]["status"], "not-required")
        self.assertEqual(workers.worker_list("browser", limit=10)["count"], 0)

    def test_stopped_status_preserves_explicit_state_over_timeout_evidence(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            started = workers.browser_start(str(self.binary), port=9351, runtime_seconds=60)
        worker_id = started["worker"]["worker_id"]
        timeout_probe = result(
            stdout=(
                "LoadState=loaded\nActiveState=failed\nSubState=failed\n"
                "Result=timeout\nExecMainStatus=0\n"
            )
        )
        with patch.object(workers.operator, "_run", return_value=timeout_probe):
            failed = workers.worker_status(worker_id, expected_kind="browser")
        self.assertEqual(failed["state"], "failed")

        with patch.object(workers.operator, "_run", return_value=result()):
            stopped = workers.worker_stop(worker_id, expected_kind="browser")
        self.assertEqual(stopped["worker"]["state"], "stopped")
        prior = stopped["worker"]["last_observation"]["prior_observation"]
        self.assertEqual(prior["state"], "failed")
        self.assertEqual(prior["properties"]["Result"], "timeout")

        with patch.object(
            workers, "_observe", side_effect=AssertionError("stopped status must not probe systemd")
        ):
            readback = workers.worker_status(worker_id, expected_kind="browser")
        self.assertEqual(readback["state"], "stopped")
        self.assertEqual(
            readback["last_observation"]["terminalization"]["release"]["status"],
            "already-absent",
        )
        self.assertEqual(
            readback["last_observation"]["prior_observation"]["properties"]["Result"],
            "timeout",
        )
        with patch.object(workers.operator, "_run", return_value=result()):
            repeated = workers.worker_stop(worker_id, expected_kind="browser")
        repeated_prior = repeated["worker"]["last_observation"]["prior_observation"]
        self.assertEqual(repeated_prior["state"], "failed")
        self.assertEqual(repeated_prior["properties"]["Result"], "timeout")
        self.assertEqual(workers.worker_list("browser", limit=10)["count"], 0)
        history = workers.worker_list("browser", limit=10, view="history")
        self.assertEqual(history["count"], 1)
        self.assertEqual(history["workers"][0]["state"], "stopped")

    def test_stopped_status_terminalizes_legacy_record_without_observation(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            started = workers.browser_start(str(self.binary), port=9353, runtime_seconds=60)
        worker = started["worker"]
        workers._update(worker["worker_id"], "stopped")
        not_failed_probe = result(
            stdout=(
                "LoadState=loaded\nActiveState=inactive\nSubState=dead\n"
            )
        )

        with patch.object(
            workers, "_observe", side_effect=AssertionError("legacy stopped status must not use full worker probe")
        ), patch.object(workers.operator, "_run", return_value=not_failed_probe) as run:
            reconciled = workers.worker_status(worker["worker_id"], expected_kind="browser")
        self.assertEqual(reconciled["state"], "stopped")
        terminalization = reconciled["last_observation"]["terminalization"]
        self.assertEqual(terminalization["release"]["status"], "released")
        self.assertEqual(terminalization["cleanup"]["status"], "completed")
        self.assertEqual(terminalization["unit_reset"]["status"], "not-required")
        self.assertEqual(run.call_count, 1)
        self.assertEqual(
            run.call_args.args[0],
            [
                "systemctl",
                "--user",
                "show",
                worker["unit"],
                "--no-pager",
                "--property=LoadState",
                "--property=ActiveState",
                "--property=SubState",
            ],
        )
        self.assertIsNone(workers.resources.inspect_resource("port:9353"))
        self.assertEqual(workers.worker_list("browser", limit=10)["count"], 0)

    def test_stopped_status_migrates_legacy_failed_unit_with_exact_probe(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            started = workers.browser_start(str(self.binary), port=9354, runtime_seconds=60)
        worker = started["worker"]
        record = workers._row(worker["worker_id"])
        terminalization = {
            "release": workers._release(record),
            "cleanup": workers._cleanup(record),
        }
        workers._update(
            worker["worker_id"],
            "stopped",
            observation={
                "state": "stopped",
                "stop": result(),
                "observed_at_unix": 123456,
                "terminalization": terminalization,
            },
        )
        failed_probe = result(
            stdout=(
                "LoadState=loaded\nActiveState=failed\nSubState=failed\n"
            )
        )
        with patch.object(
            workers, "_observe", side_effect=AssertionError("legacy stopped migration must not use full worker probe")
        ), patch.object(
            workers.operator, "_run", side_effect=[failed_probe, result()]
        ) as run:
            migrated = workers.worker_status(
                worker["worker_id"], expected_kind="browser"
            )
        self.assertEqual(run.call_count, 2)
        self.assertEqual(
            run.call_args_list[0].args[0],
            [
                "systemctl",
                "--user",
                "show",
                worker["unit"],
                "--no-pager",
                "--property=LoadState",
                "--property=ActiveState",
                "--property=SubState",
            ],
        )
        self.assertEqual(
            run.call_args_list[1].args[0],
            ["systemctl", "--user", "reset-failed", worker["unit"]],
        )
        unit_reset = migrated["last_observation"]["terminalization"]["unit_reset"]
        self.assertEqual(unit_reset["status"], "reset")
        self.assertEqual(unit_reset["probe"]["status"], "failed")
        self.assertEqual(workers.worker_list("browser", limit=10)["count"], 0)

    def test_stopped_status_retries_incomplete_terminalization_without_full_probe(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            started = workers.browser_start(str(self.binary), port=9352, runtime_seconds=60)
        worker = started["worker"]
        owner = f"worker:{worker['worker_id']}"
        workers.resources.release_resources(owner, ["port:9352"])
        workers.resources.acquire_resources(
            "foreign-owner",
            ["port:9352"],
            purpose="foreign replacement",
            ttl_seconds=60,
        )
        with patch.object(workers.operator, "_run", return_value=result()):
            stopped = workers.worker_stop(worker["worker_id"], expected_kind="browser")
        self.assertEqual(stopped["worker"]["state"], "stopped")
        self.assertEqual(
            stopped["worker"]["last_observation"]["terminalization"]["release"]["status"],
            "partial",
        )
        current = workers.worker_list("browser", limit=10)
        self.assertEqual(current["count"], 1)
        self.assertEqual(
            current["workers"][0]["projection"]["reason"],
            "terminalization-incomplete",
        )

        workers.resources.release_resources("foreign-owner", ["port:9352"])
        not_failed_probe = result(
            stdout=(
                "LoadState=loaded\nActiveState=inactive\nSubState=dead\n"
            )
        )
        with patch.object(
            workers, "_observe", side_effect=AssertionError("stopped retry must not use full worker probe")
        ), patch.object(workers.operator, "_run", return_value=not_failed_probe) as run:
            reconciled = workers.worker_status(worker["worker_id"], expected_kind="browser")
        self.assertEqual(run.call_count, 1)
        self.assertEqual(reconciled["state"], "stopped")
        self.assertEqual(
            reconciled["last_observation"]["terminalization"]["unit_reset"]["status"],
            "not-required",
        )
        self.assertEqual(workers.worker_list("browser", limit=10)["count"], 0)

    def _running_observation(self) -> dict[str, object]:
        return {
            "state": "running",
            "properties": {},
            "probe": result(),
            "observed_at_unix": 1,
        }

    @staticmethod
    def _semantic_link(
        *,
        name: str = "Next",
        target: str = "https://example.invalid/next",
        backend_node_id: str = "101",
    ) -> dict[str, object]:
        return {
            "backend_node_id": backend_node_id,
            "role": "link",
            "name": name,
            "navigation_target_sha256": hashlib.sha256(target.encode("utf-8")).hexdigest(),
        }

    def _semantic_state_payload(
        self,
        *,
        origin: str = "http://device.home.arpa",
        ready_state: str = "complete",
        title: str = "Example Domain",
        main_frame_id: str = "frame-1",
        loader_id: str = "loader-1",
        navigation_entry_id: str = "entry-1",
        elements: list[dict[str, object]] | None = None,
    ) -> dict[str, object]:
        if elements is None:
            elements = [
                {
                    "backend_node_id": "101",
                    "role": "button",
                    "name": "Target",
                }
            ]
        return {
            "schema_version": 1,
            "ok": True,
            "result_code": "ok",
            "state": {
                "origin": origin,
                "ready_state": ready_state,
                "title": title,
                "main_frame_id": main_frame_id,
                "loader_id": loader_id,
                "navigation_entry_id": navigation_entry_id,
                "elements": elements,
            },
        }

    def test_browser_semantic_node_runner_isolates_v8_write_execute_from_operator(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            worker = workers.browser_start(
                str(self.binary), port=9280, args=["--headless=new"], runtime_seconds=60
            )["worker"]
        record = workers._row(worker["worker_id"])
        fake_target = self.root / "heim-node-tool"
        fake_target.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        fake_target.chmod(0o755)
        fake_node = self.root / "node"
        fake_node.symlink_to(fake_target)
        payload = self._semantic_state_payload()
        with patch.object(workers.shutil, "which", return_value=str(fake_node)), patch.object(
            workers.operator,
            "_run",
            return_value=result(stdout=json.dumps(payload) + "\n"),
        ) as run:
            observed = workers._run_node_browser_semantic(
                record,
                {
                    "schema_version": 1,
                    "port": 9280,
                    "timeout_ms": 10_000,
                    "op": "read_state",
                },
                timeout_seconds=10,
            )
        self.assertEqual(observed, payload)
        launch = run.call_args.args[0]
        self.assertEqual(
            launch[:7],
            [
                "systemd-run",
                "--user",
                "--quiet",
                "--wait",
                "--collect",
                "--pipe",
                "--same-dir",
            ],
        )
        self.assertIn("--slice=grabowski-workers.slice", launch)
        self.assertIn("--property=NoNewPrivileges=yes", launch)
        self.assertIn("--property=ProtectSystem=full", launch)
        self.assertIn("--property=ProtectHome=read-only", launch)
        self.assertIn("--property=PrivateTmp=yes", launch)
        self.assertIn("--property=MemoryDenyWriteExecute=no", launch)
        self.assertIn(
            "--property=RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6", launch
        )
        self.assertIn("--property=RuntimeMaxSec=15s", launch)
        self.assertIn("--property=MemoryMax=512M", launch)
        separator = launch.index("--")
        child = launch[separator + 1 :]
        self.assertEqual(
            child[:5],
            [
                "/usr/bin/env",
                "-i",
                "PATH=/usr/bin:/bin",
                "LANG=C.UTF-8",
                str(fake_node),
            ],
        )
        self.assertNotIn(str(fake_target.resolve()), child[:5])
        self.assertTrue(child[-2].endswith(".mjs"))
        self.assertTrue(child[-1].endswith(".json"))
        self.assertFalse(Path(child[-2]).exists())
        self.assertFalse(Path(child[-1]).exists())

    def test_browser_semantic_node_runner_no_receipt_exposes_only_runner_status(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            worker = workers.browser_start(str(self.binary), port=9281, runtime_seconds=60)[
                "worker"
            ]
        record = workers._row(worker["worker_id"])
        fake_node = self.root / "node-no-receipt"
        fake_node.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        fake_node.chmod(0o755)
        failed = result(returncode=-5)
        failed["stderr"] = "sensitive low-level V8 diagnostic"
        with patch.object(workers.shutil, "which", return_value=str(fake_node)), patch.object(
            workers.operator, "_run", return_value=failed
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                r"runner_returncode=-5, runner_timed_out=false",
            ) as raised:
                workers._run_node_browser_semantic(
                    record,
                    {
                        "schema_version": 1,
                        "port": 9281,
                        "timeout_ms": 10_000,
                        "op": "read_state",
                    },
                    timeout_seconds=10,
                )
        self.assertNotIn("sensitive low-level V8 diagnostic", str(raised.exception))

    def test_browser_semantic_snapshot_id_is_deterministic_and_dom_bound(self) -> None:
        handle_key = b"k" * 32
        state = workers._bounded_browser_state(
            {
                "origin": "http://device.home.arpa",
                "ready_state": "complete",
                "title": "Example",
                "main_frame_id": "frame-1",
                "loader_id": "loader-1",
                "elements": [
                    {
                        "backend_node_id": "101",
                        "role": "button",
                        "name": "Target",
                    }
                ],
            }
        )
        first = workers._browser_snapshot_id("worker-a", state, handle_key)
        second = workers._browser_snapshot_id("worker-a", state, handle_key)
        self.assertEqual(first, second)
        self.assertTrue(workers._is_browser_snapshot_id(first))
        self.assertTrue(first.startswith(workers.BROWSER_SNAPSHOT_ID_PREFIX))

        reloaded_state = {**state, "loader_id": "loader-2"}
        self.assertNotEqual(
            first, workers._browser_snapshot_id("worker-a", reloaded_state, handle_key)
        )
        same_document_state = {**state, "navigation_entry_id": "entry-2"}
        self.assertNotEqual(
            first,
            workers._browser_snapshot_id(
                "worker-a", same_document_state, handle_key
            ),
        )
        self.assertNotEqual(
            first, workers._browser_snapshot_id("worker-b", state, handle_key)
        )
        self.assertNotEqual(
            first, workers._browser_snapshot_id("worker-a", state, b"q" * 32)
        )
        changed_dom = {
            **state,
            "elements": [{**state["elements"][0], "name": "Changed target"}],
        }
        self.assertNotEqual(
            first, workers._browser_snapshot_id("worker-a", changed_dom, handle_key)
        )

    def test_browser_semantic_link_target_digest_is_snapshot_and_handle_bound(self) -> None:
        handle_key = b"k" * 32
        first_element = self._semantic_link(
            name="Issues", target="https://example.invalid/issues"
        )
        second_element = self._semantic_link(
            name="Issues", target="https://example.invalid/pulls"
        )
        base = self._semantic_state_payload(elements=[first_element])["state"]
        changed = self._semantic_state_payload(elements=[second_element])["state"]
        first_state = workers._bounded_browser_state(base)
        changed_state = workers._bounded_browser_state(changed)
        first_snapshot = workers._browser_snapshot_id(
            "worker-a", first_state, handle_key
        )
        changed_snapshot = workers._browser_snapshot_id(
            "worker-a", changed_state, handle_key
        )
        self.assertNotEqual(first_snapshot, changed_snapshot)
        first_handle = workers._browser_element_id(
            "worker-a", first_snapshot, first_state["elements"][0], handle_key
        )
        changed_handle = workers._browser_element_id(
            "worker-a", changed_snapshot, changed_state["elements"][0], handle_key
        )
        self.assertNotEqual(first_handle, changed_handle)
        public = workers._browser_observation("worker-a", first_state, handle_key)
        rendered = json.dumps(public, sort_keys=True)
        self.assertNotIn("navigation_target_sha256", rendered)
        self.assertNotIn("example.invalid", rendered)

    def test_browser_semantic_element_id_is_keyed_snapshot_and_worker_bound(self) -> None:
        handle_key = b"k" * 32
        state = workers._bounded_browser_state(
            self._semantic_state_payload()["state"]
        )
        snapshot_id = workers._browser_snapshot_id("worker-a", state, handle_key)
        element = state["elements"][0]
        first = workers._browser_element_id(
            "worker-a", snapshot_id, element, handle_key
        )
        second = workers._browser_element_id(
            "worker-a", snapshot_id, element, handle_key
        )
        self.assertEqual(first, second)
        self.assertTrue(workers._is_browser_element_id(first))
        self.assertTrue(first.startswith(workers.BROWSER_ELEMENT_ID_PREFIX))
        self.assertNotEqual(
            first,
            workers._browser_element_id(
                "worker-b", snapshot_id, element, handle_key
            ),
        )
        self.assertNotEqual(
            first,
            workers._browser_element_id(
                "worker-a", snapshot_id, element, b"q" * 32
            ),
        )
        changed_state = {
            **state,
            "elements": [{**element, "name": "Changed target"}],
        }
        changed_snapshot_id = workers._browser_snapshot_id(
            "worker-a", changed_state, handle_key
        )
        self.assertNotEqual(
            first,
            workers._browser_element_id(
                "worker-a",
                changed_snapshot_id,
                changed_state["elements"][0],
                handle_key,
            ),
        )

    def test_browser_semantic_handle_key_is_private_per_worker(self) -> None:
        worker_a = self._running_browser(port=9358)
        worker_b = self._running_browser(port=9359)
        record_a = workers._row(worker_a["worker_id"])
        record_b = workers._row(worker_b["worker_id"])
        key_a = workers._browser_semantic_handle_key(record_a)
        key_b = workers._browser_semantic_handle_key(record_b)
        self.assertEqual(len(key_a), 32)
        self.assertEqual(len(key_b), 32)
        self.assertNotEqual(key_a, key_b)
        key_path = Path(record_a["config_path"]).parent / ".semantic-handle-key"
        self.assertEqual(stat.S_IMODE(key_path.stat().st_mode), 0o600)
        rendered = json.dumps(worker_a)
        self.assertNotIn(key_a.hex(), rendered)

    def test_browser_semantic_handle_key_rejects_hard_link(self) -> None:
        worker = self._running_browser(port=9356)
        record = workers._row(worker["worker_id"])
        key_path = Path(record["config_path"]).parent / ".semantic-handle-key"
        linked_path = key_path.with_name(".semantic-handle-key-link")
        os.link(key_path, linked_path)
        try:
            with self.assertRaisesRegex(PermissionError, "metadata is unsafe"):
                workers._browser_semantic_handle_key(record)
        finally:
            linked_path.unlink()

    def test_browser_semantic_legacy_worker_without_handle_key_fails_before_transport(self) -> None:
        worker = self._running_browser(port=9357)
        record = workers._row(worker["worker_id"])
        key_path = Path(record["config_path"]).parent / ".semantic-handle-key"
        key_path.unlink()
        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(workers, "_run_node_browser_semantic") as run:
            with self.assertRaisesRegex(
                RuntimeError, "predates semantic handle keys; start a fresh browser worker"
            ):
                workers.browser_semantic_observe(worker["worker_id"])
        run.assert_not_called()

    def test_browser_semantic_gateway_legacy_worker_preserves_fresh_worker_diagnostic(self) -> None:
        worker = self._running_browser(port=9376)
        record = workers._row(worker["worker_id"])
        key_path = Path(record["config_path"]).parent / ".semantic-handle-key"
        key_path.unlink()
        with patch.object(
            workers.operator, "_require_operator_capability"
        ), patch.object(
            workers.operator, "_require_operator_mutation"
        ) as require_mutation, patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic"
        ) as run, patch.object(
            workers.base, "_append_audit_with_digest", return_value="a" * 64
        ) as append_audit:
            outcome = workers.grabowski_browser_worker_semantic(
                worker["worker_id"], "observe"
            )

        self.assertFalse(outcome["ok"])
        self.assertEqual(outcome["result_code"], "fresh_worker_required")
        self.assertEqual(outcome["effect_state"], "not_applicable")
        self.assertFalse(outcome["retry_readback"]["retry_authorized"])
        self.assertEqual(
            outcome["retry_readback"]["authoritative_readback_state"],
            "unavailable",
        )
        require_mutation.assert_not_called()
        run.assert_not_called()
        self.assertEqual(append_audit.call_count, 1)

    def test_browser_semantic_gateway_legacy_worker_act_is_not_outcome_unknown(self) -> None:
        worker = self._running_browser(port=9377)
        record = workers._row(worker["worker_id"])
        key_path = Path(record["config_path"]).parent / ".semantic-handle-key"
        key_path.unlink()
        snapshot_id = workers.BROWSER_SNAPSHOT_ID_PREFIX + "a" * 64
        element_id = workers.BROWSER_ELEMENT_ID_PREFIX + "b" * 64
        with patch.object(
            workers.operator, "_require_operator_capability"
        ), patch.object(
            workers.operator, "_require_operator_mutation"
        ) as require_mutation, patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic"
        ) as run, patch.object(
            workers.base,
            "_append_audit_with_digest",
            side_effect=["a" * 64, "b" * 64],
        ) as append_audit:
            outcome = workers.grabowski_browser_worker_semantic(
                worker["worker_id"],
                "act",
                snapshot_id=snapshot_id,
                action_kind="scroll_into_view",
                element_id=element_id,
            )

        self.assertFalse(outcome["ok"])
        self.assertEqual(outcome["result_code"], "fresh_worker_required")
        self.assertEqual(outcome["effect_state"], "not_started")
        self.assertFalse(outcome["retry_readback"]["retry_authorized"])
        self.assertFalse(
            outcome["retry_readback"]["authoritative_readback_required"]
        )
        require_mutation.assert_called_once_with("browser_worker")
        run.assert_not_called()
        self.assertEqual(append_audit.call_count, 2)

    def test_browser_semantic_gateway_legacy_worker_navigate_preserves_fresh_worker_diagnostic(self) -> None:
        worker = self._running_browser(port=9378)
        record = workers._row(worker["worker_id"])
        key_path = Path(record["config_path"]).parent / ".semantic-handle-key"
        key_path.unlink()
        snapshot_id = workers.BROWSER_SNAPSHOT_ID_PREFIX + "a" * 64
        navigation_target = "https://example.test/next?token=secret-value"
        with patch.object(
            workers.operator, "_require_operator_capability"
        ), patch.object(
            workers.operator, "_require_operator_mutation"
        ) as require_mutation, patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic"
        ) as run, patch.object(
            workers.base, "_append_audit_with_digest", return_value="a" * 64
        ) as append_audit:
            outcome = workers.grabowski_browser_worker_semantic(
                worker["worker_id"],
                "act",
                snapshot_id=snapshot_id,
                action_kind="navigate",
                navigation_target=navigation_target,
            )

        self.assertFalse(outcome["ok"])
        self.assertEqual(outcome["result_code"], "fresh_worker_required")
        self.assertEqual(outcome["effect_state"], "not_started")
        self.assertFalse(outcome["retry_readback"]["retry_authorized"])
        self.assertFalse(
            outcome["retry_readback"]["authoritative_readback_required"]
        )
        require_mutation.assert_called_once_with("browser_worker")
        run.assert_not_called()
        self.assertEqual(append_audit.call_count, 1)
        self.assertNotIn(navigation_target, repr(outcome))
        self.assertNotIn("secret-value", repr(outcome))

    def test_browser_semantic_observe_bounds_and_redacts_element_projection(self) -> None:
        worker = self._running_browser(port=9360)
        raw_elements = [
            {
                "backend_node_id": str(index + 1),
                "role": "button",
                "name": ("  Target   " + str(index) + "  ") * 40,
                "selector": f"#target-{index}",
                "value": "credential-value-must-not-leak",
                "html": "<button>secret</button>",
            }
            for index in range(100)
        ]
        payload = self._semantic_state_payload(elements=raw_elements)
        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(workers, "_update") as update, patch.object(
            workers, "_run_node_browser_semantic", return_value=payload
        ) as run:
            observation = workers.browser_semantic_observe(worker["worker_id"])
        self.assertEqual(observation["schema_version"], 1)
        self.assertEqual(observation["worker_id"], worker["worker_id"])
        self.assertTrue(workers._is_browser_snapshot_id(observation["snapshot_id"]))
        self.assertEqual(observation["origin"], "http://device.home.arpa")
        self.assertEqual(observation["ready_state"], "complete")
        self.assertEqual(len(observation["elements"]), workers.BROWSER_MAX_ELEMENTS)
        for element in observation["elements"]:
            self.assertEqual(set(element), {"element_id", "role", "name"})
            self.assertTrue(workers._is_browser_element_id(element["element_id"]))
            self.assertLessEqual(len(element["role"]), workers.BROWSER_ELEMENT_ROLE_MAX)
            self.assertLessEqual(len(element["name"]), workers.BROWSER_ELEMENT_NAME_MAX)
        self.assertNotIn("main_frame_id", observation)
        self.assertNotIn("loader_id", observation)
        rendered = json.dumps(observation)
        for hidden_term in (
            "backend_node_id",
            "selector",
            "credential-value-must-not-leak",
            "<button>secret</button>",
            "Runtime.evaluate",
            "Accessibility.getFullAXTree",
            "DOM.resolveNode",
        ):
            self.assertNotIn(hidden_term, rendered)
        run.assert_called_once()
        self.assertEqual(run.call_args.args[1]["op"], "read_state")
        self.assertNotIn("selector", run.call_args.args[1])
        update.assert_not_called()

    def test_browser_semantic_act_rejects_stale_snapshot_before_effect(self) -> None:
        worker = self._running_browser(port=9361)
        initial_payload = self._semantic_state_payload(title="Before")
        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=initial_payload
        ):
            observation = workers.browser_semantic_observe(worker["worker_id"])
        stale_snapshot_id = observation["snapshot_id"]
        element_id = observation["elements"][0]["element_id"]

        changed_payload = self._semantic_state_payload(title="After navigation")
        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=changed_payload
        ) as run:
            outcome = workers.browser_semantic_act(
                worker["worker_id"],
                stale_snapshot_id,
                "scroll_into_view",
                element_id=element_id,
            )
        self.assertFalse(outcome["ok"])
        self.assertEqual(outcome["result_code"], "stale_snapshot")
        self.assertIsNone(outcome["post_action_snapshot_id"])
        self.assertEqual(outcome["requested_snapshot_id"], stale_snapshot_id)
        run.assert_called_once()
        self.assertEqual(run.call_args.args[1]["op"], "read_state")

    def test_browser_semantic_act_rejects_semantic_dom_drift_before_effect(self) -> None:
        worker = self._running_browser(port=9362)
        initial_payload = self._semantic_state_payload()
        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=initial_payload
        ):
            observation = workers.browser_semantic_observe(worker["worker_id"])
        changed_payload = self._semantic_state_payload(
            elements=[
                {
                    "backend_node_id": "101",
                    "role": "button",
                    "name": "Target changed in place",
                }
            ]
        )
        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=changed_payload
        ) as run:
            outcome = workers.browser_semantic_act(
                worker["worker_id"],
                observation["snapshot_id"],
                "scroll_into_view",
                element_id=observation["elements"][0]["element_id"],
            )
        self.assertFalse(outcome["ok"])
        self.assertEqual(outcome["result_code"], "stale_snapshot")
        run.assert_called_once()

    def test_browser_semantic_act_rejects_tampered_element_handle_before_effect(self) -> None:
        worker = self._running_browser(port=9363)
        payload = self._semantic_state_payload()
        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=payload
        ):
            observation = workers.browser_semantic_observe(worker["worker_id"])
        element_id = observation["elements"][0]["element_id"]
        replacement = "0" if element_id[-1] != "0" else "1"
        tampered = element_id[:-1] + replacement
        self.assertTrue(workers._is_browser_element_id(tampered))
        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=payload
        ) as run:
            outcome = workers.browser_semantic_act(
                worker["worker_id"],
                observation["snapshot_id"],
                "scroll_into_view",
                element_id=tampered,
            )
        self.assertFalse(outcome["ok"])
        self.assertEqual(outcome["result_code"], "element_contract")
        self.assertEqual(outcome["requested_element_id"], tampered)
        run.assert_called_once()

    def test_browser_semantic_act_rejects_cross_worker_element_replay(self) -> None:
        worker_a = self._running_browser(port=9364)
        worker_b = self._running_browser(port=9365)
        payload = self._semantic_state_payload()
        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=payload
        ):
            observation_a = workers.browser_semantic_observe(worker_a["worker_id"])
            observation_b = workers.browser_semantic_observe(worker_b["worker_id"])
        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=payload
        ) as run:
            outcome = workers.browser_semantic_act(
                worker_b["worker_id"],
                observation_b["snapshot_id"],
                "scroll_into_view",
                element_id=observation_a["elements"][0]["element_id"],
            )
        self.assertFalse(outcome["ok"])
        self.assertEqual(outcome["result_code"], "element_contract")
        run.assert_called_once()

    def test_browser_semantic_act_local_ui_scroll_uses_only_opaque_element_id(self) -> None:
        worker = self._running_browser(port=9366)
        pre_payload = self._semantic_state_payload(title="Steady")
        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=pre_payload
        ):
            observation = workers.browser_semantic_observe(worker["worker_id"])
        snapshot_id = observation["snapshot_id"]
        element_id = observation["elements"][0]["element_id"]

        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers,
            "_run_node_browser_semantic",
            side_effect=[pre_payload, pre_payload],
        ) as run:
            outcome = workers.browser_semantic_act(
                worker["worker_id"],
                snapshot_id,
                "scroll_into_view",
                element_id=element_id,
            )
        self.assertTrue(outcome["ok"])
        self.assertEqual(outcome["result_code"], "ok")
        self.assertEqual(outcome["effect_class"], "local_ui")
        self.assertEqual(outcome["requested_element_id"], element_id)
        self.assertEqual(outcome["pre_action_snapshot_id"], snapshot_id)
        self.assertEqual(outcome["post_action_snapshot_id"], snapshot_id)
        self.assertIn("credential_handling_safety", outcome["does_not_establish"])
        self.assertEqual(run.call_count, 2)
        effect_request = run.call_args_list[1].args[1]
        self.assertEqual(effect_request["op"], "scroll_into_view")
        self.assertNotIn("selector", effect_request)
        self.assertEqual(
            effect_request["expected_element"],
            workers._bounded_browser_state(pre_payload["state"])["elements"][0],
        )
        self.assertEqual(
            effect_request["expected_state"],
            workers._bounded_browser_state(pre_payload["state"]),
        )

    def test_browser_semantic_act_maps_adapter_element_toctou_to_stale_snapshot(self) -> None:
        worker = self._running_browser(port=9367)
        pre_payload = self._semantic_state_payload(title="Steady")
        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=pre_payload
        ):
            observation = workers.browser_semantic_observe(worker["worker_id"])
        stale_guard_payload = {
            "schema_version": 1,
            "ok": False,
            "result_code": "stale-snapshot",
            "state": None,
        }
        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers,
            "_run_node_browser_semantic",
            side_effect=[pre_payload, stale_guard_payload],
        ) as run:
            outcome = workers.browser_semantic_act(
                worker["worker_id"],
                observation["snapshot_id"],
                "scroll_into_view",
                element_id=observation["elements"][0]["element_id"],
            )
        self.assertFalse(outcome["ok"])
        self.assertEqual(outcome["result_code"], "stale_snapshot")
        self.assertEqual(run.call_count, 2)
        self.assertEqual(
            run.call_args_list[1].args[1]["expected_element"],
            workers._bounded_browser_state(pre_payload["state"])["elements"][0],
        )

    def test_browser_semantic_node_revalidates_element_without_public_selector(self) -> None:
        source = workers.BROWSER_SEMANTIC_NODE_SOURCE
        self.assertIn("Accessibility.getFullAXTree", source)
        self.assertIn("Accessibility.getPartialAXTree", source)
        self.assertIn("DOM.resolveNode", source)
        self.assertIn("Runtime.callFunctionOn", source)
        self.assertIn("Runtime.releaseObject", source)
        self.assertIn("Number.isSafeInteger", source)
        self.assertIn("async function readSemanticElementName", source)
        self.assertIn("function semanticDomAttribute", source)
        self.assertIn("function semanticDomRawAttribute", source)
        self.assertIn("Buffer.byteLength(value, 'utf8') > maxBytes", source)
        self.assertIn("function semanticDomTextSubtreeBlocked", source)
        self.assertIn("function semanticSnapshotString", source)
        self.assertIn("function semanticSnapshotNode", source)
        self.assertIn("function semanticSnapshotPathToTarget", source)
        self.assertIn("function semanticDomVisibilitySubtreeBlocked", source)
        self.assertIn("function semanticSnapshotHasHiddenAncestor", source)
        self.assertIn("function semanticDomValueBearingSubtreeBlocked", source)
        self.assertIn("function semanticSnapshotHasValueBearingAncestor", source)
        self.assertIn("semanticDomValueBearingSubtreeBlocked(node)", source)
        self.assertIn("function semanticSnapshotEffectiveContentEditable", source)
        self.assertIn("semanticDomRawAttribute(node, 'contenteditable', 64)", source)
        self.assertIn("if (value === 'false') return {ok: true, editable: false}", source)
        self.assertIn("function semanticFilterOpacityVisibility", source)
        self.assertIn("function semanticLayoutVisibility", source)
        self.assertIn("normalizedClipPath", source)
        self.assertIn("normalizedClip", source)
        self.assertIn("normalizedMaskImage", source)
        self.assertIn("function semanticOverflowClipping", source)
        self.assertIn("function semanticCssColorVisibility", source)
        self.assertIn("function semanticTextPaintVisibility", source)
        self.assertIn("current === targetIndex", source)
        self.assertIn("current === nodeIndex", source)
        self.assertIn("function semanticLayoutBoundsWithinClipping", source)
        self.assertIn("function semanticSnapshotBoundsWithinClippingAncestors", source)
        self.assertIn("function semanticSnapshotContentDocumentOwners", source)
        self.assertIn("function semanticSnapshotEmbeddingChainVisible", source)
        self.assertIn("contentDocumentIndex", source)
        self.assertIn("function semanticSnapshotTargetAncestorsLayoutVisible", source)
        self.assertIn("strings, layoutStyles[layoutIndex], current === targetIndex", source)
        self.assertIn("function semanticFrameIds", source)
        self.assertIn("async function readSemanticDesignModes", source)
        self.assertIn("Page.createIsolatedWorld", source)
        self.assertIn("worldName: 'grabowski-semantic-design-mode-v1'", source)
        self.assertIn("grantUniveralAccess: false", source)
        self.assertIn("contextId,", source)
        self.assertIn("expression: 'document.designMode'", source)
        self.assertIn("function semanticDesignModesAllOff", source)
        self.assertIn("async function captureSemanticVisibleSnapshot", source)
        self.assertIn("DOMSnapshot.captureSnapshot", source)
        self.assertIn("computedStyles: ['visibility', 'opacity', 'content-visibility', 'filter', 'clip-path', 'clip', 'overflow-x', 'overflow-y', 'color', '-webkit-text-fill-color', 'mask-image']", source)
        self.assertIn("includePaintOrder: false", source)
        self.assertIn("includeDOMRects: false", source)
        self.assertIn("function semanticVisibleTextFromSnapshot", source)
        self.assertIn("nodes.parentIndex", source)
        self.assertIn("layout.nodeIndex", source)
        self.assertIn("layout.styles", source)
        self.assertIn("layout.bounds", source)
        self.assertIn("layout.text", source)
        self.assertIn("function semanticLayoutBoundsVisibility", source)
        self.assertIn("parsed.box.width >= 0.5 && parsed.box.height >= 0.5", source)
        self.assertNotIn("function boundedSemanticDomText", source)
        self.assertIn("'input', 'textarea', 'select', 'option', 'optgroup', 'output', 'meter', 'progress'", source)
        self.assertIn("'textbox', 'searchbox', 'combobox', 'listbox', 'option', 'slider', 'spinbutton'", source)
        self.assertIn("'scrollbar', 'progressbar', 'meter'", source)
        self.assertIn("contentEditable.value.trim().toLowerCase() !== 'false'", source)
        self.assertIn(".toLowerCase().trim().split(/\\s+/).filter(Boolean)", source)
        self.assertIn("const rawRole = semanticDomRawAttribute(node, 'role', 512)", source)
        self.assertIn("if (!rawRole.valid) return true", source)
        self.assertIn("roleTokens.some((token) => valueBearingRoles.has(token))", source)
        self.assertIn("semanticDomRawAttribute(node, 'hidden', 64)", source)
        self.assertIn("semanticDomRawAttribute(node, 'aria-hidden', 64)", source)
        self.assertIn("semanticDomRawAttribute(node, 'inert', 64)", source)
        self.assertIn("if (semanticDomTextSubtreeBlocked(targetNode))", source)
        self.assertIn("if (semanticDomTextSubtreeBlocked(node))", source)
        self.assertIn("if (!visibility.visible)", source)
        name_reader = source[
            source.index("async function readSemanticElementName") :
            source.index("function sha256Text")
        ]
        self.assertIn("DOM.describeNode", name_reader)
        self.assertIn("depth: 0", name_reader)
        self.assertNotIn("depth: 6", name_reader)
        self.assertIn("node.localName === 'svg'", source)
        self.assertIn("node.backendNodeId !== backendNodeId", name_reader)
        self.assertNotIn("node.backendDOMNodeId !== backendNodeId", name_reader)
        self.assertIn("semanticDomAttribute(node, 'aria-label')", name_reader)
        self.assertIn("semanticDomAttribute(node, 'title')", name_reader)
        self.assertIn("semanticDomAttribute(node, 'placeholder')", name_reader)
        self.assertIn("candidates.find((candidate) => Boolean(candidate))", name_reader)
        self.assertIn("'button', 'link', 'tab', 'menuitem', 'treeitem', 'heading'", name_reader)
        self.assertNotIn("DOM.resolveNode", name_reader)
        self.assertNotIn("Runtime.callFunctionOn", name_reader)
        self.assertNotIn("attr('value')", source)
        self.assertGreaterEqual(source.count("await readSemanticElementName("), 2)
        self.assertNotIn("document.querySelector", source)
        verify = "const objectId = await verifyElementImmediately(expectedElement);"
        effect = "effect = await call('Runtime.callFunctionOn'"
        release = "await call('Runtime.releaseObject', {objectId});"
        self.assertIn(verify, source)
        self.assertIn(effect, source)
        self.assertIn(release, source)
        scroll_section = source.index("request.op === 'scroll_into_view'")
        verify_index = source.index(verify, scroll_section)
        effect_index = source.index(effect, scroll_section)
        release_index = source.index(release, scroll_section)
        self.assertLess(verify_index, effect_index)
        self.assertLess(effect_index, release_index)

    def test_browser_semantic_act_read_state_performs_no_separate_effect_call(self) -> None:
        worker = self._running_browser(port=9368)
        payload = self._semantic_state_payload(title="Read only")
        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=payload
        ):
            observation = workers.browser_semantic_observe(worker["worker_id"])
        snapshot_id = observation["snapshot_id"]

        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=payload
        ) as run:
            outcome = workers.browser_semantic_act(
                worker["worker_id"], snapshot_id, "read_state"
            )
        self.assertTrue(outcome["ok"])
        self.assertEqual(outcome["effect_class"], "read")
        self.assertIsNone(outcome["requested_element_id"])
        self.assertEqual(outcome["post_action_snapshot_id"], snapshot_id)
        run.assert_called_once()

    def test_browser_semantic_activate_requires_link_role_before_effect(self) -> None:
        worker = self._running_browser(port=9386)
        before = self._semantic_state_payload(title="Button page")
        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=before
        ):
            observation = workers.browser_semantic_observe(worker["worker_id"])

        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=before
        ) as run:
            outcome = workers.browser_semantic_act(
                worker["worker_id"],
                observation["snapshot_id"],
                "activate",
                element_id=observation["elements"][0]["element_id"],
            )

        self.assertFalse(outcome["ok"])
        self.assertEqual(outcome["result_code"], "element_contract")
        self.assertEqual(outcome["effect_class"], "network_navigation")
        self.assertEqual(outcome["effect_state"], "not_started")
        run.assert_called_once()
        self.assertEqual(run.call_args.args[1]["op"], "read_state")

    def test_browser_semantic_activate_link_uses_correlated_adapter_roundtrip(self) -> None:
        worker = self._running_browser(port=9387)
        link = self._semantic_link(name="Issues 20", target="https://github.com/heimgewebe/grabowski/issues")
        before = self._semantic_state_payload(
            title="Repository", loader_id="loader-before", elements=[link]
        )
        after = self._semantic_state_payload(
            origin="https://github.com",
            title="Issues",
            loader_id="loader-after",
            navigation_entry_id="entry-after",
            elements=[link],
        )
        after["navigation_correlation"] = "new-document"
        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=before
        ):
            observation = workers.browser_semantic_observe(worker["worker_id"])

        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", side_effect=[before, after]
        ) as run:
            outcome = workers.browser_semantic_act(
                worker["worker_id"],
                observation["snapshot_id"],
                "activate",
                element_id=observation["elements"][0]["element_id"],
            )

        self.assertTrue(outcome["ok"])
        self.assertEqual(outcome["effect_class"], "network_navigation")
        self.assertEqual(outcome["effect_state"], "observed")
        self.assertEqual(outcome["requested_element_id"], observation["elements"][0]["element_id"])
        self.assertIsNone(outcome["target_hmac_sha256"])
        self.assertNotEqual(outcome["post_action_snapshot_id"], observation["snapshot_id"])
        self.assertEqual([call.args[1]["op"] for call in run.call_args_list], ["read_state", "activate"])
        activation_request = run.call_args_list[1].args[1]
        self.assertNotIn("navigation_target", activation_request)
        self.assertEqual(activation_request["expected_element"]["role"], "link")
        self.assertEqual(activation_request["expected_state"], workers._bounded_browser_state(before["state"]))

    def test_browser_semantic_activate_adapter_stale_guard_is_not_started(self) -> None:
        worker = self._running_browser(port=9388)
        link = self._semantic_link()
        before = self._semantic_state_payload(elements=[link])
        stale = {
            "schema_version": 1,
            "ok": False,
            "result_code": "stale-snapshot",
            "state": None,
        }
        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=before
        ):
            observation = workers.browser_semantic_observe(worker["worker_id"])
        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", side_effect=[before, stale]
        ):
            outcome = workers.browser_semantic_act(
                worker["worker_id"],
                observation["snapshot_id"],
                "activate",
                element_id=observation["elements"][0]["element_id"],
            )
        self.assertFalse(outcome["ok"])
        self.assertEqual(outcome["result_code"], "stale_snapshot")
        self.assertEqual(outcome["effect_state"], "not_started")

    def test_browser_semantic_activate_uncorrelated_is_outcome_unknown(self) -> None:
        worker = self._running_browser(port=9389)
        link = self._semantic_link()
        before = self._semantic_state_payload(elements=[link])
        uncorrelated = {
            "schema_version": 1,
            "ok": False,
            "result_code": "navigation-uncorrelated",
            "state": None,
        }
        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=before
        ):
            observation = workers.browser_semantic_observe(worker["worker_id"])
        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", side_effect=[before, uncorrelated]
        ):
            outcome = workers.browser_semantic_act(
                worker["worker_id"],
                observation["snapshot_id"],
                "activate",
                element_id=observation["elements"][0]["element_id"],
            )
        self.assertFalse(outcome["ok"])
        self.assertEqual(outcome["result_code"], "outcome_unknown")
        self.assertEqual(outcome["effect_state"], "unknown")
        self.assertIsNone(outcome["post_action_snapshot_id"])

    def test_browser_semantic_node_activate_is_anchor_navigation_not_click(self) -> None:
        source = workers.BROWSER_SEMANTIC_NODE_SOURCE
        self.assertIn("request.op === 'activate'", source)
        self.assertIn("expected.role !== 'link'", source)
        self.assertIn("DOM.getDocument", source)
        self.assertIn("DOM.describeNode", source)
        self.assertIn("createHash", source)
        self.assertIn("navigation_target_sha256", source)
        self.assertIn("rawHref.includes(String.fromCharCode(92))", source)
        self.assertIn("performCorrelatedNavigation", source)
        link_start = source.index("async function readLinkNavigationTarget")
        link_end = source.index("async function performCorrelatedNavigation", link_start)
        link_source = source[link_start:link_end]
        self.assertNotIn("this.href", link_source)
        self.assertNotIn("Runtime.callFunctionOn", link_source)
        self.assertNotIn("this.click()", source)
        self.assertNotIn("dispatchEvent(new MouseEvent", source)

    def test_browser_semantic_navigate_requires_a_conservative_target(self) -> None:
        snapshot_id = workers.BROWSER_SNAPSHOT_ID_PREFIX + "a" * 64
        invalid_targets = (
            None,
            "",
            " example.com",
            "javascript:alert(1)",
            "file:///etc/passwd",
            "https://user:password@example.invalid/private",
            "https://example.invalid/path\nnext",
            "https://example.invalid:0/",
        )
        for target in invalid_targets:
            with self.subTest(target=target), self.assertRaises(ValueError):
                workers.browser_semantic_act(
                    "0" * 20,
                    snapshot_id,
                    "navigate",
                    navigation_target=target,
                )

    def test_browser_semantic_navigation_target_digest_is_worker_keyed(self) -> None:
        worker_a = self._running_browser(port=9384)
        worker_b = self._running_browser(port=9385)
        target = "https://private.invalid/path?secret=must-not-leak"
        record_a = workers._row(worker_a["worker_id"])
        record_b = workers._row(worker_b["worker_id"])

        digest_a = workers._browser_navigation_target_digest(
            worker_a["worker_id"],
            target,
            workers._browser_semantic_handle_key(record_a),
        )
        digest_b = workers._browser_navigation_target_digest(
            worker_b["worker_id"],
            target,
            workers._browser_semantic_handle_key(record_b),
        )

        self.assertRegex(digest_a, r"^[0-9a-f]{64}$")
        self.assertRegex(digest_b, r"^[0-9a-f]{64}$")
        self.assertNotEqual(digest_a, digest_b)
        self.assertNotIn(target, digest_a)
        self.assertNotIn(target, digest_b)

    def test_browser_semantic_adapter_selects_chrome_cdp_boundary(self) -> None:
        worker = self._running_browser(port=9382)
        record = workers._row(worker["worker_id"])

        adapter = workers._browser_semantic_adapter(record, timeout_seconds=10)

        self.assertIsInstance(adapter, workers.CDPAdapter)
        self.assertIsInstance(adapter, workers.ChromeCDPAdapter)

    def test_browser_semantic_navigate_uses_one_correlated_adapter_roundtrip(self) -> None:
        worker = self._running_browser(port=9378)
        before = self._semantic_state_payload(title="Before", loader_id="loader-before")
        after = self._semantic_state_payload(
            origin="https://example.invalid",
            title="After",
            loader_id="loader-after",
            navigation_entry_id="entry-after",
        )
        after["navigation_correlation"] = "new-document"
        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=before
        ):
            observation = workers.browser_semantic_observe(worker["worker_id"])

        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers,
            "_run_node_browser_semantic",
            side_effect=[before, after],
        ) as run:
            outcome = workers.browser_semantic_act(
                worker["worker_id"],
                observation["snapshot_id"],
                "navigate",
                navigation_target="https://example.invalid/path?view=semantic",
            )

        self.assertTrue(outcome["ok"])
        self.assertEqual(outcome["result_code"], "ok")
        self.assertEqual(outcome["effect_class"], "network_navigation")
        self.assertEqual(outcome["effect_state"], "observed")
        self.assertEqual(outcome["pre_action_snapshot_id"], observation["snapshot_id"])
        self.assertNotEqual(
            outcome["post_action_snapshot_id"], observation["snapshot_id"]
        )
        self.assertEqual(
            outcome["post_action_snapshot_id"], outcome["observation"]["snapshot_id"]
        )
        self.assertEqual(
            [call.args[1]["op"] for call in run.call_args_list],
            ["read_state", "navigate"],
        )
        self.assertEqual(
            run.call_args_list[1].args[1]["navigation_target"],
            "https://example.invalid/path?view=semantic",
        )
        self.assertEqual(
            run.call_args_list[1].args[1]["expected_state"],
            workers._bounded_browser_state(before["state"]),
        )
        self.assertNotIn("navigation_target", json.dumps(outcome, sort_keys=True))

    def test_browser_semantic_navigate_ack_without_readback_fails_closed(self) -> None:
        worker = self._running_browser(port=9379)
        before = self._semantic_state_payload(title="Before")
        observation_failure = {
            "schema_version": 1,
            "ok": False,
            "result_code": "transport",
            "state": None,
        }
        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=before
        ):
            observation = workers.browser_semantic_observe(worker["worker_id"])

        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers,
            "_run_node_browser_semantic",
            side_effect=[before, observation_failure],
        ) as run:
            outcome = workers.browser_semantic_act(
                worker["worker_id"],
                observation["snapshot_id"],
                "navigate",
                navigation_target="https://example.invalid/",
            )

        self.assertFalse(outcome["ok"])
        self.assertEqual(outcome["result_code"], "outcome_unknown")
        self.assertEqual(outcome["effect_state"], "unknown")
        self.assertIsNone(outcome["post_action_snapshot_id"])
        self.assertEqual(outcome["observation"]["snapshot_id"], observation["snapshot_id"])
        self.assertEqual(run.call_count, 2)

    def test_browser_semantic_navigate_error_text_is_unknown_with_fresh_readback(self) -> None:
        worker = self._running_browser(port=9380)
        before = self._semantic_state_payload(title="Before")
        navigation_error = {
            "schema_version": 1,
            "ok": False,
            "result_code": "navigation-error",
            "state": None,
        }
        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=before
        ):
            observation = workers.browser_semantic_observe(worker["worker_id"])

        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers,
            "_run_node_browser_semantic",
            side_effect=[before, navigation_error],
        ) as run:
            outcome = workers.browser_semantic_act(
                worker["worker_id"],
                observation["snapshot_id"],
                "navigate",
                navigation_target="https://example.invalid/",
            )

        self.assertFalse(outcome["ok"])
        self.assertEqual(outcome["result_code"], "navigation_failed")
        self.assertEqual(outcome["effect_state"], "unknown")
        self.assertIsNone(outcome["post_action_snapshot_id"])
        self.assertEqual(outcome["observation"]["snapshot_id"], observation["snapshot_id"])
        self.assertEqual(run.call_count, 2)

    def test_browser_semantic_node_uses_bounded_dom_name_fallback_for_empty_ax_name(self) -> None:
        execution, receipt = self._run_browser_semantic_node("read-name-fallback")

        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertTrue(receipt["ok"])
        element = receipt["state"]["elements"][0]
        self.assertEqual(element["role"], "button")
        self.assertTrue(element["name"].startswith("Dismiss onboarding "))
        self.assertEqual(len(element["name"]), 160)

    def test_browser_semantic_node_fails_closed_on_overlong_descendant_role_tokens(self) -> None:
        execution, receipt = self._run_browser_semantic_node(
            "read-long-role-token-fallback"
        )

        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertTrue(receipt["ok"])
        element = receipt["state"]["elements"][0]
        self.assertEqual(element["name"], "Proceed")
        self.assertNotIn("secret", element["name"])

    def test_browser_semantic_node_excludes_aria_meter_descendant_text(self) -> None:
        execution, receipt = self._run_browser_semantic_node("read-meter-role-fallback")
        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertTrue(receipt["ok"])
        element = receipt["state"]["elements"][0]
        self.assertEqual(element["name"], "Continue")
        self.assertNotIn("73", element["name"])

    def test_browser_semantic_node_excludes_hidden_descendant_subtrees(self) -> None:
        execution, receipt = self._run_browser_semantic_node(
            "read-hidden-descendant-fallback"
        )

        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertTrue(receipt["ok"])
        element = receipt["state"]["elements"][0]
        self.assertEqual(element["name"], "Continue")
        self.assertNotIn("secret", element["name"])

    def test_browser_semantic_node_excludes_css_hidden_layout_text(self) -> None:
        execution, receipt = self._run_browser_semantic_node(
            "read-css-hidden-fallback"
        )

        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertTrue(receipt["ok"])
        element = receipt["state"]["elements"][0]
        self.assertEqual(element["role"], "button")
        self.assertEqual(element["name"], "Continue")

    def test_browser_semantic_node_excludes_inherited_contenteditable_text(self) -> None:
        execution, receipt = self._run_browser_semantic_node(
            "read-inherited-contenteditable-fallback"
        )

        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertTrue(receipt["ok"])
        element = receipt["state"]["elements"][0]
        self.assertEqual(element["role"], "button")
        self.assertEqual(element["name"], "")

    def test_browser_semantic_node_honors_contenteditable_false_boundary(self) -> None:
        execution, receipt = self._run_browser_semantic_node(
            "read-contenteditable-false-boundary-fallback"
        )

        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertTrue(receipt["ok"])
        element = receipt["state"]["elements"][0]
        self.assertEqual(element["role"], "button")
        self.assertEqual(element["name"], "Continue")

    def test_browser_semantic_node_excludes_inherited_value_role_text(self) -> None:
        execution, receipt = self._run_browser_semantic_node(
            "read-inherited-value-role-fallback"
        )

        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertTrue(receipt["ok"])
        element = receipt["state"]["elements"][0]
        self.assertEqual(element["role"], "button")
        self.assertEqual(element["name"], "")

    def test_browser_semantic_node_excludes_inherited_value_tag_text(self) -> None:
        execution, receipt = self._run_browser_semantic_node(
            "read-inherited-value-tag-fallback"
        )

        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertTrue(receipt["ok"])
        element = receipt["state"]["elements"][0]
        self.assertEqual(element["role"], "button")
        self.assertEqual(element["name"], "")

    def test_browser_semantic_node_excludes_opacity_hidden_target_ancestor(self) -> None:
        execution, receipt = self._run_browser_semantic_node(
            "read-ancestor-opacity-fallback"
        )

        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertTrue(receipt["ok"])
        element = receipt["state"]["elements"][0]
        self.assertEqual(element["role"], "button")
        self.assertEqual(element["name"], "")

    def test_browser_semantic_node_excludes_filter_opacity_hidden_target_ancestor(self) -> None:
        execution, receipt = self._run_browser_semantic_node("read-ancestor-filter-opacity-fallback")
        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertTrue(receipt["ok"])
        self.assertEqual(receipt["state"]["elements"][0]["name"], "")

    def test_browser_semantic_node_excludes_url_backed_filter_text(self) -> None:
        execution, receipt = self._run_browser_semantic_node("read-url-filter-fallback")
        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertTrue(receipt["ok"])
        self.assertEqual(receipt["state"]["elements"][0]["name"], "")

    def test_browser_semantic_node_excludes_aria_hidden_target_ancestor(self) -> None:
        execution, receipt = self._run_browser_semantic_node(
            "read-ancestor-aria-hidden-fallback"
        )
        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertTrue(receipt["ok"])
        self.assertEqual(receipt["state"]["elements"][0]["name"], "")

    def test_browser_semantic_node_excludes_inert_target_ancestor(self) -> None:
        execution, receipt = self._run_browser_semantic_node(
            "read-ancestor-inert-fallback"
        )
        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertTrue(receipt["ok"])
        self.assertEqual(receipt["state"]["elements"][0]["name"], "")

    def test_browser_semantic_node_counts_only_target_subtree_text_limit(self) -> None:
        execution, receipt = self._run_browser_semantic_node(
            "read-text-heavy-page-fallback"
        )

        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertTrue(receipt["ok"])
        element = receipt["state"]["elements"][0]
        self.assertEqual(element["role"], "button")
        self.assertEqual(element["name"], "Continue")

    def test_browser_semantic_node_ignores_overlong_unrelated_layout_text(self) -> None:
        execution, receipt = self._run_browser_semantic_node("read-long-unrelated-text-fallback")
        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertTrue(receipt["ok"])
        self.assertEqual(receipt["state"]["elements"][0]["name"], "Continue")

    def test_browser_semantic_node_excludes_transform_collapsed_text(self) -> None:
        execution, receipt = self._run_browser_semantic_node("read-transform-zero-fallback")
        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertTrue(receipt["ok"])
        self.assertEqual(receipt["state"]["elements"][0]["name"], "")

    def test_browser_semantic_node_filters_transform_collapsed_descendant_text(self) -> None:
        execution, receipt = self._run_browser_semantic_node(
            "read-transform-zero-descendant-fallback"
        )
        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertTrue(receipt["ok"])
        self.assertEqual(receipt["state"]["elements"][0]["name"], "Continue")

    def test_browser_semantic_node_excludes_clip_path_hidden_text(self) -> None:
        execution, receipt = self._run_browser_semantic_node("read-clip-path-fallback")
        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertTrue(receipt["ok"])
        self.assertEqual(receipt["state"]["elements"][0]["name"], "")

    def test_browser_semantic_node_excludes_masked_text(self) -> None:
        execution, receipt = self._run_browser_semantic_node("read-mask-image-fallback")
        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertTrue(receipt["ok"])
        self.assertEqual(receipt["state"]["elements"][0]["name"], "")

    def test_browser_semantic_node_excludes_hidden_embedding_frame_text(self) -> None:
        execution, receipt = self._run_browser_semantic_node(
            "read-embedding-opacity-fallback"
        )
        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertTrue(receipt["ok"])
        self.assertEqual(receipt["state"]["elements"][0]["name"], "")

    def test_browser_semantic_node_excludes_overflow_clipped_text(self) -> None:
        execution, receipt = self._run_browser_semantic_node("read-overflow-clipped-fallback")
        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertTrue(receipt["ok"])
        self.assertEqual(receipt["state"]["elements"][0]["name"], "")

    def test_browser_semantic_node_preserves_fully_contained_overflow_text(self) -> None:
        execution, receipt = self._run_browser_semantic_node("read-overflow-contained-fallback")
        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertTrue(receipt["ok"])
        self.assertEqual(receipt["state"]["elements"][0]["name"], "Continue")

    def test_browser_semantic_node_excludes_transparent_color_text(self) -> None:
        execution, receipt = self._run_browser_semantic_node("read-transparent-color-fallback")
        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertTrue(receipt["ok"])
        self.assertEqual(receipt["state"]["elements"][0]["name"], "")

    def test_browser_semantic_node_excludes_transparent_text_fill(self) -> None:
        execution, receipt = self._run_browser_semantic_node("read-transparent-fill-fallback")
        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertTrue(receipt["ok"])
        self.assertEqual(receipt["state"]["elements"][0]["name"], "")

    def test_browser_semantic_node_excludes_svg_text_from_dom_fallback(self) -> None:
        execution, receipt = self._run_browser_semantic_node("read-svg-text-fallback")
        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertTrue(receipt["ok"])
        element = receipt["state"]["elements"][0]
        self.assertEqual(element["name"], "Continue")
        self.assertNotIn("secret", element["name"])

    def test_browser_semantic_node_preserves_visibility_override(self) -> None:
        execution, receipt = self._run_browser_semantic_node("read-visibility-override-fallback")
        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertTrue(receipt["ok"])
        self.assertEqual(receipt["state"]["elements"][0]["name"], "Continue")

    def test_browser_semantic_node_excludes_design_mode_editable_text(self) -> None:
        execution, receipt = self._run_browser_semantic_node("read-design-mode-fallback")
        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertTrue(receipt["ok"])
        self.assertEqual(receipt["state"]["elements"][0]["name"], "")

    def test_browser_semantic_node_excludes_child_frame_design_mode_text(self) -> None:
        execution, receipt = self._run_browser_semantic_node(
            "read-child-design-mode-fallback"
        )
        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertTrue(receipt["ok"])
        self.assertEqual(receipt["state"]["elements"][0]["name"], "")

    def test_browser_semantic_node_excludes_value_bearing_root_text(self) -> None:
        execution, receipt = self._run_browser_semantic_node(
            "read-sensitive-root-fallback"
        )

        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertTrue(receipt["ok"])
        element = receipt["state"]["elements"][0]
        self.assertEqual(element["role"], "button")
        self.assertEqual(element["name"], "")

    def test_browser_semantic_node_resolves_value_bearing_role_tokens(self) -> None:
        execution, receipt = self._run_browser_semantic_node(
            "read-role-token-descendant-fallback"
        )

        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertTrue(receipt["ok"])
        element = receipt["state"]["elements"][0]
        self.assertEqual(element["role"], "button")
        self.assertEqual(element["name"], "Proceed")
        self.assertNotIn("secret", element["name"])

    def test_browser_semantic_node_excludes_value_bearing_descendant_subtrees(self) -> None:
        execution, receipt = self._run_browser_semantic_node(
            "read-sensitive-descendant-fallback"
        )

        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertTrue(receipt["ok"])
        element = receipt["state"]["elements"][0]
        self.assertEqual(element["role"], "button")
        self.assertEqual(element["name"], "Continue")
        self.assertNotIn("secret", element["name"])

    def test_browser_semantic_node_keeps_dom_text_out_of_value_bearing_aria_role(self) -> None:
        execution, receipt = self._run_browser_semantic_node("read-value-role-fallback")

        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertTrue(receipt["ok"])
        element = receipt["state"]["elements"][0]
        self.assertEqual(element["role"], "textbox")
        self.assertEqual(element["name"], "")

    def test_browser_semantic_node_fails_closed_when_fallback_revalidation_fails(self) -> None:
        execution, receipt = self._run_browser_semantic_node(
            "scroll-fallback-revalidation-failure"
        )

        self.assertNotEqual(execution.returncode, 0)
        self.assertFalse(receipt["ok"])
        self.assertEqual(receipt["result_code"], "stale-snapshot")

    def test_browser_semantic_node_navigate_uses_page_navigate_and_error_text(self) -> None:
        source = workers.BROWSER_SEMANTIC_NODE_SOURCE
        self.assertIn("await call('Page.navigate'", source)
        self.assertIn("request.navigation_target", source)
        self.assertIn("navigation.errorText", source)
        self.assertNotIn("location.assign", source)
        self.assertNotIn("window.location", source)

    def test_browser_semantic_node_blocks_stale_drift_immediately_before_navigate(self) -> None:
        execution, receipt = self._run_browser_semantic_node("stale-before-navigate")

        self.assertNotEqual(execution.returncode, 0)
        self.assertFalse(receipt["ok"])
        self.assertEqual(receipt["result_code"], "stale-snapshot")

    def test_browser_semantic_node_rejects_identical_ack_readback_without_correlation(self) -> None:
        execution, receipt = self._run_browser_semantic_node("identical-ack-readback")

        self.assertNotEqual(execution.returncode, 0)
        self.assertFalse(receipt["ok"])
        self.assertEqual(receipt["result_code"], "navigation-uncorrelated")
        self.assertIsNone(receipt["state"])

    def test_browser_semantic_node_binds_new_document_navigation_to_loader(self) -> None:
        execution, receipt = self._run_browser_semantic_node(
            "correlated-new-document"
        )

        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertTrue(receipt["ok"])
        self.assertEqual(receipt["navigation_correlation"], "new-document")
        self.assertEqual(receipt["state"]["loader_id"], "loader-after")

    def test_browser_semantic_node_activate_binds_link_target_and_navigation(self) -> None:
        execution, receipt = self._run_browser_semantic_node(
            "activate-correlated-new-document"
        )

        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertTrue(receipt["ok"])
        self.assertEqual(receipt["navigation_correlation"], "new-document")
        self.assertEqual(receipt["state"]["loader_id"], "loader-after")
        element = receipt["state"]["elements"][0]
        self.assertEqual(element["role"], "link")
        self.assertRegex(element["navigation_target_sha256"], r"^[0-9a-f]{64}$")
        self.assertNotIn("private.invalid/issues", json.dumps(receipt, sort_keys=True))

    def test_browser_semantic_node_activate_target_drift_stops_before_navigation(self) -> None:
        execution, receipt = self._run_browser_semantic_node("activate-target-drift")

        self.assertNotEqual(execution.returncode, 0)
        self.assertFalse(receipt["ok"])
        self.assertEqual(receipt["result_code"], "stale-snapshot")
        self.assertIsNone(receipt["state"])

    def test_browser_semantic_node_activate_rejects_backslash_target_before_navigation(self) -> None:
        execution, receipt = self._run_browser_semantic_node(
            "activate-backslash-target"
        )

        self.assertNotEqual(execution.returncode, 0)
        self.assertFalse(receipt["ok"])
        self.assertEqual(receipt["result_code"], "stale-snapshot")
        self.assertIsNone(receipt["state"])

    def test_browser_semantic_node_binds_same_document_navigation_to_backend_event(self) -> None:
        execution, receipt = self._run_browser_semantic_node(
            "correlated-same-document"
        )

        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertTrue(receipt["ok"])
        self.assertEqual(receipt["navigation_correlation"], "same-document")
        self.assertEqual(receipt["state"]["navigation_entry_id"], "8")

    def test_browser_semantic_node_emits_exactly_one_correlated_receipt(self) -> None:
        source = workers.BROWSER_SEMANTIC_NODE_SOURCE
        self.assertIn("if (receiptEmitted) return;", source)
        for scenario in ("correlated-new-document", "correlated-same-document"):
            with self.subTest(scenario=scenario):
                execution, receipt = self._run_browser_semantic_node(scenario)
                lines = [
                    line for line in execution.stdout.splitlines() if line.strip()
                ]
                self.assertEqual(len(lines), 1, execution.stdout)
                self.assertEqual(execution.returncode, 0, execution.stderr)
                self.assertTrue(receipt["ok"])

    def test_browser_semantic_node_navigation_failures_never_claim_observation(self) -> None:
        for scenario, result_code in (
            ("navigation-error", "navigation-error"),
            ("transport-loss", "transport"),
            ("readback-failure", "protocol"),
        ):
            with self.subTest(scenario=scenario):
                execution, receipt = self._run_browser_semantic_node(scenario)
                self.assertNotEqual(execution.returncode, 0)
                self.assertFalse(receipt["ok"])
                self.assertEqual(receipt["result_code"], result_code)
                self.assertIsNone(receipt["state"])

    def test_browser_semantic_act_rejects_unsupported_action_kind(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported browser action kind"):
            workers.browser_semantic_act(
                "0" * 20,
                workers.BROWSER_SNAPSHOT_ID_PREFIX + "a" * 64,
                "not_supported",
            )

    def test_browser_semantic_act_fails_closed_for_unimplemented_effect_classes(self) -> None:
        worker = self._running_browser(port=9369)
        payload = self._semantic_state_payload(title="Unimplemented")
        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=payload
        ):
            observation = workers.browser_semantic_observe(worker["worker_id"])
        snapshot_id = observation["snapshot_id"]

        fake_catalog = dict(workers.BROWSER_ACTION_CATALOG)
        fake_catalog["submit_generic"] = {
            "effect_class": "external_mutation",
            "requires_element": False,
        }
        with patch.object(workers, "BROWSER_ACTION_CATALOG", fake_catalog), patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=payload
        ) as run:
            outcome = workers.browser_semantic_act(
                worker["worker_id"], snapshot_id, "submit_generic"
            )
        self.assertFalse(outcome["ok"])
        self.assertEqual(outcome["result_code"], "effect_not_implemented")
        run.assert_called_once()
        self.assertEqual(run.call_args.args[1]["op"], "read_state")

    def test_browser_semantic_gateway_observe_exposes_bounded_name_but_audit_does_not(self) -> None:
        worker = self._running_browser(port=9370)
        accessibility_name = "Transfer all funds " + "x" * 200
        payload = self._semantic_state_payload(
            origin="https://user:password@example.invalid/private?token=secret",
            title="Private account dashboard",
            elements=[
                {
                    "backend_node_id": "101",
                    "role": "button",
                    "name": accessibility_name,
                    "selector": "#dangerous-private-selector",
                }
            ],
        )
        with patch.object(
            workers.operator, "_require_operator_capability"
        ) as require_capability, patch.object(
            workers.operator, "_require_operator_mutation"
        ) as require_mutation, patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=payload
        ), patch.object(
            workers.base, "_append_audit_with_digest", return_value="a" * 64
        ) as append_audit:
            result_payload = workers.grabowski_browser_worker_semantic(
                worker["worker_id"], "observe"
            )

        self.assertTrue(result_payload["ok"])
        self.assertEqual(result_payload["operation"], "observe")
        self.assertEqual(result_payload["effect_class"], "read")
        self.assertFalse(result_payload["retry_readback"]["retry_authorized"])
        self.assertEqual(
            result_payload["retry_readback"]["authoritative_readback_state"],
            "authoritative_fresh_observation",
        )
        self.assertEqual(
            set(result_payload["observation"]["elements"][0]),
            {"element_id", "role", "name"},
        )
        self.assertEqual(
            result_payload["observation"]["elements"][0]["name"],
            accessibility_name[: workers.BROWSER_ELEMENT_NAME_MAX],
        )
        self.assertLessEqual(
            len(result_payload["observation"]["elements"][0]["name"]),
            workers.BROWSER_ELEMENT_NAME_MAX,
        )
        require_capability.assert_called_with("browser_worker")
        require_mutation.assert_not_called()
        self.assertTrue(
            result_payload["semantic_catalog"]["intents"]["navigate"]
            ["requires_navigation_target"]
        )
        activate = result_payload["semantic_catalog"]["intents"]["activate"]
        self.assertEqual(activate["effect_class"], "network_navigation")
        self.assertTrue(activate["requires_element"])
        self.assertFalse(activate["requires_navigation_target"])
        self.assertTrue(activate["requires_bound_navigation_target"])
        self.assertEqual(activate["admission"], "implemented")
        self.assertEqual(
            result_payload["semantic_catalog"]["intents"]["navigate"][
                "effect_class"
            ],
            "network_navigation",
        )
        navigation_effect = result_payload["semantic_catalog"]["effect_classes"][
            "network_navigation"
        ]
        self.assertEqual(navigation_effect["admission"], "implemented")
        self.assertTrue(navigation_effect["requires_operator_mutation"])
        self.assertFalse(
            navigation_effect["ambiguous_outcome"]["retry_authorized"]
        )
        self.assertTrue(
            navigation_effect["ambiguous_outcome"][
                "authoritative_readback_required"
            ]
        )
        self.assertFalse(
            navigation_effect["ambiguous_outcome"][
                "readback_grants_retry_authority"
            ]
        )
        for effect_class in (
            "reversible_external",
            "external_mutation",
            "high_impact",
        ):
            effect = result_payload["semantic_catalog"]["effect_classes"][
                effect_class
            ]
            self.assertEqual(effect["admission"], "fail_closed")
            self.assertFalse(effect["ambiguous_outcome"]["retry_authorized"])
            self.assertTrue(
                effect["ambiguous_outcome"]["authoritative_readback_required"]
            )
            self.assertFalse(
                effect["ambiguous_outcome"]["readback_grants_retry_authority"]
            )

        rendered = json.dumps(result_payload, sort_keys=True)
        audit_rendered = json.dumps(append_audit.call_args.args[0], sort_keys=True)
        for forbidden in (
            "password",
            "token=secret",
            "Private account dashboard",
            "#dangerous-private-selector",
            "backend_node_id",
            "Runtime.evaluate",
            "Accessibility.getFullAXTree",
        ):
            self.assertNotIn(forbidden, rendered)
            self.assertNotIn(forbidden, audit_rendered)
        self.assertIn(accessibility_name[:160], rendered)
        self.assertNotIn(accessibility_name[:160], audit_rendered)
        self.assertNotIn('"name"', audit_rendered)
        self.assertEqual(append_audit.call_count, 1)
        audit_record = append_audit.call_args.args[0]
        self.assertEqual(audit_record["operation"], "browser-semantic-outcome")
        self.assertEqual(audit_record["worker_id"], worker["worker_id"])
        self.assertEqual(audit_record["intent"], "observe")
        self.assertEqual(audit_record["effect_class"], "read")
        self.assertTrue(audit_record["ok"])
        self.assertEqual(audit_record["result_code"], "ok")
        self.assertFalse(audit_record["retry_authorized"])
        self.assertEqual(result_payload["audit"]["outcome"]["record_sha256"], "a" * 64)

    def test_browser_semantic_gateway_act_preserves_post_action_readback(self) -> None:
        worker = self._running_browser(port=9371)
        payload = self._semantic_state_payload(title="Private title")
        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=payload
        ):
            observation = workers.browser_semantic_observe(worker["worker_id"])

        with patch.object(
            workers.operator, "_require_operator_capability"
        ), patch.object(
            workers.operator, "_require_operator_mutation"
        ) as require_mutation, patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers,
            "_run_node_browser_semantic",
            side_effect=[payload, payload],
        ), patch.object(
            workers.base,
            "_append_audit_with_digest",
            side_effect=["a" * 64, "b" * 64],
        ) as append_audit:
            outcome = workers.grabowski_browser_worker_semantic(
                worker["worker_id"],
                "act",
                snapshot_id=observation["snapshot_id"],
                action_kind="scroll_into_view",
                element_id=observation["elements"][0]["element_id"],
            )

        self.assertTrue(outcome["ok"])
        self.assertEqual(outcome["effect_class"], "local_ui")
        self.assertEqual(outcome["effect_state"], "observed")
        self.assertEqual(
            outcome["retry_readback"]["authoritative_readback_state"],
            "authoritative_post_action_observation",
        )
        self.assertFalse(outcome["retry_readback"]["retry_authorized"])
        self.assertFalse(outcome["retry_readback"]["readback_grants_retry_authority"])
        self.assertNotIn("title", json.dumps(outcome))
        require_mutation.assert_called_once_with("browser_worker")
        self.assertEqual(append_audit.call_count, 2)
        audit_records = json.dumps(
            [call.args[0] for call in append_audit.call_args_list], sort_keys=True
        )
        self.assertNotIn('"name"', audit_records)
        self.assertNotIn("Target", audit_records)
        self.assertNotIn("Private title", audit_records)
        self.assertEqual(
            [call.args[0]["operation"] for call in append_audit.call_args_list],
            ["browser-semantic-intent", "browser-semantic-outcome"],
        )
        self.assertEqual(outcome["audit"]["intent"]["record_sha256"], "a" * 64)
        self.assertEqual(outcome["audit"]["outcome"]["record_sha256"], "b" * 64)

    def test_browser_semantic_gateway_activate_preserves_link_binding_and_readback(self) -> None:
        worker = self._running_browser(port=9390)
        link = self._semantic_link(name="Issues 20", target="https://github.com/heimgewebe/grabowski/issues")
        before = self._semantic_state_payload(
            title="Repository", loader_id="loader-before", elements=[link]
        )
        after = self._semantic_state_payload(
            origin="https://github.com",
            title="Issues",
            loader_id="loader-after",
            navigation_entry_id="entry-after",
            elements=[link],
        )
        after["navigation_correlation"] = "new-document"
        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=before
        ):
            observation = workers.browser_semantic_observe(worker["worker_id"])
        element_id = observation["elements"][0]["element_id"]

        with patch.object(
            workers.operator, "_require_operator_capability"
        ), patch.object(
            workers.operator, "_require_operator_mutation"
        ) as require_mutation, patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", side_effect=[before, after]
        ), patch.object(
            workers.base,
            "_append_audit_with_digest",
            side_effect=["a" * 64, "b" * 64],
        ) as append_audit:
            outcome = workers.grabowski_browser_worker_semantic(
                worker["worker_id"],
                "act",
                snapshot_id=observation["snapshot_id"],
                action_kind="activate",
                element_id=element_id,
            )

        self.assertTrue(outcome["ok"])
        self.assertEqual(outcome["intent"], "activate")
        self.assertEqual(outcome["effect_class"], "network_navigation")
        self.assertEqual(outcome["effect_state"], "observed")
        self.assertEqual(outcome["requested_element_id"], element_id)
        self.assertIsNone(outcome["target_hmac_sha256"])
        self.assertEqual(
            outcome["retry_readback"]["authoritative_readback_state"],
            "authoritative_post_action_observation",
        )
        self.assertFalse(outcome["retry_readback"]["retry_authorized"])
        self.assertFalse(outcome["retry_readback"]["readback_grants_retry_authority"])
        self.assertEqual(
            outcome["observation"]["snapshot_id"], outcome["post_action_snapshot_id"]
        )
        require_mutation.assert_called_once_with("browser_worker")
        audit_records = [call.args[0] for call in append_audit.call_args_list]
        self.assertEqual(
            [record["requested_element_id"] for record in audit_records],
            [element_id, element_id],
        )
        self.assertEqual(
            [record["target_hmac_sha256"] for record in audit_records],
            [None, None],
        )
        audit_rendered = json.dumps(audit_records, sort_keys=True)
        self.assertNotIn("Issues 20", audit_rendered)
        self.assertNotIn('"name"', audit_rendered)

    def test_browser_semantic_gateway_navigate_redacts_target_and_requires_readback(self) -> None:
        worker = self._running_browser(port=9381)
        before = self._semantic_state_payload(title="Before", loader_id="loader-before")
        after = self._semantic_state_payload(
            title="After",
            loader_id="loader-after",
            navigation_entry_id="entry-after",
        )
        after["navigation_correlation"] = "new-document"
        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=before
        ):
            observation = workers.browser_semantic_observe(worker["worker_id"])

        navigation_target = "https://example.invalid/private?token=must-not-leak"
        with patch.object(
            workers.operator, "_require_operator_capability"
        ), patch.object(
            workers.operator, "_require_operator_mutation"
        ) as require_mutation, patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers,
            "_run_node_browser_semantic",
            side_effect=[before, after],
        ), patch.object(
            workers.base,
            "_append_audit_with_digest",
            side_effect=["a" * 64, "b" * 64],
        ) as append_audit:
            outcome = workers.grabowski_browser_worker_semantic(
                worker["worker_id"],
                "act",
                snapshot_id=observation["snapshot_id"],
                action_kind="navigate",
                navigation_target=navigation_target,
            )

        self.assertTrue(outcome["ok"])
        self.assertEqual(outcome["intent"], "navigate")
        self.assertEqual(outcome["effect_class"], "network_navigation")
        self.assertEqual(
            outcome["retry_readback"]["authoritative_readback_state"],
            "authoritative_post_action_observation",
        )
        self.assertFalse(outcome["retry_readback"]["retry_authorized"])
        self.assertFalse(outcome["retry_readback"]["readback_grants_retry_authority"])
        self.assertEqual(
            outcome["observation"]["snapshot_id"], outcome["post_action_snapshot_id"]
        )
        require_mutation.assert_called_once_with("browser_worker")
        target_digest = outcome["target_hmac_sha256"]
        self.assertRegex(target_digest, r"^[0-9a-f]{64}$")
        rendered = json.dumps(outcome, sort_keys=True)
        audit_records = [call.args[0] for call in append_audit.call_args_list]
        audit_rendered = json.dumps(audit_records, sort_keys=True)
        self.assertEqual(
            [record["target_hmac_sha256"] for record in audit_records],
            [target_digest, target_digest],
        )
        self.assertNotIn(navigation_target, rendered)
        self.assertNotIn("must-not-leak", rendered)
        self.assertNotIn(navigation_target, audit_rendered)
        self.assertNotIn("must-not-leak", audit_rendered)

    def test_browser_semantic_gateway_stale_snapshot_returns_fresh_safe_handles(self) -> None:
        worker = self._running_browser(port=9372)
        initial = self._semantic_state_payload(title="Before")
        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=initial
        ):
            observation = workers.browser_semantic_observe(worker["worker_id"])
        changed = self._semantic_state_payload(title="After private navigation")
        with patch.object(
            workers.operator, "_require_operator_capability"
        ), patch.object(
            workers.operator, "_require_operator_mutation"
        ), patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=changed
        ) as run, patch.object(
            workers.base, "_append_audit_with_digest", return_value="a" * 64
        ):
            outcome = workers.grabowski_browser_worker_semantic(
                worker["worker_id"],
                "act",
                snapshot_id=observation["snapshot_id"],
                action_kind="scroll_into_view",
                element_id=observation["elements"][0]["element_id"],
            )

        self.assertFalse(outcome["ok"])
        self.assertEqual(outcome["result_code"], "stale_snapshot")
        self.assertEqual(outcome["effect_state"], "not_started")
        self.assertNotEqual(
            outcome["observation"]["snapshot_id"], observation["snapshot_id"]
        )
        self.assertEqual(
            outcome["retry_readback"]["authoritative_readback_state"],
            "pre_action_observation_only",
        )
        self.assertFalse(outcome["retry_readback"]["retry_authorized"])
        self.assertNotIn("After private navigation", json.dumps(outcome))
        run.assert_called_once()

    def test_browser_semantic_gateway_external_effects_remain_fail_closed(self) -> None:
        worker = self._running_browser(port=9373)
        payload = self._semantic_state_payload()
        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=payload
        ):
            observation = workers.browser_semantic_observe(worker["worker_id"])
        fake_catalog = dict(workers.BROWSER_ACTION_CATALOG)
        fake_catalog["submit_generic"] = {
            "effect_class": "external_mutation",
            "requires_element": False,
        }
        with patch.object(
            workers, "BROWSER_ACTION_CATALOG", fake_catalog
        ), patch.object(
            workers.operator, "_require_operator_capability"
        ), patch.object(
            workers.operator, "_require_operator_mutation"
        ) as require_mutation, patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=payload
        ) as run, patch.object(
            workers.base, "_append_audit_with_digest", return_value="a" * 64
        ) as append_audit:
            outcome = workers.grabowski_browser_worker_semantic(
                worker["worker_id"],
                "act",
                snapshot_id=observation["snapshot_id"],
                action_kind="submit_generic",
            )

        self.assertFalse(outcome["ok"])
        self.assertEqual(outcome["result_code"], "effect_not_implemented")
        self.assertEqual(outcome["effect_contract"]["admission"], "fail_closed")
        self.assertFalse(
            outcome["effect_contract"]["ambiguous_outcome"]["retry_authorized"]
        )
        self.assertTrue(
            outcome["effect_contract"]["ambiguous_outcome"][
                "authoritative_readback_required"
            ]
        )
        require_mutation.assert_not_called()
        run.assert_called_once()
        self.assertEqual(append_audit.call_count, 1)

    def test_browser_semantic_gateway_intent_audit_failure_blocks_effect(self) -> None:
        worker = self._running_browser(port=9374)
        snapshot_id = workers.BROWSER_SNAPSHOT_ID_PREFIX + "a" * 64
        element_id = workers.BROWSER_ELEMENT_ID_PREFIX + "b" * 64
        with patch.object(
            workers.operator, "_require_operator_capability"
        ), patch.object(
            workers.operator, "_require_operator_mutation"
        ), patch.object(
            workers.base,
            "_append_audit_with_digest",
            side_effect=OSError("audit unavailable"),
        ), patch.object(workers, "browser_semantic_act") as semantic_act:
            outcome = workers.grabowski_browser_worker_semantic(
                worker["worker_id"],
                "act",
                snapshot_id=snapshot_id,
                action_kind="scroll_into_view",
                element_id=element_id,
            )

        self.assertFalse(outcome["ok"])
        self.assertEqual(outcome["result_code"], "audit_unavailable")
        self.assertEqual(outcome["effect_state"], "not_started")
        self.assertFalse(outcome["audit"]["intent"]["recorded"])
        self.assertFalse(outcome["retry_readback"]["retry_authorized"])
        semantic_act.assert_not_called()

    def test_browser_semantic_gateway_ambiguous_effect_and_audit_failure_forbid_retry(self) -> None:
        worker = self._running_browser(port=9375)
        snapshot_id = workers.BROWSER_SNAPSHOT_ID_PREFIX + "a" * 64
        element_id = workers.BROWSER_ELEMENT_ID_PREFIX + "b" * 64
        with patch.object(
            workers.operator, "_require_operator_capability"
        ), patch.object(
            workers.operator, "_require_operator_mutation"
        ), patch.object(
            workers.base,
            "_append_audit_with_digest",
            side_effect=["a" * 64, OSError("outcome audit unavailable")],
        ), patch.object(
            workers, "browser_semantic_act", side_effect=RuntimeError("lost response")
        ):
            outcome = workers.grabowski_browser_worker_semantic(
                worker["worker_id"],
                "act",
                snapshot_id=snapshot_id,
                action_kind="scroll_into_view",
                element_id=element_id,
            )

        self.assertFalse(outcome["ok"])
        self.assertEqual(outcome["result_code"], "outcome_unknown")
        self.assertEqual(outcome["effect_state"], "unknown")
        self.assertTrue(outcome["audit"]["intent"]["recorded"])
        self.assertFalse(outcome["audit"]["outcome"]["recorded"])
        self.assertFalse(outcome["retry_readback"]["retry_authorized"])
        self.assertTrue(
            outcome["retry_readback"]["authoritative_readback_required"]
        )
        self.assertFalse(
            outcome["retry_readback"]["readback_grants_retry_authority"]
        )
        self.assertEqual(
            outcome["retry_readback"]["next_action_after_ambiguous_effect"],
            "perform_authoritative_readback_then_form_a_new_explicit_intent",
        )

    def test_browser_semantic_contract_does_not_change_stored_form_action_safety(self) -> None:
        worker = self._running_browser(port=9366)
        payload = self._semantic_state_payload(title="Unrelated")
        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=payload
        ):
            workers.browser_semantic_observe(worker["worker_id"])

        with patch.object(
            workers,
            "_canonical_local_origin",
            return_value=("http://device.home.arpa", "b" * 64, ["192.168.1.1"]),
        ), patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(workers, "_run_node_form_action") as action:
            with self.assertRaisesRegex(PermissionError, "confirmation mismatch"):
                workers.browser_stored_form_action(
                    worker["worker_id"],
                    expected_origin="http://device.home.arpa",
                    identity_selector="#identity",
                    protected_selector="#protected",
                    submit_selector="button",
                    confirmation="wrong",
                )
        action.assert_not_called()

        public_answer = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 80))]
        with patch.object(workers.socket, "getaddrinfo", return_value=public_answer):
            with self.assertRaisesRegex(PermissionError, "outside local"):
                workers._canonical_local_origin("http://example.invalid")

        signature = inspect.signature(workers.browser_stored_form_action)
        self.assertIn("confirmation", signature.parameters)
        self.assertNotIn("snapshot_id", signature.parameters)
        self.assertEqual(len(workers.BROWSER_FORM_RESULT_CODES), 13)

    def test_worker_list_cursor_is_bound_to_kind_and_view(self) -> None:
        with self.assertRaisesRegex(ValueError, "bound to another worker view"):
            workers.worker_list(
                "gui",
                view="history",
                cursor="browser:history:1:" + "0" * 20,
            )

    def test_bidi_record_adapter_projects_qualified_fallback(self) -> None:
        record = {
            "executable": str(self.binary),
            "port": 9555,
            "argv_json": json.dumps([
                str(self.root / "chromedriver"),
                "--port=9555",
                "--allowed-ips=127.0.0.1",
                "--verbose",
            ]),
        }
        adapter = workers._browser_record_adapter(record)
        self.assertEqual(adapter["adapter_id"], workers.BROWSER_BIDI_ADAPTER_ID)
        self.assertEqual(adapter["protocol"], "webdriver-bidi")
        self.assertEqual(adapter["selection_role"], "qualified-pre-effect-fallback")

    def test_bidi_fallback_requires_ephemeral_profile_and_effect_free_start_args(self) -> None:
        driver = self.root / "chromedriver"
        driver.write_text("#!/bin/sh\nexit 0\n")
        driver.chmod(0o755)
        with patch.object(workers, "_executable", return_value=self.binary.resolve()):
            with self.assertRaisesRegex(ValueError, "ephemeral primary and standby"):
                workers.browser_start(
                    str(self.binary),
                    port=9556,
                    persistent_profile=str(self.root / "profile"),
                    chromedriver_executable=str(driver),
                    runtime_seconds=60,
                )
            with self.assertRaisesRegex(PermissionError, "effect-free Chrome startup"):
                workers.browser_start(
                    str(self.binary),
                    port=9556,
                    args=["https://example.com"],
                    chromedriver_executable=str(driver),
                    runtime_seconds=60,
                )

    def test_bidi_fallback_returns_cdp_when_primary_is_ready(self) -> None:
        primary = {"worker": {"worker_id": "a" * 20, "state": "running"}}
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers, "_chromedriver_executable", return_value=self.root / "chromedriver"
        ), patch.object(workers, "_browser_start_cdp_worker", return_value=primary) as start_cdp, patch.object(
            workers.browser_bidi, "cdp_endpoint_ready", return_value=True
        ), patch.object(workers, "_browser_start_bidi_worker") as start_bidi:
            result_value = workers.browser_start(
                str(self.binary),
                port=9557,
                args=["--headless=new"],
                chromedriver_executable=str(self.root / "chromedriver"),
                runtime_seconds=60,
            )
        start_cdp.assert_called_once()
        start_bidi.assert_not_called()
        self.assertIs(result_value, primary)
        self.assertFalse(result_value["fallback"]["selected"])
        self.assertEqual(result_value["fallback"]["selected_adapter"], "chrome-cdp")

    def test_bidi_fallback_selects_bidi_only_after_private_primary_terminalization(self) -> None:
        primary = {"worker": {"worker_id": "b" * 20, "state": "running"}}
        fallback = {"worker": {"worker_id": "c" * 20}}
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers, "_chromedriver_executable", return_value=self.root / "chromedriver"
        ), patch.object(workers, "_browser_start_cdp_worker", return_value=primary), patch.object(
            workers.browser_bidi, "cdp_endpoint_ready", side_effect=[False, False]
        ), patch.object(
            workers, "worker_stop", return_value={"worker": {"state": "stopped"}}
        ) as stop_primary, patch.object(
            workers.resources, "inspect_resource", return_value=None
        ), patch.object(
            workers, "_browser_start_bidi_worker", return_value=fallback
        ) as start_bidi:
            result_value = workers.browser_start(
                str(self.binary),
                port=9558,
                args=["--headless=new"],
                chromedriver_executable=str(self.root / "chromedriver"),
                runtime_seconds=60,
            )
        self.assertIs(result_value, fallback)
        stop_primary.assert_called_once_with("b" * 20, expected_kind="browser")
        kwargs = start_bidi.call_args.kwargs
        self.assertEqual(kwargs["port"], 9558)
        evidence = kwargs["fallback_evidence"]
        self.assertTrue(evidence["selected"])
        self.assertFalse(evidence["effect_started"])
        self.assertEqual(evidence["effect_state"], "not_started")
        self.assertEqual(evidence["primary_worker_id"], "b" * 20)

    def test_bidi_fallback_blocks_when_private_primary_cannot_terminalize(self) -> None:
        primary = {"worker": {"worker_id": "d" * 20, "state": "running"}}
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers, "_chromedriver_executable", return_value=self.root / "chromedriver"
        ), patch.object(workers, "_browser_start_cdp_worker", return_value=primary), patch.object(
            workers.browser_bidi, "cdp_endpoint_ready", return_value=False
        ), patch.object(
            workers, "worker_stop", return_value={"worker": {"state": "running"}}
        ), patch.object(workers, "_browser_start_bidi_worker") as start_bidi:
            with self.assertRaisesRegex(RuntimeError, "could not be terminalized"):
                workers.browser_start(
                    str(self.binary),
                    port=9559,
                    args=["--headless=new"],
                    chromedriver_executable=str(self.root / "chromedriver"),
                    runtime_seconds=60,
                )
        start_bidi.assert_not_called()

    def test_bidi_fallback_blocks_when_primary_port_lease_remains(self) -> None:
        primary = {"worker": {"worker_id": "e" * 20, "state": "running"}}
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers, "_chromedriver_executable", return_value=self.root / "chromedriver"
        ), patch.object(workers, "_browser_start_cdp_worker", return_value=primary), patch.object(
            workers.browser_bidi, "cdp_endpoint_ready", return_value=False
        ), patch.object(
            workers, "worker_stop", return_value={"worker": {"state": "stopped"}}
        ), patch.object(
            workers.resources, "inspect_resource", return_value={"owner_id": "worker:other"}
        ), patch.object(workers, "_browser_start_bidi_worker") as start_bidi:
            with self.assertRaisesRegex(RuntimeError, "port lease remains active"):
                workers.browser_start(
                    str(self.binary),
                    port=9560,
                    args=["--headless=new"],
                    chromedriver_executable=str(self.root / "chromedriver"),
                    runtime_seconds=60,
                )
        start_bidi.assert_not_called()

    def test_bidi_record_adapter_accepts_configured_driver_name(self) -> None:
        record = {
            "executable": str(self.binary),
            "port": 9566,
            "argv_json": json.dumps([
                str(self.root / "chromedriver-150-custom"),
                "--port=9566",
                "--allowed-ips=127.0.0.1",
                "--verbose",
            ]),
        }
        adapter = workers._browser_record_adapter(record)
        self.assertEqual(adapter["adapter_id"], workers.BROWSER_BIDI_ADAPTER_ID)
        self.assertEqual(adapter["protocol"], "webdriver-bidi")

    def test_bidi_record_adapter_rejects_noncanonical_driver_argv(self) -> None:
        record = {
            "executable": str(self.binary),
            "port": 9567,
            "argv_json": json.dumps([
                str(self.root / "chromedriver"),
                "--port=9999",
                "--allowed-ips=127.0.0.1",
                "--verbose",
            ]),
        }
        adapter = workers._browser_record_adapter(record)
        self.assertEqual(adapter["adapter_id"], "chrome-cdp")
        self.assertEqual(adapter["protocol"], "cdp")

    def test_bidi_session_setup_failure_requires_verified_compensation(self) -> None:
        driver = self.root / "chromedriver"
        driver.write_text("#!/bin/sh\nexit 0\n")
        driver.chmod(0o755)
        evidence = {
            "schema_version": 1,
            "armed": True,
            "selected": True,
            "primary_worker_id": "9" * 20,
            "effect_started": False,
            "effect_state": "not_started",
        }
        with patch.object(workers.operator, "_run", return_value=result()), patch.object(
            workers.browser_bidi, "driver_ready"
        ), patch.object(
            workers.browser_bidi, "create_chrome_session", side_effect=RuntimeError("session failed")
        ):
            with self.assertRaisesRegex(RuntimeError, "session failed"):
                workers._browser_start_bidi_worker(
                    binary=self.binary.resolve(),
                    driver=driver.resolve(),
                    port=9568,
                    extra=["--headless=new"],
                    runtime=60,
                    fallback_evidence=evidence,
                )
        self.assertIsNone(workers.resources.inspect_resource("port:9568"))
        self.assertFalse(any((workers.WORKER_STATE / "profiles").glob("*")))

    def test_bidi_session_setup_failure_surfaces_incomplete_compensation(self) -> None:
        driver = self.root / "chromedriver"
        driver.write_text("#!/bin/sh\nexit 0\n")
        driver.chmod(0o755)
        evidence = {"schema_version": 1, "armed": True, "selected": True}
        with patch.object(workers.operator, "_run", return_value=result()), patch.object(
            workers.browser_bidi, "driver_ready"
        ), patch.object(
            workers.browser_bidi, "create_chrome_session", side_effect=RuntimeError("session failed")
        ), patch.object(
            workers, "worker_stop", side_effect=RuntimeError("stop failed")
        ):
            with self.assertRaisesRegex(RuntimeError, "compensation could not be verified"):
                workers._browser_start_bidi_worker(
                    binary=self.binary.resolve(),
                    driver=driver.resolve(),
                    port=9569,
                    extra=["--headless=new"],
                    runtime=60,
                    fallback_evidence=evidence,
                )

    def test_bidi_fallback_start_binds_private_session_and_control_plane(self) -> None:
        driver = self.root / "chromedriver"
        driver.write_text("#!/bin/sh\nexit 0\n")
        driver.chmod(0o755)
        evidence = {
            "schema_version": 1,
            "armed": True,
            "selected": True,
            "primary_worker_id": "f" * 20,
            "primary_adapter": "chrome-cdp",
            "primary_state": "stopped",
            "effect_started": False,
            "effect_state": "not_started",
            "fallback_authorized": True,
        }
        session = {
            "session_id": "session-1",
            "websocket_url": "ws://127.0.0.1:9561/session/session-1",
            "browser_version": "151.0",
            "driver_version": "150.0",
        }
        with patch.object(workers.operator, "_run", return_value=result()), patch.object(
            workers.browser_bidi, "driver_ready"
        ), patch.object(
            workers.browser_bidi, "create_chrome_session", return_value=session
        ):
            started = workers._browser_start_bidi_worker(
                binary=self.binary.resolve(),
                driver=driver.resolve(),
                port=9561,
                extra=["--headless=new"],
                runtime=60,
                fallback_evidence=evidence,
            )
        worker = started["worker"]
        self.assertEqual(worker["control_plane"]["adapter"]["id"], workers.BROWSER_BIDI_ADAPTER_ID)
        self.assertEqual(worker["control_plane"]["adapter"]["protocol"], "webdriver-bidi")
        self.assertEqual(worker["control_plane"]["browser"]["selection_role"], "qualified-pre-effect-fallback")
        self.assertIn("Firefox availability", worker["control_plane"]["does_not_establish"])
        self.assertNotIn("Firefox or WebDriver BiDi availability", worker["control_plane"]["does_not_establish"])
        self.assertTrue(started["fallback"]["session_ready"])
        record = workers._row(worker["worker_id"])
        private = Path(record["config_path"]).parent / workers.BROWSER_BIDI_SESSION_NAME
        self.assertEqual(stat.S_IMODE(private.stat().st_mode), 0o600)
        self.assertNotIn(session["session_id"], json.dumps(worker))
        self.assertNotIn(session["websocket_url"], json.dumps(worker))

    def test_semantic_adapter_selects_chrome_webdriver_bidi_record(self) -> None:
        worker_id = "e" * 20
        directory = workers.WORKER_STATE / "instances" / worker_id
        directory.mkdir(parents=True, mode=0o700)
        config = directory / "worker.json"
        config.write_text("{}")
        driver = self.root / "chromedriver"
        record = {
            "worker_id": worker_id,
            "kind": "browser",
            "executable": str(self.binary.resolve()),
            "argv_json": json.dumps([
                str(driver),
                "--port=9560",
                "--allowed-ips=127.0.0.1",
                "--verbose",
            ]),
            "config_path": str(config),
            "port": 9560,
        }
        workers._write_private_worker_json(
            directory,
            workers.BROWSER_BIDI_SESSION_NAME,
            {
                "schema_version": 1,
                "session_id": "session-2",
                "websocket_url": "ws://127.0.0.1:9560/session/session-2",
                "browser_version": "151.0",
                "driver_version": "150.0",
            },
        )
        adapter = workers._browser_semantic_adapter(record, timeout_seconds=10)
        self.assertIsInstance(adapter, workers.ChromeWebDriverBidiAdapter)

    def test_bidi_activation_target_drift_fails_before_navigation(self) -> None:
        expected = {
            "origin": "https://example.com",
            "ready_state": "complete",
            "title": "Example",
            "main_frame_id": "ctx",
            "loader_id": "loader",
            "navigation_entry_id": "entry",
            "elements": [],
        }
        original = "https://example.com/issues"
        element = {
            "backend_node_id": "1",
            "role": "link",
            "name": "Issues",
            "navigation_target_sha256": hashlib.sha256(original.encode()).hexdigest(),
        }
        connection = Mock()
        connection.__enter__ = Mock(return_value=connection)
        connection.__exit__ = Mock(return_value=None)
        with patch.object(
            workers, "_read_browser_bidi_session", return_value={"websocket_url": "ws://127.0.0.1:9561/session/x"}
        ), patch.object(workers.browser_bidi, "BidiJsonConnection", return_value=connection), patch.object(
            workers, "_browser_bidi_context", return_value="ctx"
        ), patch.object(workers, "_browser_bidi_decode_state", return_value=expected), patch.object(
            workers, "_browser_bidi_evaluate", return_value=json.dumps("https://example.com/changed")
        ):
            adapter = workers.ChromeWebDriverBidiAdapter({}, timeout_seconds=10)
            with self.assertRaisesRegex(RuntimeError, "stale-snapshot"):
                adapter.activate_link(expected_state=expected, expected_element=element)
        self.assertFalse(
            any(call.args and call.args[0] == "browsingContext.navigate" for call in connection.call.call_args_list)
        )


    def test_bidi_session_rejects_websocket_port_drift(self) -> None:
        from grabowski_browser_bidi import BrowserBidiError, _validate_chrome_ws
        with patch("grabowski_browser_bidi.socket.getaddrinfo", return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 9563))
        ]):
            with self.assertRaisesRegex(BrowserBidiError, "identity mismatch"):
                _validate_chrome_ws(
                    "ws://127.0.0.1:9563/session/session-3",
                    expected_session_id="session-3",
                    expected_port=9562,
                )

    def test_bidi_scroll_element_drift_fails_closed(self) -> None:
        expected = {
            "origin": "https://example.com",
            "ready_state": "complete",
            "title": "Example",
            "main_frame_id": "ctx",
            "loader_id": "loader",
            "navigation_entry_id": "entry",
            "elements": [],
        }
        element = {
            "backend_node_id": "7",
            "role": "heading",
            "name": "Expected heading",
            "navigation_target_sha256": None,
        }
        connection = Mock()
        connection.__enter__ = Mock(return_value=connection)
        connection.__exit__ = Mock(return_value=None)
        with patch.object(
            workers, "_read_browser_bidi_session", return_value={"websocket_url": "ws://127.0.0.1:9565/session/x"}
        ), patch.object(workers.browser_bidi, "BidiJsonConnection", return_value=connection), patch.object(
            workers, "_browser_bidi_context", return_value="ctx"
        ), patch.object(workers, "_browser_bidi_decode_state", return_value=expected), patch.object(
            workers, "_browser_bidi_evaluate", return_value=json.dumps({"role": "heading", "name": "Changed heading"})
        ):
            adapter = workers.ChromeWebDriverBidiAdapter({}, timeout_seconds=10)
            with self.assertRaisesRegex(RuntimeError, "stale-snapshot"):
                adapter.perform_local_ui_effect(
                    {"action_kind": "scroll_into_view"},
                    expected_state=expected,
                    expected_element=element,
                )


if __name__ == "__main__":
    unittest.main()
