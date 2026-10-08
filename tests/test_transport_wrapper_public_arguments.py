from __future__ import annotations

import types
import unittest
from unittest.mock import patch

from tests.test_operator_contract import _load_operator_module


class TransportWrapperPublicArgumentsTests(unittest.TestCase):
    def test_wrapper_keeps_public_transport_arguments_and_domain_policy_arguments(
        self,
    ) -> None:
        operator = _load_operator_module()
        public_arguments = {
            "slot": 1,
            "reason": "Exercise signed mutation",
            "user_intent": "Verify the transport and policy boundary",
        }
        domain_arguments = {"slot": 1}
        domain_calls: list[str] = []

        async def domain_call(name, arguments, *args, **kwargs):
            domain_calls.append(str(name))
            return {"called": True}

        tool = types.SimpleNamespace(
            is_async=True,
            context_kwarg=None,
            annotations=types.SimpleNamespace(readOnlyHint=False),
            fn_metadata=types.SimpleNamespace(
                arg_model=types.SimpleNamespace(model_fields={"slot": object()})
            ),
        )
        operator.mcp._tool_manager.call_tool = domain_call
        operator.mcp._tool_manager.get_tool = lambda _name: tool
        transport_evidence = {
            "runtime_binding_sha256": "a" * 64,
            "consumption_receipt_sha256": "b" * 64,
        }

        with (
            patch.object(
                operator.base,
                "_transport_authorize_connector_tool",
            ) as authorize,
            patch.object(
                operator,
                "_require_transport_roundtrip_for_tool",
                return_value=transport_evidence,
            ) as require_transport,
            patch.object(
                operator.grabowski_effect_interceptor,
                "fence_enforcement_required",
                return_value=False,
            ),
            patch.object(
                operator.grabowski_effect_interceptor,
                "admit_mutation",
                return_value=None,
            ) as admit_mutation,
        ):
            operator._configure_http_runtime()
            result = operator.asyncio.run(
                operator.mcp._tool_manager.call_tool("write", public_arguments)
            )

        self.assertEqual(result, {"called": True})
        authorize.assert_called_once()
        self.assertEqual(authorize.call_args.args[1], "write")
        self.assertEqual(authorize.call_args.args[2], domain_arguments)

        require_transport.assert_called_once()
        self.assertEqual(
            require_transport.call_args.kwargs["arguments"],
            domain_arguments,
        )
        self.assertEqual(
            require_transport.call_args.kwargs["transport_arguments"],
            public_arguments,
        )

        admit_mutation.assert_called_once()
        self.assertEqual(
            admit_mutation.call_args.kwargs["arguments"],
            domain_arguments,
        )
        self.assertEqual(domain_calls, ["write"])


if __name__ == "__main__":
    unittest.main()
