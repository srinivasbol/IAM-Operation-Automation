import unittest

from python.iamautomation.core import IAMAutomationService
from python.iamautomation.models import Action, EntityType, IAMRequest, OperationResult
from python.iamautomation.providers.base import InMemoryDirectoryProvider


class TestIAMAutomationService(unittest.TestCase):
    def setUp(self) -> None:
        self.provider = InMemoryDirectoryProvider()
        self.service = IAMAutomationService(self.provider)

    def test_dry_run_does_not_mutate(self):
        request = IAMRequest(
            action=Action.CREATE,
            entity_type=EntityType.PRIVILEGED_ACCOUNT,
            target="Svc App 01",
            provider="mock",
            caller="tester",
            ticket_id="INC-1",
            dry_run=True,
            attributes={"name_prefix": "svc"},
        )
        result = self.service.execute(request)
        self.assertEqual("planned", result.status)
        self.assertFalse(result.changed)

    def test_create_is_idempotent(self):
        create = IAMRequest(
            action=Action.CREATE,
            entity_type=EntityType.NON_HUMAN_IDENTITY,
            target="svc-app-01",
            provider="mock",
            caller="tester",
            ticket_id="INC-2",
            dry_run=False,
            attributes={},
        )
        first = self.service.execute(create)
        second = self.service.execute(create)
        self.assertEqual("success", first.status)
        self.assertEqual("noop", second.status)

    def test_disable_enable_reset_secret(self):
        create = IAMRequest(
            action=Action.CREATE,
            entity_type=EntityType.NON_HUMAN_IDENTITY,
            target="svc-app-02",
            provider="mock",
            caller="tester",
            ticket_id="INC-3",
            dry_run=False,
            attributes={},
        )
        self.service.execute(create)

        disable = IAMRequest(
            action=Action.DISABLE,
            entity_type=EntityType.NON_HUMAN_IDENTITY,
            target="svc-app-02",
            provider="mock",
            caller="tester",
            ticket_id="INC-3",
            dry_run=False,
            attributes={"quarantine_ou": "OU=Quarantine"},
        )
        enable = IAMRequest(
            action=Action.ENABLE,
            entity_type=EntityType.NON_HUMAN_IDENTITY,
            target="svc-app-02",
            provider="mock",
            caller="tester",
            ticket_id="INC-3",
            dry_run=False,
            attributes={},
        )
        reset = IAMRequest(
            action=Action.RESET_SECRET,
            entity_type=EntityType.NON_HUMAN_IDENTITY,
            target="svc-app-02",
            provider="mock",
            caller="tester",
            ticket_id="INC-3",
            dry_run=False,
            attributes={"secret_length": 48},
        )

        self.assertEqual("success", self.service.execute(disable).status)
        self.assertEqual("success", self.service.execute(enable).status)
        reset_result = self.service.execute(reset)
        self.assertEqual("success", reset_result.status)
        self.assertTrue(reset_result.data["mustChangePasswordAtNextLogon"])
        self.assertEqual(48, len(reset_result.data["secret"]))

    def test_validation_failure_is_returned(self):
        class DenyProvider(InMemoryDirectoryProvider):
            def validate_access(self, entity_type, target):
                return OperationResult(status="error", message="access denied", changed=False)

        service = IAMAutomationService(DenyProvider())
        request = IAMRequest(
            action=Action.CREATE,
            entity_type=EntityType.PRIVILEGED_ACCOUNT,
            target="bg-admin-03",
            provider="mock",
            caller="tester",
            ticket_id="INC-4",
            dry_run=False,
            attributes={},
        )
        result = service.execute(request)
        self.assertEqual("error", result.status)
        self.assertEqual("access denied", result.message)


if __name__ == "__main__":
    unittest.main()
