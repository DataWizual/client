import logging
from typing import Dict, Any

# Import all available advisors
from auditor.ai.rule_based import RuleBasedAdvisor
from auditor.ai.external_llm import ExternalLLMAdvisor
from auditor.ai.local_llm import LocalLLMAdvisor
from auditor.ai.base import AIAdvisor

logger = logging.getLogger(__name__)


class AIAdvisorFactory:

    @staticmethod
    def create(
        ai_config: Dict[str, Any], global_config: Dict[str, Any] = None
    ) -> AIAdvisor:
        # RCA Fix: Integrate global safety constraints
        global_config = global_config or {}
        is_offline = global_config.get("scanner", {}).get("offline_mode", False)
        # Дефолт False — явное поведение: внешний LLM разрешён если не указано иное.
        # Пользователь должен явно включить offline_mode: true чтобы заблокировать внешние вызовы.

        # Get mode from config, default to rule_based for stability
        mode = ai_config.get("mode", "rule_based")

        # RCA: Safety Lock - force rule_based if offline_mode is active
        if is_offline and mode == "external":
            logger.error(
                "🛡️ Security Policy Violation: 'external' advisory access blocked while offline_mode=true."
            )
            logger.warning(
                "🔄 Advisory Core: Forcing 'deterministic' mode for data safety."
            )
            mode = "rule_based"

        logger.info(f"⚙️ Expert Engine: Initializing advisor mode: '{mode}'")

        if mode == "external":
            return ExternalLLMAdvisor(ai_config)

        if mode == "local":
            return LocalLLMAdvisor(ai_config)

        # Fallback to deterministic rule-based logic
        if mode != "rule_based":
            logger.warning(
                f"⚠️ Invalid analysis mode '{mode}'. Falling back to 'rule_based'."
            )

        return RuleBasedAdvisor()
