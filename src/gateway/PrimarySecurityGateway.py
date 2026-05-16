import re
import hmac
import hashlib
import unicodedata
from typing import Optional, List


class TaskSpecification:
    def __init__(self, task_id: str, domains: List[str], payload: str, token: str):
        self.task_id          = task_id
        self.required_domains = domains
        self.payload          = payload
        self.auth_token       = token   # token de sessão HMAC — não o segredo


class PrimarySecurityGateway:
    """
    Camada 1: Gateway de Borda e Sanitizador Especialista.
    A primeira linha de defesa. Nenhuma linguagem natural passa daqui.
    """

    HOSTILE_PATTERNS = [
        # ── Português ──────────────────────────────────────────────────────
        r"ignore as (regras|instrucoes)",
        r"esqueca (tudo|o que foi dito)",
        r"modo (desenvolvedor|root|livre)",
        r"voce (agora|sempre) e",
        r"bypasse",
        r"sem restricoes",
        r"activa (o )?(modo|protocolo)",
        # ── Inglês ─────────────────────────────────────────────────────────
        r"ignore (previous|all|your) (instructions?|rules?|guidelines?)",
        r"forget (everything|all|your instructions)",
        r"you are now",
        r"pretend (you are|to be)",
        r"act as (an? |a )?(unfiltered|unrestricted|free)",
        r"(developer|jailbreak|god|dan) mode",
        r"bypass (the )?(filter|security|restrictions?)",
        r"disregard (your )?(instructions?|rules?)",
        r"override (your )?(instructions?|safety)",
    ]

    def __init__(self, system_secret: str):
        self._secret = system_secret   # privado — nunca exposto directamente

    @staticmethod
    def _normalize(text: str) -> str:
        """
        Normalização Unicode: converte "ígnoré ás regras" → "ignore as regras".
        Impede obfuscação por substituição de caracteres acentuados.
        """
        nfkd = unicodedata.normalize("NFKD", text)
        ascii_text = nfkd.encode("ascii", errors="ignore").decode("ascii")
        return ascii_text.lower()

    def _scan_for_injection(self, raw_text: str) -> bool:
        """Verificação determinística por regex sobre texto normalizado."""
        normalized = self._normalize(raw_text)
        for pattern in self.HOSTILE_PATTERNS:
            if re.search(pattern, normalized):
                return True
        return False

    def _mint_session_token(self, task_id: str) -> str:
        """
        Gera um token de sessão HMAC-SHA256(segredo, task_id).
        O segredo nunca viaja — apenas o token derivado.
        """
        return hmac.new(
            self._secret.encode(),
            task_id.encode(),
            hashlib.sha256
        ).hexdigest()[:16].upper()

    def intercept_and_process(
        self, raw_user_input: str, target_domains: List[str]
    ) -> Optional[TaskSpecification]:
        print("\n[GATEWAY PRIMÁRIO] -> Iniciando varredura de segurança na entrada bruta...")

        if self._scan_for_injection(raw_user_input):
            print("⚠️ [GATEWAY CRITICAL] -> Padrão hostil detectado. Tráfego abortado na borda.")
            return None

        clean_payload = raw_user_input.strip()
        task_hash     = hashlib.sha256(clean_payload.encode()).hexdigest()[:6].upper()
        task_id       = f"TSK-{task_hash}"
        session_token = self._mint_session_token(task_id)

        print(f"[GATEWAY PRIMÁRIO] -> Tráfego auditado e limpo. Encapsulando [{task_id}].")
        return TaskSpecification(
            task_id=task_id,
            domains=target_domains,
            payload=clean_payload,
            token=session_token
        )

    def verify_token(self, task_id: str, token: str) -> bool:
        """
        Verifica um token recebido pelo Manager.
        Usa hmac.compare_digest — resistente a timing attacks.
        """
        expected = self._mint_session_token(task_id)
        return hmac.compare_digest(expected, token)

