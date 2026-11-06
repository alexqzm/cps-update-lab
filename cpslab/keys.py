"""Ключи ролей стенда.

cosign (ECDSA P-256): builder — сборочный агент, independent_builder — контрольная пересборка,
vendor — подпись пакета, repository — журнал хранилища, reviewer, sast и tester — рецензирование,
анализ и испытания, attacker — собственный ключ нарушителя. OpenPGP (GnuPG): vendor подписывает
коммиты и теги, attacker — теги своей ветки. Ed25519: vendor_boot — подпись образа, которую
проверяет загрузчик устройства; gate — квитанции и VSA гейта.

Закрытые ключи лежат в keys/private, открытые якоря доверия получателя — в keys/public.
Ключи учебные и создаются заново при инициализации стенда.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
from pathlib import Path

from .receipt import load_key, new_key, raw_public
from .util import cosign, cosign_env, gpg, run

COSIGN_ROLES = ("builder", "independent_builder", "vendor", "repository", "reviewer", "sast", "tester",
                "attacker")
ED25519_ROLES = ("gate", "vendor_boot")
GPG_IDS = {"vendor": "Учебный поставщик <vendor@cpslab.invalid>",
           "attacker": "Нарушитель <attacker@cpslab.invalid>"}


def _short_home(path: Path) -> Path:
    """Сокеты gpg-agent лежат в каталоге связки, а длина пути сокета ограничена 108 байтами.
    Для длинного пути делается короткая символическая ссылка во временном каталоге."""
    if len(str(path)) <= 60:
        return path
    link = Path(tempfile.gettempdir()) / f"cpslab-gpg-{hashlib.sha256(str(path).encode()).hexdigest()[:10]}"
    if not link.is_symlink() or link.resolve() != path.resolve():
        link.unlink(missing_ok=True)
        link.symlink_to(path, target_is_directory=True)
    return link


class Keys:
    def __init__(self, home: Path):
        self.home = Path(home)
        self.private = self.home / "keys" / "private"
        self.public = self.home / "keys" / "public"
        self.gnupg_dir = self.home / "keys" / "gnupg"

    @property
    def gnupg(self) -> Path:
        self.gnupg_dir.mkdir(parents=True, exist_ok=True)
        self.gnupg_dir.chmod(0o700)
        return _short_home(self.gnupg_dir)

    # --- создание ---
    def init(self) -> "Keys":
        self.private.mkdir(parents=True, exist_ok=True)
        self.public.mkdir(parents=True, exist_ok=True)
        for role in COSIGN_ROLES:
            if not (self.private / f"{role}.key").exists():
                run([cosign(), "generate-key-pair", "--output-key-prefix", role], cwd=self.private, env=cosign_env())
            if role != "attacker":
                shutil.copy(self.private / f"{role}.pub", self.public / f"{role}.pub")
        for who, uid in GPG_IDS.items():
            if not (self.private / f"gpg_{who}.fpr").exists():
                run([gpg(), "--homedir", self.gnupg, "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
                     "--quick-gen-key", uid, "ed25519", "sign", "never"])
                out = run([gpg(), "--homedir", self.gnupg, "--batch", "--with-colons", "--list-keys", uid]).stdout
                fpr = next(ln.split(":")[9] for ln in out.splitlines() if ln.startswith("fpr:"))
                (self.private / f"gpg_{who}.fpr").write_text(fpr + "\n")
        exported = run([gpg(), "--homedir", self.gnupg, "--batch", "--armor", "--export", self.fpr("vendor")]).stdout
        (self.public / "tag_signers.asc").write_text(exported)
        for role in ED25519_ROLES:
            if not (self.private / f"{role}.pem").exists():
                new_key(self.private / f"{role}.pem")
            (self.public / f"{role}.pk").write_text(self.ed25519_pk(role).hex() + "\n")
        return self

    def close(self) -> None:
        """Остановить gpg-agent связки стенда (нужно в тестах и при удалении каталога)."""
        if self.gnupg_dir.exists() and shutil.which("gpgconf"):
            run(["gpgconf", "--homedir", self.gnupg, "--kill", "all"], check=False)

    # --- доступ ---
    def cosign_key(self, role: str) -> Path:
        return self.private / f"{role}.key"

    def cosign_pub(self, role: str) -> Path:
        return self.private / f"{role}.pub"

    def fpr(self, who: str) -> str:
        return (self.private / f"gpg_{who}.fpr").read_text().strip()

    def ed25519(self, role: str):
        return load_key(self.private / f"{role}.pem")

    def ed25519_pk(self, role: str) -> bytes:
        return raw_public(self.ed25519(role).public_key())

    def gate_key(self):
        return self.ed25519("gate")

    def gate_pk(self) -> bytes:
        return self.ed25519_pk("gate")

    def gpg_env(self) -> dict:
        env = dict(os.environ)
        env["GNUPGHOME"] = str(self.gnupg)
        return env
