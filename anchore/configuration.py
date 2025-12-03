import os
import shutil
import tarfile
import datetime
from pathlib import Path
import yaml
from importlib.resources import files
import filecmp


from anchore.util.tools import load_and_merge


class AnchoreConfiguration:
    """
    Python 3.10+ Anchore configuration handler.
    Path-agnostic, works for env override, project-relative, or system install.
    """

    # ---------------------------------------------------------
    # Determine Anchore data directory
    # ---------------------------------------------------------
    _anchore_env = os.getenv("ANCHOREDATADIR")
    if _anchore_env:
        DEFAULT_ANCHORE_DATA_DIR = Path(_anchore_env)
    else:
        # Use project-relative directory if no env var set
        DEFAULT_ANCHORE_DATA_DIR = Path.cwd() / "anchore"

    DEFAULT_CONFIG_DIR = DEFAULT_ANCHORE_DATA_DIR / "conf"
    DEFAULT_CONFIG_FILE = DEFAULT_CONFIG_DIR / "config.yaml"
    DEFAULT_TMP_DIR = DEFAULT_ANCHORE_DATA_DIR / "anchoretmp"

    # Package resource locations
    EXAMPLE_CONFIG_DIR = files("anchore") / "conf"
    EXAMPLE_CONFIG_FILE = files("anchore") / "conf" / "config.yaml"
    DEFAULT_PKG_DIR = files("anchore")
    DEFAULT_SCRIPTS_DIR = files("anchore") / "anchore-modules"
    DEFAULT_ANON_ANCHORE_USERNAME = 'anon@ancho.re'
    DEFAULT_ANON_ANCHORE_PASSWORD = 'pbiU2RYZ2XrmYQ'
    DEFAULT_ANCHORE_CLIENT_URL = 'https://ancho.re/v1/account/users'
    DEFAULT_ANCHORE_TOKEN_URL = 'https://ancho.re/oauth/token'
    DEFAULT_ANCHORE_FEEDS_URL = 'https://ancho.re/v1/service/feeds'
    DEFAULT_ANCHORE_POLICY_URL = 'https://ancho.re/v1/service/policies/policy'
    DEFAULT_ANCHORE_AUTH_CONN_TIMEOUT = 10
    DEFAULT_ANCHORE_AUTH_MAX_RETRIES = 3
    DEFAULT_ANCHORE_FEEDS_CONN_TIMEOUT = 45
    DEFAULT_ANCHORE_FEEDS_MAX_RETRIES = 3
    DEFAULT_ANCHORE_POLICY_CONN_TIMEOUT = 45
    DEFAULT_ANCHORE_POLICY_MAX_RETRIES = 3
    DEFAULT_ANCHORE_DB_DRIVER = "anchore_image_db_fs"
    DEFAULT_ANCHORE_SQUASH_DRIVER = "docker_export"

    try:
        DEFAULT_EXTRASCRIPTS_DIR = files("anchore-modules")
    except ModuleNotFoundError:
        DEFAULT_EXTRASCRIPTS_DIR = None

    DEFAULTS = {
        "anchore_data_dir": str(DEFAULT_ANCHORE_DATA_DIR),
        "anchore_db_driver": "anchore_image_db_fs",
        "feeds_dir": "feeds",
        "feeds_url": "https://ancho.re/v1/service/feeds",
        "feeds_conn_timeout": 45,
        "feeds_max_retries": 3,
        "policy_dir": "policy",
        "policy_url": "https://ancho.re/v1/service/policies/policy",
        "policy_conn_timeout": 45,
        "policy_max_retries": 3,
        "image_data_store": "data",
        "tmpdir": str(DEFAULT_TMP_DIR),
        "pkg_dir": str(DEFAULT_PKG_DIR),
        "scripts_dir": str(DEFAULT_SCRIPTS_DIR),
        "user_scripts_dir": "user-scripts",
        "extra_scripts_dir": str(DEFAULT_EXTRASCRIPTS_DIR) if DEFAULT_EXTRASCRIPTS_DIR else None,
        "docker_conn": "unix://var/run/docker.sock",
        "docker_conn_timeout": "120",
        "anchore_client_url": "https://ancho.re/v1/account/users",
        "anchore_token_url": "https://ancho.re/oauth/token",
        "anchore_auth_conn_timeout": 10,
        "anchore_auth_max_retries": 3,
        "squash_driver": "docker_export"
    }

    # ---------------------------------------------------------
    def __init__(self, cliargs=None):
        self.cliargs = cliargs or {}

        # Find or create config file
        self.config_dir, self.config_file = self.find_config_file()

        # Load + merge configuration
        self.data = load_and_merge(
            file_path=str(self.config_file),
            defaults=self.DEFAULTS
        )

        # Apply CLI overrides if any
        for k, v in self.cliargs.get("config_overrides", {}).items():
            if k in self.data:
                self.data[k] = v

        # Ensure required directories exist
        self._prepare_paths()

    # ---------------------------------------------------------
    # Path / setup helpers
    # ---------------------------------------------------------
    def _prepare_paths(self):
        """Ensure directories exist and normalize relative paths."""
        base = Path(self.data["anchore_data_dir"])
        base.mkdir(parents=True, exist_ok=True)

        tmpdir = Path(self.data["tmpdir"])
        tmpdir.mkdir(parents=True, exist_ok=True)

        # Relative paths normalization
        for key in ("image_data_store", "feeds_dir", "policy_dir", "user_scripts_dir"):
            path = Path(self.data[key])
            if not path.is_absolute():
                path = base / path
            path.mkdir(parents=True, exist_ok=True)
            self.data[key] = str(path)

        # User script subdirectories
        user_scripts = Path(self.data["user_scripts_dir"])
        for d in ["analyzers", "gates", "queries", "multi-queries", "shell-utils"]:
            (user_scripts / d).mkdir(exist_ok=True)

        # Sync shell-utils scripts
        self._sync_shell_utils(
            src=Path(self.data["scripts_dir"]) / "shell-utils",
            dest=Path(self.data["user_scripts_dir"]) / "shell-utils"
        )

    def _sync_shell_utils(self, src: Path, dest: Path):
        """Copy updated shell-utils files into user directory."""
        if not src.exists():
            return

        cmp = filecmp.dircmp(src, dest)
        for f in cmp.left_only + cmp.diff_files:
            shutil.copy(src / f, dest / f)

    # ---------------------------------------------------------
    # Config file handling
    # ---------------------------------------------------------
    def find_config_file(self):
        """Locate or create config file."""
        default_dir = self.DEFAULT_CONFIG_DIR
        default_file = self.DEFAULT_CONFIG_FILE

        # 1. Project/home config exists
        if default_file.exists():
            return default_dir, default_file

        # 2. System-wide config exists
        etc_file = Path("/etc/anchore/config.yaml")
        if etc_file.exists():
            return etc_file.parent, etc_file

        # 3. Copy example config
        default_dir.mkdir(parents=True, exist_ok=True)
        for entry in self.EXAMPLE_CONFIG_DIR.iterdir():
            dest = default_dir / entry.name
            if not dest.exists():
                shutil.copy(str(entry), str(dest))

        return default_dir, default_file

    # ---------------------------------------------------------
    # Dict-like access
    # ---------------------------------------------------------
    def __getitem__(self, item):
        return self.data[item]

    def __setitem__(self, key, value):
        self.data[key] = value

    def __str__(self):
        return yaml.safe_dump(self.data)

    # ---------------------------------------------------------
    # Backup / restore
    # ---------------------------------------------------------
    def backup(self, destdir="/tmp"):
        destdir = Path(destdir)
        dateval = datetime.datetime.now().isoformat("-")
        backupfile = destdir / f"anchore-backup-{dateval}.tar.gz"

        data_dir = Path(self.data["anchore_data_dir"])
        image_dir = Path(self.data["image_data_store"])

        with tarfile.open(backupfile, "w:gz") as tf:
            tf.add(str(data_dir))
            if data_dir not in image_dir.parents:
                tf.add(str(image_dir))
            if data_dir not in self.config_dir.parents:
                tf.add(str(self.config_dir))

        return str(backupfile)

    def restore(self, dest_root, backup_file):
        dest_root = Path(dest_root)
        if not dest_root.exists():
            raise RuntimeError("Destination root directory does not exist")

        backup_file = Path(backup_file)
        if not backup_file.exists():
            raise RuntimeError(f"Backup file {backup_file} not found")

        with tarfile.open(backup_file, "r:gz") as tf:
            tf.extractall(path=dest_root)

        return str(dest_root)
