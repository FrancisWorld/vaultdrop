from dataclasses import dataclass

from .auth import PasswordService
from .config import Settings
from .database import Database
from .maintenance import Maintenance
from .ratelimit import AttemptLimiter
from .s3 import S3Service
from .services.accounts import AccountService
from .services.files import FileService
from .services.shares import ShareService
from .services.uploads import UploadService


@dataclass
class Container:
    """Every long-lived collaborator, built once per application instance."""

    settings: Settings
    database: Database
    s3: S3Service
    accounts: AccountService
    uploads: UploadService
    shares: ShareService
    files: FileService
    maintenance: Maintenance


def build_container(settings: Settings) -> Container:
    database = Database(settings.database_url)
    s3 = S3Service(settings)
    passwords = PasswordService(settings)
    window = settings.attempt_window_seconds
    uploads = UploadService(database, s3, settings)
    return Container(
        settings=settings,
        database=database,
        s3=s3,
        accounts=AccountService(
            database,
            passwords,
            AttemptLimiter(database, settings.login_attempt_limit, window),
            settings,
        ),
        uploads=uploads,
        shares=ShareService(
            database,
            s3,
            passwords,
            AttemptLimiter(database, settings.password_attempt_limit, window),
            settings,
        ),
        files=FileService(database, s3),
        maintenance=Maintenance(database, uploads, window),
    )
