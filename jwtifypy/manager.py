from datetime import datetime, timedelta, timezone
import uuid
import jwt
from typing import Optional, Union, Dict, Any

from jwtifypy.store import JWTStore


class JWTManager:
    """
    Менеджер JWT токенов для создания и декодирования JWT с поддержкой разных ключей.
    """

    def __init__(self, key: Optional[str] = None):
        """
        Инициализация менеджера с указанным ключом.

        Args:
            key (Optional[str]): Имя ключа для подписи JWT. Если не указан, используется 'default'.
        """
        if key is None:
            key = 'default'
        self.key = JWTStore.get_key(key)

    def create_token(
        self,
        subject: Union[str, int],
        token_type: str,
        expires_delta: Optional[Union[timedelta, int]] = None,
        fresh: Optional[bool] = None,
        issuer: Optional[str] = None,
        audience: Optional[str] = None,
        **user_claims: Any
    ) -> str:
        """
        Создать JWT токен с произвольными параметрами.

        Args:
            subject (Union[str, int]): Субъект токена (например, идентификатор пользователя).
            token_type (str): Тип токена ('access', 'refresh' и т.п.).
            expires_delta (Optional[Union[timedelta, int]]): Время жизни токена (timedelta или количество секунд).
            fresh (Optional[bool]): Является ли токен "свежим".
            issuer (Optional[str]): Издатель токена.
            audience (Optional[str]): Аудитория токена.
            additional_claims (Optional[Dict[str, Any]]): Дополнительные пользовательские поля в payload.

        Returns:
            str: Закодированный JWT токен.
        """
        now = datetime.now(tz=timezone.utc)
        jwt_id = str(uuid.uuid4())

        payload = {
            "type": token_type,
            "sub": subject,
            "jti": jwt_id,
            "iat": now,
            "nbf": now,
        }

        if expires_delta is not None:
            if isinstance(expires_delta, int):
                expires_delta = timedelta(seconds=expires_delta)
            payload["exp"] = now + expires_delta

        if fresh is not None:
            payload["fresh"] = fresh

        if issuer is not None:
            payload["iss"] = issuer

        if audience is not None:
            payload["aud"] = audience

        if user_claims:
            payload.update(user_claims)

        token = jwt.encode(
            payload,
            self.key.get_private_key(),
            algorithm=self.key.algorithm
        )
        return token

    def decode_token(
        self,
        token: str,
        options: Optional[Dict[str, Any]] = None,
        audience: Optional[str] = None,
        issuer: Optional[str] = None,
        leeway: Union[float, timedelta] = 0,
    ) -> Dict[str, Any]:
        """
        Декодировать и проверить JWT токен.

        Args:
            token (str): JWT токен для декодирования.
            verify_exp (bool): Проверять ли срок годности токена (exp).
            audience (Optional[str]): Ожидаемая аудитория токена.
            issuer (Optional[str]): Ожидаемый издатель токена.

        Returns:
            Dict[str, Any]: Расшифрованный payload токена.

        Raises:
            jwt.ExpiredSignatureError: Если срок действия токена истёк.
            jwt.InvalidTokenError: Если токен недействителен по другим причинам.
        """
        base_options = JWTStore.get_options()
        if base_options and options:
            base_options.update(options)
        elif options and not base_options:
            base_options = options

        base_leeway = JWTStore.get_leeway()
        if leeway != 0:
            base_leeway = leeway
        elif base_leeway is None:
            base_leeway = 0

        return jwt.decode(
            token,
            self.key.get_public_key(),
            algorithms=[self.key.algorithm],
            audience=audience,
            issuer=issuer,
            options=base_options,
            leeway=base_leeway
        )

    def create_access_token(
        self,
        subject: Union[str, int],
        expires_delta: Optional[timedelta] = timedelta(minutes=15),
        fresh: bool = False,
        issuer: Optional[str] = None,
        audience: Optional[str] = None
    ) -> str:
        """
        Создать access-токен с дефолтными параметрами.

        Args:
            subject (Union[str, int]): Субъект токена.
            expires_delta (Optional[timedelta]): Время жизни токена. По умолчанию 15 минут.
            fresh (bool): Флаг свежести токена.
            issuer (Optional[str]): Издатель токена.
            audience (Optional[str]): Аудитория токена.
        Returns:
            str: Access JWT токен.
        """
        return self.create_token(
            subject=subject,
            token_type="access",
            expires_delta=expires_delta,
            fresh=fresh,
            issuer=issuer,
            audience=audience
        )

    def create_refresh_token(
        self,
        subject: Union[str, int],
        expires_delta: Optional[timedelta] = timedelta(days=31),
        issuer: Optional[str] = None,
        audience: Optional[str] = None
    ) -> str:
        """
        Создать refresh-токен с дефолтными параметрами.

        Args:
            subject (Union[str, int]): Субъект токена.
            expires_delta (Optional[timedelta]): Время жизни токена. По умолчанию 31 день.
            issuer (Optional[str]): Издатель токена.
            audience (Optional[str]): Аудитория токена.

        Returns:
            str: Refresh JWT токен.
        """
        return self.create_token(
            subject=subject,
            token_type="refresh",
            expires_delta=expires_delta,
            issuer=issuer,
            audience=audience
        )
