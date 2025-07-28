from datetime import datetime, timedelta
from typing import Iterable, Optional, Sequence, Union, Dict, Any

from jwtifypy.query import JWTQuery
from jwtifypy.utils import MISSING


class JWTManager:
    """
    Менеджер для работы с JWT, предоставляющий удобные классовые методы
    для создания, декодирования токенов и выбора ключа.

    Внутри использует класс JWTQuery для выполнения операций.
    """

    @classmethod
    def _query_manager(cls) -> JWTQuery:
        """
        Получить новый экземпляр JWTQuery для выполнения операций.

        Returns:
            JWTQuery: Новый объект для работы с JWT.
        """
        return JWTQuery()

    @classmethod
    def using(cls, key: Optional[str] = None) -> JWTQuery:
        """
        Выбрать ключ по имени для последующих операций.

        Args:
            key (Optional[str]): Имя ключа из хранилища JWTStore.
                Если None — используется ключ 'default'.

        Returns:
            JWTQuery: Объект JWTQuery, связанный с выбранным ключом.
        """
        return cls._query_manager().using(key)

    @classmethod
    def with_issuer(
        cls,
        issuer_for_encoding: str = MISSING,
        issuer_for_decoding: Optional[Union[str, Sequence[str]]] = MISSING,
    ) -> JWTQuery:
        """
        Установить издателя (issuer) для кодирования и декодирования токенов.

        Args:
            issuer_for_encoding (str): Значение issuer при создании токена.
            issuer_for_decoding (Optional[Union[str, Sequence[str]]]): Значение issuer при проверке токена.
                Если None — используется значение для кодирования.

        Returns:
            JWTQuery: Объект JWTQuery с установленным issuer.
        """
        return cls._query_manager().with_issuer(
            issuer_for_encoding=issuer_for_encoding,
            issuer_for_decoding=issuer_for_decoding,
        )

    @classmethod
    def with_audience(
        cls,
        audience_for_encoding: Optional[str] = MISSING,
        audience_for_decoding: Optional[Union[str, Iterable[str]]] = MISSING,
    ) -> JWTQuery:
        """
        Установить аудиторию (audience) для кодирования и декодирования токенов.

        Args:
            audience_for_encoding (Optional[str]): Значение audience при создании токена.
            audience_for_decoding (Optional[Union[str, Iterable[str]]]): Значение audience при проверке токена.
                Если None — используется значение для кодирования.

        Returns:
            JWTQuery: Объект JWTQuery с установленным audience.
        """
        return cls._query_manager().with_audience(
            audience_for_encoding=audience_for_encoding,
            audience_for_decoding=audience_for_decoding,
        )

    @classmethod
    def create_token(
        cls,
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
            fresh (Optional[bool]): Флаг "свежести" токена.
            issuer (Optional[str]): Издатель токена.
            audience (Optional[str]): Аудитория токена.
            **user_claims: Дополнительные пользовательские поля для payload.

        Returns:
            str: Закодированный JWT токен.
        """
        return cls._query_manager().create_token(
            subject=subject,
            token_type=token_type,
            expires_delta=expires_delta,
            fresh=fresh,
            issuer=issuer,
            audience=audience,
            **user_claims
        )

    @classmethod
    def create_access_token(
        cls,
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
            expires_delta (Optional[timedelta]): Время жизни токена, по умолчанию 15 минут.
            fresh (bool): Флаг "свежести" токена.
            issuer (Optional[str]): Издатель токена.
            audience (Optional[str]): Аудитория токена.

        Returns:
            str: Access JWT токен.
        """
        return cls._query_manager().create_access_token(
            subject=subject,
            expires_delta=expires_delta,
            fresh=fresh,
            issuer=issuer,
            audience=audience
        )

    @classmethod
    def create_refresh_token(
        cls,
        subject: Union[str, int],
        expires_delta: Optional[timedelta] = timedelta(days=31),
        issuer: Optional[str] = None,
        audience: Optional[str] = None
    ) -> str:
        """
        Создать refresh-токен с дефолтными параметрами.

        Args:
            subject (Union[str, int]): Субъект токена.
            expires_delta (Optional[timedelta]): Время жизни токена, по умолчанию 31 день.
            issuer (Optional[str]): Издатель токена.
            audience (Optional[str]): Аудитория токена.

        Returns:
            str: Refresh JWT токен.
        """
        return cls._query_manager().create_refresh_token(
            subject=subject,
            expires_delta=expires_delta,
            issuer=issuer,
            audience=audience
        )

    @classmethod
    def decode_token(
        cls,
        token: str,
        options: Optional[Dict[str, Any]] = None,
        audience: Optional[Union[str, Iterable[str]]] = None,
        issuer: Optional[Union[str, Sequence[str]]] = None,
        leeway: Union[float, timedelta] = 0,
    ) -> Dict[str, Any]:
        """
        Декодировать и проверить JWT токен.

        Args:
            token (str): JWT токен для декодирования.
            options (Optional[Dict[str, Any]]): Опции декодирования PyJWT.
            audience (Optional[Union[str, Iterable[str]]]): Ожидаемая аудитория токена.
            issuer (Optional[Union[str, Sequence[str]]]): Ожидаемый издатель токена.
            leeway (Union[float, timedelta]): Допустимое смещение времени при проверке срока действия.

        Returns:
            Dict[str, Any]: Расшифрованный payload токена.

        Raises:
            jwt.ExpiredSignatureError: Если срок действия токена истек.
            jwt.InvalidTokenError: Если токен недействителен по другим причинам.
        """
        return cls._query_manager().decode_token(
            token=token,
            options=options,
            audience=audience,
            issuer=issuer,
            leeway=leeway
        )
