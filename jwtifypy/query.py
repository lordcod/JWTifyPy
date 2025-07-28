import copy
from datetime import datetime, timedelta, timezone
import uuid
import jwt
from typing import Iterable, Optional, Sequence, Union, Dict, Any

from jwtifypy.key import JWTKey
from jwtifypy.store import JWTStore
from jwtifypy.utils import MISSING


class JWTQuery:
    def __init__(self):
        """
        Инициализирует объект JWTQuery с ключом по умолчанию из JWTStore.
        Также инициализирует параметры issuer и audience для кодирования и декодирования.
        """
        self.__key = None
        self._issuer_encoding: Optional[str] = None
        self._issuer_decoding: Optional[Union[str, Sequence[str]]] = None
        self._audience_encoding: Optional[str] = None
        self._audience_decoding: Optional[Union[str, Iterable[str]]] = None

    @property
    def key(self):
        if self.__key is None:
            return JWTStore.get_key('default')
        return self.__key

    @key.setter
    def key(self, value: Union[str, JWTKey]):
        if isinstance(value, JWTKey):
            self.__key = value
        else:
            self.__key = JWTStore.get_key(value)

    def copy(self):
        """
        Создает поверхностную копию текущего объекта JWTQuery.

        Returns:
            JWTQuery: Новый объект с таким же состоянием.
        """
        return copy.copy(self)

    def using(self, key: Optional[str] = None):
        """
        Выбирает ключ для работы с JWT по его имени.

        Args:
            key (Optional[str]): Имя ключа из хранилища JWTStore. 
                Если None — используется ключ 'default'.

        Returns:
            JWTQuery: self (для цепочного вызова).
        """
        if key is None:
            self.key = JWTStore.get_key('default')
        else:
            self.key = JWTStore.get_key(key)
        return self

    def with_issuer(
        self,
        issuer_for_encoding: str = MISSING,
        issuer_for_decoding: Optional[Union[str, Sequence[str]]] = None,
    ):
        """
        Устанавливает значение издателя (issuer) для кодирования и декодирования токена.

        Args:
            issuer_for_encoding (str): Значение issuer при создании токена.
            issuer_for_decoding (Optional[Union[str, Sequence[str]]]): Ожидаемое значение issuer при проверке токена.
                Если None — используется значение для кодирования.

        Raises:
            ValueError: Если ни один из параметров не передан.

        Returns:
            JWTQuery: self (для цепочного вызова).
        """
        if issuer_for_encoding is not MISSING:
            self._issuer_encoding = issuer_for_encoding
        if issuer_for_decoding is None:
            self._issuer_decoding = self._issuer_encoding
        else:
            self._issuer_decoding = issuer_for_decoding
        return self

    def with_audience(
        self,
        audience_for_encoding: Optional[str] = MISSING,
        audience_for_decoding: Optional[Union[str, Iterable[str]]] = None,
    ):
        """
        Устанавливает значение аудитории (audience) для кодирования и декодирования токена.

        Args:
            audience_for_encoding (Optional[str]): Значение audience при создании токена.
            audience_for_decoding (Optional[Union[str, Iterable[str]]]): Ожидаемое значение audience при проверке токена.
                Если None — используется значение для кодирования.

        Raises:
            ValueError: Если ни один из параметров не передан.

        Returns:
            JWTQuery: self (для цепочного вызова).
        """
        if audience_for_encoding is not MISSING:
            self._audience_encoding = audience_for_encoding
        if audience_for_decoding is None:
            self._audience_decoding = self._audience_encoding
        else:
            self._audience_decoding = audience_for_decoding
        return self

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
        Создает JWT токен с заданными параметрами и дополнительными пользовательскими полями.

        Args:
            subject (Union[str, int]): Идентификатор субъекта токена (например, user_id).
            token_type (str): Тип токена (например, "access" или "refresh").
            expires_delta (Optional[Union[timedelta, int]]): Время жизни токена — либо timedelta, либо число секунд.
            fresh (Optional[bool]): Флаг, указывающий на "свежесть" токена.
            issuer (Optional[str]): Значение издателя (перекрывает установленное через with_issuer).
            audience (Optional[str]): Значение аудитории (перекрывает установленное через with_audience).
            **user_claims: Дополнительные поля для включения в payload.

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

        payload["iss"] = issuer if issuer is not None else self._issuer_encoding
        payload["aud"] = audience if audience is not None else self._audience_encoding

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
        audience: Optional[Union[str, Iterable[str]]] = None,
        issuer: Optional[Union[str, Sequence[str]]] = None,
        leeway: Union[float, timedelta] = 0,
    ) -> Dict[str, Any]:
        """
        Декодирует и проверяет JWT токен, валидируя подпись, срок действия, issuer и audience.

        Args:
            token (str): JWT токен для декодирования.
            options (Optional[Dict[str, Any]]): Опции для библиотеки PyJWT (например, {"verify_exp": True}).
            audience (Optional[Union[str, Iterable[str]]]): Ожидаемое значение audience.
            issuer (Optional[Union[str, Sequence[str]]]): Ожидаемое значение issuer.
            leeway (Union[float, timedelta]): Допустимое смещение времени при проверке срока действия.

        Returns:
            Dict[str, Any]: Расшифрованный payload токена.

        Raises:
            jwt.ExpiredSignatureError: Если токен просрочен.
            jwt.InvalidTokenError: Если токен невалиден по другим причинам.
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

        audience = audience if audience else self._audience_decoding
        issuer = issuer if issuer else self._issuer_decoding

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
        audience: Optional[Union[str, Iterable[str]]] = None,
        issuer: Optional[Union[str, Sequence[str]]] = None,
    ) -> str:
        """
        Создает access JWT токен с дефолтным временем жизни 15 минут.

        Args:
            subject (Union[str, int]): Идентификатор субъекта токена.
            expires_delta (Optional[timedelta]): Время жизни токена.
            fresh (bool): Флаг "свежести" токена.
            issuer (Optional[Union[str, Sequence[str]]]): Издатель токена.
            audience (Optional[Union[str, Iterable[str]]]): Аудитория токена.

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
        audience: Optional[Union[str, Iterable[str]]] = None,
        issuer: Optional[Union[str, Sequence[str]]] = None,
    ) -> str:
        """
        Создает refresh JWT токен с дефолтным временем жизни 31 день.

        Args:
            subject (Union[str, int]): Идентификатор субъекта токена.
            expires_delta (Optional[timedelta]): Время жизни токена.
            issuer (Optional[Union[str, Sequence[str]]]): Издатель токена.
            audience (Optional[Union[str, Iterable[str]]]): Аудитория токена.

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
